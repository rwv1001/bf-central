import hashlib
import hmac
import logging
import os
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from functools import wraps

import requests
from flask import Flask, g, jsonify, request
from models import (
    CentralDevice,
    CentralUser,
    OutboundQueue,
    Site,
    SiteDeviceRegistration,
    SiteUserRegistration,
    db,
)

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ["DATABASE_URL"]
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _queue_to_site(site_id: str, event_type: str, payload: dict) -> None:
    """Append an outbound event for a site. Caller must commit."""
    db.session.add(OutboundQueue(site_id=site_id, event_type=event_type, payload=payload))


def _device_sync_payload(device: "CentralDevice", user: "CentralUser") -> dict:
    """Full user+device payload in the same shape as GET /api/v1/device."""
    return {
        "mac_address": device.mac_address,
        "email": device.user_email,
        "first_name": user.first_name if user else None,
        "last_name": user.last_name if user else None,
        "phone_number": user.phone_number if user else None,
        "assigned_vlan": device.assigned_vlan,
        "device_name": device.device_name,
        "is_wired": bool(device.is_wired),
        "connection_type": device.connection_type,
        "ssid": device.ssid,
        "device_blocked": bool(device.internet_blocked),
        "user_blocked": bool(user.blocked) if user else False,
        "network_password_hash": (user.network_password_hash or "") if user else "",
        "sync_to_all_sites": bool(getattr(user, "sync_to_all_sites", False)) if user else False,
    }


def _fan_out_synced_device(device: "CentralDevice", user: "CentralUser", exclude_site_id: str) -> int:
    """Queue an import_user_device push to every active site except the source.
    Used for users flagged sync_to_all_sites so all sites hold the record
    before the device ever connects there. Caller must commit."""
    payload = _device_sync_payload(device, user)
    count = 0
    for site in Site.query.filter_by(active=True).all():
        if site.site_id == exclude_site_id:
            continue
        _queue_to_site(site.site_id, "import_user_device", payload)
        count += 1
    return count


# ── Auth decorator ────────────────────────────────────────────────────────────

def require_site_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key", "").strip()
        if not key:
            return jsonify({"error": "Missing X-API-Key header"}), 401
        site = Site.query.filter_by(api_key_hash=_sha256(key), active=True).first()
        if not site:
            return jsonify({"error": "Invalid API key"}), 403
        site.last_seen_at = datetime.now(timezone.utc)
        db.session.commit()
        g.site = site
        return f(*args, **kwargs)
    return decorated


# ── Inbound events: site → central ───────────────────────────────────────────

@app.route("/api/v1/event", methods=["POST"])
@require_site_key
def receive_event():
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "JSON body required"}), 400

    event_type = body.get("event_type", "").strip()
    data = body.get("data") or {}

    source_site_id = body.get("source_site_id", "").strip()
    if source_site_id and source_site_id != g.site.site_id:
        logger.warning(
            "receive_event: source_site_id mismatch — body claims %r but API key identifies %r",
            source_site_id, g.site.site_id,
        )
        return jsonify({"error": "source_site_id mismatch: body says " + repr(source_site_id) + " but API key identifies " + repr(g.site.site_id)}), 400

    handlers = {
        "device_registered":   _on_device_registered,
        "device_reassigned":   _on_device_reassigned,
        "device_blocked":      _on_device_blocked,
        "device_unblocked":    _on_device_unblocked,
        "device_unregistered": _on_device_unregistered,
        "user_blocked":        _on_user_blocked,
        "user_unblocked":      _on_user_unblocked,
        "user_updated":        _on_user_updated,
    }
    handler = handlers.get(event_type)
    if not handler:
        return jsonify({"error": f"Unknown event_type: {event_type!r}"}), 400
    return handler(g.site, data)


def _on_device_registered(site: Site, data: dict):
    from sqlalchemy.exc import IntegrityError
    mac = data.get("mac_address", "").lower().strip()
    email = (data.get("email") or "").lower().strip()
    if not mac or not email:
        return jsonify({"error": "mac_address and email required"}), 400

    now = datetime.now(timezone.utc)

    with db.session.no_autoflush:
        # Upsert user — flush immediately so autoflush doesn't fire mid-query
        user = CentralUser.query.filter_by(email=email).first()
        if not user:
            user = CentralUser(
                email=email,
                first_name=data.get("first_name"),
                last_name=data.get("last_name"),
                phone_number=data.get("phone_number"),
                network_password_hash=data.get("network_password_hash") or None,
                source_site_id=site.site_id,
            )
            db.session.add(user)
        else:
            # Fill in name fields if previously unknown
            if data.get("first_name") and not user.first_name:
                user.first_name = data["first_name"]
            if data.get("last_name") and not user.last_name:
                user.last_name = data["last_name"]
            if data.get("network_password_hash") and not user.network_password_hash:
                user.network_password_hash = data["network_password_hash"]
            user.updated_at = now

        try:
            db.session.flush()
        except IntegrityError:
            db.session.rollback()
            user = CentralUser.query.filter_by(email=email).first()

        # Upsert device
        device = CentralDevice.query.filter_by(mac_address=mac).first()
        if not device:
            device = CentralDevice(
                mac_address=mac,
                user_email=email,
                assigned_vlan=data.get("assigned_vlan"),
                device_name=data.get("device_name"),
                is_wired=bool(data.get("is_wired")),
                connection_type=data.get("connection_type") or None,
                ssid=data.get("ssid") or None,
                source_site_id=site.site_id,
            )
            db.session.add(device)
        else:
            if data.get("is_wired") is not None:
                device.is_wired = bool(data["is_wired"])
            if data.get("connection_type"):
                device.connection_type = data["connection_type"]
            if data.get("ssid"):
                device.ssid = data["ssid"]
            device.updated_at = now

        try:
            db.session.flush()
        except IntegrityError:
            db.session.rollback()
            device = CentralDevice.query.filter_by(mac_address=mac).first()

    # Record this site holds the device and user
    if not SiteDeviceRegistration.query.filter_by(site_id=site.site_id, mac_address=mac).first():
        db.session.add(SiteDeviceRegistration(site_id=site.site_id, mac_address=mac))
    if not SiteUserRegistration.query.filter_by(site_id=site.site_id, user_email=email).first():
        db.session.add(SiteUserRegistration(site_id=site.site_id, user_email=email))

    # Full replication: flag the user and push the record to every other site.
    fanned_out = 0
    if data.get("sync_to_all_sites"):
        if not user.sync_to_all_sites:
            user.sync_to_all_sites = True
        fanned_out = _fan_out_synced_device(device, user, exclude_site_id=site.site_id)

    db.session.commit()
    logger.info("device_registered: %s from site %s (user=%s, sync_fanout=%d)",
                mac, site.site_id, email, fanned_out)

    # Return full current state so the site can immediately apply any blocks
    return jsonify({
        "status": "ok",
        "device_blocked": bool(device.internet_blocked),
        "device_blocked_reason": device.blocked_reason if device.internet_blocked else None,
        "user_blocked": bool(user.blocked),
        "user_blocked_reason": user.blocked_reason if user.blocked else None,
    })


def _on_device_reassigned(site: Site, data: dict):
    mac       = data.get("mac_address", "").lower().strip()
    new_email = (data.get("email") or "").lower().strip()
    old_email = (data.get("old_email") or "").lower().strip()
    if not mac or not new_email:
        return jsonify({"error": "mac_address and email required"}), 400

    now = datetime.now(timezone.utc)

    # Update the central device owner
    device = CentralDevice.query.filter_by(mac_address=mac).first()
    if device:
        device.user_email = new_email
        device.updated_at = now

    # Ensure new user exists centrally
    new_user = CentralUser.query.filter_by(email=new_email).first()
    if not new_user:
        new_user = CentralUser(
            email=new_email,
            first_name=data.get("first_name"),
            last_name=data.get("last_name"),
            phone_number=data.get("phone_number"),
            source_site_id=site.site_id,
        )
        db.session.add(new_user)

    # Add SiteUserRegistration for new owner; drop old owner's reg at this site
    # if they have no remaining devices here.
    if old_email and old_email != new_email:
        old_user_other_count = (
            db.session.query(CentralDevice)
            .join(SiteDeviceRegistration,
                  CentralDevice.mac_address == SiteDeviceRegistration.mac_address)
            .filter(
                SiteDeviceRegistration.site_id == site.site_id,
                CentralDevice.user_email == old_email,
                CentralDevice.mac_address != mac,
            ).count()
        )
        if old_user_other_count == 0:
            old_user_reg = SiteUserRegistration.query.filter_by(
                site_id=site.site_id, user_email=old_email
            ).first()
            if old_user_reg:
                db.session.delete(old_user_reg)

    if not SiteUserRegistration.query.filter_by(site_id=site.site_id, user_email=new_email).first():
        db.session.add(SiteUserRegistration(site_id=site.site_id, user_email=new_email))

    # Fan out to all other sites that hold this device
    other_regs = SiteDeviceRegistration.query.filter(
        SiteDeviceRegistration.mac_address == mac,
        SiteDeviceRegistration.site_id != site.site_id,
    ).all()
    for reg in other_regs:
        _queue_to_site(reg.site_id, "reassign_device", data)

    db.session.commit()
    logger.info(
        "device_reassigned: %s from site %s (%s → %s) → queued to %d site(s)",
        mac, site.site_id, old_email, new_email, len(other_regs),
    )
    return jsonify({"status": "ok", "queued_to": [r.site_id for r in other_regs]})


def _on_device_blocked(site: Site, data: dict):
    mac = data.get("mac_address", "").lower().strip()
    if not mac:
        return jsonify({"error": "mac_address required"}), 400

    now = datetime.now(timezone.utc)
    device = CentralDevice.query.filter_by(mac_address=mac).first()
    if not device:
        return jsonify({"error": "Device not found"}), 404

    device.internet_blocked = True
    device.blocked_at = now
    device.blocked_reason = data.get("reason")
    device.updated_at = now

    # Propagate to all other sites that hold this device
    other_regs = SiteDeviceRegistration.query.filter(
        SiteDeviceRegistration.mac_address == mac,
        SiteDeviceRegistration.site_id != site.site_id,
    ).all()
    for reg in other_regs:
        _queue_to_site(reg.site_id, "block_device", {
            "mac_address": mac,
            "reason": data.get("reason"),
        })

    db.session.commit()
    logger.info("device_blocked: %s from site %s → queued to %d site(s)", mac, site.site_id, len(other_regs))
    return jsonify({"status": "ok", "queued_to": [r.site_id for r in other_regs]})


def _on_device_unblocked(site: Site, data: dict):
    mac = data.get("mac_address", "").lower().strip()
    if not mac:
        return jsonify({"error": "mac_address required"}), 400

    now = datetime.now(timezone.utc)
    device = CentralDevice.query.filter_by(mac_address=mac).first()
    if not device:
        return jsonify({"error": "Device not found"}), 404

    device.internet_blocked = False
    device.blocked_at = None
    device.blocked_reason = None
    device.updated_at = now

    other_regs = SiteDeviceRegistration.query.filter(
        SiteDeviceRegistration.mac_address == mac,
        SiteDeviceRegistration.site_id != site.site_id,
    ).all()
    for reg in other_regs:
        _queue_to_site(reg.site_id, "unblock_device", {"mac_address": mac})

    db.session.commit()
    logger.info("device_unblocked: %s from site %s → queued to %d site(s)", mac, site.site_id, len(other_regs))
    return jsonify({"status": "ok", "queued_to": [r.site_id for r in other_regs]})


def _on_user_blocked(site: Site, data: dict):
    email = (data.get("email") or "").lower().strip()
    if not email:
        return jsonify({"error": "email required"}), 400

    now = datetime.now(timezone.utc)
    user = CentralUser.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    user.blocked = True
    user.blocked_at = now
    user.blocked_reason = data.get("reason")
    user.updated_at = now

    # Mark all their devices blocked centrally too
    for dev in CentralDevice.query.filter_by(user_email=email).all():
        if not dev.internet_blocked:
            dev.internet_blocked = True
            dev.blocked_at = now
            dev.updated_at = now

    # Propagate to all other sites that hold this user
    other_regs = SiteUserRegistration.query.filter(
        SiteUserRegistration.user_email == email,
        SiteUserRegistration.site_id != site.site_id,
    ).all()
    for reg in other_regs:
        _queue_to_site(reg.site_id, "block_user", {
            "email": email,
            "reason": data.get("reason"),
        })

    db.session.commit()
    logger.info("user_blocked: %s from site %s → queued to %d site(s)", email, site.site_id, len(other_regs))
    return jsonify({"status": "ok", "queued_to": [r.site_id for r in other_regs]})


def _on_user_unblocked(site: Site, data: dict):
    email = (data.get("email") or "").lower().strip()
    if not email:
        return jsonify({"error": "email required"}), 400

    now = datetime.now(timezone.utc)
    user = CentralUser.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    user.blocked = False
    user.blocked_at = None
    user.blocked_reason = None
    user.updated_at = now

    other_regs = SiteUserRegistration.query.filter(
        SiteUserRegistration.user_email == email,
        SiteUserRegistration.site_id != site.site_id,
    ).all()
    for reg in other_regs:
        _queue_to_site(reg.site_id, "unblock_user", {"email": email})

    db.session.commit()
    logger.info("user_unblocked: %s from site %s → queued to %d site(s)", email, site.site_id, len(other_regs))
    return jsonify({"status": "ok", "queued_to": [r.site_id for r in other_regs]})


def _on_user_updated(site: Site, data: dict):
    """A site has updated a user's profile (name, phone, password hash, VLAN overrides).

    Central updates its own record and fans the update out to all other sites
    that hold this user.
    """
    email = (data.get("email") or "").lower().strip()
    if not email:
        return jsonify({"error": "email required"}), 400

    now = datetime.now(timezone.utc)
    user = CentralUser.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    fields = ("first_name", "last_name", "phone_number", "network_password_hash",
              "allowed_vlans_override", "allowed_vlans_deny",
              "adoptable_vlans_override", "adoptable_vlans_deny")
    for f in fields:
        if f in data:
            setattr(user, f, data[f] or None)
    if data.get("sync_to_all_sites"):
        user.sync_to_all_sites = True
    user.updated_at = now

    data = dict(data)
    data["sync_to_all_sites"] = bool(user.sync_to_all_sites)

    if user.sync_to_all_sites:
        # Synced users propagate to every active site, creating the user where absent.
        targets = [s.site_id for s in Site.query.filter_by(active=True).all()
                   if s.site_id != site.site_id]
    else:
        targets = [r.site_id for r in SiteUserRegistration.query.filter(
            SiteUserRegistration.user_email == email,
            SiteUserRegistration.site_id != site.site_id,
        ).all()]
    for target in targets:
        _queue_to_site(target, "update_user", data)

    db.session.commit()
    logger.info("user_updated: %s from site %s → queued to %d site(s)", email, site.site_id, len(targets))
    return jsonify({"status": "ok", "queued_to": targets})


def _on_device_unregistered(site: Site, data: dict):
    """A site has unregistered a device (user clicked the email unregister link).

    Central removes the reporting site's SiteDeviceRegistration and pushes an
    unregister_device instruction to every other site that still holds the
    device, so those sites also close ownership and remove Kea reservations.
    """
    mac = data.get("mac_address", "").lower().strip()
    if not mac:
        return jsonify({"error": "mac_address required"}), 400

    # Push to every other site that currently holds the device before we delete anything.
    other_regs = SiteDeviceRegistration.query.filter(
        SiteDeviceRegistration.mac_address == mac,
        SiteDeviceRegistration.site_id != site.site_id,
    ).all()
    for reg in other_regs:
        _queue_to_site(reg.site_id, "unregister_device", {"mac_address": mac})

    # Remove ALL SiteDeviceRegistration entries for this device (reporting site and any
    # other sites that received the push — they will never send device_unregistered back,
    # so their entries would otherwise remain as permanent ghosts in central's DB).
    SiteDeviceRegistration.query.filter_by(mac_address=mac).delete()

    # Always delete the central device record.
    device = CentralDevice.query.filter_by(mac_address=mac).first()
    if device:
        db.session.delete(device)

    db.session.commit()
    logger.info(
        "device_unregistered: %s from site %s → queued to %d other site(s), all regs purged",
        mac, site.site_id, len(other_regs),
    )
    return jsonify({"status": "ok", "queued_to": [r.site_id for r in other_regs]})


# ── Outbound queue: site polls for pending messages ───────────────────────────

@app.route("/api/v1/queue/pending", methods=["GET"])
@require_site_key
def get_pending_queue():
    """
    Site polls this endpoint to receive queued instructions from central.
    Items are marked 'sent'; the site must ack each one via POST /api/v1/ack.
    Items not acked within 5 minutes are reset to 'pending' by the background
    worker and will be returned again on the next poll.
    """
    items = (
        OutboundQueue.query
        .filter_by(site_id=g.site.site_id, status="pending")
        .order_by(OutboundQueue.created_at)
        .limit(50)
        .all()
    )
    now = datetime.now(timezone.utc)
    result = []
    for item in items:
        item.attempts += 1
        item.last_attempt_at = now
        item.status = "sent"
        result.append({
            "queue_id": item.id,
            "event_type": item.event_type,
            "data": item.payload,
        })
    db.session.commit()
    return jsonify({"items": result})


@app.route("/api/v1/ack", methods=["POST"])
@require_site_key
def ack_queue_item():
    """Site acknowledges successful processing of a queued outbound item."""
    body = request.get_json(silent=True) or {}
    queue_id = body.get("queue_id")
    if not queue_id:
        return jsonify({"error": "queue_id required"}), 400

    item = OutboundQueue.query.filter_by(id=queue_id, site_id=g.site.site_id).first()
    if not item:
        return jsonify({"error": "Not found"}), 404

    item.status = "acknowledged"
    item.acknowledged_at = datetime.now(timezone.utc)
    db.session.commit()
    return jsonify({"status": "ok"})


# ── Device lookup: site queries for an unknown MAC ────────────────────────────

@app.route("/api/v1/device/<path:mac_address>", methods=["GET"])
@require_site_key
def get_device(mac_address):
    """
    Called when a site sees a MAC it doesn't recognise locally.
    If found, records this site as holding the registration (for future
    block propagation) and returns full current state including block status.
    """
    mac = mac_address.lower().strip()
    device = CentralDevice.query.filter_by(mac_address=mac).first()
    if not device:
        return jsonify({"error": "Not found"}), 404

    user = CentralUser.query.filter_by(email=device.user_email).first() if device.user_email else None

    # Record this site now holds this registration
    if not SiteDeviceRegistration.query.filter_by(site_id=g.site.site_id, mac_address=mac).first():
        db.session.add(SiteDeviceRegistration(site_id=g.site.site_id, mac_address=mac))
    if user and not SiteUserRegistration.query.filter_by(site_id=g.site.site_id, user_email=user.email).first():
        db.session.add(SiteUserRegistration(site_id=g.site.site_id, user_email=user.email))
    db.session.commit()

    return jsonify({
        "mac_address": device.mac_address,
        "email": device.user_email,
        "first_name": user.first_name if user else None,
        "last_name": user.last_name if user else None,
        "phone_number": user.phone_number if user else None,
        "assigned_vlan": device.assigned_vlan,
        "device_name": device.device_name,
        "is_wired": bool(device.is_wired),
        "connection_type": device.connection_type,
        "ssid": device.ssid,
        "device_blocked": bool(device.internet_blocked),
        "device_blocked_reason": device.blocked_reason if device.internet_blocked else None,
        "user_blocked": bool(user.blocked) if user else False,
        "user_blocked_reason": user.blocked_reason if user and user.blocked else None,
        "network_password_hash": user.network_password_hash or "",
    })


# ── Admin: register a new site ────────────────────────────────────────────────

@app.route("/api/v1/user/<path:email>", methods=["GET"])
@require_site_key
def get_user(email):
    """
    Look up a user by email address.
    Returns first_name, last_name, phone_number if known.
    Used by sites during the step-1 registration check to pre-fill name fields
    for a user who registered at a different site.
    """
    email = email.lower().strip()
    user = CentralUser.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "Not found"}), 404

    # Record that this site is associated with this user (for future fan-out)
    if not SiteUserRegistration.query.filter_by(site_id=g.site.site_id, user_email=user.email).first():
        db.session.add(SiteUserRegistration(site_id=g.site.site_id, user_email=user.email))
        db.session.commit()

    return jsonify({
        "email": user.email,
        "first_name": user.first_name or "",
        "last_name": user.last_name or "",
        "phone_number": user.phone_number or "",
        "blocked": bool(user.blocked),
        "network_password_hash": user.network_password_hash or "",
    })

# ── Bootstrap: full sync for a (new) site ──────────────────────────────────

@app.route("/api/v1/bootstrap", methods=["GET"])
@require_site_key
def bootstrap_sync():
    """Return every sync-flagged user and their devices so a newly registered
    site can seed its local database (and Kea reservations) in one call.
    Also records this site as holding each returned user/device so future
    updates and blocks fan out to it."""
    users = CentralUser.query.filter_by(sync_to_all_sites=True).all()
    user_payloads = []
    device_payloads = []
    user_by_email = {}
    for user in users:
        user_by_email[user.email] = user
        user_payloads.append({
            "email": user.email,
            "first_name": user.first_name or "",
            "last_name": user.last_name or "",
            "phone_number": user.phone_number or "",
            "blocked": bool(user.blocked),
            "network_password_hash": user.network_password_hash or "",
            "sync_to_all_sites": True,
        })
        if not SiteUserRegistration.query.filter_by(
                site_id=g.site.site_id, user_email=user.email).first():
            db.session.add(SiteUserRegistration(site_id=g.site.site_id, user_email=user.email))

    if user_by_email:
        devices = CentralDevice.query.filter(
            CentralDevice.user_email.in_(list(user_by_email.keys()))
        ).all()
        for device in devices:
            device_payloads.append(
                _device_sync_payload(device, user_by_email.get(device.user_email))
            )
            if not SiteDeviceRegistration.query.filter_by(
                    site_id=g.site.site_id, mac_address=device.mac_address).first():
                db.session.add(SiteDeviceRegistration(
                    site_id=g.site.site_id, mac_address=device.mac_address))

    db.session.commit()
    logger.info("bootstrap: site %s pulled %d user(s), %d device(s)",
                g.site.site_id, len(user_payloads), len(device_payloads))
    return jsonify({"users": user_payloads, "devices": device_payloads})

# ── Admin: register a new site ────────────────────────────────────────────────

@app.route("/api/v1/admin/site", methods=["POST"])
def register_site():
    """
    One-time call to register a premises with central and obtain its API key.
    Protected by the ADMIN_KEY environment variable.
    """
    admin_key = request.headers.get("X-Admin-Key", "").strip()
    expected = os.environ.get("ADMIN_KEY", "")
    if not admin_key or not expected or not hmac.compare_digest(admin_key, expected):
        return jsonify({"error": "Forbidden"}), 403

    body = request.get_json(silent=True) or {}
    site_id = body.get("site_id", "").strip()
    api_url = body.get("api_url", "").strip()
    display_name = body.get("display_name", site_id).strip()

    if not site_id or not api_url:
        return jsonify({"error": "site_id and api_url required"}), 400

    # Re-register is allowed: a rebuilt/damaged site has lost its API key.
    # ADMIN_KEY is required, so this is an intentional rotation, not a leak.
    existing = Site.query.filter_by(site_id=site_id).first()
    api_key = secrets.token_urlsafe(40)
    reissued = existing is not None

    if existing:
        existing.display_name = display_name
        existing.api_url = api_url
        existing.api_key_hash = _sha256(api_key)
        existing.active = True
    else:
        db.session.add(Site(
            site_id=site_id,
            display_name=display_name,
            api_url=api_url,
            api_key_hash=_sha256(api_key),
            active=True,
        ))

    db.session.commit()

    if reissued:
        logger.info("Site re-registered (API key rotated): %s (%s)", site_id, api_url)
        return jsonify({
            "site_id": site_id,
            "api_key": api_key,
            "reissued": True,
            "note": "Site already existed; api_key was rotated. Store it as CENTRAL_API_KEY in the site .env — it will not be shown again. The previous key is now invalid.",
        }), 200

    logger.info("New site registered: %s (%s)", site_id, api_url)
    return jsonify({
        "site_id": site_id,
        "api_key": api_key,
        "reissued": False,
        "note": "Store api_key as CENTRAL_API_KEY in the site .env — it will not be shown again.",
    }), 201

# ── Health check ──────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


# ── Background worker: push outbound queue items to sites ────────────────────

def _push_delivery_worker():
    """Daemon thread: push pending outbound_queue items to each site's /api/v1/push
    endpoint every 10 seconds.  On HTTP 200 the item is marked 'acknowledged';
    on any failure it stays 'pending' and will be retried on the next cycle.
    """
    while True:
        time.sleep(10)
        try:
            with app.app_context():
                pending = (
                    OutboundQueue.query
                    .filter_by(status="pending")
                    .order_by(OutboundQueue.created_at)
                    .limit(100)
                    .all()
                )
                for item in pending:
                    site = Site.query.filter_by(site_id=item.site_id).first()
                    if not site or not site.api_url:
                        logger.warning("push: no api_url for site %s, skipping item %d", item.site_id, item.id)
                        continue
                    push_secret = site.push_secret or ""
                    try:
                        resp = requests.post(
                            f"{site.api_url.rstrip('/')}/api/v1/push",
                            json={"event_type": item.event_type, "data": item.payload},
                            headers={
                                "Content-Type": "application/json",
                                "X-Push-Secret": push_secret,
                            },
                            timeout=10,
                        )
                        if resp.status_code == 200:
                            item.status = "acknowledged"
                            item.attempts += 1
                            item.last_attempt_at = datetime.now(timezone.utc)
                            logger.info("push: delivered %s to %s (item %d)", item.event_type, item.site_id, item.id)
                        else:
                            item.attempts += 1
                            item.last_attempt_at = datetime.now(timezone.utc)
                            logger.warning("push: %s → %s HTTP %d (item %d)", item.event_type, item.site_id, resp.status_code, item.id)
                    except Exception as exc:
                        item.attempts += 1
                        item.last_attempt_at = datetime.now(timezone.utc)
                        logger.warning("push: failed to deliver to %s (item %d): %s", item.site_id, item.id, exc)
                if pending:
                    db.session.commit()
        except Exception as exc:
            logger.error("push delivery worker error: %s", exc)


# ── Startup ───────────────────────────────────────────────────────────────────

with app.app_context():
    db.create_all()
    logger.info("Database tables verified/created")

threading.Thread(target=_push_delivery_worker, daemon=True, name="push-delivery").start()
