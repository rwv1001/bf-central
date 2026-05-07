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

    handlers = {
        "device_registered":   _on_device_registered,
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
                source_site_id=site.site_id,
            )
            db.session.add(user)
        else:
            # Fill in name fields if previously unknown
            if data.get("first_name") and not user.first_name:
                user.first_name = data["first_name"]
            if data.get("last_name") and not user.last_name:
                user.last_name = data["last_name"]
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
                source_site_id=site.site_id,
            )
            db.session.add(device)
        else:
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

    db.session.commit()
    logger.info("device_registered: %s from site %s (user=%s)", mac, site.site_id, email)

    # Return full current state so the site can immediately apply any blocks
    return jsonify({
        "status": "ok",
        "device_blocked": bool(device.internet_blocked),
        "device_blocked_reason": device.blocked_reason if device.internet_blocked else None,
        "user_blocked": bool(user.blocked),
        "user_blocked_reason": user.blocked_reason if user.blocked else None,
    })


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
    user.updated_at = now

    # Fan out to all other sites that hold this user
    other_regs = SiteUserRegistration.query.filter(
        SiteUserRegistration.user_email == email,
        SiteUserRegistration.site_id != site.site_id,
    ).all()
    for reg in other_regs:
        _queue_to_site(reg.site_id, "update_user", data)

    db.session.commit()
    logger.info("user_updated: %s from site %s → queued to %d site(s)", email, site.site_id, len(other_regs))
    return jsonify({"status": "ok", "queued_to": [r.site_id for r in other_regs]})


def _on_device_unregistered(site: Site, data: dict):
    """A site has unregistered a device (user clicked the email unregister link).

    Central removes the reporting site's SiteDeviceRegistration and pushes an
    unregister_device instruction to every other site that still holds the
    device, so those sites also close ownership and remove Kea reservations.
    """
    mac = data.get("mac_address", "").lower().strip()
    if not mac:
        return jsonify({"error": "mac_address required"}), 400

    # Find all *other* sites that hold this device before we delete the reporter's reg
    other_regs = SiteDeviceRegistration.query.filter(
        SiteDeviceRegistration.mac_address == mac,
        SiteDeviceRegistration.site_id != site.site_id,
    ).all()

    # Remove this site's registration record
    own_reg = SiteDeviceRegistration.query.filter_by(
        site_id=site.site_id, mac_address=mac
    ).first()
    if own_reg:
        db.session.delete(own_reg)

    # Push unregister_device to every other site that holds the device
    for reg in other_regs:
        _queue_to_site(reg.site_id, "unregister_device", {"mac_address": mac})

    # If no other site holds the device any more, remove the central record entirely
    if not other_regs:
        device = CentralDevice.query.filter_by(mac_address=mac).first()
        if device:
            db.session.delete(device)

    db.session.commit()
    logger.info(
        "device_unregistered: %s from site %s → queued to %d other site(s)",
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
        "device_blocked": bool(device.internet_blocked),
        "device_blocked_reason": device.blocked_reason if device.internet_blocked else None,
        "user_blocked": bool(user.blocked) if user else False,
        "user_blocked_reason": user.blocked_reason if user and user.blocked else None,
    })


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
    if Site.query.filter_by(site_id=site_id).first():
        return jsonify({"error": f"Site {site_id!r} already exists"}), 409

    api_key = secrets.token_urlsafe(40)
    db.session.add(Site(
        site_id=site_id,
        display_name=display_name,
        api_url=api_url,
        api_key_hash=_sha256(api_key),
        active=True,
    ))
    db.session.commit()

    logger.info("New site registered: %s (%s)", site_id, api_url)
    return jsonify({
        "site_id": site_id,
        "api_key": api_key,
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
