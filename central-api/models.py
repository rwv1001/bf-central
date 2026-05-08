from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Site(db.Model):
    __tablename__ = "sites"

    id = db.Column(db.Integer, primary_key=True)
    site_id = db.Column(db.String(64), unique=True, nullable=False)
    display_name = db.Column(db.String(128))
    api_url = db.Column(db.String(256), nullable=False)
    api_key_hash = db.Column(db.String(256), nullable=False)
    push_secret = db.Column(db.String(256))
    last_seen_at = db.Column(db.DateTime(timezone=True))
    active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class CentralUser(db.Model):
    __tablename__ = "central_users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(256), unique=True, nullable=False)
    first_name = db.Column(db.String(128))
    last_name = db.Column(db.String(128))
    phone_number = db.Column(db.String(64))
    network_password_hash = db.Column(db.Text)
    blocked = db.Column(db.Boolean, default=False, nullable=False)
    blocked_at = db.Column(db.DateTime(timezone=True))
    blocked_reason = db.Column(db.Text)
    source_site_id = db.Column(db.String(64))
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class CentralDevice(db.Model):
    __tablename__ = "central_devices"

    id = db.Column(db.Integer, primary_key=True)
    mac_address = db.Column(db.String(17), unique=True, nullable=False)
    user_email = db.Column(db.String(256))
    assigned_vlan = db.Column(db.Integer)
    device_name = db.Column(db.String(128))
    internet_blocked = db.Column(db.Boolean, default=False, nullable=False)
    blocked_at = db.Column(db.DateTime(timezone=True))
    blocked_reason = db.Column(db.Text)
    is_wired = db.Column(db.Boolean, default=False, nullable=False)
    source_site_id = db.Column(db.String(64))
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class SiteDeviceRegistration(db.Model):
    """Records which local sites hold a device's registration."""

    __tablename__ = "site_device_registrations"
    __table_args__ = (db.UniqueConstraint("site_id", "mac_address"),)

    id = db.Column(db.Integer, primary_key=True)
    site_id = db.Column(db.String(64), nullable=False)
    mac_address = db.Column(db.String(17), nullable=False)
    registered_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class SiteUserRegistration(db.Model):
    """Records which local sites hold a user's registration."""

    __tablename__ = "site_user_registrations"
    __table_args__ = (db.UniqueConstraint("site_id", "user_email"),)

    id = db.Column(db.Integer, primary_key=True)
    site_id = db.Column(db.String(64), nullable=False)
    user_email = db.Column(db.String(256), nullable=False)
    registered_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class OutboundQueue(db.Model):
    """Messages queued from central to a site, pending acknowledgement."""

    __tablename__ = "outbound_queue"

    id = db.Column(db.Integer, primary_key=True)
    site_id = db.Column(db.String(64), nullable=False)
    event_type = db.Column(db.String(64), nullable=False)
    payload = db.Column(db.JSON, nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    attempts = db.Column(db.Integer, default=0, nullable=False)
    last_attempt_at = db.Column(db.DateTime(timezone=True))
    acknowledged_at = db.Column(db.DateTime(timezone=True))
    # pending → sent (delivered to site poll) → acknowledged (site acked)
    status = db.Column(db.String(32), default="pending", nullable=False)
