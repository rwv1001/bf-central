"""
Database models for bf-central
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

db = SQLAlchemy()


class Admin(db.Model):
    """Admin users for the web interface"""
    __tablename__ = 'admins'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='scrypt')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<Admin {self.username}>'


class User(db.Model):
    """Centrally registered users"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    phone_number = db.Column(db.String(20))
    allowed_vlans = db.Column(db.Text)       # comma-separated VLAN IDs
    begin_date = db.Column(db.Date, nullable=False)
    expiry_date = db.Column(db.Date, nullable=True)  # NULL = no expiration
    blocked = db.Column(db.Boolean, default=False, nullable=False)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.String(100), default='admin')

    devices = db.relationship('Device', backref='user', lazy=True,
                              cascade='all, delete-orphan')

    @property
    def full_name(self):
        return f"{self.first_name or ''} {self.last_name or ''}".strip()

    @property
    def is_active(self):
        today = datetime.utcnow().date()
        if self.blocked:
            return False
        if self.expiry_date is not None and today > self.expiry_date:
            return False
        return self.begin_date <= today

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'full_name': self.full_name,
            'phone_number': self.phone_number,
            'allowed_vlans': self.allowed_vlans,
            'begin_date': self.begin_date.isoformat() if self.begin_date else None,
            'expiry_date': self.expiry_date.isoformat() if self.expiry_date else None,
            'blocked': self.blocked,
            'is_active': self.is_active,
            'notes': self.notes,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self):
        return f'<User {self.email}>'


class Device(db.Model):
    """Registered network devices"""
    __tablename__ = 'devices'

    id = db.Column(db.Integer, primary_key=True)
    mac_address = db.Column(db.String(17), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    device_name = db.Column(db.String(100))
    registration_status = db.Column(db.String(50), default='registered', index=True)
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime)
    registered_at_location = db.Column(db.String(255))  # hostname / site identifier

    def to_dict(self):
        return {
            'id': self.id,
            'mac_address': self.mac_address,
            'user_id': self.user_id,
            'device_name': self.device_name,
            'registration_status': self.registration_status,
            'registered_at': self.registered_at.isoformat() if self.registered_at else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'registered_at_location': self.registered_at_location,
            'user': self.user.to_dict() if self.user else None,
        }

    def __repr__(self):
        return f'<Device {self.mac_address}>'


class ApiKey(db.Model):
    """API keys for bf-network site authentication"""
    __tablename__ = 'api_keys'

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    site_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used_at = db.Column(db.DateTime)

    @staticmethod
    def generate():
        return secrets.token_hex(32)

    def __repr__(self):
        return f'<ApiKey site={self.site_name}>'
