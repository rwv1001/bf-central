"""
bf-central – Central registration server for bf-network.

Provides:
  - REST API (v1) consumed by remote bf-network portals
  - Admin web interface for managing users, devices, and API keys
"""

import os
import re
import functools
from datetime import datetime, date
from urllib.parse import urlparse

from flask import (
    Flask, jsonify, request, render_template, redirect, url_for,
    session, flash, abort
)
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv

from models import db, Admin, User, Device, ApiKey

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'change-me-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL',
    'postgresql://bfcentral:bfcentral@db:5432/bfcentral'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MAC_RE = re.compile(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$')


def normalize_mac(mac: str) -> str:
    """Return MAC in lowercase colon notation, e.g. aa:bb:cc:dd:ee:ff."""
    clean = re.sub(r'[^0-9a-fA-F]', '', mac).lower()
    if len(clean) != 12:
        raise ValueError(f'Invalid MAC address: {mac}')
    return ':'.join(clean[i:i+2] for i in range(0, 12, 2))


def require_api_key(f):
    """Decorator: require a valid API key in the X-API-Key header."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get('X-API-Key', '').strip()
        if not key:
            return jsonify({'error': 'Missing API key'}), 401
        api_key = ApiKey.query.filter_by(key=key, active=True).first()
        if not api_key:
            return jsonify({'error': 'Invalid or inactive API key'}), 403
        api_key.last_used_at = datetime.utcnow()
        db.session.commit()
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    """Decorator: require an authenticated admin session."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin_id'):
            return redirect(url_for('admin_login', next=request.path))
        return f(*args, **kwargs)
    return decorated


def parse_date(value: str):
    """Parse ISO date string to a date object, or raise ValueError."""
    return datetime.strptime(value, '%Y-%m-%d').date()


# ---------------------------------------------------------------------------
# Public routes
# ---------------------------------------------------------------------------

@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'service': 'bf-central'})


# ---------------------------------------------------------------------------
# REST API v1
# ---------------------------------------------------------------------------

@app.route('/api/v1/users/lookup', methods=['GET'])
@require_api_key
def api_user_lookup():
    """Look up a user by email address.

    Query params:
      email – the user's email address

    Returns 200 with user JSON if found and active, 404 otherwise.
    """
    email = request.args.get('email', '').strip().lower()
    if not email:
        return jsonify({'error': 'email parameter required'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'found': False}), 404

    return jsonify({'found': True, 'user': user.to_dict()})


@app.route('/api/v1/devices/lookup', methods=['GET'])
@require_api_key
def api_device_lookup():
    """Look up a device by MAC address.

    Query params:
      mac – MAC address (any common separator format)

    Returns 200 with device + user JSON if found, 404 otherwise.
    """
    raw_mac = request.args.get('mac', '').strip()
    if not raw_mac:
        return jsonify({'error': 'mac parameter required'}), 400

    try:
        mac = normalize_mac(raw_mac)
    except ValueError:
        return jsonify({'error': 'Invalid MAC address format'}), 400

    device = Device.query.filter_by(mac_address=mac).first()
    if not device:
        return jsonify({'found': False}), 404

    return jsonify({'found': True, 'device': device.to_dict()})


@app.route('/api/v1/users', methods=['POST'])
@require_api_key
def api_create_user():
    """Create or update a user record.

    JSON body:
      email          – required
      first_name     – optional
      last_name      – optional
      phone_number   – optional
      allowed_vlans  – optional, comma-separated VLAN IDs
      begin_date     – optional ISO date (defaults to today)
      expiry_date    – optional ISO date (null = no expiry)
      notes          – optional
    """
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    if not email:
        return jsonify({'error': 'email is required'}), 400

    user = User.query.filter_by(email=email).first()
    created = user is None

    if created:
        user = User(email=email)
        db.session.add(user)

    if 'first_name' in data:
        user.first_name = data['first_name']
    if 'last_name' in data:
        user.last_name = data['last_name']
    if 'phone_number' in data:
        user.phone_number = data['phone_number']
    if 'allowed_vlans' in data:
        user.allowed_vlans = data['allowed_vlans']
    if 'notes' in data:
        user.notes = data['notes']

    begin_date_str = data.get('begin_date')
    user.begin_date = parse_date(begin_date_str) if begin_date_str else date.today()

    expiry_date_str = data.get('expiry_date')
    user.expiry_date = parse_date(expiry_date_str) if expiry_date_str else None

    user.updated_at = datetime.utcnow()
    db.session.commit()

    status_code = 201 if created else 200
    return jsonify({'user': user.to_dict()}), status_code


@app.route('/api/v1/users/<int:user_id>', methods=['PUT'])
@require_api_key
def api_update_user(user_id):
    """Update a user record by ID."""
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json(silent=True) or {}
    if 'first_name' in data:
        user.first_name = data['first_name']
    if 'last_name' in data:
        user.last_name = data['last_name']
    if 'phone_number' in data:
        user.phone_number = data['phone_number']
    if 'allowed_vlans' in data:
        user.allowed_vlans = data['allowed_vlans']
    if 'notes' in data:
        user.notes = data['notes']
    if 'blocked' in data:
        user.blocked = bool(data['blocked'])
    if 'begin_date' in data:
        user.begin_date = parse_date(data['begin_date'])
    if 'expiry_date' in data:
        user.expiry_date = parse_date(data['expiry_date']) if data['expiry_date'] else None

    user.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'user': user.to_dict()})


@app.route('/api/v1/devices', methods=['POST'])
@require_api_key
def api_register_device():
    """Register a device.

    JSON body:
      mac_address              – required
      user_id                  – optional (link to user)
      device_name              – optional
      registration_status      – optional (default: 'registered')
      registered_at_location   – optional site identifier
    """
    data = request.get_json(silent=True) or {}
    raw_mac = (data.get('mac_address') or '').strip()
    if not raw_mac:
        return jsonify({'error': 'mac_address is required'}), 400

    try:
        mac = normalize_mac(raw_mac)
    except ValueError:
        return jsonify({'error': 'Invalid MAC address format'}), 400

    device = Device.query.filter_by(mac_address=mac).first()
    created = device is None

    if created:
        device = Device(mac_address=mac)
        db.session.add(device)

    if 'user_id' in data:
        device.user_id = data['user_id']
    if 'device_name' in data:
        device.device_name = data['device_name']
    if 'registration_status' in data:
        device.registration_status = data['registration_status']
    if 'registered_at_location' in data:
        device.registered_at_location = data['registered_at_location']

    device.last_seen = datetime.utcnow()
    db.session.commit()

    status_code = 201 if created else 200
    return jsonify({'device': device.to_dict()}), status_code


@app.route('/api/v1/devices/<string:mac>/seen', methods=['POST'])
@require_api_key
def api_device_seen(mac):
    """Update the last_seen timestamp for a device."""
    try:
        mac = normalize_mac(mac)
    except ValueError:
        return jsonify({'error': 'Invalid MAC address format'}), 400

    device = Device.query.filter_by(mac_address=mac).first()
    if not device:
        return jsonify({'error': 'Device not found'}), 404

    device.last_seen = datetime.utcnow()
    db.session.commit()
    return jsonify({'ok': True})


# ---------------------------------------------------------------------------
# Admin – authentication
# ---------------------------------------------------------------------------

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin_id'):
        return redirect(url_for('admin_dashboard'))

    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        admin = Admin.query.filter_by(username=username).first()
        if admin and admin.check_password(password):
            session['admin_id'] = admin.id
            admin.last_login = datetime.utcnow()
            db.session.commit()
            # Only allow redirects to relative paths within this application.
            # Reject anything with a scheme or netloc to prevent open-redirect
            # attacks via a user-supplied 'next' parameter.
            next_path = request.args.get('next', '')
            parsed = urlparse(next_path)
            if next_path and not parsed.scheme and not parsed.netloc and parsed.path.startswith('/'):
                return redirect(parsed.path)
            return redirect(url_for('admin_dashboard'))
        error = 'Invalid username or password'

    return render_template('admin_login.html', error=error)


@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login'))


# ---------------------------------------------------------------------------
# Admin – dashboard
# ---------------------------------------------------------------------------

@app.route('/admin')
@require_admin
def admin_dashboard():
    user_count = User.query.count()
    device_count = Device.query.count()
    api_key_count = ApiKey.query.filter_by(active=True).count()
    return render_template(
        'admin_dashboard.html',
        user_count=user_count,
        device_count=device_count,
        api_key_count=api_key_count,
    )


# ---------------------------------------------------------------------------
# Admin – user management
# ---------------------------------------------------------------------------

@app.route('/admin/users')
@require_admin
def admin_users():
    users = User.query.order_by(User.email).all()
    return render_template('admin_users.html', users=users)


@app.route('/admin/users/add', methods=['GET', 'POST'])
@require_admin
def admin_add_user():
    error = None
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        phone_number = request.form.get('phone_number', '').strip()
        allowed_vlans = request.form.get('allowed_vlans', '').strip()
        begin_date_str = request.form.get('begin_date', '').strip()
        expiry_date_str = request.form.get('expiry_date', '').strip()
        notes = request.form.get('notes', '').strip()

        if not email:
            error = 'Email is required'
        elif User.query.filter_by(email=email).first():
            error = 'A user with that email already exists'
        else:
            try:
                begin_date = parse_date(begin_date_str) if begin_date_str else date.today()
                expiry_date = parse_date(expiry_date_str) if expiry_date_str else None
            except ValueError:
                error = 'Invalid date format (use YYYY-MM-DD)'

        if not error:
            user = User(
                email=email,
                first_name=first_name,
                last_name=last_name,
                phone_number=phone_number,
                allowed_vlans=allowed_vlans or None,
                begin_date=begin_date,
                expiry_date=expiry_date,
                notes=notes,
                created_by='admin',
            )
            db.session.add(user)
            db.session.commit()
            flash(f'User {email} added successfully.', 'success')
            return redirect(url_for('admin_users'))

    return render_template('admin_add_user.html', error=error, today=date.today().isoformat())


@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@require_admin
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)
    error = None

    if request.method == 'POST':
        user.first_name = request.form.get('first_name', '').strip()
        user.last_name = request.form.get('last_name', '').strip()
        user.phone_number = request.form.get('phone_number', '').strip()
        user.allowed_vlans = request.form.get('allowed_vlans', '').strip() or None
        user.notes = request.form.get('notes', '').strip()
        user.blocked = bool(request.form.get('blocked'))

        begin_date_str = request.form.get('begin_date', '').strip()
        expiry_date_str = request.form.get('expiry_date', '').strip()
        try:
            user.begin_date = parse_date(begin_date_str) if begin_date_str else user.begin_date
            user.expiry_date = parse_date(expiry_date_str) if expiry_date_str else None
        except ValueError:
            error = 'Invalid date format (use YYYY-MM-DD)'

        if not error:
            user.updated_at = datetime.utcnow()
            db.session.commit()
            flash(f'User {user.email} updated.', 'success')
            return redirect(url_for('admin_users'))

    return render_template('admin_edit_user.html', user=user, error=error)


@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@require_admin
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    email = user.email
    db.session.delete(user)
    db.session.commit()
    flash(f'User {email} deleted.', 'success')
    return redirect(url_for('admin_users'))


# ---------------------------------------------------------------------------
# Admin – device management
# ---------------------------------------------------------------------------

@app.route('/admin/devices')
@require_admin
def admin_devices():
    devices = Device.query.order_by(Device.registered_at.desc()).all()
    return render_template('admin_devices.html', devices=devices)


@app.route('/admin/devices/<int:device_id>/delete', methods=['POST'])
@require_admin
def admin_delete_device(device_id):
    device = Device.query.get_or_404(device_id)
    mac = device.mac_address
    db.session.delete(device)
    db.session.commit()
    flash(f'Device {mac} deleted.', 'success')
    return redirect(url_for('admin_devices'))


# ---------------------------------------------------------------------------
# Admin – API key management
# ---------------------------------------------------------------------------

@app.route('/admin/api-keys')
@require_admin
def admin_api_keys():
    keys = ApiKey.query.order_by(ApiKey.created_at.desc()).all()
    return render_template('admin_api_keys.html', keys=keys)


@app.route('/admin/api-keys/add', methods=['GET', 'POST'])
@require_admin
def admin_add_api_key():
    new_key = None
    error = None
    if request.method == 'POST':
        site_name = request.form.get('site_name', '').strip()
        description = request.form.get('description', '').strip()
        if not site_name:
            error = 'Site name is required'
        else:
            new_key = ApiKey.generate()
            api_key = ApiKey(
                key=new_key,
                site_name=site_name,
                description=description,
            )
            db.session.add(api_key)
            db.session.commit()

    return render_template('admin_add_api_key.html', new_key=new_key, error=error)


@app.route('/admin/api-keys/<int:key_id>/revoke', methods=['POST'])
@require_admin
def admin_revoke_api_key(key_id):
    api_key = ApiKey.query.get_or_404(key_id)
    api_key.active = False
    db.session.commit()
    flash(f'API key for {api_key.site_name} revoked.', 'success')
    return redirect(url_for('admin_api_keys'))


# ---------------------------------------------------------------------------
# DB initialisation helper
# ---------------------------------------------------------------------------

def init_db():
    """Create tables and seed a default admin if none exist."""
    with app.app_context():
        db.create_all()
        if not Admin.query.first():
            default_password = os.getenv('ADMIN_PASSWORD', 'admin123')
            admin = Admin(username='admin')
            admin.set_password(default_password)
            db.session.add(admin)
            db.session.commit()
            print('Created default admin user (change the password after first login)')


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=8081, debug=os.getenv('FLASK_DEBUG', 'false').lower() == 'true')
