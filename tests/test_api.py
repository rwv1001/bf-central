"""
Tests for bf-central REST API
"""

import pytest
import json
import sys
import os

# Use an in-memory SQLite database for tests (must be set before importing app)
os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
os.environ['SECRET_KEY'] = 'test-secret'

# Add app directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from app import app as flask_app, init_db
from models import db, User, Device, ApiKey
from datetime import date


@pytest.fixture
def client():
    flask_app.config['TESTING'] = True

    with flask_app.app_context():
        db.drop_all()
        db.create_all()

        # Seed an API key
        key = ApiKey(key='test-api-key-12345', site_name='test-site', active=True)
        db.session.add(key)

        # Seed a test user
        user = User(
            email='alice@example.com',
            first_name='Alice',
            last_name='Smith',
            allowed_vlans='30,40',
            begin_date=date(2024, 1, 1),
        )
        db.session.add(user)
        db.session.flush()

        # Seed a test device linked to alice
        device = Device(
            mac_address='aa:bb:cc:dd:ee:ff',
            user_id=user.id,
            device_name='Alice Laptop',
            registration_status='registered',
            registered_at_location='site-a',
        )
        db.session.add(device)
        db.session.commit()

    with flask_app.test_client() as c:
        yield c


API_HEADERS = {'X-API-Key': 'test-api-key-12345', 'Content-Type': 'application/json'}


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

def test_health(client):
    r = client.get('/health')
    assert r.status_code == 200
    data = r.get_json()
    assert data['status'] == 'ok'
    assert data['service'] == 'bf-central'


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def test_api_requires_key(client):
    r = client.get('/api/v1/users/lookup?email=alice@example.com')
    assert r.status_code == 401


def test_api_rejects_bad_key(client):
    r = client.get(
        '/api/v1/users/lookup?email=alice@example.com',
        headers={'X-API-Key': 'wrong-key'}
    )
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# User lookup
# ---------------------------------------------------------------------------

def test_user_lookup_found(client):
    r = client.get(
        '/api/v1/users/lookup?email=alice@example.com',
        headers=API_HEADERS
    )
    assert r.status_code == 200
    data = r.get_json()
    assert data['found'] is True
    assert data['user']['email'] == 'alice@example.com'
    assert data['user']['first_name'] == 'Alice'
    assert data['user']['allowed_vlans'] == '30,40'


def test_user_lookup_not_found(client):
    r = client.get(
        '/api/v1/users/lookup?email=nobody@example.com',
        headers=API_HEADERS
    )
    assert r.status_code == 404
    data = r.get_json()
    assert data['found'] is False


def test_user_lookup_missing_email(client):
    r = client.get('/api/v1/users/lookup', headers=API_HEADERS)
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# Device lookup
# ---------------------------------------------------------------------------

def test_device_lookup_found(client):
    r = client.get(
        '/api/v1/devices/lookup?mac=aa:bb:cc:dd:ee:ff',
        headers=API_HEADERS
    )
    assert r.status_code == 200
    data = r.get_json()
    assert data['found'] is True
    assert data['device']['mac_address'] == 'aa:bb:cc:dd:ee:ff'
    assert data['device']['user']['email'] == 'alice@example.com'


def test_device_lookup_mac_normalisation(client):
    """MAC addresses in various formats should all resolve."""
    for mac in ['AA:BB:CC:DD:EE:FF', 'aabbccddeeff', 'AA-BB-CC-DD-EE-FF']:
        r = client.get(
            f'/api/v1/devices/lookup?mac={mac}',
            headers=API_HEADERS
        )
        assert r.status_code == 200, f"Failed for MAC: {mac}"


def test_device_lookup_not_found(client):
    r = client.get(
        '/api/v1/devices/lookup?mac=11:22:33:44:55:66',
        headers=API_HEADERS
    )
    assert r.status_code == 404


def test_device_lookup_invalid_mac(client):
    r = client.get(
        '/api/v1/devices/lookup?mac=not-a-mac',
        headers=API_HEADERS
    )
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# Create / update user
# ---------------------------------------------------------------------------

def test_create_user(client):
    payload = {
        'email': 'bob@example.com',
        'first_name': 'Bob',
        'last_name': 'Jones',
        'allowed_vlans': '40',
        'begin_date': '2024-01-01',
    }
    r = client.post('/api/v1/users', headers=API_HEADERS, data=json.dumps(payload))
    assert r.status_code == 201
    data = r.get_json()
    assert data['user']['email'] == 'bob@example.com'
    assert data['user']['allowed_vlans'] == '40'


def test_create_user_idempotent(client):
    """POSTing the same email twice should update, not create a duplicate."""
    payload = {'email': 'alice@example.com', 'first_name': 'Alicia'}
    r = client.post('/api/v1/users', headers=API_HEADERS, data=json.dumps(payload))
    assert r.status_code == 200  # 200 = updated
    data = r.get_json()
    assert data['user']['first_name'] == 'Alicia'


def test_create_user_missing_email(client):
    r = client.post('/api/v1/users', headers=API_HEADERS, data=json.dumps({}))
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# Register device
# ---------------------------------------------------------------------------

def test_register_device(client):
    # First create a user to link
    with flask_app.app_context():
        user = User.query.filter_by(email='alice@example.com').first()
        uid = user.id

    payload = {
        'mac_address': '11:22:33:44:55:66',
        'user_id': uid,
        'device_name': 'Test Phone',
        'registered_at_location': 'site-b',
    }
    r = client.post('/api/v1/devices', headers=API_HEADERS, data=json.dumps(payload))
    assert r.status_code == 201
    data = r.get_json()
    assert data['device']['mac_address'] == '11:22:33:44:55:66'
    assert data['device']['registered_at_location'] == 'site-b'


def test_register_device_idempotent(client):
    """Registering the same MAC twice should update (200), not error."""
    payload = {'mac_address': 'aa:bb:cc:dd:ee:ff', 'device_name': 'Updated Name'}
    r = client.post('/api/v1/devices', headers=API_HEADERS, data=json.dumps(payload))
    assert r.status_code == 200
    data = r.get_json()
    assert data['device']['device_name'] == 'Updated Name'


def test_register_device_missing_mac(client):
    r = client.post('/api/v1/devices', headers=API_HEADERS, data=json.dumps({}))
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# Update user
# ---------------------------------------------------------------------------

def test_update_user(client):
    with flask_app.app_context():
        user = User.query.filter_by(email='alice@example.com').first()
        uid = user.id

    payload = {'allowed_vlans': '10,20,30', 'blocked': False}
    r = client.put(f'/api/v1/users/{uid}', headers=API_HEADERS, data=json.dumps(payload))
    assert r.status_code == 200
    data = r.get_json()
    assert data['user']['allowed_vlans'] == '10,20,30'


def test_update_user_not_found(client):
    r = client.put('/api/v1/users/9999', headers=API_HEADERS, data=json.dumps({'blocked': True}))
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Device last-seen
# ---------------------------------------------------------------------------

def test_device_seen(client):
    r = client.post('/api/v1/devices/aa:bb:cc:dd:ee:ff/seen', headers=API_HEADERS)
    assert r.status_code == 200
    assert r.get_json()['ok'] is True


def test_device_seen_not_found(client):
    r = client.post('/api/v1/devices/11:22:33:44:55:00/seen', headers=API_HEADERS)
    assert r.status_code == 404
