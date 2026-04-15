# bf-central

Central registration server for [bf-network](https://github.com/rwv1001/bf-network).

## Purpose

bf-network deploys a captive portal at each physical location (site). Without bf-central, users must register their devices separately at every site they visit.

**bf-central** provides a single source of truth for user and device registrations. Any bf-network portal can query bf-central to check whether a device or user is already registered, so registration only needs to be done **once** regardless of which site the user connects to first.

## Architecture

```
       Site A (bf-network)          Site B (bf-network)
       ┌─────────────────┐          ┌─────────────────┐
       │ Captive Portal  │          │ Captive Portal  │
       └────────┬────────┘          └────────┬────────┘
                │  X-API-Key                 │  X-API-Key
                │                            │
                ▼                            ▼
         ┌─────────────────────────────────────┐
         │            bf-central               │
         │   REST API  +  Admin Web Interface  │
         │          PostgreSQL DB              │
         └─────────────────────────────────────┘
```

When a device connects at Site B, the portal calls bf-central to check whether the device's MAC (or the user's email) is already registered. If it is, the device gets immediate access without the user having to fill in the registration form again.

## API

All `/api/v1/` endpoints require an `X-API-Key` header containing a valid API key created via the admin panel.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/users/lookup?email=<email>` | Look up a user by email |
| GET | `/api/v1/devices/lookup?mac=<mac>` | Look up a device by MAC address |
| POST | `/api/v1/users` | Create or update a user |
| PUT | `/api/v1/users/<id>` | Update a user by ID |
| POST | `/api/v1/devices` | Register a device |
| POST | `/api/v1/devices/<mac>/seen` | Update device last-seen timestamp |
| GET | `/health` | Health check (no auth required) |

### Example: look up a device

```bash
curl -H "X-API-Key: <key>" \
  https://central.example.com/api/v1/devices/lookup?mac=aa:bb:cc:dd:ee:ff
```

Response (found):
```json
{
  "found": true,
  "device": {
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "registration_status": "registered",
    "registered_at_location": "site-a",
    "user": {
      "email": "alice@example.com",
      "allowed_vlans": "30,40",
      "is_active": true
    }
  }
}
```

Response (not found):
```json
{ "found": false }
```

## Quick Start

### 1. Clone and configure

```bash
cp .env.example .env
# Edit .env: set SECRET_KEY and DB_PASSWORD
```

### 2. Start with Docker Compose

```bash
./setup.sh
# or manually:
docker compose up -d --build
```

### 3. Access the admin panel

Open `http://localhost:8081/admin` in your browser.  
Default credentials: **admin / admin123** (change after first login).

### 4. Create an API key

In the admin panel, go to **API Keys → New Key**.  
Copy the generated key and add it to each bf-network portal's environment:

```bash
# In bf-network .env
CENTRAL_API_URL=https://central.example.com
CENTRAL_API_KEY=<your-key>
```

## Development

### Install dependencies

```bash
pip install -r app/requirements.txt
```

### Run locally (SQLite)

```bash
cd app
DATABASE_URL=sqlite:///dev.db python app.py
```

### Run tests

```bash
pip install pytest
python -m pytest tests/ -v
```

## Directory Structure

```
bf-central/
├── app/
│   ├── app.py            # Flask application + API routes
│   ├── models.py         # SQLAlchemy models
│   ├── requirements.txt
│   ├── Dockerfile
│   └── templates/        # Admin web interface
├── tests/
│   └── test_api.py       # pytest test suite
├── init-db.sql           # PostgreSQL schema
├── docker-compose.yml
├── .env.example
└── setup.sh
```
