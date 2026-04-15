-- bf-central database schema

CREATE TABLE IF NOT EXISTS admins (
    id            SERIAL PRIMARY KEY,
    username      VARCHAR(100) UNIQUE NOT NULL,
    email         VARCHAR(255),
    password_hash VARCHAR(255) NOT NULL,
    created_at    TIMESTAMP DEFAULT NOW(),
    last_login    TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_admins_username ON admins(username);

CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    email         VARCHAR(255) UNIQUE NOT NULL,
    first_name    VARCHAR(100),
    last_name     VARCHAR(100),
    phone_number  VARCHAR(20),
    allowed_vlans TEXT,
    begin_date    DATE NOT NULL,
    expiry_date   DATE,
    blocked       BOOLEAN NOT NULL DEFAULT FALSE,
    notes         TEXT,
    created_at    TIMESTAMP DEFAULT NOW(),
    updated_at    TIMESTAMP DEFAULT NOW(),
    created_by    VARCHAR(100) DEFAULT 'admin'
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

CREATE TABLE IF NOT EXISTS devices (
    id                      SERIAL PRIMARY KEY,
    mac_address             VARCHAR(17) UNIQUE NOT NULL,
    user_id                 INTEGER REFERENCES users(id) ON DELETE SET NULL,
    device_name             VARCHAR(100),
    registration_status     VARCHAR(50) NOT NULL DEFAULT 'registered',
    registered_at           TIMESTAMP DEFAULT NOW(),
    last_seen               TIMESTAMP,
    registered_at_location  VARCHAR(255)
);
CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address);
CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);

CREATE TABLE IF NOT EXISTS api_keys (
    id           SERIAL PRIMARY KEY,
    key          VARCHAR(64) UNIQUE NOT NULL,
    site_name    VARCHAR(100) NOT NULL,
    description  TEXT,
    active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMP DEFAULT NOW(),
    last_used_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_api_keys_key ON api_keys(key);
