#!/usr/bin/env bash
set -e

echo "=== bf-central setup ==="

if [ ! -f .env ]; then
    cp .env.example .env
    echo "[!] Created .env from .env.example – edit it before proceeding."
    echo "    Set SECRET_KEY and DB_PASSWORD at minimum."
    read -r -p "Press Enter to continue with defaults, or Ctrl-C to edit .env first..."
fi

echo "[*] Starting services..."
docker compose up -d --build

echo "[*] Waiting for database..."
sleep 8

echo "[*] Initialising database..."
docker compose exec web python app.py --init 2>/dev/null || true

echo ""
echo "=== Setup complete ==="
echo "Admin panel: http://localhost:8081/admin"
echo "Health check: http://localhost:8081/health"
echo ""
echo "Default credentials: admin / admin123"
echo "(Change password after first login via Admin → edit admin)"
