#!/bin/sh
set -e

echo "=== bf-central API starting ==="

# Wait for Postgres to be ready
echo "Waiting for database..."
until python -c "
import os, psycopg2
psycopg2.connect(os.environ['DATABASE_URL']).close()
" 2>/dev/null; do
    sleep 2
done
echo "Database ready."

exec gunicorn \
    --bind 0.0.0.0:5000 \
    --workers "${GUNICORN_WORKERS:-2}" \
    --timeout 30 \
    --access-logfile - \
    app:app
