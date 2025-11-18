#!/bin/bash
set -e

echo "🚀 Starting Suranku Tenants Service..."
echo "=================================================="

# Function to wait for Vault secrets
wait_for_vault_secrets() {
    echo "⏳ Waiting for Vault secrets to be available..."
    local max_attempts=30
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        if [ -f "/vault/secrets/keycloak-admin" ]; then
            echo "📂 Loading Keycloak admin credentials from Vault..."
            source /vault/secrets/keycloak-admin
            echo "✅ Vault secrets loaded!"
            echo "   - KEYCLOAK_ADMIN_USERNAME: ${KEYCLOAK_ADMIN_USERNAME}"
            echo "   - KEYCLOAK_ADMIN_PASSWORD: [REDACTED]"
            return 0
        fi
        attempt=$((attempt + 1))
        echo "   Attempt $attempt/$max_attempts: Vault secrets not ready yet..."
        sleep 2
    done

    echo "⚠️ Vault secrets not found after $max_attempts attempts, using environment variables..."
    return 1
}

# Wait for and source Vault-injected secrets
wait_for_vault_secrets

# Function to wait for database
wait_for_db() {
    echo "⏳ Waiting for database to be ready..."
    python3 -c "
import time
import os
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError

database_url = os.environ.get('DATABASE_URL')
max_retries = 30
delay = 2

for attempt in range(max_retries):
    try:
        engine = create_engine(database_url)
        with engine.connect() as conn:
            conn.execute(text('SELECT 1'))
        print('✅ Database is ready!')
        break
    except OperationalError:
        print(f'⏳ Database not ready (attempt {attempt + 1}/{max_retries})')
        if attempt < max_retries - 1:
            time.sleep(delay)
        else:
            print('❌ Database connection failed')
            exit(1)
"
}

# Function to create tables
create_tables() {
    echo "🏗️ Creating database tables..."
    python3 create_all_tables.py
    if [ $? -eq 0 ]; then
        echo "✅ Database tables created successfully!"
    else
        echo "❌ Failed to create database tables"
        exit 1
    fi
}

# Main startup sequence
echo "1️⃣ Checking database connection..."
wait_for_db

echo "2️⃣ Initializing database schema..."
create_tables

echo "3️⃣ Starting FastAPI service..."
echo "=================================================="
exec uvicorn main:app --host 0.0.0.0 --port 8000 --reload