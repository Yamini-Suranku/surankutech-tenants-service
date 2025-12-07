#!/usr/bin/env python3
"""
Ensure the target Postgres database from DATABASE_URL exists.
Creates it via the default `postgres` database if missing.
"""

import os
import sys
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError


def ensure_database():
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        print("DATABASE_URL not set; nothing to ensure", file=sys.stderr)
        return

    url = make_url(database_url)
    target_db = url.database
    if not target_db:
        print("No database name in DATABASE_URL; skipping ensure step", file=sys.stderr)
        return

    # If the target db is already postgres, nothing to do
    if target_db.lower() == "postgres":
        return

    admin_url = url.set(database="postgres")
    engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as conn:
            exists = conn.execute(
                text("SELECT 1 FROM pg_database WHERE datname = :db"),
                {"db": target_db},
            ).scalar()
            if exists:
                print(f"Database '{target_db}' already exists.")
                return

            print(f"Creating database '{target_db}'...")
            conn.execute(text(f'CREATE DATABASE "{target_db}"'))
            print(f"Database '{target_db}' created.")
    except OperationalError as exc:
        print(f"Failed to ensure database '{target_db}': {exc}", file=sys.stderr)
        raise


if __name__ == "__main__":
    ensure_database()
