"""
One-off migration to add data-plane metadata columns to tenant_app_access.

Usage:
    python scripts/migrations/20240210_add_tenant_app_access_metadata.py
"""

import os
import sys
from sqlalchemy import text

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

from shared.database import engine  # noqa: E402

ALTER_STATEMENTS = [
    "ALTER TABLE tenant_app_access ADD COLUMN IF NOT EXISTS network_tier VARCHAR(30) DEFAULT 'shared'",
    "ALTER TABLE tenant_app_access ADD COLUMN IF NOT EXISTS ingress_hostname VARCHAR(255)",
    "ALTER TABLE tenant_app_access ADD COLUMN IF NOT EXISTS provisioning_state VARCHAR(50) DEFAULT 'not_started'",
    "ALTER TABLE tenant_app_access ADD COLUMN IF NOT EXISTS dns_status VARCHAR(50) DEFAULT 'pending'",
    "ALTER TABLE tenant_app_access ADD COLUMN IF NOT EXISTS provisioning_error TEXT",
    "ALTER TABLE tenant_app_access ADD COLUMN IF NOT EXISTS last_synced_at TIMESTAMP NULL",
    "CREATE INDEX IF NOT EXISTS idx_app_access_provisioning ON tenant_app_access (tenant_id, app_name, provisioning_state)"
]


def run():
    print("🔧 Applying tenant_app_access metadata migration...")
    with engine.begin() as connection:
        for stmt in ALTER_STATEMENTS:
            print(f"   • {stmt}")
            connection.execute(text(stmt))
    print("✅ Migration complete")


if __name__ == "__main__":
    run()
