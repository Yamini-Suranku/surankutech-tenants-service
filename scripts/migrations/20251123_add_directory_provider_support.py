"""
Add provider_type and Azure Entra Graph fields to tenant_ldap_configs so we can
differentiate between classic LDAP connectors and Microsoft Graph directory sync.

Usage:
    python scripts/migrations/20251123_add_directory_provider_support.py
"""

import os
import sys
from sqlalchemy import text

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

from shared.database import engine  # noqa: E402

STATEMENTS = [
    # Provider metadata
    "ALTER TABLE tenant_ldap_configs ADD COLUMN IF NOT EXISTS provider_type VARCHAR(50) NOT NULL DEFAULT 'ldap'",
    "CREATE INDEX IF NOT EXISTS idx_ldap_provider_type ON tenant_ldap_configs (provider_type)",
    "ALTER TABLE tenant_ldap_configs ADD COLUMN IF NOT EXISTS graph_tenant_id VARCHAR(100) NULL",
    "ALTER TABLE tenant_ldap_configs ADD COLUMN IF NOT EXISTS graph_client_id VARCHAR(100) NULL",
    # Allow nulls for LDAP-only fields so Graph configs don't require them
    "ALTER TABLE tenant_ldap_configs ALTER COLUMN connection_url DROP NOT NULL",
    "ALTER TABLE tenant_ldap_configs ALTER COLUMN bind_dn DROP NOT NULL",
    "ALTER TABLE tenant_ldap_configs ALTER COLUMN users_dn DROP NOT NULL"
]


def run():
    print("\n🔧 Applying directory provider support migration...")
    with engine.begin() as connection:
        for stmt in STATEMENTS:
            print(f"   • {stmt}")
            connection.execute(text(stmt))
    print("✅ Migration complete\n")


if __name__ == "__main__":
    run()
