"""
Add organization-scoped directory columns so each org can have its own LDAP/Azure config.

Usage:
    python scripts/migrations/20251122_add_org_directory_scope.py
"""

import os
import sys
from sqlalchemy import text

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

from shared.database import engine  # noqa: E402

STATEMENTS = [
    # tenant_ldap_configs org scope + indexes
    "ALTER TABLE tenant_ldap_configs ADD COLUMN IF NOT EXISTS organization_id VARCHAR(36) NULL",
    "ALTER TABLE tenant_ldap_configs DROP CONSTRAINT IF EXISTS tenant_ldap_configs_tenant_id_key",
    "ALTER TABLE tenant_ldap_configs DROP CONSTRAINT IF EXISTS uix_ldap_tenant_org",
    "ALTER TABLE tenant_ldap_configs ADD CONSTRAINT uix_ldap_tenant_org UNIQUE (tenant_id, organization_id)",
    "CREATE INDEX IF NOT EXISTS idx_ldap_config_org ON tenant_ldap_configs (organization_id)",
    # tenant_ldap_sync_history org scope + index
    "ALTER TABLE tenant_ldap_sync_history ADD COLUMN IF NOT EXISTS organization_id VARCHAR(36) NULL",
    "CREATE INDEX IF NOT EXISTS idx_ldap_sync_org ON tenant_ldap_sync_history (organization_id)"
]


def run():
    print("\n🔧 Applying organization-scoped directory migration...")
    with engine.begin() as connection:
        for stmt in STATEMENTS:
            print(f"   • {stmt}")
            connection.execute(text(stmt))
    print("✅ Migration complete\n")


if __name__ == "__main__":
    run()
