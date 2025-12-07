"""
Add DirectoryUser, DirectoryGroup, and DirectoryGroupMembership tables
to cache Azure Entra ID and LDAP directory data for faster access and role mapping.

Usage:
    python scripts/migrations/20251129_add_directory_cache_tables.py
"""

import os
import sys
from sqlalchemy import text

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

from shared.database import engine  # noqa: E402

STATEMENTS = [
    # Create DirectoryUser table
    """CREATE TABLE directory_users (
        id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
        tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        organization_id VARCHAR(36) REFERENCES organizations(id) ON DELETE CASCADE,
        ldap_config_id VARCHAR(36) NOT NULL REFERENCES tenant_ldap_configs(id) ON DELETE CASCADE,
        external_id VARCHAR(255) NOT NULL,
        provider_type VARCHAR(50) NOT NULL,
        username VARCHAR(255),
        email VARCHAR(255),
        display_name VARCHAR(255),
        first_name VARCHAR(255),
        last_name VARCHAR(255),
        enabled BOOLEAN NOT NULL DEFAULT TRUE,
        attributes JSON,
        last_synced_at TIMESTAMP NOT NULL DEFAULT NOW(),
        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    )""",

    # Create DirectoryGroup table
    """CREATE TABLE directory_groups (
        id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
        tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        organization_id VARCHAR(36) REFERENCES organizations(id) ON DELETE CASCADE,
        ldap_config_id VARCHAR(36) NOT NULL REFERENCES tenant_ldap_configs(id) ON DELETE CASCADE,
        external_id VARCHAR(255) NOT NULL,
        provider_type VARCHAR(50) NOT NULL,
        name VARCHAR(255) NOT NULL,
        display_name VARCHAR(255),
        description TEXT,
        email VARCHAR(255),
        security_enabled BOOLEAN NOT NULL DEFAULT TRUE,
        attributes JSON,
        last_synced_at TIMESTAMP NOT NULL DEFAULT NOW(),
        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    )""",

    # Create DirectoryGroupMembership table
    """CREATE TABLE directory_group_memberships (
        id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
        directory_group_id VARCHAR(36) NOT NULL REFERENCES directory_groups(id) ON DELETE CASCADE,
        directory_user_id VARCHAR(36) NOT NULL REFERENCES directory_users(id) ON DELETE CASCADE,
        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        last_synced_at TIMESTAMP NOT NULL DEFAULT NOW()
    )""",

    # Create indexes for DirectoryUser
    "CREATE INDEX idx_directory_user_tenant ON directory_users(tenant_id)",
    "CREATE INDEX idx_directory_user_org ON directory_users(organization_id)",
    "CREATE INDEX idx_directory_user_config ON directory_users(ldap_config_id)",
    "CREATE INDEX idx_directory_user_external ON directory_users(external_id)",
    "CREATE INDEX idx_directory_user_provider ON directory_users(provider_type)",
    "CREATE INDEX idx_directory_user_email ON directory_users(email)",
    "CREATE INDEX idx_directory_user_sync ON directory_users(last_synced_at)",
    "CREATE UNIQUE INDEX uix_directory_user_config_external ON directory_users(ldap_config_id, external_id)",

    # Create indexes for DirectoryGroup
    "CREATE INDEX idx_directory_group_tenant ON directory_groups(tenant_id)",
    "CREATE INDEX idx_directory_group_org ON directory_groups(organization_id)",
    "CREATE INDEX idx_directory_group_config ON directory_groups(ldap_config_id)",
    "CREATE INDEX idx_directory_group_external ON directory_groups(external_id)",
    "CREATE INDEX idx_directory_group_provider ON directory_groups(provider_type)",
    "CREATE INDEX idx_directory_group_name ON directory_groups(name)",
    "CREATE INDEX idx_directory_group_sync ON directory_groups(last_synced_at)",
    "CREATE UNIQUE INDEX uix_directory_group_config_external ON directory_groups(ldap_config_id, external_id)",

    # Create indexes for DirectoryGroupMembership
    "CREATE INDEX idx_membership_group ON directory_group_memberships(directory_group_id)",
    "CREATE INDEX idx_membership_user ON directory_group_memberships(directory_user_id)",
    "CREATE INDEX idx_membership_sync ON directory_group_memberships(last_synced_at)",
    "CREATE UNIQUE INDEX uix_directory_membership ON directory_group_memberships(directory_group_id, directory_user_id)",
]

def migrate():
    """Apply the migration"""
    print("Creating directory cache tables (DirectoryUser, DirectoryGroup, DirectoryGroupMembership)...")

    with engine.connect() as conn:
        for statement in STATEMENTS:
            try:
                print(f"Executing: {statement[:80]}...")
                conn.execute(text(statement))
                conn.commit()
            except Exception as e:
                print(f"Error executing statement: {e}")
                print(f"Statement was: {statement}")
                raise

    print("✅ Directory cache tables migration completed successfully!")

def rollback():
    """Rollback the migration"""
    print("Rolling back directory cache tables migration...")

    rollback_statements = [
        "DROP TABLE IF EXISTS directory_group_memberships CASCADE",
        "DROP TABLE IF EXISTS directory_groups CASCADE",
        "DROP TABLE IF EXISTS directory_users CASCADE",
    ]

    with engine.connect() as conn:
        for statement in rollback_statements:
            print(f"Executing rollback: {statement}")
            conn.execute(text(statement))
            conn.commit()

    print("✅ Rollback completed successfully!")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "rollback":
        rollback()
    else:
        migrate()