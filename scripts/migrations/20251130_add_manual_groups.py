"""
Add manual groups and group memberships tables for email-invited users.
These complement directory groups from Azure AD/LDAP for complete group management.

Usage:
    python scripts/migrations/20251130_add_manual_groups.py
"""

import os
import sys
from sqlalchemy import text

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

APP_DIR = os.path.join(ROOT_DIR, "app")
if APP_DIR not in sys.path:
    sys.path.append(APP_DIR)

from shared.database import engine  # noqa: E402

STATEMENTS = [
    # Create manual groups table
    """CREATE TABLE organization_groups (
        id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
        tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        organization_id VARCHAR(36) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        display_name VARCHAR(255),
        description TEXT,
        color VARCHAR(7) DEFAULT '#6366f1',
        source_type VARCHAR(50) NOT NULL DEFAULT 'manual',
        created_by VARCHAR(36) REFERENCES users(id),
        app_role_mappings JSON DEFAULT '{}',
        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    )""",

    # Create manual group memberships table
    """CREATE TABLE organization_group_memberships (
        id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
        organization_group_id VARCHAR(36) NOT NULL REFERENCES organization_groups(id) ON DELETE CASCADE,
        user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        created_by VARCHAR(36) REFERENCES users(id)
    )""",

    # Create indexes for organization_groups
    "CREATE INDEX idx_org_group_tenant ON organization_groups(tenant_id)",
    "CREATE INDEX idx_org_group_organization ON organization_groups(organization_id)",
    "CREATE INDEX idx_org_group_name ON organization_groups(name)",
    "CREATE INDEX idx_org_group_source ON organization_groups(source_type)",
    "CREATE UNIQUE INDEX uix_org_group_name_org ON organization_groups(organization_id, name)",

    # Create indexes for organization_group_memberships
    "CREATE INDEX idx_org_group_membership_group ON organization_group_memberships(organization_group_id)",
    "CREATE INDEX idx_org_group_membership_user ON organization_group_memberships(user_id)",
    "CREATE UNIQUE INDEX uix_org_group_membership ON organization_group_memberships(organization_group_id, user_id)",
]

def migrate():
    """Apply the migration"""
    print("Creating manual groups tables (organization_groups, organization_group_memberships)...")

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

    print("✅ Manual groups migration completed successfully!")

def rollback():
    """Rollback the migration"""
    print("Rolling back manual groups migration...")

    rollback_statements = [
        "DROP TABLE IF EXISTS organization_group_memberships CASCADE",
        "DROP TABLE IF EXISTS organization_groups CASCADE",
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