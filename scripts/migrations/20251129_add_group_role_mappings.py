"""
Add group_role_mappings JSON field to tenant_ldap_configs to persist
Azure Entra ID group-to-role mappings in the database.

Usage:
    python scripts/migrations/20251129_add_group_role_mappings.py
"""

import os
import sys
from sqlalchemy import text

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

from shared.database import engine  # noqa: E402

STATEMENTS = [
    # Add JSON field for group role mappings
    "ALTER TABLE tenant_ldap_configs ADD COLUMN IF NOT EXISTS group_role_mappings JSON DEFAULT '{}'",
]

def migrate():
    """Apply the migration"""
    print("Adding group_role_mappings field to tenant_ldap_configs...")

    with engine.connect() as conn:
        for statement in STATEMENTS:
            print(f"Executing: {statement}")
            conn.execute(text(statement))
            conn.commit()

    print("✅ Migration completed successfully!")

def rollback():
    """Rollback the migration"""
    print("Rolling back group_role_mappings migration...")

    rollback_statements = [
        "ALTER TABLE tenant_ldap_configs DROP COLUMN IF EXISTS group_role_mappings",
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