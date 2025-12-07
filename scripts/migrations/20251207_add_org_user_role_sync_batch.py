"""
Add sync_batch_id tracking to organization_user_roles so Org Admin UI can report
which directory sync batch granted each member's roles.

Usage:
    python scripts/migrations/20251207_add_org_user_role_sync_batch.py
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
    # Add nullable sync_batch_id column to record the originating directory sync run
    """ALTER TABLE organization_user_roles
        ADD COLUMN IF NOT EXISTS sync_batch_id VARCHAR(36)
    """,

    # Index for faster lookups when joining to sync history
    "CREATE INDEX IF NOT EXISTS idx_org_user_role_sync_batch ON organization_user_roles(sync_batch_id)",

    # Foreign key so cascading deletes (or manual cleanup) stay consistent
    """DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'fk_org_user_roles_sync_batch'
            ) THEN
                ALTER TABLE organization_user_roles
                    ADD CONSTRAINT fk_org_user_roles_sync_batch
                    FOREIGN KEY (sync_batch_id)
                    REFERENCES tenant_ldap_sync_history(id)
                    ON DELETE SET NULL;
            END IF;
        END $$;
    """,
]

ROLLBACK_STATEMENTS = [
    "ALTER TABLE organization_user_roles DROP CONSTRAINT IF EXISTS fk_org_user_roles_sync_batch",
    "DROP INDEX IF EXISTS idx_org_user_role_sync_batch",
    "ALTER TABLE organization_user_roles DROP COLUMN IF EXISTS sync_batch_id",
]

def migrate():
    """Apply the migration"""
    print("Adding sync_batch_id to organization_user_roles ...")

    with engine.connect() as conn:
        for statement in STATEMENTS:
            try:
                snippet = " ".join(statement.split())
                print(f"Executing: {snippet[:80]}...")
                conn.execute(text(statement))
                conn.commit()
            except Exception as exc:
                print(f"Error executing statement: {exc}")
                print(f"Failed statement: {statement}")
                raise

    print("✅ sync_batch_id column added successfully")


def rollback():
    """Rollback the migration"""
    print("Rolling back sync_batch_id migration ...")

    with engine.connect() as conn:
        for statement in ROLLBACK_STATEMENTS:
            print(f"Executing rollback: {statement}")
            conn.execute(text(statement))
            conn.commit()

    print("✅ Rollback completed")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "rollback":
        rollback()
    else:
        migrate()
