"""Migration: add organization columns to invitations"""
from sqlalchemy import text
from shared.database import engine

STATEMENTS = [
    "ALTER TABLE invitations ADD COLUMN IF NOT EXISTS organization_id VARCHAR(36)",
    "ALTER TABLE invitations ADD COLUMN IF NOT EXISTS organization_hostname VARCHAR(255)",
    "CREATE INDEX IF NOT EXISTS idx_invitations_org_id ON invitations(organization_id)"
]

def run():
    with engine.begin() as conn:
        for stmt in STATEMENTS:
            conn.execute(text(stmt))
    print("✅ Migration completed: invitations now track organization context")

if __name__ == "__main__":
    run()
