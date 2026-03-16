#!/usr/bin/env python3
"""Add organization_user_profiles table for org-scoped user avatars."""

from pathlib import Path
import sys

from sqlalchemy import text

sys.path.append(str(Path(__file__).resolve().parents[1]))

from shared.database import engine


DDL = """
CREATE TABLE IF NOT EXISTS organization_user_profiles (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    organization_id VARCHAR(36) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    avatar_url VARCHAR(500) NULL,
    created_at TIMESTAMP NULL DEFAULT NOW(),
    updated_at TIMESTAMP NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS uix_org_user_profile
    ON organization_user_profiles(organization_id, user_id);
CREATE INDEX IF NOT EXISTS idx_org_user_profiles_lookup
    ON organization_user_profiles(tenant_id, organization_id, user_id);
"""


def main() -> None:
    with engine.begin() as conn:
        for statement in [s.strip() for s in DDL.split(";") if s.strip()]:
            conn.execute(text(statement))
    print("organization_user_profiles migration applied")


if __name__ == "__main__":
    main()
