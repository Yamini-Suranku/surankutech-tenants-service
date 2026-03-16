from sqlalchemy import text

from shared.database import engine


def run() -> None:
    statements = [
        """
        ALTER TABLE audit_logs
        ADD COLUMN IF NOT EXISTS organization_id VARCHAR(36)
        """,
        """
        UPDATE audit_logs al
        SET organization_id = o.id
        FROM organizations o
        WHERE al.organization_id IS NULL
          AND al.tenant_id = o.tenant_id
          AND lower(coalesce(al.details->>'org_slug', '')) = lower(coalesce(o.slug, ''))
        """,
        """
        UPDATE audit_logs al
        SET organization_id = org_map.organization_id
        FROM (
            SELECT o1.tenant_id, o1.id AS organization_id
            FROM organizations o1
            WHERE (
                SELECT count(*)
                FROM organizations o2
                WHERE o2.tenant_id = o1.tenant_id
            ) = 1
        ) org_map
        WHERE al.organization_id IS NULL
          AND al.tenant_id = org_map.tenant_id
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_audit_tenant_org_action_date
        ON audit_logs (tenant_id, organization_id, action, created_at)
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_audit_org_created_at
        ON audit_logs (organization_id, created_at)
        """,
    ]

    with engine.begin() as conn:
        for statement in statements:
            conn.execute(text(statement))

    print("Applied org scope migration for audit logs")


if __name__ == "__main__":
    run()
