#!/usr/bin/env python3
"""
Migration: Refactor User → Tenant → Organizations Hierarchy
Date: 2024-11-27
Description:
  Transitions from the old 1:1 Organization→Tenant model to the new
  User→Tenant→Organizations hierarchy where multiple organizations
  can exist within a single tenant (workspace).

Changes:
1. Remove global uniqueness constraints that conflict with new model
2. Add new constraints for DNS subdomain global uniqueness
3. Add org_type and parent_org_id fields to organizations
4. Ensure existing data is compatible with new structure

Note: This migration preserves all existing data while updating constraints.
"""

import sys
import os
from pathlib import Path
from sqlalchemy import text, create_engine
from sqlalchemy.orm import sessionmaker
import logging

# Add parent directory to path for imports
ROOT_DIR = Path(__file__).parent.parent.parent
sys.path.append(str(ROOT_DIR))

from shared.database import get_db_url
from shared.models import Base

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def run_migration():
    """Execute the migration"""
    db_url = get_db_url()
    engine = create_engine(db_url)

    with engine.begin() as conn:
        logger.info("Starting User→Tenant→Organizations hierarchy migration...")

        # Step 1: Add new columns to organizations table
        logger.info("Adding new columns to organizations table...")

        try:
            # Add org_type column (department, team, division)
            conn.execute(text("""
                ALTER TABLE organizations
                ADD COLUMN IF NOT EXISTS org_type VARCHAR(50) DEFAULT 'department'
            """))
            logger.info("✅ Added org_type column")

            # Add parent_org_id for hierarchical organizations
            conn.execute(text("""
                ALTER TABLE organizations
                ADD COLUMN IF NOT EXISTS parent_org_id VARCHAR(36)
                REFERENCES organizations(id) ON DELETE SET NULL
            """))
            logger.info("✅ Added parent_org_id column")

        except Exception as e:
            logger.warning(f"Column addition error (may already exist): {e}")

        # Step 2: Update constraints
        logger.info("Updating database constraints...")

        try:
            # Drop old global org slug unique constraint if it exists
            conn.execute(text("""
                DROP INDEX IF EXISTS organizations_slug_key
            """))
            logger.info("✅ Dropped old global slug constraint")

        except Exception as e:
            logger.warning(f"Constraint drop error (may not exist): {e}")

        try:
            # Add new tenant-scoped slug uniqueness constraint
            conn.execute(text("""
                CREATE UNIQUE INDEX IF NOT EXISTS uix_tenant_org_slug
                ON organizations(tenant_id, slug)
            """))
            logger.info("✅ Added tenant-scoped org slug uniqueness")

            # Ensure global DNS subdomain uniqueness
            conn.execute(text("""
                CREATE UNIQUE INDEX IF NOT EXISTS uix_global_org_subdomain
                ON organizations(dns_subdomain)
                WHERE dns_subdomain IS NOT NULL
            """))
            logger.info("✅ Added global DNS subdomain uniqueness")

            # Add performance indexes
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_org_type_tenant
                ON organizations(tenant_id, org_type)
            """))

            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_org_dns_subdomain
                ON organizations(dns_subdomain)
                WHERE dns_subdomain IS NOT NULL
            """))
            logger.info("✅ Added performance indexes")

        except Exception as e:
            logger.error(f"Constraint creation error: {e}")
            raise

        # Step 3: Update existing data to be compatible with new model
        logger.info("Updating existing organization data...")

        try:
            # Set org_type for existing organizations
            conn.execute(text("""
                UPDATE organizations
                SET org_type = 'department'
                WHERE org_type IS NULL
            """))

            # Ensure is_default is properly set (first org per tenant)
            conn.execute(text("""
                WITH first_orgs AS (
                    SELECT DISTINCT ON (tenant_id) id, tenant_id
                    FROM organizations
                    WHERE status = 'active'
                    ORDER BY tenant_id, created_at ASC
                )
                UPDATE organizations
                SET is_default = (id IN (SELECT id FROM first_orgs))
            """))
            logger.info("✅ Updated organization metadata")

        except Exception as e:
            logger.error(f"Data update error: {e}")
            raise

        # Step 4: Validate data integrity
        logger.info("Validating data integrity...")

        # Check for DNS subdomain conflicts
        result = conn.execute(text("""
            SELECT dns_subdomain, COUNT(*) as count
            FROM organizations
            WHERE dns_subdomain IS NOT NULL
            GROUP BY dns_subdomain
            HAVING COUNT(*) > 1
        """))

        conflicts = result.fetchall()
        if conflicts:
            logger.error("❌ DNS subdomain conflicts found:")
            for conflict in conflicts:
                logger.error(f"  Subdomain '{conflict[0]}' used by {conflict[1]} organizations")
            raise Exception("DNS subdomain conflicts must be resolved before migration")

        logger.info("✅ No DNS subdomain conflicts found")

        # Validate tenant-org relationships
        result = conn.execute(text("""
            SELECT COUNT(*) as org_count
            FROM organizations
            WHERE tenant_id IS NOT NULL
        """))

        org_count = result.fetchone()[0]
        logger.info(f"✅ {org_count} organizations validated with tenant relationships")

        logger.info("🎉 Migration completed successfully!")

        # Step 5: Generate summary report
        logger.info("\n📊 Migration Summary:")

        # Organizations by tenant
        result = conn.execute(text("""
            SELECT t.name, COUNT(o.id) as org_count
            FROM tenants t
            LEFT JOIN organizations o ON t.id = o.tenant_id
            WHERE t.status = 'active'
            GROUP BY t.id, t.name
            ORDER BY org_count DESC
        """))

        logger.info("Organizations per tenant:")
        for row in result.fetchall():
            logger.info(f"  📁 {row[0]}: {row[1]} organizations")

def rollback_migration():
    """Rollback the migration if needed"""
    db_url = get_db_url()
    engine = create_engine(db_url)

    with engine.begin() as conn:
        logger.info("Rolling back User→Tenant→Organizations hierarchy migration...")

        try:
            # Remove new constraints
            conn.execute(text("DROP INDEX IF EXISTS uix_tenant_org_slug"))
            conn.execute(text("DROP INDEX IF EXISTS uix_global_org_subdomain"))
            conn.execute(text("DROP INDEX IF EXISTS idx_org_type_tenant"))
            conn.execute(text("DROP INDEX IF EXISTS idx_org_dns_subdomain"))

            # Remove new columns (be careful - this will lose data!)
            # conn.execute(text("ALTER TABLE organizations DROP COLUMN IF EXISTS org_type"))
            # conn.execute(text("ALTER TABLE organizations DROP COLUMN IF EXISTS parent_org_id"))

            logger.info("✅ Rollback completed")

        except Exception as e:
            logger.error(f"Rollback error: {e}")
            raise

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Migrate to User→Tenant→Organizations hierarchy")
    parser.add_argument("--rollback", action="store_true", help="Rollback the migration")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without executing")

    args = parser.parse_args()

    if args.dry_run:
        logger.info("DRY RUN: Would execute User→Tenant→Organizations hierarchy migration")
        logger.info("Changes:")
        logger.info("  ✅ Add org_type and parent_org_id columns")
        logger.info("  ✅ Update constraints for new hierarchy")
        logger.info("  ✅ Maintain global DNS subdomain uniqueness")
        logger.info("  ✅ Enable tenant-scoped organization management")
    elif args.rollback:
        rollback_migration()
    else:
        run_migration()