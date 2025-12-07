#!/usr/bin/env python3
"""
Migration script to fix app_roles format in user_tenants table
Converts list format ['tenant_admin'] to proper dict format {'platform': ['tenant_admin']}
"""

import os
import sys
import psycopg2
import json
import logging
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def fix_app_roles_format():
    """Fix app_roles format from list to dictionary"""
    try:
        db_url = os.getenv('DATABASE_URL')
        if not db_url:
            raise ValueError("DATABASE_URL environment variable not set")

        conn = psycopg2.connect(db_url)
        cur = conn.cursor()

        # Find all records where app_roles is stored as a list
        cur.execute("""
            SELECT id, app_roles
            FROM user_tenants
            WHERE jsonb_typeof(app_roles) = 'array'
        """)

        problematic_records = cur.fetchall()

        if not problematic_records:
            logger.info("No problematic records found. All app_roles are already in correct format.")
            return True

        logger.info(f"Found {len(problematic_records)} records with incorrect app_roles format")

        # Fix each record
        fixed_count = 0
        for record_id, app_roles in problematic_records:
            logger.info(f"Fixing record {record_id}: {app_roles}")

            # Convert list to proper dictionary format
            if isinstance(app_roles, list):
                # Convert list of roles to platform app roles
                fixed_app_roles = {"platform": app_roles}
            else:
                logger.warning(f"Unexpected app_roles type for record {record_id}: {type(app_roles)}")
                continue

            # Update the record
            cur.execute("""
                UPDATE user_tenants
                SET app_roles = %s
                WHERE id = %s
            """, (json.dumps(fixed_app_roles), record_id))

            fixed_count += 1
            logger.info(f"Fixed record {record_id}: {app_roles} -> {fixed_app_roles}")

        # Commit changes
        conn.commit()

        logger.info(f"Successfully fixed {fixed_count} records")

        # Verify the fix
        cur.execute("""
            SELECT id, app_roles
            FROM user_tenants
            WHERE jsonb_typeof(app_roles) = 'array'
        """)

        remaining_problematic = cur.fetchall()
        if remaining_problematic:
            logger.error(f"Still have {len(remaining_problematic)} problematic records after fix!")
            return False

        logger.info("✅ All app_roles are now in correct dictionary format")

        cur.close()
        conn.close()
        return True

    except Exception as e:
        logger.error(f"Error fixing app_roles format: {e}")
        return False

if __name__ == "__main__":
    success = fix_app_roles_format()
    sys.exit(0 if success else 1)