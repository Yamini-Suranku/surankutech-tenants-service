#!/usr/bin/env python3
"""
Kubernetes Database Reset Script
Resets platform data in PostgreSQL running in Kubernetes
"""

import subprocess
import logging
import sys

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def run_kubectl_sql(sql_command, database='tenants_service'):
    """Execute SQL command via kubectl exec"""
    try:
        cmd = [
            "kubectl", "exec", "-n", "shared-services", "suranku-postgres-0", "--",
            "psql", "-U", "postgres", "-d", database, "-c", sql_command
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        logger.error(f"SQL command failed: {e.stderr}")
        raise

def reset_database():
    """Reset all platform data in tenants_service database"""
    logger.info("🗄️  Resetting tenants_service database...")

    # Check current data
    logger.info("📊 Checking current data...")

    check_sql = """
    SELECT 'users' as table_name, COUNT(*) as count FROM users
    UNION ALL SELECT 'tenants', COUNT(*) FROM tenants
    UNION ALL SELECT 'organizations', COUNT(*) FROM organizations
    UNION ALL SELECT 'invitations', COUNT(*) FROM invitations
    UNION ALL SELECT 'user_tenants', COUNT(*) FROM user_tenants
    ORDER BY table_name;
    """

    try:
        result = run_kubectl_sql(check_sql)
        logger.info("Current record counts:")
        logger.info(result)

        # Check if there's any data
        if "0" in result and result.count("0") == result.count("\n") - 2:  # All zeros
            logger.info("✅ Database already clean - no data to remove")
            return

    except Exception as e:
        logger.warning(f"Could not check current data: {e}")

    # Reset all platform data
    logger.info("🧹 Cleaning all platform data...")

    reset_sql = """
    -- Delete in dependency order
    DELETE FROM email_logs;
    DELETE FROM password_reset_tokens;
    DELETE FROM organization_user_roles;
    DELETE FROM organization_app_access;
    DELETE FROM invitations;
    DELETE FROM user_tenants;
    DELETE FROM tenant_app_access;
    DELETE FROM tenant_settings;
    DELETE FROM tenant_ldap_configs;
    DELETE FROM tenant_ldap_sync_history;
    DELETE FROM tenant_domains;
    DELETE FROM tenant_api_keys;
    DELETE FROM audit_logs;
    DELETE FROM social_accounts;
    DELETE FROM organizations;
    DELETE FROM tenants;
    DELETE FROM users;

    -- Show what was deleted
    SELECT 'Reset complete!' as status;
    """

    try:
        result = run_kubectl_sql(reset_sql)
        logger.info("Database reset output:")
        logger.info(result)
    except Exception as e:
        logger.error(f"Failed to reset database: {e}")
        return False

    # Verify cleanup
    logger.info("🔍 Verifying cleanup...")

    verify_sql = """
    SELECT 'users' as table_name, COUNT(*) as remaining FROM users
    UNION ALL SELECT 'tenants', COUNT(*) FROM tenants
    UNION ALL SELECT 'organizations', COUNT(*) FROM organizations
    UNION ALL SELECT 'invitations', COUNT(*) FROM invitations
    ORDER BY table_name;
    """

    try:
        result = run_kubectl_sql(verify_sql)
        logger.info("Final record counts:")
        logger.info(result)

        if "0" in result and result.count("0") == 4:  # All should be 0
            logger.info("✅ Database reset complete! All platform data removed")
        else:
            logger.warning("⚠️  Some records may remain after cleanup")

    except Exception as e:
        logger.warning(f"Could not verify cleanup: {e}")

    return True

def reset_sequences():
    """Reset any sequences (though this schema uses UUIDs)"""
    logger.info("🔄 Checking for sequences to reset...")

    seq_sql = "SELECT sequence_name FROM information_schema.sequences WHERE sequence_schema = 'public';"

    try:
        result = run_kubectl_sql(seq_sql)
        if result.strip() and "0 rows" not in result:
            logger.info("Found sequences to reset:")
            logger.info(result)
            # Reset sequences if any exist
            # This would be database-specific reset logic
        else:
            logger.info("ℹ️  No sequences found (UUID-based schema)")
    except Exception as e:
        logger.warning(f"Could not check sequences: {e}")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Reset PostgreSQL database in Kubernetes")
    parser.add_argument("--force", action="store_true", help="Skip confirmation")

    args = parser.parse_args()

    if not args.force:
        print("⚠️  This will DELETE ALL platform data from the database!")
        confirmation = input("Type 'RESET' to confirm: ")
        if confirmation != 'RESET':
            print("❌ Reset cancelled")
            return

    logger.info("🚀 Starting database reset...")

    try:
        success = reset_database()
        if success:
            reset_sequences()
            logger.info("🎉 Database reset complete!")
        else:
            logger.error("❌ Database reset failed")
            sys.exit(1)

    except Exception as e:
        logger.error(f"❌ Database reset failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()