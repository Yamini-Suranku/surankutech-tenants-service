#!/usr/bin/env python3
"""
Platform Data Reset Script
Completely resets all platform data for clean testing of new User→Tenant→Organizations model

⚠️  DANGER: This script will DELETE ALL DATA including:
- All database records (users, tenants, organizations, invitations, etc.)
- Keycloak users and sessions
- DNS records for organizations
- Kubernetes ingress resources

Use only in development/testing environments!
"""

import sys
import os
import asyncio
import subprocess
from pathlib import Path
from sqlalchemy import text, create_engine
from sqlalchemy.orm import sessionmaker
import logging
import httpx

# Add parent directory to path for imports
ROOT_DIR = Path(__file__).parent.parent
sys.path.append(str(ROOT_DIR))

from shared.database import DATABASE_URL
from modules.keycloak_client import KeycloakClient

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

class PlatformReset:
    def __init__(self):
        self.db_url = DATABASE_URL
        # Ensure we're using the correct database URL format
        if 'tenants_service' not in self.db_url:
            # If DATABASE_URL points to suranku_platform, we need to use tenants_service
            self.db_url = self.db_url.replace('/suranku_platform', '/tenants_service')
            if 'tenants_service' not in self.db_url and self.db_url.endswith('/suranku_platform'):
                # Fallback: just replace database name
                self.db_url = self.db_url.rsplit('/', 1)[0] + '/tenants_service'

        self.engine = create_engine(self.db_url)
        self.keycloak_client = KeycloakClient()

        logger.info(f"Using database: {self.db_url.split('/')[-1]}")

    def _run_kubectl_sql(self, sql_command, database='tenants_service'):
        """Execute SQL command via kubectl exec"""
        try:
            cmd = [
                "kubectl", "exec", "-n", "shared-services", "suranku-postgres-0", "--",
                "psql", "-U", "postgres", "-d", database, "-c", sql_command
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            raise Exception(f"SQL command failed: {e.stderr}")

    async def reset_database(self):
        """Reset all database tables using kubectl exec"""
        logger.info("🗄️  Resetting database...")

        try:
            # Check current data first
            logger.info("📊 Checking current data...")
            check_sql = """
            SELECT 'users' as table_name, COUNT(*) as count FROM users
            UNION ALL SELECT 'tenants', COUNT(*) FROM tenants
            UNION ALL SELECT 'organizations', COUNT(*) FROM organizations
            UNION ALL SELECT 'invitations', COUNT(*) FROM invitations
            UNION ALL SELECT 'user_tenants', COUNT(*) FROM user_tenants
            ORDER BY table_name;
            """

            result = self._run_kubectl_sql(check_sql)
            logger.info("Current record counts:")

            # Parse result to check if there's data
            lines = result.strip().split('\n')
            has_data = False
            for line in lines:
                if '|' in line and not line.startswith('-') and 'table_name' not in line:
                    parts = line.split('|')
                    if len(parts) >= 2:
                        count_str = parts[1].strip()
                        if count_str.isdigit() and int(count_str) > 0:
                            has_data = True
                            logger.info(f"  📋 {parts[0].strip()}: {count_str} records")

            if not has_data:
                logger.info("✅ Database already clean - no data to remove")
                return

            # Reset all platform data
            logger.info("🧹 Cleaning all platform data...")
            reset_sql = """
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
            """

            self._run_kubectl_sql(reset_sql)
            logger.info("✅ Database deletion completed")

            # Check for sequences
            logger.info("🔄 Checking for sequences...")
            seq_sql = "SELECT sequence_name FROM information_schema.sequences WHERE sequence_schema = 'public';"

            seq_result = self._run_kubectl_sql(seq_sql)
            if '(0 rows)' in seq_result or not seq_result.strip():
                logger.info("  ℹ️  No sequences found (UUID-based schema)")
            else:
                logger.info("  🔄 Sequences found but no reset needed for UUIDs")

            # Verify cleanup
            logger.info("🔍 Verifying cleanup...")
            verify_result = self._run_kubectl_sql(check_sql)

            # Check if all counts are 0
            all_clean = True
            for line in verify_result.strip().split('\n'):
                if '|' in line and not line.startswith('-') and 'table_name' not in line:
                    parts = line.split('|')
                    if len(parts) >= 2:
                        count_str = parts[1].strip()
                        if count_str.isdigit() and int(count_str) > 0:
                            all_clean = False
                            break

            if all_clean:
                logger.info("✅ Database reset complete! All platform data removed")
            else:
                logger.warning("⚠️  Some records may remain after cleanup")
                logger.info("Final counts:")
                logger.info(verify_result)

        except Exception as e:
            logger.error(f"❌ Database reset failed: {e}")
            raise

    async def reset_keycloak(self):
        """Reset Keycloak users and sessions"""
        logger.info("🔐 Resetting Keycloak...")

        try:
            # Use working Keycloak configuration (newer version without /auth)
            base_url = os.getenv("KEYCLOAK_BASE_URL", "https://id.local.suranku")
            realm = "suranku-platform"
            admin_username = os.getenv("KEYCLOAK_ADMIN_USERNAME", "admin")
            admin_password = os.getenv("KEYCLOAK_ADMIN_PASSWORD", "admin")

            keycloak_ca_cert = os.getenv("KEYCLOAK_CA_CERT")
            if keycloak_ca_cert and not Path(keycloak_ca_cert).exists():
                logger.warning(f"Provided KEYCLOAK_CA_CERT '{keycloak_ca_cert}' does not exist. Falling back to default SSL verification.")
                keycloak_ca_cert = None

            verify_ssl = os.getenv("KEYCLOAK_VERIFY_SSL", "true").lower() != "false"
            httpx_verify = keycloak_ca_cert or verify_ssl

            async with httpx.AsyncClient(verify=httpx_verify) as client:
                # Get admin token from master realm
                logger.info("Getting admin token...")
                token_response = await client.post(
                    f"{base_url}/realms/master/protocol/openid-connect/token",
                    data={
                        "grant_type": "password",
                        "client_id": "admin-cli",
                        "username": admin_username,
                        "password": admin_password
                    }
                )

                if token_response.status_code != 200:
                    logger.error(f"Failed to get admin token: {token_response.status_code}")
                    logger.error(f"Response: {token_response.text}")
                    return False

                token_data = token_response.json()
                access_token = token_data["access_token"]
                logger.info("✅ Got admin token")

                # Check if realm exists
                realm_response = await client.get(
                    f"{base_url}/admin/realms/{realm}",
                    headers={"Authorization": f"Bearer {access_token}"}
                )

                if realm_response.status_code == 404:
                    logger.info(f"⚪ Realm '{realm}' does not exist - nothing to clean")
                    return True
                elif realm_response.status_code != 200:
                    logger.error(f"Failed to check realm: {realm_response.status_code}")
                    return False

                # Get all users in suranku-platform realm
                response = await client.get(
                    f"{base_url}/admin/realms/{realm}/users",
                    headers={"Authorization": f"Bearer {access_token}"}
                )

                if response.status_code == 200:
                    users = response.json()
                    logger.info(f"  Found {len(users)} Keycloak users")

                    platform_admin_usernames = {
                        name.strip().lower()
                        for name in os.getenv("PLATFORM_ADMIN_USERNAMES", "platform-admin@suranku.com").split(",")
                        if name.strip()
                    }

                    # Delete each user
                    for user in users:
                        user_id = user['id']
                        username = user.get('username', 'unknown')
                        username_lower = username.lower()

                        # Skip admin users
                        if username_lower in ['admin', 'service-account-admin-cli']:
                            logger.info(f"  ⚪ Skipping admin user: {username}")
                            continue
                        if username_lower in platform_admin_usernames:
                            logger.info(f"  ⚪ Skipping platform admin user: {username}")
                            continue

                        delete_response = await client.delete(
                            f"{base_url}/admin/realms/{realm}/users/{user_id}",
                            headers={"Authorization": f"Bearer {access_token}"}
                        )

                        if delete_response.status_code == 204:
                            logger.info(f"  ✅ Deleted Keycloak user: {username}")
                        else:
                            logger.warning(f"  ⚠️  Failed to delete user {username}: {delete_response.status_code}")

                # Clear all user sessions
                session_response = await client.delete(
                    f"{base_url}/admin/realms/{realm}/logout-all",
                    headers={"Authorization": f"Bearer {access_token}"}
                )

                if session_response.status_code in [200, 204]:
                    logger.info("  ✅ Cleared all user sessions")
                else:
                    logger.warning(f"  ⚠️  Failed to clear sessions: {session_response.status_code}")

        except Exception as e:
            logger.error(f"❌ Keycloak reset failed: {e}")

    async def cleanup_kubernetes_resources(self):
        """Clean up Kubernetes ingress resources for organizations"""
        logger.info("☸️  Cleaning up Kubernetes resources...")

        try:
            # Find all ingresses with our labels
            result = subprocess.run([
                "kubectl", "get", "ingress",
                "-l", "suranku.com/provisioned-by=tenant-services",
                "-o", "jsonpath={range .items[*]}{.metadata.namespace} {.metadata.name}{\"\\n\"}{end}",
                "--all-namespaces"
            ], capture_output=True, text=True, check=True)

            ingress_entries = [line.strip() for line in result.stdout.strip().splitlines() if line.strip()]
            if ingress_entries:
                logger.info(f"  Found {len(ingress_entries)} ingress resources")

                # Delete each ingress with its namespace
                for entry in ingress_entries:
                    parts = entry.split()
                    if len(parts) != 2:
                        logger.warning(f"  ⚠️  Unexpected ingress entry format: '{entry}'")
                        continue
                    namespace, ingress_name = parts
                    try:
                        subprocess.run([
                            "kubectl", "delete", "ingress", ingress_name,
                            "-n", namespace, "--ignore-not-found"
                        ], check=True, capture_output=True)
                        logger.info(f"  ✅ Deleted ingress: {namespace}/{ingress_name}")
                    except subprocess.CalledProcessError as e:
                        logger.warning(f"  ⚠️  Failed to delete ingress {namespace}/{ingress_name}: {e}")
            else:
                logger.info("  ⚪ No ingress resources found")

            # Clean up any certificates
            result = subprocess.run([
                "kubectl", "get", "certificates",
                "-l", "suranku.com/provisioned-by=tenant-services",
                "-o", "jsonpath={range .items[*]}{.metadata.namespace} {.metadata.name}{\"\\n\"}{end}",
                "--all-namespaces"
            ], capture_output=True, text=True, check=True)

            cert_entries = [line.strip() for line in result.stdout.strip().splitlines() if line.strip()]
            if cert_entries:
                logger.info(f"  Found {len(cert_entries)} certificates")

                for entry in cert_entries:
                    parts = entry.split()
                    if len(parts) != 2:
                        logger.warning(f"  ⚠️  Unexpected certificate entry format: '{entry}'")
                        continue
                    namespace, cert_name = parts
                    try:
                        subprocess.run([
                            "kubectl", "delete", "certificate", cert_name,
                            "-n", namespace, "--ignore-not-found"
                        ], check=True, capture_output=True)
                        logger.info(f"  ✅ Deleted certificate: {namespace}/{cert_name}")
                    except subprocess.CalledProcessError as e:
                        logger.warning(f"  ⚠️  Failed to delete certificate {namespace}/{cert_name}: {e}")
            else:
                logger.info("  ⚪ No certificates found")

        except subprocess.CalledProcessError as e:
            logger.warning(f"  ⚠️  Kubectl command failed: {e}")
        except Exception as e:
            logger.error(f"❌ Kubernetes cleanup failed: {e}")

    async def cleanup_dns_records(self):
        """Clean up DNS records for local development"""
        logger.info("🌐 Cleaning up DNS records...")

        # List of known org subdomains to clean up
        known_subdomains = [
            'palls2.local.suranku',
            'tommy.local.suranku',
            'acme.local.suranku',
            'beta.local.suranku',
            'test.local.suranku',
            'demo.local.suranku'
        ]

        # For local development, we primarily need to clean /etc/hosts
        hosts_file = '/etc/hosts'

        try:
            if os.path.exists(hosts_file):
                with open(hosts_file, 'r') as f:
                    lines = f.readlines()

                # Filter out SurankuTech entries
                cleaned_lines = []
                removed_count = 0

                for line in lines:
                    if any(subdomain in line for subdomain in known_subdomains):
                        logger.info(f"  ✅ Removing DNS entry: {line.strip()}")
                        removed_count += 1
                    else:
                        cleaned_lines.append(line)

                if removed_count > 0:
                    # Write back cleaned hosts file (requires sudo)
                    logger.info(f"  📝 Would remove {removed_count} DNS entries from {hosts_file}")
                    logger.info("  ⚠️  Manual cleanup required: sudo access needed for /etc/hosts")
                    logger.info("  💡 Run: sudo sed -i '/local.suranku/d' /etc/hosts")
                else:
                    logger.info("  ⚪ No DNS entries found in /etc/hosts")
            else:
                logger.info("  ⚪ /etc/hosts not found")

        except Exception as e:
            logger.warning(f"  ⚠️  DNS cleanup error: {e}")

    async def cleanup_kafka_topics(self):
        """Clean up Kafka topics to prevent stale events"""
        logger.info("📨 Cleaning up Kafka topics...")

        try:
            # List of topics to clean
            topics_to_clean = [
                'tenant.events.v1',
                'tenant.provisioning.v1'
            ]

            for topic in topics_to_clean:
                try:
                    # Delete and recreate topic to clear all messages
                    logger.info(f"  🗑️  Deleting topic: {topic}")
                    delete_result = subprocess.run([
                        "kubectl", "exec", "-n", "messaging", "kafka-0", "--",
                        "kafka-topics", "--bootstrap-server", "localhost:9092",
                        "--delete", "--topic", topic
                    ], capture_output=True, text=True, check=False)

                    if delete_result.returncode == 0:
                        logger.info(f"  ✅ Deleted topic: {topic}")
                    else:
                        logger.info(f"  ⚪ Topic {topic} didn't exist or couldn't be deleted")

                    # Wait a moment for deletion to complete
                    await asyncio.sleep(2)

                    # Recreate topic
                    logger.info(f"  ➕ Recreating topic: {topic}")
                    create_result = subprocess.run([
                        "kubectl", "exec", "-n", "messaging", "kafka-0", "--",
                        "kafka-topics", "--bootstrap-server", "localhost:9092",
                        "--create", "--topic", topic,
                        "--partitions", "3", "--replication-factor", "1"
                    ], capture_output=True, text=True, check=True)

                    logger.info(f"  ✅ Recreated topic: {topic}")

                except subprocess.CalledProcessError as e:
                    logger.warning(f"  ⚠️  Failed to recreate topic {topic}: {e}")

            # Reset consumer group offsets if they exist
            logger.info("  🔄 Resetting consumer group offsets...")
            try:
                subprocess.run([
                    "kubectl", "exec", "-n", "messaging", "kafka-0", "--",
                    "kafka-consumer-groups", "--bootstrap-server", "localhost:9092",
                    "--group", "tenants-provisioner", "--reset-offsets",
                    "--to-earliest", "--all-topics", "--execute"
                ], capture_output=True, text=True, check=False)
                logger.info("  ✅ Reset consumer group offsets")
            except subprocess.CalledProcessError:
                logger.info("  ⚪ Consumer group didn't exist or couldn't be reset")

        except Exception as e:
            logger.error(f"❌ Kafka cleanup failed: {e}")

    async def reset_all(self):
        """Reset everything"""
        logger.info("🔄 Starting complete platform reset...")
        logger.info("⚠️  This will DELETE ALL DATA - Press Ctrl+C within 5 seconds to cancel...")

        try:
            await asyncio.sleep(5)
        except KeyboardInterrupt:
            logger.info("❌ Reset cancelled by user")
            return

        logger.info("🚀 Starting reset process...")

        # Reset in order of dependencies
        await self.cleanup_kubernetes_resources()
        await self.cleanup_dns_records()
        await self.cleanup_kafka_topics()
        await self.reset_keycloak()
        await self.reset_database()

        logger.info("✨ Platform reset complete!")
        logger.info("\n📋 Next steps:")
        logger.info("1. Start fresh with user registration")
        logger.info("2. Create organizations with new tenant hierarchy")
        logger.info("3. Test the new User → Tenant → Organizations model")
        logger.info("4. DNS entries for new orgs will be created automatically")

    async def verify_reset(self):
        """Verify that reset was successful"""
        logger.info("🔍 Verifying reset...")

        with self.engine.begin() as conn:
            # Check key tables
            tables_to_check = ['users', 'tenants', 'organizations', 'invitations']

            for table in tables_to_check:
                result = conn.execute(text(f"SELECT COUNT(*) FROM {table}"))
                count = result.fetchone()[0]

                if count == 0:
                    logger.info(f"  ✅ {table}: empty")
                else:
                    logger.warning(f"  ⚠️  {table}: {count} records remaining")

        logger.info("✅ Verification complete")

async def main():
    reset = PlatformReset()

    import argparse
    parser = argparse.ArgumentParser(description="Reset platform data")
    parser.add_argument("--database-only", action="store_true", help="Reset only database")
    parser.add_argument("--keycloak-only", action="store_true", help="Reset only Keycloak")
    parser.add_argument("--kubernetes-only", action="store_true", help="Reset only Kubernetes")
    parser.add_argument("--dns-only", action="store_true", help="Reset only DNS")
    parser.add_argument("--kafka-only", action="store_true", help="Reset only Kafka topics")
    parser.add_argument("--verify", action="store_true", help="Verify reset")
    parser.add_argument("--force", action="store_true", help="Skip confirmation")

    args = parser.parse_args()

    if args.verify:
        await reset.verify_reset()
    elif args.database_only:
        await reset.reset_database()
    elif args.keycloak_only:
        await reset.reset_keycloak()
    elif args.kubernetes_only:
        await reset.cleanup_kubernetes_resources()
    elif args.dns_only:
        await reset.cleanup_dns_records()
    elif args.kafka_only:
        await reset.cleanup_kafka_topics()
    else:
        if not args.force:
            logger.info("⚠️  This will reset ALL platform data!")
            confirmation = input("Type 'RESET' to confirm: ")
            if confirmation != 'RESET':
                logger.info("❌ Reset cancelled")
                return

        await reset.reset_all()

if __name__ == "__main__":
    asyncio.run(main())
