#!/usr/bin/env python3
"""
Direct Keycloak Cleanup Script
Cleans up Keycloak users using the correct API endpoint structure for newer Keycloak versions
"""

import asyncio
import httpx
import os
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

async def cleanup_keycloak_users():
    """Clean up Keycloak users directly"""

    # Configuration for newer Keycloak (no /auth prefix)
    base_url = "http://keycloak.local.suranku"
    realm = "suranku-platform"
    admin_username = os.getenv("KEYCLOAK_ADMIN_USERNAME", "admin")
    admin_password = os.getenv("KEYCLOAK_ADMIN_PASSWORD", "admin")  # Default for local dev

    logger.info(f"🔐 Cleaning up Keycloak users in realm: {realm}")

    try:
        async with httpx.AsyncClient() as client:
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
                logger.error(f"❌ Failed to get admin token: {token_response.status_code}")
                logger.error(f"Response: {token_response.text}")
                return False

            token_data = token_response.json()
            access_token = token_data["access_token"]
            logger.info("✅ Got admin token")

            # Check if suranku-platform realm exists
            realm_response = await client.get(
                f"{base_url}/admin/realms/{realm}",
                headers={"Authorization": f"Bearer {access_token}"}
            )

            if realm_response.status_code == 404:
                logger.info(f"⚪ Realm '{realm}' does not exist - nothing to clean")
                return True
            elif realm_response.status_code != 200:
                logger.error(f"❌ Failed to check realm: {realm_response.status_code}")
                return False

            # Get all users in the realm
            users_response = await client.get(
                f"{base_url}/admin/realms/{realm}/users",
                headers={"Authorization": f"Bearer {access_token}"}
            )

            if users_response.status_code != 200:
                logger.error(f"❌ Failed to get users: {users_response.status_code}")
                return False

            users = users_response.json()
            logger.info(f"📊 Found {len(users)} users in realm '{realm}'")

            if not users:
                logger.info("✅ No users to delete")
                return True

            # Delete each user
            deleted_count = 0
            for user in users:
                user_id = user['id']
                username = user.get('username', 'unknown')
                email = user.get('email', 'no-email')

                # Skip service accounts and admin users
                if username.startswith('service-account-'):
                    logger.info(f"  ⚪ Skipping service account: {username}")
                    continue

                delete_response = await client.delete(
                    f"{base_url}/admin/realms/{realm}/users/{user_id}",
                    headers={"Authorization": f"Bearer {access_token}"}
                )

                if delete_response.status_code == 204:
                    logger.info(f"  ✅ Deleted user: {username} ({email})")
                    deleted_count += 1
                else:
                    logger.warning(f"  ⚠️  Failed to delete user {username}: {delete_response.status_code}")

            # Clear all user sessions in the realm
            session_response = await client.delete(
                f"{base_url}/admin/realms/{realm}/logout-all",
                headers={"Authorization": f"Bearer {access_token}"}
            )

            if session_response.status_code in [200, 204]:
                logger.info("  ✅ Cleared all user sessions")
            else:
                logger.warning(f"  ⚠️  Failed to clear sessions: {session_response.status_code}")

            logger.info(f"🎉 Keycloak cleanup complete! Deleted {deleted_count} users")
            return True

    except Exception as e:
        logger.error(f"❌ Keycloak cleanup failed: {e}")
        return False

if __name__ == "__main__":
    success = asyncio.run(cleanup_keycloak_users())
    exit(0 if success else 1)