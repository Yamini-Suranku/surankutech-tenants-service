#!/usr/bin/env python3
"""
Platform Admin Management Script
Provides utilities to manage the default platform admin account
"""

import os
import sys
import requests
import json
import getpass
import logging
from typing import Optional, Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Keycloak configuration
KEYCLOAK_URL = os.getenv('KEYCLOAK_URL', 'http://keycloak.shared-services.svc.cluster.local:8080')
REALM = 'suranku-platform'
ADMIN_CLIENT = 'admin-cli'

DEFAULT_ADMIN_USERNAME = 'platform-admin@suranku.com'

class KeycloakAdminClient:
    def __init__(self):
        self.base_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}"
        self.token = None

    def get_admin_token(self, admin_username: str, admin_password: str) -> bool:
        """Get admin access token for Keycloak admin operations"""
        try:
            token_url = f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token"
            data = {
                'client_id': ADMIN_CLIENT,
                'username': admin_username,
                'password': admin_password,
                'grant_type': 'password'
            }

            response = requests.post(token_url, data=data, timeout=10)
            response.raise_for_status()

            token_data = response.json()
            self.token = token_data['access_token']
            return True

        except Exception as e:
            logger.error(f"Failed to get admin token: {e}")
            return False

    def get_headers(self) -> Dict[str, str]:
        """Get headers with admin token"""
        if not self.token:
            raise Exception("No admin token available")
        return {
            'Authorization': f'Bearer {self.token}',
            'Content-Type': 'application/json'
        }

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user by username"""
        try:
            url = f"{self.base_url}/users"
            params = {'username': username}
            response = requests.get(url, headers=self.get_headers(), params=params, timeout=10)
            response.raise_for_status()

            users = response.json()
            return users[0] if users else None

        except Exception as e:
            logger.error(f"Failed to get user {username}: {e}")
            return None

    def update_user_password(self, user_id: str, new_password: str, temporary: bool = False) -> bool:
        """Update user password"""
        try:
            url = f"{self.base_url}/users/{user_id}/reset-password"
            data = {
                'type': 'password',
                'value': new_password,
                'temporary': temporary
            }

            response = requests.put(url, headers=self.get_headers(), json=data, timeout=10)
            response.raise_for_status()
            return True

        except Exception as e:
            logger.error(f"Failed to update password: {e}")
            return False

    def create_platform_admin_user(self, username: str, password: str, email: str = None) -> bool:
        """Create a new platform admin user"""
        try:
            url = f"{self.base_url}/users"

            user_data = {
                'username': username,
                'email': email or username,
                'firstName': 'Platform',
                'lastName': 'Administrator',
                'enabled': True,
                'emailVerified': True,
                'credentials': [{
                    'type': 'password',
                    'value': password,
                    'temporary': False
                }],
                'realmRoles': ['platform_admin', 'platform-admins'],
                'groups': ['platform-admins'],
                'attributes': {
                    'created_by': ['script'],
                    'description': ['Platform administrator account created via management script']
                }
            }

            response = requests.post(url, headers=self.get_headers(), json=user_data, timeout=10)
            response.raise_for_status()

            # Get the created user ID and assign client roles
            user = self.get_user_by_username(username)
            if user:
                self.assign_client_roles(user['id'])

            return True

        except Exception as e:
            logger.error(f"Failed to create user: {e}")
            return False

    def assign_client_roles(self, user_id: str) -> bool:
        """Assign DarkHole admin client role to user"""
        try:
            # Get DarkHole client
            clients_url = f"{self.base_url}/clients"
            params = {'clientId': 'darkhole-client'}
            response = requests.get(clients_url, headers=self.get_headers(), params=params, timeout=10)
            response.raise_for_status()

            clients = response.json()
            if not clients:
                logger.warning("DarkHole client not found")
                return False

            client_id = clients[0]['id']

            # Get admin role
            roles_url = f"{self.base_url}/clients/{client_id}/roles"
            response = requests.get(roles_url, headers=self.get_headers(), timeout=10)
            response.raise_for_status()

            roles = response.json()
            admin_role = next((role for role in roles if role['name'] == 'admin'), None)

            if not admin_role:
                logger.warning("Admin role not found in DarkHole client")
                return False

            # Assign role to user
            assign_url = f"{self.base_url}/users/{user_id}/role-mappings/clients/{client_id}"
            response = requests.post(assign_url, headers=self.get_headers(), json=[admin_role], timeout=10)
            response.raise_for_status()

            return True

        except Exception as e:
            logger.error(f"Failed to assign client roles: {e}")
            return False

def show_current_admin_info():
    """Show information about current platform admin setup"""
    print("\n" + "="*60)
    print("🔐 PLATFORM ADMIN INFORMATION")
    print("="*60)
    print(f"📧 Default Admin Username: {DEFAULT_ADMIN_USERNAME}")
    print(f"🔑 Default Admin Password: SurankuAdmin2024!")
    print(f"🏷️  Admin Roles: platform_admin, platform-admins")
    print(f"🎯 Client Roles: darkhole-client/admin")
    print(f"👥 Groups: platform-admins")
    print("="*60)
    print("⚠️  SECURITY WARNING:")
    print("   Please change the default password immediately after first login!")
    print("   Use this script's 'update-password' command to change it.")
    print("="*60)

def change_admin_password():
    """Interactive password change for platform admin"""
    print("\n🔐 Change Platform Admin Password")
    print("-" * 40)

    # Get current Keycloak admin credentials
    print("First, provide Keycloak master admin credentials:")
    keycloak_admin_user = input("Keycloak Admin Username: ")
    keycloak_admin_pass = getpass.getpass("Keycloak Admin Password: ")

    # Connect to Keycloak
    client = KeycloakAdminClient()
    if not client.get_admin_token(keycloak_admin_user, keycloak_admin_pass):
        print("❌ Failed to authenticate with Keycloak admin")
        return False

    # Get current platform admin user
    user = client.get_user_by_username(DEFAULT_ADMIN_USERNAME)
    if not user:
        print(f"❌ Platform admin user {DEFAULT_ADMIN_USERNAME} not found")
        return False

    print(f"\n✅ Found platform admin user: {user['username']}")

    # Get new password
    while True:
        new_password = getpass.getpass("New Platform Admin Password: ")
        confirm_password = getpass.getpass("Confirm New Password: ")

        if new_password != confirm_password:
            print("❌ Passwords don't match. Try again.")
            continue

        if len(new_password) < 8:
            print("❌ Password must be at least 8 characters long.")
            continue

        break

    # Update password
    if client.update_user_password(user['id'], new_password, temporary=False):
        print("✅ Platform admin password updated successfully!")
        print("🔐 Please test the new credentials by logging in.")
        return True
    else:
        print("❌ Failed to update password")
        return False

def create_additional_admin():
    """Create an additional platform admin user"""
    print("\n👤 Create Additional Platform Admin")
    print("-" * 40)

    # Get current Keycloak admin credentials
    print("First, provide Keycloak master admin credentials:")
    keycloak_admin_user = input("Keycloak Admin Username: ")
    keycloak_admin_pass = getpass.getpass("Keycloak Admin Password: ")

    # Connect to Keycloak
    client = KeycloakAdminClient()
    if not client.get_admin_token(keycloak_admin_user, keycloak_admin_pass):
        print("❌ Failed to authenticate with Keycloak admin")
        return False

    # Get new admin details
    new_username = input("New Admin Username (email): ")
    new_password = getpass.getpass("New Admin Password: ")

    # Validate input
    if '@' not in new_username:
        print("❌ Username should be a valid email address")
        return False

    if len(new_password) < 8:
        print("❌ Password must be at least 8 characters long")
        return False

    # Check if user already exists
    if client.get_user_by_username(new_username):
        print(f"❌ User {new_username} already exists")
        return False

    # Create user
    if client.create_platform_admin_user(new_username, new_password):
        print(f"✅ Platform admin {new_username} created successfully!")
        print("🔐 User can now login with platform admin privileges.")
        return True
    else:
        print("❌ Failed to create new admin user")
        return False

def main():
    if len(sys.argv) < 2:
        print("\nSuranku Platform Admin Management")
        print("=" * 35)
        print("Usage: python manage_platform_admin.py <command>")
        print("\nCommands:")
        print("  info              - Show current platform admin information")
        print("  update-password   - Change platform admin password")
        print("  create-admin      - Create additional platform admin user")
        print("\nExamples:")
        print("  python manage_platform_admin.py info")
        print("  python manage_platform_admin.py update-password")
        print("  python manage_platform_admin.py create-admin")
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == 'info':
        show_current_admin_info()
    elif command == 'update-password':
        change_admin_password()
    elif command == 'create-admin':
        create_additional_admin()
    else:
        print(f"❌ Unknown command: {command}")
        print("Available commands: info, update-password, create-admin")
        sys.exit(1)

if __name__ == "__main__":
    main()