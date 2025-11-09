import httpx
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import os
import asyncio
from urllib.parse import urlencode

logger = logging.getLogger(__name__)

class KeycloakClient:
    """Client for interacting with Keycloak for tenant and user management"""

    def __init__(self):
        self.base_url = os.getenv("KEYCLOAK_URL", "http://keycloak:8080")
        self.realm = os.getenv("KEYCLOAK_REALM", "suranku-platform")
        self.client_id = os.getenv("KEYCLOAK_CLIENT_ID", "tenants-service")
        self.client_secret = os.getenv("KEYCLOAK_CLIENT_SECRET")
        self.admin_username = os.getenv("KEYCLOAK_ADMIN_USERNAME", "admin")
        self.admin_password = os.getenv("KEYCLOAK_ADMIN_PASSWORD")

        self.token_cache = {}
        self.token_expires_at = None

    async def get_admin_token(self) -> str:
        """Get admin access token for Keycloak API calls"""
        try:
            if (self.token_cache.get("access_token") and
                self.token_expires_at and
                datetime.now().timestamp() < self.token_expires_at):
                return self.token_cache["access_token"]

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/realms/master/protocol/openid-connect/token",
                    data={
                        "grant_type": "password",
                        "client_id": "admin-cli",
                        "username": self.admin_username,
                        "password": self.admin_password
                    }
                )

                if response.status_code != 200:
                    raise Exception(f"Failed to get admin token: {response.text}")

                token_data = response.json()
                self.token_cache = token_data

                # Set expiration with buffer
                expires_in = token_data.get("expires_in", 300)
                self.token_expires_at = datetime.now().timestamp() + expires_in - 30

                return token_data["access_token"]

        except Exception as e:
            logger.error(f"Keycloak admin token error: {e}")
            raise Exception(f"Failed to authenticate with Keycloak: {str(e)}")

    async def create_user_with_tenant(
        self,
        email: str,
        password: str,
        first_name: str,
        last_name: str,
        tenant_id: str,
        app_roles: Dict[str, List[str]]
    ) -> str:
        """Create user in Keycloak and assign to tenant groups with app roles"""
        try:
            token = await self.get_admin_token()

            async with httpx.AsyncClient() as client:
                # Create user with unverified email for traditional registration
                user_data = {
                    "username": email,
                    "email": email,
                    "firstName": first_name,
                    "lastName": last_name,
                    "enabled": False,  # Disabled until email verified
                    "emailVerified": False,  # Email not verified yet
                    "credentials": [{
                        "type": "password",
                        "value": password,
                        "temporary": False
                    }],
                    "attributes": {
                        "tenant_id": [tenant_id],
                        "email_verification_pending": ["true"]
                    }
                }

                response = await client.post(
                    f"{self.base_url}/admin/realms/{self.realm}/users",
                    headers={"Authorization": f"Bearer {token}"},
                    json=user_data
                )

                if response.status_code != 201:
                    if response.status_code == 409:
                        raise Exception("User with this email already exists")
                    raise Exception(f"Failed to create user: {response.text}")

                # Get user ID from location header
                user_id = response.headers["Location"].split("/")[-1]

                # Create tenant group if it doesn't exist and get group ID
                group_id = await self._ensure_tenant_group(tenant_id, token, client)

                # Add user to tenant group using correct group ID
                await client.put(
                    f"{self.base_url}/admin/realms/{self.realm}/users/{user_id}/groups/{group_id}",
                    headers={"Authorization": f"Bearer {token}"}
                )

                # Assign app-specific roles
                await self._assign_app_roles(user_id, app_roles, token, client)

                return user_id

        except Exception as e:
            logger.error(f"User creation error: {e}")
            raise Exception(f"Failed to create user: {str(e)}")

    async def create_social_user(
        self,
        email: str,
        first_name: str,
        last_name: str,
        provider: str,
        social_id: str
    ) -> str:
        """Create user from social login"""
        try:
            token = await self.get_admin_token()

            async with httpx.AsyncClient() as client:
                user_data = {
                    "username": email,
                    "email": email,
                    "firstName": first_name,
                    "lastName": last_name,
                    "enabled": True,
                    "emailVerified": True,
                    "attributes": {
                        "social_provider": [provider],
                        "social_id": [social_id]
                    },
                    "federatedIdentities": [{
                        "identityProvider": provider,
                        "userId": social_id,
                        "userName": email
                    }]
                }

                response = await client.post(
                    f"{self.base_url}/admin/realms/{self.realm}/users",
                    headers={"Authorization": f"Bearer {token}"},
                    json=user_data
                )

                if response.status_code != 201:
                    if response.status_code == 409:
                        # SECURITY FIX: Do NOT automatically link accounts!
                        # This prevents account takeover attacks
                        raise Exception(f"Account with email {email} already exists. Please use account linking flow or different email.")
                    raise Exception(f"Failed to create social user: {response.text}")

                user_id = response.headers["Location"].split("/")[-1]
                return user_id

        except Exception as e:
            logger.error(f"Social user creation error: {e}")
            raise Exception(f"Failed to create social user: {str(e)}")

    async def get_social_provider_config(self, provider: str) -> Optional[Dict[str, Any]]:
        """Get social provider configuration"""
        try:
            token = await self.get_admin_token()

            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/admin/realms/{self.realm}/identity-provider/instances/{provider}",
                    headers={"Authorization": f"Bearer {token}"}
                )

                if response.status_code == 200:
                    return response.json()
                return None

        except Exception as e:
            logger.error(f"Provider config error: {e}")
            return None

    async def build_social_auth_url(
        self,
        provider: str,
        state: str,
        redirect_uri: str
    ) -> str:
        """Build social authentication URL"""
        params = {
            "client_id": f"{provider}-client",
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
            "redirect_uri": redirect_uri
        }

        return f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/auth?{urlencode(params)}"

    async def exchange_social_code(
        self,
        provider: str,
        code: str,
        state: str
    ) -> Dict[str, Any]:
        """Exchange authorization code for tokens"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/token",
                    data={
                        "grant_type": "authorization_code",
                        "client_id": f"{provider}-client",
                        "code": code,
                        "redirect_uri": f"{self.base_url}/realms/{self.realm}/broker/{provider}/endpoint"
                    }
                )

                if response.status_code != 200:
                    raise Exception(f"Token exchange failed: {response.text}")

                return response.json()

        except Exception as e:
            logger.error(f"Token exchange error: {e}")
            raise Exception(f"Failed to exchange code: {str(e)}")

    async def get_social_user_info(
        self,
        provider: str,
        access_token: str
    ) -> Dict[str, Any]:
        """Get user info from social provider"""
        try:
            provider_endpoints = {
                "google": "https://www.googleapis.com/oauth2/v2/userinfo",
                "github": "https://api.github.com/user",
                "microsoft": "https://graph.microsoft.com/v1.0/me"
            }

            endpoint = provider_endpoints.get(provider)
            if not endpoint:
                raise Exception(f"Unsupported provider: {provider}")

            async with httpx.AsyncClient() as client:
                response = await client.get(
                    endpoint,
                    headers={"Authorization": f"Bearer {access_token}"}
                )

                if response.status_code != 200:
                    raise Exception(f"Failed to get user info: {response.text}")

                user_info = response.json()

                # Normalize user info across providers
                normalized = {
                    "id": user_info.get("id") or user_info.get("sub"),
                    "email": user_info.get("email"),
                    "first_name": user_info.get("given_name") or user_info.get("name", "").split(" ")[0],
                    "last_name": user_info.get("family_name") or " ".join(user_info.get("name", "").split(" ")[1:]),
                    "avatar_url": user_info.get("picture") or user_info.get("avatar_url"),
                    "profile_url": user_info.get("html_url") or user_info.get("link"),
                    "raw_data": user_info
                }

                return normalized

        except Exception as e:
            logger.error(f"User info error: {e}")
            raise Exception(f"Failed to get user info: {str(e)}")

    async def activate_user_after_verification(self, keycloak_id: str, app_roles: Dict[str, List[str]] = None) -> bool:
        """Activate Keycloak user after email verification and assign roles"""
        try:
            token = await self.get_admin_token()

            async with httpx.AsyncClient() as client:
                # Enable the user and mark email as verified
                user_update = {
                    "enabled": True,
                    "emailVerified": True,
                    "attributes": {
                        "email_verification_pending": ["false"]
                    }
                }

                response = await client.put(
                    f"{self.base_url}/admin/realms/{self.realm}/users/{keycloak_id}",
                    headers={"Authorization": f"Bearer {token}"},
                    json=user_update
                )

                if response.status_code not in [200, 204]:
                    logger.error(f"Failed to activate Keycloak user: {response.text}")
                    return False

                logger.info(f"Keycloak user {keycloak_id} activated successfully")

                # Assign app roles if provided (for tenant registration)
                if app_roles:
                    logger.info(f"Assigning app roles to user {keycloak_id}: {app_roles}")
                    await self._assign_app_roles(keycloak_id, app_roles, token, client)
                    logger.info(f"Successfully assigned roles to user {keycloak_id}")

                return True

        except Exception as e:
            logger.error(f"Keycloak user activation error: {e}")
            return False

    async def authenticate_user(self, email: str, password: str) -> Dict[str, Any]:
        """Authenticate user with email and password using Keycloak"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/token",
                    data={
                        "grant_type": "password",
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                        "username": email,
                        "password": password,
                        "scope": "openid profile email"
                    }
                )

                if response.status_code != 200:
                    error_data = response.json()
                    error_msg = error_data.get('error_description', 'Authentication failed')

                    # Check if this is due to disabled account (unverified email)
                    if 'Account is not enabled' in error_msg or 'disabled' in error_msg.lower():
                        # Check if user exists in our database to provide better error message
                        from services.shared.database import get_db
                        from services.shared.models import User
                        db = next(get_db())
                        try:
                            user = db.query(User).filter(User.email == email).first()
                            if user and not user.is_email_verified:
                                raise Exception("Please verify your email address before logging in. Check your inbox for the verification email.")
                        finally:
                            db.close()

                    raise Exception(error_msg)

                token_data = response.json()

                # Get user info with the access token
                user_response = await client.get(
                    f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/userinfo",
                    headers={"Authorization": f"Bearer {token_data['access_token']}"}
                )

                if user_response.status_code != 200:
                    raise Exception("Failed to get user info")

                user_info = user_response.json()

                return {
                    "access_token": token_data["access_token"],
                    "refresh_token": token_data.get("refresh_token"),
                    "expires_in": token_data.get("expires_in", 3600),
                    "user_info": user_info
                }

        except Exception as e:
            logger.error(f"Authentication error: {e}")
            raise Exception(f"Authentication failed: {str(e)}")

    async def generate_user_token(self, user_id: str) -> str:
        """Generate JWT token for user"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/token",
                    data={
                        "grant_type": "client_credentials",
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                        "scope": "openid profile email"
                    }
                )

                if response.status_code != 200:
                    raise Exception(f"Token generation failed: {response.text}")

                return response.json()["access_token"]

        except Exception as e:
            logger.error(f"Token generation error: {e}")
            raise Exception(f"Failed to generate token: {str(e)}")

    async def generate_tenant_token(
        self,
        user_id: str,
        tenant_id: str,
        app_roles: Dict[str, List[str]]
    ) -> str:
        """Generate JWT token with tenant context"""
        try:
            token = await self.get_admin_token()

            # This would implement custom token generation with tenant claims
            # For now, returning a basic token
            return await self.generate_user_token(user_id)

        except Exception as e:
            logger.error(f"Tenant token generation error: {e}")
            raise Exception(f"Failed to generate tenant token: {str(e)}")

    async def _ensure_tenant_group(self, tenant_id: str, token: str, client: httpx.AsyncClient):
        """Ensure tenant group exists in Keycloak"""
        try:
            # Check if group exists
            response = await client.get(
                f"{self.base_url}/admin/realms/{self.realm}/groups",
                headers={"Authorization": f"Bearer {token}"},
                params={"search": tenant_id}
            )

            groups = response.json()
            for group in groups:
                if group["name"] == tenant_id:
                    return group["id"]

            # Create group if it doesn't exist
            group_data = {
                "name": tenant_id,
                "attributes": {
                    "tenant_id": [tenant_id]
                }
            }

            response = await client.post(
                f"{self.base_url}/admin/realms/{self.realm}/groups",
                headers={"Authorization": f"Bearer {token}"},
                json=group_data
            )

            if response.status_code != 201:
                raise Exception(f"Failed to create group: {response.text}")

            # Get the created group ID from location header
            group_id = response.headers["Location"].split("/")[-1]
            return group_id

        except Exception as e:
            logger.error(f"Group creation error: {e}")
            raise

    async def _assign_app_roles(
        self,
        user_id: str,
        app_roles: Dict[str, List[str]],
        token: str,
        client: httpx.AsyncClient
    ):
        """Assign app-specific roles to user"""
        try:
            for app_name, roles in app_roles.items():
                client_name = f"{app_name}-client"

                # First, get the internal client ID (UUID) from Keycloak
                clients_response = await client.get(
                    f"{self.base_url}/admin/realms/{self.realm}/clients",
                    headers={"Authorization": f"Bearer {token}"},
                    params={"clientId": client_name}
                )

                if clients_response.status_code != 200:
                    logger.error(f"Failed to find client {client_name}: {clients_response.text}")
                    continue

                clients_list = clients_response.json()
                if not clients_list:
                    logger.error(f"Client {client_name} not found in Keycloak")
                    continue

                app_client_id = clients_list[0]["id"]  # Internal UUID
                logger.info(f"Found client {client_name} with ID: {app_client_id}")

                for role in roles:
                    # Get role data
                    role_response = await client.get(
                        f"{self.base_url}/admin/realms/{self.realm}/clients/{app_client_id}/roles/{role}",
                        headers={"Authorization": f"Bearer {token}"}
                    )

                    if role_response.status_code == 200:
                        role_data = role_response.json()
                        logger.info(f"Found role {role} for client {client_name}")

                        # Assign role to user using the internal client ID
                        assign_response = await client.post(
                            f"{self.base_url}/admin/realms/{self.realm}/users/{user_id}/role-mappings/clients/{app_client_id}",
                            headers={"Authorization": f"Bearer {token}"},
                            json=[role_data]
                        )

                        if assign_response.status_code in [201, 204]:
                            logger.info(f"Successfully assigned role {role} from {client_name} to user {user_id}")
                        else:
                            logger.error(f"Failed to assign role {role}: {assign_response.status_code} - {assign_response.text}")
                    else:
                        logger.error(f"Role {role} not found for client {client_name}: {role_response.status_code}")

        except Exception as e:
            logger.error(f"Role assignment error: {e}")
            import traceback
            logger.error(traceback.format_exc())
            # Don't fail user creation if role assignment fails

    async def _get_user_by_email(
        self,
        email: str,
        token: str,
        client: httpx.AsyncClient
    ) -> Optional[Dict[str, Any]]:
        """Get user by email"""
        try:
            response = await client.get(
                f"{self.base_url}/admin/realms/{self.realm}/users",
                headers={"Authorization": f"Bearer {token}"},
                params={"email": email}
            )

            if response.status_code == 200:
                users = response.json()
                return users[0] if users else None
            return None

        except Exception as e:
            logger.error(f"User lookup error: {e}")
            return None

    async def _link_social_account(
        self,
        user_id: str,
        provider: str,
        social_id: str,
        email: str,
        token: str,
        client: httpx.AsyncClient
    ):
        """Link social account to existing user"""
        try:
            federated_identity = {
                "identityProvider": provider,
                "userId": social_id,
                "userName": email
            }

            response = await client.post(
                f"{self.base_url}/admin/realms/{self.realm}/users/{user_id}/federated-identity/{provider}",
                headers={"Authorization": f"Bearer {token}"},
                json=federated_identity
            )

            if response.status_code not in [201, 204]:
                logger.warning(f"Failed to link social account: {response.text}")

        except Exception as e:
            logger.error(f"Social account linking error: {e}")
            # Don't fail if linking fails

    async def update_user_password(self, keycloak_id: str, new_password: str) -> bool:
        """Update user password in Keycloak"""
        try:
            token = await self.get_admin_token()

            async with httpx.AsyncClient() as client:
                # Update user password
                password_update = {
                    "type": "password",
                    "value": new_password,
                    "temporary": False
                }

                response = await client.put(
                    f"{self.base_url}/admin/realms/{self.realm}/users/{keycloak_id}/reset-password",
                    headers={"Authorization": f"Bearer {token}"},
                    json=password_update
                )

                if response.status_code == 204:
                    logger.info(f"Password updated successfully for user {keycloak_id}")
                    return True
                else:
                    logger.error(f"Failed to update password: {response.status_code} - {response.text}")
                    return False

        except Exception as e:
            logger.error(f"Password update error: {e}")
            return False

    async def add_existing_user_to_tenant(
        self,
        user_email: str,
        tenant_id: str,
        app_roles: Dict[str, List[str]]
    ) -> str:
        """Add existing Keycloak user to new tenant group with roles"""
        try:
            token = await self.get_admin_token()

            async with httpx.AsyncClient() as client:
                # Find existing user by email
                users_response = await client.get(
                    f"{self.base_url}/admin/realms/{self.realm}/users",
                    headers={"Authorization": f"Bearer {token}"},
                    params={"email": user_email, "exact": "true"}
                )

                if users_response.status_code != 200:
                    raise Exception(f"Failed to search for user: {users_response.text}")

                users = users_response.json()
                if not users:
                    raise Exception(f"User {user_email} not found in Keycloak")

                user_id = users[0]["id"]
                logger.info(f"Found existing user: {user_email} (ID: {user_id})")

                # Create tenant group if it doesn't exist and get group ID
                group_id = await self._ensure_tenant_group(tenant_id, token, client)
                logger.info(f"Ensured tenant group exists: {tenant_id} (Group ID: {group_id})")

                # Add existing user to new tenant group
                group_response = await client.put(
                    f"{self.base_url}/admin/realms/{self.realm}/users/{user_id}/groups/{group_id}",
                    headers={"Authorization": f"Bearer {token}"}
                )

                if group_response.status_code not in [200, 204]:
                    logger.warning(f"Failed to add user to group: {group_response.text}")
                else:
                    logger.info(f"Added user {user_email} to tenant group {tenant_id}")

                # Assign app-specific roles for the new tenant
                await self._assign_app_roles(user_id, app_roles, token, client)
                logger.info(f"Assigned app roles to user {user_email} for tenant {tenant_id}: {app_roles}")

                return user_id

        except Exception as e:
            logger.error(f"Failed to add existing user {user_email} to tenant {tenant_id}: {e}")
            raise Exception(f"Failed to add user to tenant: {str(e)}")

    # ===== LDAP FEDERATION METHODS =====

    async def create_ldap_federation(
        self,
        tenant_id: str,
        ldap_config: Dict[str, Any]
    ) -> str:
        """Create LDAP user federation in Keycloak"""
        try:
            token = await self.get_admin_token()

            async with httpx.AsyncClient() as client:
                # Build Keycloak LDAP component configuration
                component_data = {
                    "name": f"ldap-{tenant_id}",
                    "providerId": "ldap",
                    "providerType": "org.keycloak.storage.UserStorageProvider",
                    "parentId": self.realm,
                    "config": {
                        # Connection settings
                        "enabled": [str(ldap_config.get("enabled", True)).lower()],
                        "priority": ["1"],
                        "editMode": [ldap_config.get("edit_mode", "READ_ONLY")],
                        "syncRegistrations": [str(ldap_config.get("sync_registrations", True)).lower()],
                        "vendor": [ldap_config.get("vendor", "ad")],
                        "usernameLDAPAttribute": [ldap_config.get("username_ldap_attribute", "sAMAccountName")],
                        "rdnLDAPAttribute": [ldap_config.get("rdn_ldap_attribute", "cn")],
                        "uuidLDAPAttribute": [ldap_config.get("uuid_ldap_attribute", "objectGUID")],
                        "userObjectClasses": [ldap_config.get("user_object_class", "person")],

                        # LDAP connection
                        "connectionUrl": [ldap_config.get("connection_url")],
                        "bindDn": [ldap_config.get("bind_dn")],
                        "bindCredential": [ldap_config.get("bind_credential")],
                        "connectionTimeout": [str(ldap_config.get("connection_timeout", 30000))],
                        "readTimeout": [str(ldap_config.get("read_timeout", 30000))],
                        "useTruststoreSpi": [ldap_config.get("use_truststore_spi", "ldapsOnly")],

                        # User search
                        "usersDn": [ldap_config.get("users_dn")],
                        "searchScope": [ldap_config.get("search_scope", "2")],  # 1=ONE_LEVEL, 2=SUBTREE

                        # Import settings
                        "importEnabled": [str(ldap_config.get("import_enabled", True)).lower()],
                        "batchSizeForSync": [str(ldap_config.get("batch_size", 1000))],

                        # Sync periods (in seconds, Keycloak expects milliseconds)
                        "fullSyncPeriod": [str(ldap_config.get("full_sync_period", 604800) * 1000)],
                        "changedSyncPeriod": [str(ldap_config.get("changed_sync_period", 86400) * 1000)],

                        # Pagination
                        "pagination": ["true"],

                        # Authentication type
                        "authType": ["simple"],

                        # Custom user filter
                        "customUserSearchFilter": [ldap_config.get("user_ldap_filter", "")],
                    }
                }

                # Create LDAP component
                response = await client.post(
                    f"{self.base_url}/admin/realms/{self.realm}/components",
                    headers={"Authorization": f"Bearer {token}"},
                    json=component_data
                )

                if response.status_code != 201:
                    raise Exception(f"Failed to create LDAP federation: {response.text}")

                # Extract federation ID from Location header
                federation_id = response.headers["Location"].split("/")[-1]
                logger.info(f"Created LDAP federation: {federation_id} for tenant {tenant_id}")

                # Create user attribute mappers
                await self._create_ldap_attribute_mappers(
                    federation_id,
                    ldap_config,
                    token,
                    client
                )

                # Create group mapper if groups are configured
                if ldap_config.get("groups_dn"):
                    group_mapper_id = await self._create_ldap_group_mapper(
                        federation_id,
                        ldap_config,
                        token,
                        client
                    )
                    return federation_id, group_mapper_id

                return federation_id, None

        except Exception as e:
            logger.error(f"LDAP federation creation error: {e}")
            raise Exception(f"Failed to create LDAP federation: {str(e)}")

    async def _create_ldap_attribute_mappers(
        self,
        federation_id: str,
        ldap_config: Dict[str, Any],
        token: str,
        client: httpx.AsyncClient
    ):
        """Create LDAP attribute mappers for user attributes"""
        try:
            attribute_mappers = [
                {
                    "name": "email",
                    "providerId": "user-attribute-ldap-mapper",
                    "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
                    "parentId": federation_id,
                    "config": {
                        "ldap.attribute": [ldap_config.get("email_ldap_attribute", "mail")],
                        "is.mandatory.in.ldap": ["true"],
                        "always.read.value.from.ldap": ["true"],
                        "read.only": ["true"],
                        "user.model.attribute": ["email"]
                    }
                },
                {
                    "name": "first name",
                    "providerId": "user-attribute-ldap-mapper",
                    "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
                    "parentId": federation_id,
                    "config": {
                        "ldap.attribute": [ldap_config.get("first_name_ldap_attribute", "givenName")],
                        "is.mandatory.in.ldap": ["true"],
                        "always.read.value.from.ldap": ["true"],
                        "read.only": ["true"],
                        "user.model.attribute": ["firstName"]
                    }
                },
                {
                    "name": "last name",
                    "providerId": "user-attribute-ldap-mapper",
                    "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
                    "parentId": federation_id,
                    "config": {
                        "ldap.attribute": [ldap_config.get("last_name_ldap_attribute", "sn")],
                        "is.mandatory.in.ldap": ["true"],
                        "always.read.value.from.ldap": ["true"],
                        "read.only": ["true"],
                        "user.model.attribute": ["lastName"]
                    }
                },
                {
                    "name": "username",
                    "providerId": "user-attribute-ldap-mapper",
                    "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
                    "parentId": federation_id,
                    "config": {
                        "ldap.attribute": [ldap_config.get("username_ldap_attribute", "sAMAccountName")],
                        "is.mandatory.in.ldap": ["true"],
                        "always.read.value.from.ldap": ["false"],
                        "read.only": ["true"],
                        "user.model.attribute": ["username"]
                    }
                }
            ]

            for mapper in attribute_mappers:
                response = await client.post(
                    f"{self.base_url}/admin/realms/{self.realm}/components",
                    headers={"Authorization": f"Bearer {token}"},
                    json=mapper
                )

                if response.status_code != 201:
                    logger.warning(f"Failed to create mapper {mapper['name']}: {response.text}")
                else:
                    logger.info(f"Created LDAP attribute mapper: {mapper['name']}")

        except Exception as e:
            logger.error(f"Attribute mapper creation error: {e}")
            # Don't fail if mappers fail, LDAP federation can still work

    async def _create_ldap_group_mapper(
        self,
        federation_id: str,
        ldap_config: Dict[str, Any],
        token: str,
        client: httpx.AsyncClient
    ) -> Optional[str]:
        """Create LDAP group mapper"""
        try:
            group_mapper = {
                "name": "group mapper",
                "providerId": "group-ldap-mapper",
                "providerType": "org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
                "parentId": federation_id,
                "config": {
                    "mode": ["LDAP_ONLY"],  # Don't sync groups to Keycloak, only read from LDAP
                    "membership.attribute.type": [ldap_config.get("group_membership_type", "DN")],
                    "user.roles.retrieve.strategy": ["LOAD_GROUPS_BY_MEMBER_ATTRIBUTE"],
                    "groups.dn": [ldap_config.get("groups_dn")],
                    "group.name.ldap.attribute": [ldap_config.get("group_name_ldap_attribute", "cn")],
                    "group.object.classes": [ldap_config.get("group_object_class", "group")],
                    "preserve.group.inheritance": ["true"],
                    "membership.ldap.attribute": [ldap_config.get("group_membership_attribute", "member")],
                    "membership.user.ldap.attribute": [ldap_config.get("rdn_ldap_attribute", "cn")],
                    "groups.ldap.filter": [""],
                    "drop.non.existing.groups.during.sync": ["false"]
                }
            }

            response = await client.post(
                f"{self.base_url}/admin/realms/{self.realm}/components",
                headers={"Authorization": f"Bearer {token}"},
                json=group_mapper
            )

            if response.status_code != 201:
                logger.warning(f"Failed to create group mapper: {response.text}")
                return None

            group_mapper_id = response.headers["Location"].split("/")[-1]
            logger.info(f"Created LDAP group mapper: {group_mapper_id}")
            return group_mapper_id

        except Exception as e:
            logger.error(f"Group mapper creation error: {e}")
            return None

    async def update_ldap_federation(
        self,
        federation_id: str,
        ldap_config: Dict[str, Any]
    ) -> bool:
        """Update existing LDAP federation configuration"""
        try:
            token = await self.get_admin_token()

            async with httpx.AsyncClient() as client:
                # Get existing component
                response = await client.get(
                    f"{self.base_url}/admin/realms/{self.realm}/components/{federation_id}",
                    headers={"Authorization": f"Bearer {token}"}
                )

                if response.status_code != 200:
                    raise Exception(f"Failed to get LDAP federation: {response.text}")

                component = response.json()

                # Update configuration
                for key, value in ldap_config.items():
                    # Map Python config keys to Keycloak config keys
                    keycloak_key = self._map_config_key(key)
                    if keycloak_key and value is not None:
                        component["config"][keycloak_key] = [str(value)]

                # Update component
                update_response = await client.put(
                    f"{self.base_url}/admin/realms/{self.realm}/components/{federation_id}",
                    headers={"Authorization": f"Bearer {token}"},
                    json=component
                )

                if update_response.status_code not in [200, 204]:
                    raise Exception(f"Failed to update LDAP federation: {update_response.text}")

                logger.info(f"Updated LDAP federation: {federation_id}")
                return True

        except Exception as e:
            logger.error(f"LDAP federation update error: {e}")
            return False

    async def delete_ldap_federation(self, federation_id: str) -> bool:
        """Delete LDAP federation from Keycloak"""
        try:
            token = await self.get_admin_token()

            async with httpx.AsyncClient() as client:
                response = await client.delete(
                    f"{self.base_url}/admin/realms/{self.realm}/components/{federation_id}",
                    headers={"Authorization": f"Bearer {token}"}
                )

                if response.status_code not in [200, 204]:
                    raise Exception(f"Failed to delete LDAP federation: {response.text}")

                logger.info(f"Deleted LDAP federation: {federation_id}")
                return True

        except Exception as e:
            logger.error(f"LDAP federation deletion error: {e}")
            return False

    async def trigger_ldap_sync(
        self,
        federation_id: str,
        sync_type: str = "triggerFullSync"
    ) -> Dict[str, Any]:
        """Trigger LDAP sync (full or changed users)

        Args:
            federation_id: Keycloak LDAP component ID
            sync_type: 'triggerFullSync' or 'triggerChangedUsersSync'
        """
        try:
            token = await self.get_admin_token()

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/admin/realms/{self.realm}/user-storage/{federation_id}/sync",
                    headers={"Authorization": f"Bearer {token}"},
                    params={"action": sync_type}
                )

                if response.status_code != 200:
                    raise Exception(f"Failed to trigger LDAP sync: {response.text}")

                sync_result = response.json()
                logger.info(f"LDAP sync triggered: {sync_result}")

                return {
                    "status": sync_result.get("status", "success"),
                    "added": sync_result.get("added", 0),
                    "updated": sync_result.get("updated", 0),
                    "removed": sync_result.get("removed", 0),
                    "failed": sync_result.get("failed", 0)
                }

        except Exception as e:
            logger.error(f"LDAP sync trigger error: {e}")
            raise Exception(f"Failed to trigger LDAP sync: {str(e)}")

    async def test_ldap_connection(
        self,
        connection_url: str,
        bind_dn: str,
        bind_credential: str,
        connection_timeout: int = 30
    ) -> Dict[str, Any]:
        """Test LDAP connection without creating federation"""
        try:
            token = await self.get_admin_token()

            async with httpx.AsyncClient() as client:
                # Create a test component (temporary)
                test_component = {
                    "name": f"test-ldap-{datetime.now().timestamp()}",
                    "providerId": "ldap",
                    "providerType": "org.keycloak.storage.UserStorageProvider",
                    "parentId": self.realm,
                    "config": {
                        "enabled": ["false"],  # Disabled so it doesn't affect realm
                        "connectionUrl": [connection_url],
                        "bindDn": [bind_dn],
                        "bindCredential": [bind_credential],
                        "connectionTimeout": [str(connection_timeout * 1000)],
                        "authType": ["simple"],
                        "vendor": ["ad"]
                    }
                }

                # Test connection by attempting to create component
                response = await client.post(
                    f"{self.base_url}/admin/realms/{self.realm}/components",
                    headers={"Authorization": f"Bearer {token}"},
                    json=test_component
                )

                if response.status_code == 201:
                    # Connection successful, delete test component
                    test_id = response.headers["Location"].split("/")[-1]
                    await client.delete(
                        f"{self.base_url}/admin/realms/{self.realm}/components/{test_id}",
                        headers={"Authorization": f"Bearer {token}"}
                    )

                    return {
                        "success": True,
                        "message": "LDAP connection successful",
                        "details": {
                            "server": connection_url,
                            "bind_dn": bind_dn
                        }
                    }
                else:
                    error_text = response.text
                    return {
                        "success": False,
                        "message": "LDAP connection failed",
                        "details": {
                            "error": error_text,
                            "server": connection_url
                        }
                    }

        except Exception as e:
            logger.error(f"LDAP connection test error: {e}")
            return {
                "success": False,
                "message": f"LDAP connection test failed: {str(e)}",
                "details": {"exception": str(e)}
            }

    def _map_config_key(self, key: str) -> Optional[str]:
        """Map Python config keys to Keycloak LDAP config keys"""
        key_mapping = {
            "enabled": "enabled",
            "connection_url": "connectionUrl",
            "bind_dn": "bindDn",
            "bind_credential": "bindCredential",
            "connection_timeout": "connectionTimeout",
            "read_timeout": "readTimeout",
            "users_dn": "usersDn",
            "user_object_class": "userObjectClasses",
            "username_ldap_attribute": "usernameLDAPAttribute",
            "rdn_ldap_attribute": "rdnLDAPAttribute",
            "uuid_ldap_attribute": "uuidLDAPAttribute",
            "user_ldap_filter": "customUserSearchFilter",
            "search_scope": "searchScope",
            "edit_mode": "editMode",
            "vendor": "vendor",
            "sync_registrations": "syncRegistrations",
            "import_enabled": "importEnabled",
            "batch_size": "batchSizeForSync",
            "full_sync_period": "fullSyncPeriod",
            "changed_sync_period": "changedSyncPeriod"
        }
        return key_mapping.get(key)