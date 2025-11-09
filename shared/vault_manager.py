"""
HashiCorp Vault Credential Manager
Dedicated implementation for Vault secret management
"""

import os
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

import hvac
from hvac.exceptions import VaultError, InvalidPath, Forbidden

logger = logging.getLogger(__name__)

class VaultCredentialManager:
    """HashiCorp Vault credential manager for tenant secrets"""

    def __init__(self):
        self.vault_url = os.getenv("VAULT_URL", "http://vault:8200")
        self.vault_token = os.getenv("VAULT_TOKEN")
        self.vault_username = os.getenv("VAULT_USERNAME")
        self.vault_password = os.getenv("VAULT_PASSWORD")
        self.vault_role_id = os.getenv("VAULT_ROLE_ID")
        self.vault_secret_id = os.getenv("VAULT_SECRET_ID")
        self.mount_point = os.getenv("VAULT_MOUNT_POINT", "secret")

        self.client = None
        self._initialize_client()

    def _initialize_client(self):
        """Initialize and authenticate Vault client"""
        try:
            self.client = hvac.Client(url=self.vault_url)

            # Try different authentication methods
            if self.vault_token:
                self.client.token = self.vault_token
                logger.info("Using Vault token authentication")
            elif self.vault_username and self.vault_password:
                self.client.auth.userpass.login(
                    username=self.vault_username,
                    password=self.vault_password
                )
                logger.info("Authenticated to Vault using userpass")
            elif self.vault_role_id and self.vault_secret_id:
                self.client.auth.approle.login(
                    role_id=self.vault_role_id,
                    secret_id=self.vault_secret_id
                )
                logger.info("Authenticated to Vault using AppRole")
            else:
                raise ValueError("No Vault authentication method configured")

            if not self.client.is_authenticated():
                raise ValueError("Failed to authenticate to Vault")

        except Exception as e:
            logger.error(f"Failed to initialize Vault client: {e}")
            raise

    def _get_tenant_path(self, tenant_id: str, service: str, key_name: str) -> str:
        """Generate tenant-specific secret path"""
        return f"tenants/{tenant_id}/{service}/{key_name}"

    async def store_secret(self, tenant_id: str, service: str, key_name: str,
                          secret_data: Dict[str, Any], metadata: Dict[str, Any] = None) -> str:
        """Store secret in Vault KV store"""
        try:
            path = self._get_tenant_path(tenant_id, service, key_name)

            # Add metadata
            enriched_data = {
                **secret_data,
                "_metadata": {
                    "created_at": datetime.utcnow().isoformat(),
                    "tenant_id": tenant_id,
                    "service": service,
                    "key_name": key_name,
                    **(metadata or {})
                }
            }

            # Store in Vault KV v2
            response = self.client.secrets.kv.v2.create_or_update_secret(
                path=path,
                mount_point=self.mount_point,
                secret=enriched_data
            )

            logger.info(f"Secret stored in Vault: {path}")
            return f"vault://{self.mount_point}/{path}"

        except VaultError as e:
            logger.error(f"Vault error storing secret: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to store secret in Vault: {e}")
            raise

    async def get_secret(self, tenant_id: str, service: str, key_name: str) -> Optional[Dict[str, Any]]:
        """Retrieve secret from Vault"""
        try:
            path = self._get_tenant_path(tenant_id, service, key_name)

            response = self.client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=self.mount_point
            )

            if response and 'data' in response and 'data' in response['data']:
                secret_data = response['data']['data']
                # Remove metadata from returned data
                secret_data.pop('_metadata', None)
                return secret_data

            return None

        except InvalidPath:
            logger.debug(f"Secret not found: {path}")
            return None
        except VaultError as e:
            logger.error(f"Vault error retrieving secret: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to retrieve secret from Vault: {e}")
            raise

    async def delete_secret(self, tenant_id: str, service: str, key_name: str) -> bool:
        """Delete secret from Vault"""
        try:
            path = self._get_tenant_path(tenant_id, service, key_name)

            self.client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=path,
                mount_point=self.mount_point
            )

            logger.info(f"Secret deleted from Vault: {path}")
            return True

        except InvalidPath:
            logger.debug(f"Secret not found for deletion: {path}")
            return False
        except VaultError as e:
            logger.error(f"Vault error deleting secret: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to delete secret from Vault: {e}")
            raise

    async def list_tenant_secrets(self, tenant_id: str, service: str = None) -> List[str]:
        """List secrets for a tenant"""
        try:
            if service:
                path_prefix = f"tenants/{tenant_id}/{service}"
            else:
                path_prefix = f"tenants/{tenant_id}"

            response = self.client.secrets.kv.v2.list_secrets(
                path=path_prefix,
                mount_point=self.mount_point
            )

            if response and 'data' in response and 'keys' in response['data']:
                return response['data']['keys']

            return []

        except InvalidPath:
            return []
        except VaultError as e:
            logger.error(f"Vault error listing secrets: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to list secrets from Vault: {e}")
            raise

    async def test_connection(self) -> Dict[str, Any]:
        """Test Vault connection and authentication"""
        try:
            if not self.client:
                return {"success": False, "error": "Vault client not initialized"}

            if not self.client.is_authenticated():
                return {"success": False, "error": "Not authenticated to Vault"}

            # Test by reading server health
            health = self.client.sys.read_health_status()

            return {
                "success": True,
                "backend": "vault",
                "url": self.vault_url,
                "mount_point": self.mount_point,
                "authenticated": True,
                "server_health": health
            }

        except Exception as e:
            return {
                "success": False,
                "backend": "vault",
                "error": str(e)
            }

    async def rotate_secret(self, tenant_id: str, service: str, key_name: str,
                           new_secret_data: Dict[str, Any]) -> str:
        """Rotate a secret (create new version)"""
        try:
            # Store new version
            result = await self.store_secret(tenant_id, service, key_name, new_secret_data,
                                           {"rotated_at": datetime.utcnow().isoformat()})

            logger.info(f"Secret rotated for {tenant_id}/{service}/{key_name}")
            return result

        except Exception as e:
            logger.error(f"Failed to rotate secret: {e}")
            raise

    async def bulk_delete_tenant_secrets(self, tenant_id: str) -> int:
        """Delete all secrets for a tenant (for cleanup)"""
        try:
            secrets = await self.list_tenant_secrets(tenant_id)
            deleted_count = 0

            for service in secrets:
                service_secrets = await self.list_tenant_secrets(tenant_id, service)
                for key_name in service_secrets:
                    try:
                        await self.delete_secret(tenant_id, service, key_name)
                        deleted_count += 1
                    except Exception as e:
                        logger.error(f"Failed to delete {tenant_id}/{service}/{key_name}: {e}")

            logger.info(f"Deleted {deleted_count} secrets for tenant {tenant_id}")
            return deleted_count

        except Exception as e:
            logger.error(f"Failed to bulk delete secrets for tenant {tenant_id}: {e}")
            raise