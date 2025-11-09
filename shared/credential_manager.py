"""
Universal Credential Manager
Main coordinator that switches between Vault and AWS Secrets Manager based on environment configuration
"""

import os
import logging
from typing import Dict, List, Any, Optional
from enum import Enum

logger = logging.getLogger(__name__)

class CredentialBackend(Enum):
    VAULT = "vault"
    AWS_SECRETS_MANAGER = "aws_secrets_manager"

class CredentialManager:
    """Universal credential manager with pluggable backends"""

    def __init__(self):
        # Get backend from environment (default to Vault)
        backend_env = os.getenv("CREDENTIAL_BACKEND", "vault").lower()

        if backend_env == "aws_secrets_manager":
            self.backend_type = CredentialBackend.AWS_SECRETS_MANAGER
        else:
            self.backend_type = CredentialBackend.VAULT

        self.backend = None
        self._initialize_backend()

    def _initialize_backend(self):
        """Initialize the configured backend"""
        try:
            if self.backend_type == CredentialBackend.VAULT:
                from .vault_manager import VaultCredentialManager
                self.backend = VaultCredentialManager()
                logger.info("Initialized Vault credential backend")

            elif self.backend_type == CredentialBackend.AWS_SECRETS_MANAGER:
                from .aws_secrets_manager import AWSSecretsManagerCredentialManager
                self.backend = AWSSecretsManagerCredentialManager()
                logger.info("Initialized AWS Secrets Manager credential backend")

        except Exception as e:
            logger.error(f"Failed to initialize {self.backend_type.value} backend: {e}")
            # Try fallback backend
            self._try_fallback_backend()

    def _try_fallback_backend(self):
        """Try to initialize fallback backend if primary fails"""
        try:
            if self.backend_type == CredentialBackend.VAULT:
                logger.warning("Vault failed, trying AWS Secrets Manager as fallback")
                from .aws_secrets_manager import AWSSecretsManagerCredentialManager
                self.backend = AWSSecretsManagerCredentialManager()
                self.backend_type = CredentialBackend.AWS_SECRETS_MANAGER
                logger.info("Fallback to AWS Secrets Manager successful")

            elif self.backend_type == CredentialBackend.AWS_SECRETS_MANAGER:
                logger.warning("AWS Secrets Manager failed, trying Vault as fallback")
                from .vault_manager import VaultCredentialManager
                self.backend = VaultCredentialManager()
                self.backend_type = CredentialBackend.VAULT
                logger.info("Fallback to Vault successful")

        except Exception as e:
            logger.error(f"Fallback backend also failed: {e}")
            raise RuntimeError("No credential backend available")

    async def switch_backend(self, backend_type: CredentialBackend) -> bool:
        """Switch to a different backend at runtime"""
        try:
            old_backend = self.backend_type
            self.backend_type = backend_type
            self._initialize_backend()

            # Test the new backend
            test_result = await self.test_connection()
            if test_result["success"]:
                logger.info(f"Successfully switched from {old_backend.value} to {backend_type.value}")
                return True
            else:
                # Revert on failure
                self.backend_type = old_backend
                self._initialize_backend()
                logger.error(f"Failed to switch to {backend_type.value}, reverted to {old_backend.value}")
                return False

        except Exception as e:
            logger.error(f"Error switching backend: {e}")
            return False

    def get_backend_info(self) -> Dict[str, Any]:
        """Get information about the current backend"""
        return {
            "backend_type": self.backend_type.value,
            "backend_class": self.backend.__class__.__name__ if self.backend else None,
            "configured_from_env": os.getenv("CREDENTIAL_BACKEND", "vault")
        }

    # AI Provider specific methods
    async def store_ai_provider_credentials(self, tenant_id: str, provider_type: str,
                                          credentials: Dict[str, Any], metadata: Dict[str, Any] = None) -> str:
        """Store AI provider credentials"""
        return await self.backend.store_secret(
            tenant_id=tenant_id,
            service="ai_providers",
            key_name=provider_type,
            secret_data=credentials,
            metadata=metadata
        )

    async def get_ai_provider_credentials(self, tenant_id: str, provider_type: str) -> Optional[Dict[str, Any]]:
        """Get AI provider credentials"""
        return await self.backend.get_secret(
            tenant_id=tenant_id,
            service="ai_providers",
            key_name=provider_type
        )

    async def delete_ai_provider_credentials(self, tenant_id: str, provider_type: str) -> bool:
        """Delete AI provider credentials"""
        return await self.backend.delete_secret(
            tenant_id=tenant_id,
            service="ai_providers",
            key_name=provider_type
        )

    async def list_ai_providers(self, tenant_id: str) -> List[str]:
        """List all configured AI providers for a tenant"""
        return await self.backend.list_tenant_secrets(
            tenant_id=tenant_id,
            service="ai_providers"
        )

    # Generic secret methods (delegate to backend)
    async def store_secret(self, tenant_id: str, service: str, key_name: str,
                          secret_data: Dict[str, Any], metadata: Dict[str, Any] = None) -> str:
        """Store a generic secret"""
        return await self.backend.store_secret(tenant_id, service, key_name, secret_data, metadata)

    async def get_secret(self, tenant_id: str, service: str, key_name: str) -> Optional[Dict[str, Any]]:
        """Get a generic secret"""
        return await self.backend.get_secret(tenant_id, service, key_name)

    async def delete_secret(self, tenant_id: str, service: str, key_name: str) -> bool:
        """Delete a generic secret"""
        return await self.backend.delete_secret(tenant_id, service, key_name)

    async def list_tenant_secrets(self, tenant_id: str, service: str = None) -> List[str]:
        """List secrets for a tenant"""
        return await self.backend.list_tenant_secrets(tenant_id, service)

    async def test_connection(self) -> Dict[str, Any]:
        """Test connection to the active backend"""
        if not self.backend:
            return {"success": False, "error": "No backend initialized"}

        result = await self.backend.test_connection()
        result["backend_type"] = self.backend_type.value
        return result

    async def rotate_secret(self, tenant_id: str, service: str, key_name: str,
                           new_secret_data: Dict[str, Any]) -> str:
        """Rotate a secret"""
        return await self.backend.rotate_secret(tenant_id, service, key_name, new_secret_data)

    async def bulk_delete_tenant_secrets(self, tenant_id: str) -> int:
        """Delete all secrets for a tenant"""
        return await self.backend.bulk_delete_tenant_secrets(tenant_id)

    # Database/Connector specific methods
    async def store_database_credentials(self, tenant_id: str, database_name: str,
                                       credentials: Dict[str, Any]) -> str:
        """Store database credentials"""
        return await self.store_secret(tenant_id, "databases", database_name, credentials)

    async def get_database_credentials(self, tenant_id: str, database_name: str) -> Optional[Dict[str, Any]]:
        """Get database credentials"""
        return await self.get_secret(tenant_id, "databases", database_name)

    async def store_integration_credentials(self, tenant_id: str, integration_name: str,
                                          credentials: Dict[str, Any]) -> str:
        """Store third-party integration credentials"""
        return await self.store_secret(tenant_id, "integrations", integration_name, credentials)

    async def get_integration_credentials(self, tenant_id: str, integration_name: str) -> Optional[Dict[str, Any]]:
        """Get third-party integration credentials"""
        return await self.get_secret(tenant_id, "integrations", integration_name)

# Global instance
_credential_manager: Optional[CredentialManager] = None

def get_credential_manager() -> CredentialManager:
    """Get the global credential manager instance"""
    global _credential_manager
    if _credential_manager is None:
        _credential_manager = CredentialManager()
    return _credential_manager

# Convenience functions for AI providers
async def store_ai_provider_key(tenant_id: str, provider: str, api_key: str,
                               endpoint: str = None, metadata: Dict[str, Any] = None) -> str:
    """Store AI provider API key"""
    manager = get_credential_manager()
    credentials = {"api_key": api_key}
    if endpoint:
        credentials["endpoint"] = endpoint

    return await manager.store_ai_provider_credentials(tenant_id, provider, credentials, metadata)

async def get_ai_provider_key(tenant_id: str, provider: str) -> Optional[str]:
    """Get AI provider API key"""
    manager = get_credential_manager()
    credentials = await manager.get_ai_provider_credentials(tenant_id, provider)
    return credentials.get("api_key") if credentials else None

async def get_ai_provider_config(tenant_id: str, provider: str) -> Optional[Dict[str, Any]]:
    """Get complete AI provider configuration"""
    manager = get_credential_manager()
    return await manager.get_ai_provider_credentials(tenant_id, provider)

async def test_credential_backend() -> Dict[str, Any]:
    """Test the current credential backend"""
    manager = get_credential_manager()
    return await manager.test_connection()

async def get_backend_status() -> Dict[str, Any]:
    """Get status and info about the credential backend"""
    manager = get_credential_manager()
    test_result = await manager.test_connection()
    backend_info = manager.get_backend_info()

    return {
        **backend_info,
        "connection_test": test_result,
        "environment_variables": {
            "CREDENTIAL_BACKEND": os.getenv("CREDENTIAL_BACKEND", "vault"),
            "VAULT_URL": os.getenv("VAULT_URL", "http://vault:8200"),
            "AWS_REGION": os.getenv("AWS_REGION", "us-west-2"),
            "ENVIRONMENT": os.getenv("ENVIRONMENT", "dev")
        }
    }