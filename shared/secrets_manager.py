"""
AWS Secrets Manager Service
Comprehensive secrets management for user and admin API keys with encryption, audit, and rotation
"""

import json
import boto3
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from botocore.exceptions import ClientError, BotoCoreError
import asyncio
from functools import wraps
import hashlib
import base64

logger = logging.getLogger(__name__)

class SecretsManagerError(Exception):
    """Custom exception for secrets manager operations"""
    pass

class SecretsAuditLogger:
    """Audit logging for secrets operations"""

    def __init__(self):
        self.audit_logger = logging.getLogger("secrets.audit")

    def log_access(self, operation: str, secret_name: str, tenant_id: str,
                   user_id: str, success: bool, metadata: Dict = None):
        """Log secret access operations"""
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "operation": operation,
            "secret_name": secret_name,
            "tenant_id": tenant_id,
            "user_id": user_id,
            "success": success,
            "metadata": metadata or {}
        }

        if success:
            self.audit_logger.info(f"SECRET_ACCESS: {json.dumps(audit_entry)}")
        else:
            self.audit_logger.error(f"SECRET_ACCESS_FAILED: {json.dumps(audit_entry)}")

def audit_secrets_operation(operation: str):
    """Decorator for auditing secrets operations"""
    def decorator(func):
        @wraps(func)
        async def wrapper(self, *args, **kwargs):
            tenant_id = kwargs.get('tenant_id') or (args[0] if args else 'unknown')
            user_id = kwargs.get('user_id', 'system')
            secret_name = kwargs.get('secret_name') or (args[1] if len(args) > 1 else 'unknown')

            try:
                result = await func(self, *args, **kwargs)
                self.audit_logger.log_access(
                    operation=operation,
                    secret_name=secret_name,
                    tenant_id=tenant_id,
                    user_id=user_id,
                    success=True,
                    metadata={"function": func.__name__}
                )
                return result
            except Exception as e:
                self.audit_logger.log_access(
                    operation=operation,
                    secret_name=secret_name,
                    tenant_id=tenant_id,
                    user_id=user_id,
                    success=False,
                    metadata={"error": str(e), "function": func.__name__}
                )
                raise
        return wrapper
    return decorator

class AWSSecretsManager:
    """
    Comprehensive AWS Secrets Manager service for user and admin secrets
    """

    def __init__(self, region_name: str = "us-west-2", environment: str = "dev"):
        """
        Initialize AWS Secrets Manager client

        Args:
            region_name: AWS region for secrets storage
            environment: Environment (dev, test, prod) for secret namespacing
        """
        self.region_name = region_name
        self.environment = environment
        self.client = boto3.client('secretsmanager', region_name=region_name)
        self.audit_logger = SecretsAuditLogger()

        # Secret naming patterns
        self.namespace_prefix = f"suranku/{environment}"
        self.user_secrets_prefix = f"{self.namespace_prefix}/tenants"
        self.admin_secrets_prefix = f"{self.namespace_prefix}/admin"
        self.system_secrets_prefix = f"{self.namespace_prefix}/system"

    def _generate_secret_name(self, category: str, tenant_id: str = None,
                             service: str = None, key_name: str = None) -> str:
        """
        Generate standardized secret names

        Args:
            category: user, admin, or system
            tenant_id: Tenant ID for user secrets
            service: Service name (ai_providers, connectors, etc.)
            key_name: Specific key name

        Returns:
            Formatted secret name
        """
        parts = [self.namespace_prefix]

        if category == "user" and tenant_id:
            parts.extend(["tenants", tenant_id])
        elif category == "admin":
            parts.append("admin")
        elif category == "system":
            parts.append("system")
        else:
            raise ValueError(f"Invalid category: {category}")

        if service:
            parts.append(service)
        if key_name:
            parts.append(key_name)

        return "/".join(parts)

    def _generate_secret_hash(self, secret_value: str) -> str:
        """Generate hash for secret integrity verification"""
        return hashlib.sha256(secret_value.encode()).hexdigest()[:16]

    @audit_secrets_operation("store_user_secret")
    async def store_user_secret(self, tenant_id: str, service: str, key_name: str,
                               secret_value: str, metadata: Dict = None, user_id: str = None) -> str:
        """
        Store user API key securely

        Args:
            tenant_id: Tenant identifier
            service: Service name (ai_providers, connectors, etc.)
            key_name: Specific key name (openai, anthropic, etc.)
            secret_value: The actual secret/API key
            metadata: Additional metadata to store with secret
            user_id: User performing the operation

        Returns:
            Secret ARN
        """
        secret_name = self._generate_secret_name("user", tenant_id, service, key_name)

        secret_data = {
            "secret_value": secret_value,
            "tenant_id": tenant_id,
            "service": service,
            "key_name": key_name,
            "created_at": datetime.utcnow().isoformat(),
            "created_by": user_id or "system",
            "metadata": metadata or {},
            "integrity_hash": self._generate_secret_hash(secret_value)
        }

        try:
            # Check if secret exists
            try:
                await self._get_secret_async(secret_name)
                # Secret exists, update it
                response = await self._update_secret_async(secret_name, secret_data)
                operation = "update"
            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException':
                    # Secret doesn't exist, create it
                    response = await self._create_secret_async(secret_name, secret_data)
                    operation = "create"
                else:
                    raise

            logger.info(f"Successfully {operation}d user secret: {secret_name}")
            return response['ARN']

        except Exception as e:
            logger.error(f"Failed to store user secret {secret_name}: {e}")
            raise SecretsManagerError(f"Failed to store secret: {e}")

    @audit_secrets_operation("get_user_secret")
    async def get_user_secret(self, tenant_id: str, service: str, key_name: str,
                             user_id: str = None) -> Optional[str]:
        """
        Retrieve user API key

        Args:
            tenant_id: Tenant identifier
            service: Service name
            key_name: Specific key name
            user_id: User performing the operation

        Returns:
            Secret value or None if not found
        """
        secret_name = self._generate_secret_name("user", tenant_id, service, key_name)

        try:
            secret_data = await self._get_secret_async(secret_name)
            secret_dict = json.loads(secret_data['SecretString'])

            # Verify integrity
            stored_hash = secret_dict.get('integrity_hash')
            secret_value = secret_dict.get('secret_value')

            if stored_hash and secret_value:
                computed_hash = self._generate_secret_hash(secret_value)
                if stored_hash != computed_hash:
                    logger.error(f"Secret integrity check failed for {secret_name}")
                    raise SecretsManagerError("Secret integrity verification failed")

            return secret_value

        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                return None
            logger.error(f"Failed to retrieve user secret {secret_name}: {e}")
            raise SecretsManagerError(f"Failed to retrieve secret: {e}")

    @audit_secrets_operation("list_user_secrets")
    async def list_user_secrets(self, tenant_id: str, service: str = None,
                               user_id: str = None) -> List[Dict[str, Any]]:
        """
        List user secrets for a tenant

        Args:
            tenant_id: Tenant identifier
            service: Optional service filter
            user_id: User performing the operation

        Returns:
            List of secret metadata (without actual secret values)
        """
        if service:
            name_filter = self._generate_secret_name("user", tenant_id, service)
        else:
            name_filter = self._generate_secret_name("user", tenant_id)

        try:
            secrets = await self._list_secrets_async(name_filter)

            secret_list = []
            for secret in secrets:
                # Get metadata without exposing secret value
                try:
                    secret_data = await self._get_secret_async(secret['ARN'])
                    secret_dict = json.loads(secret_data['SecretString'])

                    secret_info = {
                        "name": secret['Name'],
                        "arn": secret['ARN'],
                        "service": secret_dict.get('service'),
                        "key_name": secret_dict.get('key_name'),
                        "created_at": secret_dict.get('created_at'),
                        "created_by": secret_dict.get('created_by'),
                        "last_accessed": secret.get('LastAccessedDate'),
                        "metadata": secret_dict.get('metadata', {})
                    }
                    secret_list.append(secret_info)
                except Exception as e:
                    logger.warning(f"Failed to get metadata for secret {secret['Name']}: {e}")

            return secret_list

        except Exception as e:
            logger.error(f"Failed to list user secrets for tenant {tenant_id}: {e}")
            raise SecretsManagerError(f"Failed to list secrets: {e}")

    @audit_secrets_operation("delete_user_secret")
    async def delete_user_secret(self, tenant_id: str, service: str, key_name: str,
                                user_id: str = None, immediate: bool = False) -> bool:
        """
        Delete user API key

        Args:
            tenant_id: Tenant identifier
            service: Service name
            key_name: Specific key name
            user_id: User performing the operation
            immediate: If True, delete immediately without recovery window

        Returns:
            True if deleted successfully
        """
        secret_name = self._generate_secret_name("user", tenant_id, service, key_name)

        try:
            if immediate:
                await self._delete_secret_immediate_async(secret_name)
            else:
                await self._delete_secret_async(secret_name)

            logger.info(f"Successfully deleted user secret: {secret_name}")
            return True

        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                return False
            logger.error(f"Failed to delete user secret {secret_name}: {e}")
            raise SecretsManagerError(f"Failed to delete secret: {e}")

    @audit_secrets_operation("rotate_user_secret")
    async def rotate_user_secret(self, tenant_id: str, service: str, key_name: str,
                                new_secret_value: str, user_id: str = None) -> str:
        """
        Rotate user API key with versioning

        Args:
            tenant_id: Tenant identifier
            service: Service name
            key_name: Specific key name
            new_secret_value: New secret value
            user_id: User performing the operation

        Returns:
            New secret version ARN
        """
        secret_name = self._generate_secret_name("user", tenant_id, service, key_name)

        try:
            # Get current secret for metadata
            current_secret = await self._get_secret_async(secret_name)
            current_dict = json.loads(current_secret['SecretString'])

            # Create new version with rotation metadata
            new_secret_data = {
                **current_dict,
                "secret_value": new_secret_value,
                "rotated_at": datetime.utcnow().isoformat(),
                "rotated_by": user_id or "system",
                "previous_version": current_secret.get('VersionId'),
                "integrity_hash": self._generate_secret_hash(new_secret_value)
            }

            response = await self._update_secret_async(secret_name, new_secret_data)

            logger.info(f"Successfully rotated user secret: {secret_name}")
            return response['ARN']

        except Exception as e:
            logger.error(f"Failed to rotate user secret {secret_name}: {e}")
            raise SecretsManagerError(f"Failed to rotate secret: {e}")

    async def bulk_delete_tenant_secrets(self, tenant_id: str, user_id: str = None) -> int:
        """
        Delete all secrets for a tenant (for tenant cleanup)

        Args:
            tenant_id: Tenant identifier
            user_id: User performing the operation

        Returns:
            Number of secrets deleted
        """
        tenant_secrets = await self.list_user_secrets(tenant_id, user_id=user_id)
        deleted_count = 0

        for secret in tenant_secrets:
            try:
                await self._delete_secret_immediate_async(secret['arn'])
                deleted_count += 1
            except Exception as e:
                logger.error(f"Failed to delete secret {secret['name']}: {e}")

        return deleted_count

    # Async wrapper methods for boto3 operations
    async def _create_secret_async(self, name: str, secret_data: Dict) -> Dict:
        """Create secret asynchronously"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self.client.create_secret,
            {
                'Name': name,
                'SecretString': json.dumps(secret_data),
                'Description': f"User secret for {secret_data.get('service', 'unknown')} service"
            }
        )

    async def _update_secret_async(self, name: str, secret_data: Dict) -> Dict:
        """Update secret asynchronously"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self.client.update_secret,
            {
                'SecretId': name,
                'SecretString': json.dumps(secret_data)
            }
        )

    async def _get_secret_async(self, secret_id: str) -> Dict:
        """Get secret asynchronously"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self.client.get_secret_value,
            {'SecretId': secret_id}
        )

    async def _delete_secret_async(self, secret_id: str) -> Dict:
        """Delete secret asynchronously (with recovery window)"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self.client.delete_secret,
            {'SecretId': secret_id, 'RecoveryWindowInDays': 30}
        )

    async def _delete_secret_immediate_async(self, secret_id: str) -> Dict:
        """Delete secret immediately asynchronously"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self.client.delete_secret,
            {'SecretId': secret_id, 'ForceDeleteWithoutRecovery': True}
        )

    async def _list_secrets_async(self, name_filter: str) -> List[Dict]:
        """List secrets asynchronously"""
        loop = asyncio.get_event_loop()

        def list_secrets():
            paginator = self.client.get_paginator('list_secrets')
            secrets = []
            for page in paginator.paginate(
                Filters=[
                    {
                        'Key': 'name',
                        'Values': [f"{name_filter}*"]
                    }
                ]
            ):
                secrets.extend(page.get('SecretList', []))
            return secrets

        return await loop.run_in_executor(None, list_secrets)

# Global instance for dependency injection
secrets_manager: Optional[AWSSecretsManager] = None

def get_secrets_manager() -> AWSSecretsManager:
    """Get secrets manager instance"""
    global secrets_manager
    if secrets_manager is None:
        import os
        environment = os.getenv("ENVIRONMENT", "dev")
        region = os.getenv("AWS_REGION", "us-west-2")
        secrets_manager = AWSSecretsManager(region_name=region, environment=environment)
    return secrets_manager

# Convenience functions for common operations
async def store_ai_provider_key(tenant_id: str, provider: str, api_key: str,
                               metadata: Dict = None, user_id: str = None) -> str:
    """Store AI provider API key"""
    sm = get_secrets_manager()
    return await sm.store_user_secret(
        tenant_id=tenant_id,
        service="ai_providers",
        key_name=provider,
        secret_value=api_key,
        metadata=metadata,
        user_id=user_id
    )

async def get_ai_provider_key(tenant_id: str, provider: str, user_id: str = None) -> Optional[str]:
    """Get AI provider API key"""
    sm = get_secrets_manager()
    return await sm.get_user_secret(
        tenant_id=tenant_id,
        service="ai_providers",
        key_name=provider,
        user_id=user_id
    )

async def store_connector_credentials(tenant_id: str, connector_name: str,
                                     credentials: Dict, user_id: str = None) -> str:
    """Store connector credentials"""
    sm = get_secrets_manager()
    return await sm.store_user_secret(
        tenant_id=tenant_id,
        service="connectors",
        key_name=connector_name,
        secret_value=json.dumps(credentials),
        user_id=user_id
    )

async def get_connector_credentials(tenant_id: str, connector_name: str,
                                   user_id: str = None) -> Optional[Dict]:
    """Get connector credentials"""
    sm = get_secrets_manager()
    credentials_str = await sm.get_user_secret(
        tenant_id=tenant_id,
        service="connectors",
        key_name=connector_name,
        user_id=user_id
    )
    return json.loads(credentials_str) if credentials_str else None