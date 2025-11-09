"""
AWS Secrets Manager Credential Manager
Dedicated implementation for AWS Secrets Manager
"""

import os
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

import boto3
from botocore.exceptions import ClientError, BotoCoreError

logger = logging.getLogger(__name__)

class AWSSecretsManagerCredentialManager:
    """AWS Secrets Manager credential manager for tenant secrets"""

    def __init__(self):
        self.region_name = os.getenv("AWS_REGION", "us-west-2")
        self.environment = os.getenv("ENVIRONMENT", "dev")
        self.namespace_prefix = f"suranku/{self.environment}"

        # Initialize AWS client
        try:
            self.client = boto3.client('secretsmanager', region_name=self.region_name)
        except Exception as e:
            logger.error(f"Failed to initialize AWS Secrets Manager client: {e}")
            raise

    def _generate_secret_name(self, tenant_id: str, service: str, key_name: str) -> str:
        """Generate AWS Secrets Manager compatible secret name"""
        return f"{self.namespace_prefix}/tenants/{tenant_id}/{service}/{key_name}"

    def _extract_path_components(self, secret_name: str) -> tuple:
        """Extract tenant_id, service, key_name from secret name"""
        try:
            # Remove namespace prefix
            relative_path = secret_name.replace(f"{self.namespace_prefix}/tenants/", "")
            parts = relative_path.split("/")

            if len(parts) >= 3:
                tenant_id = parts[0]
                service = parts[1]
                key_name = "/".join(parts[2:])  # Handle nested key names
                return tenant_id, service, key_name
            else:
                return None, None, None
        except Exception:
            return None, None, None

    async def store_secret(self, tenant_id: str, service: str, key_name: str,
                          secret_data: Dict[str, Any], metadata: Dict[str, Any] = None) -> str:
        """Store secret in AWS Secrets Manager"""
        try:
            secret_name = self._generate_secret_name(tenant_id, service, key_name)

            # Prepare secret value with metadata
            secret_value = {
                "data": secret_data,
                "metadata": {
                    "created_at": datetime.utcnow().isoformat(),
                    "tenant_id": tenant_id,
                    "service": service,
                    "key_name": key_name,
                    **(metadata or {})
                }
            }

            try:
                # Try to update existing secret
                response = self.client.update_secret(
                    SecretId=secret_name,
                    SecretString=json.dumps(secret_value),
                    Description=f"Suranku {service} credentials for tenant {tenant_id}"
                )
                operation = "updated"
            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException':
                    # Create new secret
                    response = self.client.create_secret(
                        Name=secret_name,
                        SecretString=json.dumps(secret_value),
                        Description=f"Suranku {service} credentials for tenant {tenant_id}"
                    )
                    operation = "created"
                else:
                    raise

            logger.info(f"Secret {operation} in AWS Secrets Manager: {secret_name}")
            return response['ARN']

        except ClientError as e:
            logger.error(f"AWS Secrets Manager error: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to store secret in AWS Secrets Manager: {e}")
            raise

    async def get_secret(self, tenant_id: str, service: str, key_name: str) -> Optional[Dict[str, Any]]:
        """Retrieve secret from AWS Secrets Manager"""
        try:
            secret_name = self._generate_secret_name(tenant_id, service, key_name)

            response = self.client.get_secret_value(SecretId=secret_name)

            if 'SecretString' in response:
                secret_value = json.loads(response['SecretString'])
                return secret_value.get('data', secret_value)

            return None

        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                logger.debug(f"Secret not found: {secret_name}")
                return None
            logger.error(f"AWS Secrets Manager error retrieving secret: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to retrieve secret from AWS Secrets Manager: {e}")
            raise

    async def delete_secret(self, tenant_id: str, service: str, key_name: str) -> bool:
        """Delete secret from AWS Secrets Manager"""
        try:
            secret_name = self._generate_secret_name(tenant_id, service, key_name)

            self.client.delete_secret(
                SecretId=secret_name,
                ForceDeleteWithoutRecovery=True
            )

            logger.info(f"Secret deleted from AWS Secrets Manager: {secret_name}")
            return True

        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                logger.debug(f"Secret not found for deletion: {secret_name}")
                return False
            logger.error(f"AWS Secrets Manager error deleting secret: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to delete secret from AWS Secrets Manager: {e}")
            raise

    async def list_tenant_secrets(self, tenant_id: str, service: str = None) -> List[str]:
        """List secrets for a tenant"""
        try:
            if service:
                name_filter = f"{self.namespace_prefix}/tenants/{tenant_id}/{service}/"
            else:
                name_filter = f"{self.namespace_prefix}/tenants/{tenant_id}/"

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
                for secret in page.get('SecretList', []):
                    secret_name = secret['Name']
                    _, _, key_name = self._extract_path_components(secret_name)
                    if key_name:
                        secrets.append(key_name)

            return secrets

        except Exception as e:
            logger.error(f"Failed to list secrets from AWS Secrets Manager: {e}")
            raise

    async def test_connection(self) -> Dict[str, Any]:
        """Test AWS Secrets Manager connection"""
        try:
            # Try to list secrets (with limit to test connectivity)
            response = self.client.list_secrets(MaxResults=1)

            return {
                "success": True,
                "backend": "aws_secrets_manager",
                "region": self.region_name,
                "namespace": self.namespace_prefix,
                "accessible": True
            }

        except ClientError as e:
            return {
                "success": False,
                "backend": "aws_secrets_manager",
                "error": f"AWS Error: {e.response['Error']['Code']} - {e.response['Error']['Message']}"
            }
        except Exception as e:
            return {
                "success": False,
                "backend": "aws_secrets_manager",
                "error": str(e)
            }

    async def rotate_secret(self, tenant_id: str, service: str, key_name: str,
                           new_secret_data: Dict[str, Any]) -> str:
        """Rotate a secret (update with new value)"""
        try:
            # Store new version with rotation metadata
            result = await self.store_secret(
                tenant_id, service, key_name, new_secret_data,
                {"rotated_at": datetime.utcnow().isoformat()}
            )

            logger.info(f"Secret rotated for {tenant_id}/{service}/{key_name}")
            return result

        except Exception as e:
            logger.error(f"Failed to rotate secret: {e}")
            raise

    async def bulk_delete_tenant_secrets(self, tenant_id: str) -> int:
        """Delete all secrets for a tenant (for cleanup)"""
        try:
            # List all secrets for tenant
            name_filter = f"{self.namespace_prefix}/tenants/{tenant_id}/"

            paginator = self.client.get_paginator('list_secrets')
            secrets_to_delete = []

            for page in paginator.paginate(
                Filters=[
                    {
                        'Key': 'name',
                        'Values': [f"{name_filter}*"]
                    }
                ]
            ):
                for secret in page.get('SecretList', []):
                    secrets_to_delete.append(secret['Name'])

            # Delete each secret
            deleted_count = 0
            for secret_name in secrets_to_delete:
                try:
                    self.client.delete_secret(
                        SecretId=secret_name,
                        ForceDeleteWithoutRecovery=True
                    )
                    deleted_count += 1
                except Exception as e:
                    logger.error(f"Failed to delete secret {secret_name}: {e}")

            logger.info(f"Deleted {deleted_count} secrets for tenant {tenant_id}")
            return deleted_count

        except Exception as e:
            logger.error(f"Failed to bulk delete secrets for tenant {tenant_id}: {e}")
            raise

    async def get_secret_metadata(self, tenant_id: str, service: str, key_name: str) -> Optional[Dict[str, Any]]:
        """Get secret metadata without retrieving the actual secret value"""
        try:
            secret_name = self._generate_secret_name(tenant_id, service, key_name)

            response = self.client.describe_secret(SecretId=secret_name)

            return {
                "name": response.get('Name'),
                "arn": response.get('ARN'),
                "description": response.get('Description'),
                "created_date": response.get('CreatedDate').isoformat() if response.get('CreatedDate') else None,
                "last_accessed_date": response.get('LastAccessedDate').isoformat() if response.get('LastAccessedDate') else None,
                "last_changed_date": response.get('LastChangedDate').isoformat() if response.get('LastChangedDate') else None,
                "version_id": response.get('VersionIdsToStages', {})
            }

        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                return None
            logger.error(f"AWS Secrets Manager error getting metadata: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to get secret metadata: {e}")
            raise