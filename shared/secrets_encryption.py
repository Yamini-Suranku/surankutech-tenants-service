"""
Advanced Encryption Service for Secrets
Provides additional encryption layer for sensitive data using AWS KMS
"""

import boto3
import base64
import json
import logging
from typing import Dict, Optional, Any
from botocore.exceptions import ClientError
import asyncio
from datetime import datetime

logger = logging.getLogger(__name__)

class EncryptionError(Exception):
    """Custom exception for encryption operations"""
    pass

class SecretsEncryption:
    """
    Advanced encryption service using AWS KMS for additional security layer
    """

    def __init__(self, kms_key_id: str, region_name: str = "us-west-2"):
        """
        Initialize encryption service

        Args:
            kms_key_id: AWS KMS key ID for encryption
            region_name: AWS region
        """
        self.kms_key_id = kms_key_id
        self.region_name = region_name
        self.kms_client = boto3.client('kms', region_name=region_name)

    async def encrypt_secret(self, plaintext: str, context: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Encrypt sensitive data using KMS

        Args:
            plaintext: The secret to encrypt
            context: Additional encryption context for security

        Returns:
            Dictionary containing encrypted data and metadata
        """
        try:
            encryption_context = {
                "service": "suranku-secrets",
                "timestamp": datetime.utcnow().isoformat(),
                **(context or {})
            }

            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.kms_client.encrypt(
                    KeyId=self.kms_key_id,
                    Plaintext=plaintext.encode('utf-8'),
                    EncryptionContext=encryption_context
                )
            )

            encrypted_data = {
                "encrypted_blob": base64.b64encode(response['CiphertextBlob']).decode('utf-8'),
                "key_id": response['KeyId'],
                "encryption_context": encryption_context,
                "encrypted_at": datetime.utcnow().isoformat(),
                "algorithm": "AWS_KMS_ENCRYPT"
            }

            logger.info(f"Successfully encrypted secret with KMS key: {self.kms_key_id}")
            return encrypted_data

        except ClientError as e:
            logger.error(f"KMS encryption failed: {e}")
            raise EncryptionError(f"Failed to encrypt secret: {e}")
        except Exception as e:
            logger.error(f"Unexpected encryption error: {e}")
            raise EncryptionError(f"Encryption error: {e}")

    async def decrypt_secret(self, encrypted_data: Dict[str, Any]) -> str:
        """
        Decrypt sensitive data using KMS

        Args:
            encrypted_data: Dictionary containing encrypted data and metadata

        Returns:
            Decrypted plaintext secret
        """
        try:
            encrypted_blob = base64.b64decode(encrypted_data['encrypted_blob'])
            encryption_context = encrypted_data.get('encryption_context', {})

            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.kms_client.decrypt(
                    CiphertextBlob=encrypted_blob,
                    EncryptionContext=encryption_context
                )
            )

            plaintext = response['Plaintext'].decode('utf-8')
            logger.info("Successfully decrypted secret")
            return plaintext

        except ClientError as e:
            logger.error(f"KMS decryption failed: {e}")
            raise EncryptionError(f"Failed to decrypt secret: {e}")
        except Exception as e:
            logger.error(f"Unexpected decryption error: {e}")
            raise EncryptionError(f"Decryption error: {e}")

    async def re_encrypt_secret(self, encrypted_data: Dict[str, Any],
                               new_key_id: str = None) -> Dict[str, Any]:
        """
        Re-encrypt secret with new key or update encryption context

        Args:
            encrypted_data: Current encrypted data
            new_key_id: Optional new KMS key ID

        Returns:
            Re-encrypted data with new metadata
        """
        try:
            # First decrypt
            plaintext = await self.decrypt_secret(encrypted_data)

            # Then encrypt with new key or updated context
            target_key_id = new_key_id or self.kms_key_id

            new_context = {
                "service": "suranku-secrets",
                "timestamp": datetime.utcnow().isoformat(),
                "re_encrypted": "true",
                "previous_encryption": encrypted_data.get('encrypted_at')
            }

            # Update the key ID for re-encryption
            original_key_id = self.kms_key_id
            self.kms_key_id = target_key_id

            try:
                new_encrypted_data = await self.encrypt_secret(plaintext, new_context)
                logger.info(f"Successfully re-encrypted secret with key: {target_key_id}")
                return new_encrypted_data
            finally:
                # Restore original key ID
                self.kms_key_id = original_key_id

        except Exception as e:
            logger.error(f"Re-encryption failed: {e}")
            raise EncryptionError(f"Failed to re-encrypt secret: {e}")

    async def generate_data_key(self, key_spec: str = "AES_256") -> Dict[str, str]:
        """
        Generate data encryption key for envelope encryption

        Args:
            key_spec: Key specification (AES_256, AES_128)

        Returns:
            Dictionary with plaintext and encrypted data keys
        """
        try:
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.kms_client.generate_data_key(
                    KeyId=self.kms_key_id,
                    KeySpec=key_spec
                )
            )

            return {
                "plaintext_key": base64.b64encode(response['Plaintext']).decode('utf-8'),
                "encrypted_key": base64.b64encode(response['CiphertextBlob']).decode('utf-8'),
                "key_id": response['KeyId']
            }

        except ClientError as e:
            logger.error(f"Data key generation failed: {e}")
            raise EncryptionError(f"Failed to generate data key: {e}")

class AdvancedSecretsManager:
    """
    Enhanced secrets manager with additional encryption layer
    Combines AWS Secrets Manager with KMS encryption for maximum security
    """

    def __init__(self, secrets_manager, encryption_service: SecretsEncryption):
        """
        Initialize advanced secrets manager

        Args:
            secrets_manager: Base AWS Secrets Manager instance
            encryption_service: KMS encryption service
        """
        self.secrets_manager = secrets_manager
        self.encryption_service = encryption_service

    async def store_encrypted_secret(self, tenant_id: str, service: str, key_name: str,
                                   secret_value: str, metadata: Dict = None,
                                   user_id: str = None) -> str:
        """
        Store secret with additional KMS encryption layer

        Args:
            tenant_id: Tenant identifier
            service: Service name
            key_name: Key name
            secret_value: Secret to encrypt and store
            metadata: Additional metadata
            user_id: User performing operation

        Returns:
            Secret ARN
        """
        try:
            # First, encrypt the secret with KMS
            encryption_context = {
                "tenant_id": tenant_id,
                "service": service,
                "key_name": key_name
            }

            encrypted_data = await self.encryption_service.encrypt_secret(
                secret_value, encryption_context
            )

            # Store the encrypted data in Secrets Manager
            enhanced_metadata = {
                **(metadata or {}),
                "encryption_method": "kms_double_encryption",
                "kms_key_id": self.encryption_service.kms_key_id
            }

            return await self.secrets_manager.store_user_secret(
                tenant_id=tenant_id,
                service=service,
                key_name=key_name,
                secret_value=json.dumps(encrypted_data),
                metadata=enhanced_metadata,
                user_id=user_id
            )

        except Exception as e:
            logger.error(f"Failed to store encrypted secret: {e}")
            raise EncryptionError(f"Failed to store encrypted secret: {e}")

    async def get_encrypted_secret(self, tenant_id: str, service: str, key_name: str,
                                  user_id: str = None) -> Optional[str]:
        """
        Retrieve and decrypt secret with KMS decryption

        Args:
            tenant_id: Tenant identifier
            service: Service name
            key_name: Key name
            user_id: User performing operation

        Returns:
            Decrypted secret value
        """
        try:
            # Get encrypted data from Secrets Manager
            encrypted_data_str = await self.secrets_manager.get_user_secret(
                tenant_id=tenant_id,
                service=service,
                key_name=key_name,
                user_id=user_id
            )

            if not encrypted_data_str:
                return None

            # Parse encrypted data
            encrypted_data = json.loads(encrypted_data_str)

            # Decrypt with KMS
            decrypted_secret = await self.encryption_service.decrypt_secret(encrypted_data)

            return decrypted_secret

        except Exception as e:
            logger.error(f"Failed to get encrypted secret: {e}")
            raise EncryptionError(f"Failed to retrieve encrypted secret: {e}")

    async def rotate_encrypted_secret(self, tenant_id: str, service: str, key_name: str,
                                     new_secret_value: str, user_id: str = None) -> str:
        """
        Rotate secret with KMS re-encryption

        Args:
            tenant_id: Tenant identifier
            service: Service name
            key_name: Key name
            new_secret_value: New secret value
            user_id: User performing operation

        Returns:
            New secret ARN
        """
        try:
            # Encrypt new secret with KMS
            encryption_context = {
                "tenant_id": tenant_id,
                "service": service,
                "key_name": key_name,
                "rotation": "true"
            }

            encrypted_data = await self.encryption_service.encrypt_secret(
                new_secret_value, encryption_context
            )

            # Rotate in Secrets Manager
            return await self.secrets_manager.rotate_user_secret(
                tenant_id=tenant_id,
                service=service,
                key_name=key_name,
                new_secret_value=json.dumps(encrypted_data),
                user_id=user_id
            )

        except Exception as e:
            logger.error(f"Failed to rotate encrypted secret: {e}")
            raise EncryptionError(f"Failed to rotate encrypted secret: {e}")

# Factory function for creating advanced secrets manager
def create_advanced_secrets_manager(kms_key_id: str, environment: str = "dev",
                                   region_name: str = "us-west-2") -> AdvancedSecretsManager:
    """
    Create advanced secrets manager with KMS encryption

    Args:
        kms_key_id: KMS key ID for encryption
        environment: Environment name
        region_name: AWS region

    Returns:
        Configured AdvancedSecretsManager instance
    """
    from .secrets_manager import AWSSecretsManager

    base_secrets_manager = AWSSecretsManager(region_name=region_name, environment=environment)
    encryption_service = SecretsEncryption(kms_key_id=kms_key_id, region_name=region_name)

    return AdvancedSecretsManager(base_secrets_manager, encryption_service)