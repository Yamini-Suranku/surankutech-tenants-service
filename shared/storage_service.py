"""
MinIO Storage Service for File Uploads
Handles profile pictures, company logos, and other file storage needs
"""

import os
import uuid
import logging
from datetime import datetime, timedelta
from typing import Optional, Tuple, BinaryIO
from minio import Minio
from minio.error import S3Error
import magic
from PIL import Image
import io

logger = logging.getLogger(__name__)

class StorageService:
    """MinIO-based storage service for file uploads"""

    # Allowed file types and sizes
    ALLOWED_IMAGE_TYPES = {
        'image/jpeg': ['.jpg', '.jpeg'],
        'image/png': ['.png'],
        'image/webp': ['.webp'],
        'image/gif': ['.gif'],
        'image/svg+xml': ['.svg']
    }

    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
    MAX_LOGO_SIZE = (500, 500)  # Max dimensions for logos
    MAX_AVATAR_SIZE = (400, 400)  # Max dimensions for avatars

    def __init__(self):
        self.endpoint = os.getenv("MINIO_ENDPOINT", "localhost:9000")
        self.access_key = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
        self.secret_key = os.getenv("MINIO_SECRET_KEY", "minioadmin123")
        self.secure = os.getenv("MINIO_SECURE", "false").lower() == "true"
        self.region = os.getenv("MINIO_REGION", "us-east-1")

        # Initialize MinIO client
        self.client = Minio(
            self.endpoint,
            access_key=self.access_key,
            secret_key=self.secret_key,
            secure=self.secure
        )

        # Bucket names
        self.avatars_bucket = "user-avatars"
        self.logos_bucket = "company-logos"
        self.documents_bucket = "tenant-documents"

        # Ensure buckets exist
        self._ensure_buckets()

    def _ensure_buckets(self):
        """Ensure all required buckets exist"""
        buckets = [self.avatars_bucket, self.logos_bucket, self.documents_bucket]

        for bucket_name in buckets:
            try:
                if not self.client.bucket_exists(bucket_name):
                    self.client.make_bucket(bucket_name, location=self.region)
                    logger.info(f"Created MinIO bucket: {bucket_name}")

                    # Set public read policy for images
                    if bucket_name in [self.avatars_bucket, self.logos_bucket]:
                        policy = {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"AWS": "*"},
                                    "Action": ["s3:GetObject"],
                                    "Resource": [f"arn:aws:s3:::{bucket_name}/*"]
                                }
                            ]
                        }
                        import json
                        self.client.set_bucket_policy(bucket_name, json.dumps(policy))
                        logger.info(f"Set public read policy for bucket: {bucket_name}")

            except S3Error as e:
                logger.error(f"Error ensuring bucket {bucket_name}: {e}")
                raise Exception(f"Failed to initialize storage bucket: {bucket_name}")

    def validate_image_file(self, file_data: bytes, filename: str) -> Tuple[bool, str]:
        """
        Validate uploaded image file

        Args:
            file_data: File content as bytes
            filename: Original filename

        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            # Check file size
            if len(file_data) > self.MAX_FILE_SIZE:
                return False, f"File size exceeds {self.MAX_FILE_SIZE // (1024*1024)}MB limit"

            # Check file type using python-magic
            mime_type = magic.from_buffer(file_data, mime=True)

            if mime_type not in self.ALLOWED_IMAGE_TYPES:
                allowed_types = ', '.join(self.ALLOWED_IMAGE_TYPES.keys())
                return False, f"Invalid file type. Allowed types: {allowed_types}"

            # Validate file can be opened as image
            try:
                with Image.open(io.BytesIO(file_data)) as img:
                    # Check image dimensions (not too small)
                    if img.width < 50 or img.height < 50:
                        return False, "Image dimensions too small (minimum 50x50 pixels)"

                    # Check if image is too large (memory safety)
                    if img.width > 5000 or img.height > 5000:
                        return False, "Image dimensions too large (maximum 5000x5000 pixels)"

            except Exception as e:
                return False, f"Invalid image file: {str(e)}"

            return True, ""

        except Exception as e:
            logger.error(f"File validation error: {e}")
            return False, f"File validation failed: {str(e)}"

    def resize_image(self, file_data: bytes, max_size: Tuple[int, int], quality: int = 85) -> bytes:
        """
        Resize and optimize image

        Args:
            file_data: Original image data
            max_size: Maximum (width, height)
            quality: JPEG quality (1-100)

        Returns:
            Optimized image data
        """
        try:
            with Image.open(io.BytesIO(file_data)) as img:
                # Convert to RGB if necessary (for JPEG)
                if img.mode in ('RGBA', 'LA', 'P'):
                    img = img.convert('RGB')

                # Calculate new dimensions maintaining aspect ratio
                img.thumbnail(max_size, Image.Resampling.LANCZOS)

                # Save to bytes
                output = io.BytesIO()
                img.save(output, format='JPEG', quality=quality, optimize=True)
                return output.getvalue()

        except Exception as e:
            logger.error(f"Image resize error: {e}")
            raise Exception(f"Failed to resize image: {str(e)}")

    def upload_avatar(self, user_id: str, file_data: bytes, filename: str) -> str:
        """
        Upload user avatar to MinIO

        Args:
            user_id: User ID
            file_data: Image file data
            filename: Original filename

        Returns:
            Public URL of uploaded avatar
        """
        try:
            # Validate file
            is_valid, error_msg = self.validate_image_file(file_data, filename)
            if not is_valid:
                raise ValueError(error_msg)

            # Resize image
            resized_data = self.resize_image(file_data, self.MAX_AVATAR_SIZE)

            # Generate unique filename
            file_extension = '.jpg'  # Always save as JPEG after processing
            object_name = f"avatars/{user_id}/{uuid.uuid4()}{file_extension}"

            # Upload to MinIO
            self.client.put_object(
                bucket_name=self.avatars_bucket,
                object_name=object_name,
                data=io.BytesIO(resized_data),
                length=len(resized_data),
                content_type='image/jpeg'
            )

            # Generate public URL through Kong Gateway
            kong_base_url = os.getenv("KONG_GATEWAY_URL", "http://localhost:8000")
            public_url = f"{kong_base_url}/api/storage/{self.avatars_bucket}/{object_name}"

            logger.info(f"Avatar uploaded successfully for user {user_id}: {public_url}")
            return public_url

        except Exception as e:
            logger.error(f"Avatar upload error for user {user_id}: {e}")
            raise Exception(f"Failed to upload avatar: {str(e)}")

    def upload_company_logo(self, tenant_id: str, file_data: bytes, filename: str) -> str:
        """
        Upload company logo to MinIO

        Args:
            tenant_id: Tenant ID
            file_data: Image file data
            filename: Original filename

        Returns:
            Public URL of uploaded logo
        """
        try:
            # Validate file
            is_valid, error_msg = self.validate_image_file(file_data, filename)
            if not is_valid:
                raise ValueError(error_msg)

            # Resize image
            resized_data = self.resize_image(file_data, self.MAX_LOGO_SIZE)

            # Generate unique filename
            file_extension = '.jpg'  # Always save as JPEG after processing
            object_name = f"logos/{tenant_id}/{uuid.uuid4()}{file_extension}"

            # Upload to MinIO
            self.client.put_object(
                bucket_name=self.logos_bucket,
                object_name=object_name,
                data=io.BytesIO(resized_data),
                length=len(resized_data),
                content_type='image/jpeg'
            )

            # Generate public URL through Kong Gateway
            kong_base_url = os.getenv("KONG_GATEWAY_URL", "http://localhost:8000")
            public_url = f"{kong_base_url}/api/storage/{self.logos_bucket}/{object_name}"

            logger.info(f"Logo uploaded successfully for tenant {tenant_id}: {public_url}")
            return public_url

        except Exception as e:
            logger.error(f"Logo upload error for tenant {tenant_id}: {e}")
            raise Exception(f"Failed to upload logo: {str(e)}")

    def delete_file_by_url(self, file_url: str) -> bool:
        """
        Delete file by its public URL

        Args:
            file_url: Public URL of the file

        Returns:
            True if deleted successfully, False otherwise
        """
        try:
            # Parse URL to extract bucket and object name
            # Expected format: http://localhost:9000/bucket-name/object-name
            url_parts = file_url.replace(f"http://{self.endpoint}/", "").split("/", 1)
            if len(url_parts) != 2:
                return False

            bucket_name, object_name = url_parts

            # Delete object
            self.client.remove_object(bucket_name, object_name)
            logger.info(f"File deleted successfully: {file_url}")
            return True

        except Exception as e:
            logger.error(f"File deletion error for URL {file_url}: {e}")
            return False

    def get_presigned_url(self, bucket_name: str, object_name: str, expires: timedelta = timedelta(hours=1)) -> str:
        """
        Generate presigned URL for temporary access

        Args:
            bucket_name: MinIO bucket name
            object_name: Object name in bucket
            expires: URL expiration time

        Returns:
            Presigned URL
        """
        try:
            url = self.client.presigned_get_object(bucket_name, object_name, expires=expires)
            return url
        except Exception as e:
            logger.error(f"Presigned URL generation error: {e}")
            raise Exception(f"Failed to generate presigned URL: {str(e)}")

    def health_check(self) -> dict:
        """
        Check MinIO connection and bucket status

        Returns:
            Health status dictionary
        """
        try:
            # List buckets to test connection
            buckets = list(self.client.list_buckets())

            return {
                "status": "healthy",
                "endpoint": self.endpoint,
                "buckets": [bucket.name for bucket in buckets],
                "timestamp": datetime.utcnow().isoformat()
            }

        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "endpoint": self.endpoint,
                "timestamp": datetime.utcnow().isoformat()
            }

# Global storage service instance
storage_service = StorageService()