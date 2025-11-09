"""
File Upload Module
Handles avatar and logo uploads with MinIO storage
"""

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
import logging
from datetime import datetime

from services.shared.database import get_db
from services.shared.auth import TokenData, get_current_token_data
from services.shared.models import User, Tenant, UserTenant, AuditLog

logger = logging.getLogger(__name__)

# Create router for file upload endpoints
router = APIRouter(tags=["file-upload"])

@router.post("/users/{user_id}/avatar")
async def upload_user_avatar(
    user_id: str,
    file: UploadFile = File(...),
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db)
):
    """Upload user avatar image"""
    try:
        # Verify user has permission to upload avatar (either own avatar or admin)
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Check if user is uploading their own avatar or is an admin
        current_user = db.query(User).filter(User.keycloak_id == token_data.sub).first()
        if not current_user:
            raise HTTPException(status_code=404, detail="Current user not found")

        if str(current_user.id) != user_id:
            # Check if user is admin in any tenant they share
            shared_tenants = db.query(UserTenant).filter(
                UserTenant.user_id == current_user.id,
                UserTenant.tenant_id.in_(
                    db.query(UserTenant.tenant_id).filter(UserTenant.user_id == user_id)
                )
            ).all()

            is_admin = any(
                "admin" in ut.app_roles.get("darkhole", []) or
                "admin" in ut.app_roles.get("darkfolio", []) or
                "admin" in ut.app_roles.get("confiploy", [])
                for ut in shared_tenants
            )

            if not is_admin:
                raise HTTPException(status_code=403, detail="Permission denied")

        # Validate file
        if not file.content_type or not file.content_type.startswith('image/'):
            raise HTTPException(status_code=400, detail="File must be an image")

        # Read file data
        file_data = await file.read()

        # Upload to MinIO using storage service
        from services.shared.storage_service import storage_service

        try:
            avatar_url = storage_service.upload_avatar(user_id, file_data, file.filename)

            # Delete old avatar if exists
            if user.avatar_url:
                storage_service.delete_file_by_url(user.avatar_url)

            # Update user avatar URL in database
            user.avatar_url = avatar_url
            db.commit()

            # Get current user's tenant for audit log
            current_user_tenant = db.query(UserTenant).filter(
                UserTenant.user_id == current_user.id,
                UserTenant.status == "active"
            ).first()

            if current_user_tenant:
                # Create audit log
                audit_log = AuditLog(
                    tenant_id=current_user_tenant.tenant_id,
                    action="avatar_uploaded",
                    resource_type="user",
                    resource_id=user_id,
                    user_id=current_user.id,
                    details={"avatar_url": avatar_url, "filename": file.filename}
                )
                db.add(audit_log)
                db.commit()

            return {
                "success": True,
                "message": "Avatar uploaded successfully",
                "avatar_url": avatar_url
            }

        except Exception as storage_error:
            raise HTTPException(status_code=500, detail=f"Upload failed: {str(storage_error)}")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Avatar upload error: {e}")
        raise HTTPException(status_code=500, detail="Avatar upload failed")

@router.post("/tenants/{tenant_id}/logo")
async def upload_tenant_logo(
    tenant_id: str,
    file: UploadFile = File(...),
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db)
):
    """Upload tenant/company logo"""
    try:
        # Temporary: Allow all authenticated users for logo upload
        # TODO: Restore proper tenant access check after debugging database issues
        logger.info(f"Logo upload for tenant {tenant_id} by user {token_data.sub}")

        # Verify user exists (still needed for audit log)
        current_user = db.query(User).filter(User.keycloak_id == token_data.sub).first()
        if not current_user:
            raise HTTPException(status_code=404, detail="Current user not found")

        # Get tenant
        tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant not found")

        # Validate file
        if not file.content_type or not file.content_type.startswith('image/'):
            raise HTTPException(status_code=400, detail="File must be an image")

        # Read file data
        file_data = await file.read()

        # Upload to MinIO using storage service
        from services.shared.storage_service import storage_service

        try:
            logo_url = storage_service.upload_company_logo(tenant_id, file_data, file.filename)

            # Delete old logo if exists
            if tenant.logo_url:
                storage_service.delete_file_by_url(tenant.logo_url)

            # Update tenant logo URL in database
            tenant.logo_url = logo_url
            db.commit()

            # Create audit log
            audit_log = AuditLog(
                action="logo_uploaded",
                resource_type="tenant",
                resource_id=tenant_id,
                user_id=current_user.id,
                tenant_id=tenant_id,
                details={"logo_url": logo_url, "filename": file.filename}
            )
            db.add(audit_log)
            db.commit()

            return {
                "success": True,
                "message": "Logo uploaded successfully",
                "logo_url": logo_url
            }

        except Exception as storage_error:
            raise HTTPException(status_code=500, detail=f"Upload failed: {str(storage_error)}")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Logo upload error: {e}")
        raise HTTPException(status_code=500, detail="Logo upload failed")

@router.get("/storage/health")
async def storage_health_check():
    """Check MinIO storage health"""
    try:
        from services.shared.storage_service import storage_service
        health_status = storage_service.health_check()
        return health_status
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }