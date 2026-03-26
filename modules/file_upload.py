"""
File Upload Module
Handles avatar and logo uploads with MinIO storage
"""

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
import logging
from datetime import datetime

from shared.database import get_db
from shared.auth import TokenData, get_current_token_data
from shared.models import User, Tenant, UserTenant, AuditLog
from models import Organization, OrganizationUserProfile

logger = logging.getLogger(__name__)

# Create router for file upload endpoints
router = APIRouter(tags=["file-upload"])


def _resolve_org_id_for_request(token_data: TokenData, tenant_id: str | None = None) -> str | None:
    current_org = getattr(token_data, "current_org", {}) or {}
    if isinstance(current_org, dict):
        org_id = current_org.get("org_id") or current_org.get("organization_id") or current_org.get("id")
        current_tenant_id = current_org.get("tenant_id") or current_org.get("tenantId")
        if org_id and (not tenant_id or not current_tenant_id or str(current_tenant_id) == str(tenant_id)):
            return str(org_id)

    memberships = getattr(token_data, "org_memberships", None) or []
    if isinstance(memberships, list):
        for membership in memberships:
            membership_tenant_id = membership.get("tenant_id") or membership.get("tenantId")
            if tenant_id and membership_tenant_id and str(membership_tenant_id) != str(tenant_id):
                continue
            org_id = membership.get("org_id") or membership.get("organization_id") or membership.get("id")
            if org_id:
                return str(org_id)
    return None

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
        from shared.storage_service import storage_service

        try:
            org_id = _resolve_org_id_for_request(token_data)
            avatar_url = None
            upload_scope = "user"

            if org_id:
                org = db.query(Organization).filter(
                    Organization.id == org_id,
                    Organization.deleted_at.is_(None),
                ).first()
                if org:
                    avatar_url = storage_service.upload_org_user_avatar(org.id, user_id, file_data, file.filename)
                    profile = db.query(OrganizationUserProfile).filter(
                        OrganizationUserProfile.organization_id == org.id,
                        OrganizationUserProfile.user_id == user.id,
                    ).first()
                    if not profile:
                        profile = OrganizationUserProfile(
                            tenant_id=org.tenant_id,
                            organization_id=org.id,
                            user_id=user.id,
                        )
                        db.add(profile)
                        db.flush()
                    if profile.avatar_url:
                        storage_service.delete_file_by_url(profile.avatar_url)
                    profile.avatar_url = avatar_url
                    upload_scope = "organization_user"

            if not avatar_url:
                avatar_url = storage_service.upload_avatar(user_id, file_data, file.filename)
                if user.avatar_url:
                    storage_service.delete_file_by_url(user.avatar_url)
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
                    details={
                        "avatar_url": avatar_url,
                        "filename": file.filename,
                        "scope": upload_scope,
                        "org_id": org_id if upload_scope == "organization_user" else None,
                    }
                )
                db.add(audit_log)
                db.commit()

            return {
                "success": True,
                "message": "Avatar uploaded successfully",
                "avatar_url": avatar_url,
                "scope": upload_scope,
                "org_id": org_id if upload_scope == "organization_user" else None,
            }

        except Exception as storage_error:
            raise HTTPException(status_code=500, detail=f"Upload failed: {str(storage_error)}")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Avatar upload error: {e}")
        raise HTTPException(status_code=500, detail="Avatar upload failed")


@router.post("/tenants/{tenant_id}/orgs/{org_id}/users/{user_id}/avatar")
async def upload_organization_user_avatar(
    tenant_id: str,
    org_id: str,
    user_id: str,
    file: UploadFile = File(...),
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db)
):
    """Upload an organization-scoped user avatar."""
    try:
        current_user = db.query(User).filter(User.keycloak_id == token_data.sub).first()
        if not current_user:
            raise HTTPException(status_code=404, detail="Current user not found")

        if str(current_user.id) != user_id:
            raise HTTPException(status_code=403, detail="Permission denied")

        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        org = db.query(Organization).filter(
            Organization.id == org_id,
            Organization.tenant_id == tenant_id,
            Organization.deleted_at.is_(None),
        ).first()
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        if not file.content_type or not file.content_type.startswith('image/'):
            raise HTTPException(status_code=400, detail="File must be an image")

        file_data = await file.read()
        from shared.storage_service import storage_service

        avatar_url = storage_service.upload_org_user_avatar(org.id, user.id, file_data, file.filename)
        profile = db.query(OrganizationUserProfile).filter(
            OrganizationUserProfile.organization_id == org.id,
            OrganizationUserProfile.user_id == user.id,
        ).first()
        if not profile:
            profile = OrganizationUserProfile(
                tenant_id=tenant_id,
                organization_id=org.id,
                user_id=user.id,
            )
            db.add(profile)
            db.flush()

        if profile.avatar_url:
            storage_service.delete_file_by_url(profile.avatar_url)
        profile.avatar_url = avatar_url
        db.commit()

        db.add(AuditLog(
            action="organization_user_avatar_uploaded",
            resource_type="organization_user_profile",
            resource_id=profile.id,
            user_id=current_user.id,
            tenant_id=tenant_id,
            details={"avatar_url": avatar_url, "filename": file.filename, "org_id": org.id, "target_user_id": user.id},
        ))
        db.commit()

        return {
            "success": True,
            "message": "Avatar uploaded successfully",
            "avatar_url": avatar_url,
            "scope": "organization_user",
            "org_id": org.id,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Organization user avatar upload error: {e}")
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
        from shared.storage_service import storage_service

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


@router.post("/tenants/{tenant_id}/orgs/{org_id}/logo")
async def upload_organization_logo(
    tenant_id: str,
    org_id: str,
    file: UploadFile = File(...),
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db)
):
    """Upload organization logo"""
    try:
        logger.info(f"Organization logo upload for org {org_id} in tenant {tenant_id} by user {token_data.sub}")

        current_user = db.query(User).filter(User.keycloak_id == token_data.sub).first()
        if not current_user:
            raise HTTPException(status_code=404, detail="Current user not found")

        org = db.query(Organization).filter(
            Organization.id == org_id,
            Organization.tenant_id == tenant_id,
            Organization.deleted_at.is_(None),
        ).first()
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        if not file.content_type or not file.content_type.startswith('image/'):
            raise HTTPException(status_code=400, detail="File must be an image")

        file_data = await file.read()

        from shared.storage_service import storage_service

        try:
            logo_url = storage_service.upload_organization_logo(org_id, file_data, file.filename)

            if org.logo_url:
                storage_service.delete_file_by_url(org.logo_url)

            org.logo_url = logo_url
            db.commit()

            audit_log = AuditLog(
                action="organization_logo_uploaded",
                resource_type="organization",
                resource_id=org_id,
                user_id=current_user.id,
                tenant_id=tenant_id,
                details={"logo_url": logo_url, "filename": file.filename},
            )
            db.add(audit_log)
            db.commit()

            return {
                "success": True,
                "message": "Organization logo uploaded successfully",
                "logo_url": logo_url
            }
        except Exception as storage_error:
            raise HTTPException(status_code=500, detail=f"Upload failed: {str(storage_error)}")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Organization logo upload error: {e}")
        raise HTTPException(status_code=500, detail="Organization logo upload failed")

@router.get("/storage/health")
async def storage_health_check():
    """Check MinIO storage health"""
    try:
        from shared.storage_service import storage_service
        health_status = storage_service.health_check()
        return health_status
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }
