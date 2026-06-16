"""
Admin Info routes for platform-wide administration
Provides authentication server information and platform statistics
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from typing import List, Optional
import logging
import os
from datetime import datetime

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))

from shared.database import get_db
from shared.auth import get_current_token_data, TokenData, require_platform_admin_access
from shared.models import AuditLog, Tenant, TenantAppAccess, User, UserStatus, UserTenant
from modules.platform_auth_policy import (
    get_platform_auth_settings,
    serialize_platform_auth_settings,
    update_platform_auth_settings,
)
from modules.keycloak_client import KeycloakClient

router = APIRouter()
logger = logging.getLogger(__name__)


class PlatformAuthSettingsUpdate(BaseModel):
    social_login_enabled: Optional[bool] = None
    tenant_approval_required: Optional[bool] = None
    enabled_social_providers: Optional[List[str]] = Field(default=None)


class TenantApprovalRequest(BaseModel):
    reason: Optional[str] = Field(default=None, max_length=1000)


DEFAULT_TENANT_ADMIN_APP_ROLES = {
    "darkhole": ["admin"],
    "darkfolio": ["admin"],
    "confiploy": ["admin"],
}


def require_platform_admin(token_data: TokenData) -> bool:
    """Check if user has platform admin access"""
    return require_platform_admin_access(token_data)


def _require_platform_admin_or_403(token_data: TokenData) -> None:
    if not require_platform_admin(token_data):
        raise HTTPException(status_code=403, detail="Platform admin access required")


def _admin_identity(token_data: TokenData) -> str:
    return token_data.email or token_data.preferred_username or token_data.sub or "unknown"


def _tenant_admin_summary(db: Session, tenant_id: str) -> dict:
    user_tenant = db.query(UserTenant).filter(UserTenant.tenant_id == tenant_id).order_by(UserTenant.created_at.asc()).first()
    if not user_tenant:
        return {}

    user = db.query(User).filter(User.id == user_tenant.user_id).first()
    if not user:
        return {}

    return {
        "id": user.id,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "status": user.status,
        "is_email_verified": user.is_email_verified,
        "membership_status": user_tenant.status,
        "app_roles": user_tenant.app_roles or {},
    }

@router.get("/admin/auth-server-info")
async def get_auth_server_info(
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db)
):
    """Get authentication server configuration and statistics"""
    try:
        _require_platform_admin_or_403(token_data)

        # Get user statistics
        total_users = db.query(User).count()
        active_users = db.query(User).filter(User.status == UserStatus.ACTIVE).count()
        total_tenants = db.query(Tenant).count()
        active_tenants = db.query(Tenant).filter(Tenant.is_active == True).count()

        # Detect authentication configuration
        keycloak_enabled = bool(os.getenv('KEYCLOAK_SERVER_URL'))
        ldap_enabled = bool(os.getenv('LDAP_SERVER_URL'))

        # Build auth methods array
        auth_methods = []
        primary_auth_method = "internal"

        if keycloak_enabled:
            auth_methods.append({
                "type": "keycloak",
                "config": {
                    "server": os.getenv('KEYCLOAK_SERVER_URL', 'http://localhost:8080'),
                    "realm": os.getenv('KEYCLOAK_REALM', 'suranku-platform'),
                    "client_id": os.getenv('KEYCLOAK_CLIENT_ID', 'suranku-api')
                },
                "status": "active",
                "user_sync": "enabled"
            })
            primary_auth_method = "keycloak"

        if ldap_enabled:
            auth_methods.append({
                "type": "ldap",
                "config": {
                    "server": os.getenv('LDAP_SERVER_URL'),
                    "base_dn": os.getenv('LDAP_BASE_DN'),
                    "bind_dn": os.getenv('LDAP_BIND_DN')
                },
                "status": "active",
                "user_sync": "enabled"
            })
            if primary_auth_method == "internal":
                primary_auth_method = "ldap"

        # Always include internal auth as fallback
        auth_methods.append({
            "type": "internal",
            "config": {
                "password_policy": "standard",
                "session_timeout": "24h"
            },
            "status": "active",
            "user_sync": "local"
        })

        # Build response
        response = {
            "auth_methods": auth_methods,
            "primary_auth_method": primary_auth_method,
            "user_statistics": {
                "total": total_users,
                "active": active_users,
                "keycloak": total_users if keycloak_enabled else 0,  # Simplified for now
                "local": total_users if not keycloak_enabled else 0,
                "tenants": {
                    "total": total_tenants,
                    "active": active_tenants
                }
            },
            "last_sync": datetime.utcnow().isoformat(),
            "server_status": "healthy"
        }

        logger.info(f"Retrieved auth server info for admin user {token_data.sub}")
        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving auth server info: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve authentication server information")


@router.get("/admin/platform-auth-settings")
async def get_admin_platform_auth_settings(
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db),
):
    _require_platform_admin_or_403(token_data)
    return serialize_platform_auth_settings(get_platform_auth_settings(db))


@router.put("/admin/platform-auth-settings")
async def put_admin_platform_auth_settings(
    request: PlatformAuthSettingsUpdate,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db),
):
    _require_platform_admin_or_403(token_data)
    settings = update_platform_auth_settings(
        db,
        social_login_enabled=request.social_login_enabled,
        tenant_approval_required=request.tenant_approval_required,
        enabled_social_providers=request.enabled_social_providers,
        updated_by=_admin_identity(token_data),
    )
    return serialize_platform_auth_settings(settings)


@router.get("/admin/pending-tenants")
async def list_pending_tenants(
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db),
):
    _require_platform_admin_or_403(token_data)
    tenants = db.query(Tenant).filter(
        Tenant.subscription_status.in_(["pending_approval", "rejected"])
    ).order_by(Tenant.created_at.desc()).all()

    return {
        "items": [
            {
                "id": tenant.id,
                "name": tenant.name,
                "domain": tenant.domain,
                "subscription_status": tenant.subscription_status,
                "plan_id": tenant.plan_id,
                "is_active": tenant.is_active,
                "created_at": tenant.created_at.isoformat() if tenant.created_at else None,
                "trial_expires_at": tenant.trial_expires_at.isoformat() if tenant.trial_expires_at else None,
                "admin_user": _tenant_admin_summary(db, tenant.id),
                "settings": tenant.settings or {},
            }
            for tenant in tenants
        ]
    }


@router.post("/admin/pending-tenants/{tenant_id}/approve")
async def approve_pending_tenant(
    tenant_id: str,
    request: TenantApprovalRequest | None = None,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db),
):
    _require_platform_admin_or_403(token_data)
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    tenant.is_active = True
    tenant.subscription_status = "trial"
    settings = dict(tenant.settings or {})
    settings.update({
        "platform_approval_status": "approved",
        "platform_approved_by": _admin_identity(token_data),
        "platform_approved_at": datetime.utcnow().isoformat(),
        "platform_approval_reason": request.reason if request else None,
    })
    tenant.settings = settings

    user_tenants = db.query(UserTenant).filter(UserTenant.tenant_id == tenant.id).all()
    keycloak_client = KeycloakClient()
    for user_tenant in user_tenants:
        user = db.query(User).filter(User.id == user_tenant.user_id).first()
        if user and user.is_email_verified:
            app_roles = user_tenant.app_roles or DEFAULT_TENANT_ADMIN_APP_ROLES
            try:
                keycloak_user_id = await keycloak_client.add_existing_user_to_tenant(
                    user_email=user.email,
                    tenant_id=tenant.id,
                    app_roles=app_roles,
                )
                if not user.keycloak_id:
                    user.keycloak_id = keycloak_user_id
            except Exception as exc:
                db.rollback()
                logger.error("Failed to provision approved tenant %s in Keycloak: %s", tenant.id, exc)
                raise HTTPException(status_code=502, detail="Tenant approval failed while provisioning auth access")

            user_tenant.status = UserStatus.ACTIVE
            user_tenant.joined_at = user_tenant.joined_at or datetime.utcnow()

    db.add(AuditLog(
        tenant_id=tenant.id,
        action="tenant_platform_approved",
        resource_type="tenant",
        resource_id=tenant.id,
        details={"approved_by": _admin_identity(token_data), "reason": request.reason if request else None},
    ))
    db.commit()
    return {"status": "approved", "tenant_id": tenant.id}


@router.post("/admin/pending-tenants/{tenant_id}/reject")
async def reject_pending_tenant(
    tenant_id: str,
    request: TenantApprovalRequest | None = None,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db),
):
    _require_platform_admin_or_403(token_data)
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    tenant.is_active = False
    tenant.subscription_status = "rejected"
    settings = dict(tenant.settings or {})
    settings.update({
        "platform_approval_status": "rejected",
        "platform_rejected_by": _admin_identity(token_data),
        "platform_rejected_at": datetime.utcnow().isoformat(),
        "platform_rejection_reason": request.reason if request else None,
    })
    tenant.settings = settings

    db.query(UserTenant).filter(UserTenant.tenant_id == tenant.id).update({"status": UserStatus.SUSPENDED})
    db.query(TenantAppAccess).filter(TenantAppAccess.tenant_id == tenant.id).update({"is_enabled": False})
    db.add(AuditLog(
        tenant_id=tenant.id,
        action="tenant_platform_rejected",
        resource_type="tenant",
        resource_id=tenant.id,
        details={"rejected_by": _admin_identity(token_data), "reason": request.reason if request else None},
    ))
    db.commit()
    return {"status": "rejected", "tenant_id": tenant.id}
