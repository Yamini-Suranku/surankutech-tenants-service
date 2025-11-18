"""
Organization Management Module
Handles organization-level operations within the tenant -> organization -> apps hierarchy
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Dict, Any
import logging
from datetime import datetime

from shared.database import get_db
from shared.auth import TokenData, get_current_token_data, require_platform_admin_access
from shared.models import Tenant, User, UserTenant, TenantAppAccess, AuditLog
from modules.tenant_management import (
    get_or_create_user_from_token,
    get_app_user_limit,
    get_trial_features,
    seed_app_access_metadata,
    mark_app_for_enable,
    mark_app_for_disable,
    ensure_user_has_app_admin,
    notify_app_enabled,
    notify_app_disabled,
)

logger = logging.getLogger(__name__)

# Create router for organization management endpoints
router = APIRouter(tags=["organization-management"])

# App catalog - centralized definition
APP_CATALOG = {
    "darkhole": {
        "name": "DarkHole",
        "description": "AI governance & guard rails",
        "version": "v2.1.3",
        "category": "AI Safety",
        "icon": "🔮"
    },
    "darkfolio": {
        "name": "DarkFolio",
        "description": "Model cost visibility & analytics",
        "version": "v1.8.2",
        "category": "Analytics",
        "icon": "📊"
    },
    "confiploy": {
        "name": "ConfiPloy",
        "description": "Configuration & rollout management",
        "version": "v1.5.1",
        "category": "DevOps",
        "icon": "⚙️"
    }
}

@router.get("/tenants/{tenant_id}/orgs")
async def list_organizations(
    tenant_id: str,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db)
):
    """List all organizations within a tenant"""
    # Verify user access to tenant
    user = get_or_create_user_from_token(db, token_data)
    user_tenant = db.query(UserTenant).filter(
        UserTenant.user_id == user.id,
        UserTenant.tenant_id == tenant_id
    ).first()

    if not user_tenant:
        raise HTTPException(status_code=403, detail="Access denied to tenant")

    # For now, return the tenant as the default organization
    # In the future, this will return multiple organizations
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    return {
        "organizations": [
            {
                "id": "default",
                "name": tenant.name,
                "domain": tenant.domain,
                "tenant_id": tenant_id,
                "is_default": True,
                "created_at": tenant.created_at.isoformat(),
                "member_count": 1  # Simplified for now
            }
        ]
    }

@router.get("/tenants/{tenant_id}/orgs/{org_id}/apps")
async def get_organization_apps(
    tenant_id: str,
    org_id: str,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db)
):
    """Get available and enabled apps for an organization"""
    # Verify user access to tenant
    user = get_or_create_user_from_token(db, token_data)
    user_tenant = db.query(UserTenant).filter(
        UserTenant.user_id == user.id,
        UserTenant.tenant_id == tenant_id
    ).first()

    if not user_tenant:
        raise HTTPException(status_code=403, detail="Access denied to tenant")

    # Get app access metadata for this tenant
    app_access_records = db.query(TenantAppAccess).filter(
        TenantAppAccess.tenant_id == tenant_id
    ).all()
    enabled_app_ids = {app.app_name for app in app_access_records if app.is_enabled}
    app_access_map = {access.app_name: access for access in app_access_records}

    # Build available apps list with enabled status
    available_apps = []
    enabled_apps_list = []

    for app_id, app_info in APP_CATALOG.items():
        app_data = {
            "id": app_id,
            "name": app_info["name"],
            "description": app_info["description"],
            "version": app_info["version"],
            "category": app_info["category"],
            "icon": app_info["icon"],
            "enabled": app_id in enabled_app_ids
        }

        access_record = app_access_map.get(app_id)
        if access_record:
            app_data.update({
                "ingress_hostname": access_record.ingress_hostname,
                "network_tier": access_record.network_tier,
                "provisioning_state": access_record.provisioning_state,
                "dns_status": access_record.dns_status,
                "provisioning_error": access_record.provisioning_error,
                "last_synced_at": access_record.last_synced_at.isoformat() if access_record.last_synced_at else None,
                "enabled_features": access_record.enabled_features or [],
                "user_limit": access_record.user_limit,
                "current_users": access_record.current_users
            })

        available_apps.append(app_data)

        if app_id in enabled_app_ids:
            enabled_apps_list.append(app_data)

    return {
        "tenant_id": tenant_id,
        "org_id": org_id,
        "available_apps": available_apps,
        "enabled_apps": enabled_apps_list
    }

@router.post("/tenants/{tenant_id}/orgs/{org_id}/apps/{app_id}/enable")
async def enable_organization_app(
    tenant_id: str,
    org_id: str,
    app_id: str,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db)
):
    """Enable an app for an organization"""
    # Verify user access and app exists
    if app_id not in APP_CATALOG:
        raise HTTPException(status_code=404, detail=f"App {app_id} not found in catalog")

    user = get_or_create_user_from_token(db, token_data)
    user_tenant = db.query(UserTenant).filter(
        UserTenant.user_id == user.id,
        UserTenant.tenant_id == tenant_id
    ).first()

    if not user_tenant:
        raise HTTPException(status_code=403, detail="Access denied to tenant")

    # Check if user has admin role in any app within this tenant
    has_admin_role = False
    for app in ["darkhole", "darkfolio", "confiploy"]:
        app_roles = user_tenant.app_roles.get(app, [])
        if any(role in ["admin", "administrator"] for role in app_roles):
            has_admin_role = True
            break

    if not has_admin_role:
        raise HTTPException(status_code=403, detail="Admin or administrator role required to manage apps")

    # Check for existing app access record
    app_access = db.query(TenantAppAccess).filter(
        TenantAppAccess.tenant_id == tenant_id,
        TenantAppAccess.app_name == app_id
    ).first()

    if not app_access:
        # Create new app access record
        app_access = TenantAppAccess(
            tenant_id=tenant_id,
            app_name=app_id,
            is_enabled=True,
            user_limit=get_app_user_limit(app_id, "trial"),
            current_users=1,
            enabled_features=get_trial_features(app_id)
        )
        seed_app_access_metadata(app_access, user_tenant.tenant, app_id)
        db.add(app_access)
    else:
        # Enable existing app
        app_access.is_enabled = True
        mark_app_for_enable(app_access, user_tenant.tenant, app_id)

    ensure_user_has_app_admin(user_tenant, app_id)

    # Create audit log
    audit_log = AuditLog(
        tenant_id=tenant_id,
        user_id=user.id,
        action="app_enabled",
        resource_type="app",
        resource_id=app_id,
        details={
            "app_name": APP_CATALOG[app_id]["name"],
            "org_id": org_id,
            "enabled_by": user.email
        }
    )
    db.add(audit_log)

    db.commit()

    await notify_app_enabled(user_tenant.tenant, app_access, user.email, org_id)

    return {
        "status": "enabled",
        "message": f"App {APP_CATALOG[app_id]['name']} enabled for organization",
        "tenant_id": tenant_id,
        "org_id": org_id,
        "app_id": app_id,
        "app_name": APP_CATALOG[app_id]["name"]
    }

@router.post("/tenants/{tenant_id}/orgs/{org_id}/apps/{app_id}/disable")
async def disable_organization_app(
    tenant_id: str,
    org_id: str,
    app_id: str,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db)
):
    """Disable an app for an organization"""
    # Verify user access
    user = get_or_create_user_from_token(db, token_data)
    user_tenant = db.query(UserTenant).filter(
        UserTenant.user_id == user.id,
        UserTenant.tenant_id == tenant_id
    ).first()

    if not user_tenant:
        raise HTTPException(status_code=403, detail="Access denied to tenant")

    # Check if user has admin role in any app within this tenant
    has_admin_role = False
    for app in ["darkhole", "darkfolio", "confiploy"]:
        app_roles = user_tenant.app_roles.get(app, [])
        if any(role in ["admin", "administrator"] for role in app_roles):
            has_admin_role = True
            break

    if not has_admin_role:
        raise HTTPException(status_code=403, detail="Admin or administrator role required to manage apps")

    # Find and disable the app
    app_access = db.query(TenantAppAccess).filter(
        TenantAppAccess.tenant_id == tenant_id,
        TenantAppAccess.app_name == app_id
    ).first()

    if app_access:
        app_access.is_enabled = False
        app_access.current_users = 0
        mark_app_for_disable(app_access)

        # Create audit log
        audit_log = AuditLog(
            tenant_id=tenant_id,
            user_id=user.id,
            action="app_disabled",
            resource_type="app",
            resource_id=app_id,
            details={
                "app_name": APP_CATALOG.get(app_id, {}).get("name", app_id),
                "org_id": org_id,
                "disabled_by": user.email
            }
        )
        db.add(audit_log)

        db.commit()

        await notify_app_disabled(user_tenant.tenant, app_id, user.email, org_id)

    return {
        "status": "disabled",
        "message": f"App {APP_CATALOG.get(app_id, {}).get('name', app_id)} disabled for organization",
        "tenant_id": tenant_id,
        "org_id": org_id,
        "app_id": app_id
    }

@router.delete("/tenants/{tenant_id}/orgs/{org_id}")
async def delete_organization(
    tenant_id: str,
    org_id: str,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db)
):
    """Delete an organization (currently deletes the entire tenant since we have flat structure)"""
    # Verify user access to tenant
    user = get_or_create_user_from_token(db, token_data)
    user_tenant = db.query(UserTenant).filter(
        UserTenant.user_id == user.id,
        UserTenant.tenant_id == tenant_id
    ).first()

    if not user_tenant:
        raise HTTPException(status_code=403, detail="Access denied to tenant")

    # Check if user has admin role for this tenant
    has_admin_role = False
    for app in ["darkhole", "darkfolio", "confiploy"]:
        app_roles = user_tenant.app_roles.get(app, [])
        if any(role in ["admin", "administrator"] for role in app_roles):
            has_admin_role = True
            break

    if not has_admin_role:
        raise HTTPException(status_code=403, detail="Admin or administrator role required to delete organization")

    # Find the tenant creator/owner - the first user who joined with admin roles
    tenant_creator = db.query(UserTenant).filter(
        UserTenant.tenant_id == tenant_id,
        UserTenant.status == "active"
    ).order_by(UserTenant.created_at.asc()).first()

    # Only allow the original creator to delete the organization
    if not tenant_creator or tenant_creator.user_id != user.id:
        raise HTTPException(
            status_code=403,
            detail="Only the organization creator/owner can delete this organization"
        )

    # Get the tenant
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Check if there are other active users in this tenant
    other_users_count = db.query(UserTenant).filter(
        UserTenant.tenant_id == tenant_id,
        UserTenant.user_id != user.id,
        UserTenant.status == "active"
    ).count()

    if other_users_count > 0:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot delete organization with {other_users_count} other active members. Remove all other members first."
        )

    # Soft delete - mark as inactive instead of hard delete to preserve audit trail
    tenant.is_active = False

    # Also deactivate all user-tenant relationships
    db.query(UserTenant).filter(UserTenant.tenant_id == tenant_id).update({
        "status": "deleted"
    })

    # Disable all app access for this tenant
    db.query(TenantAppAccess).filter(TenantAppAccess.tenant_id == tenant_id).update({
        "is_enabled": False,
        "current_users": 0
    })

    # Create audit log
    audit_log = AuditLog(
        tenant_id=tenant_id,
        user_id=user.id,
        action="organization_deleted",
        resource_type="organization",
        resource_id=org_id,
        details={
            "organization_name": tenant.name,
            "domain": tenant.domain,
            "deleted_by": user.email,
            "other_users_count": other_users_count
        }
    )
    db.add(audit_log)

    db.commit()

    return {
        "status": "deleted",
        "message": f"Organization '{tenant.name}' has been deleted successfully",
        "tenant_id": tenant_id,
        "org_id": org_id
    }

# Cross-tenant organization access routes
@router.get("/orgs/{org_id}")
async def get_organization_details(
    org_id: str,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db)
):
    """Get organization details by org_id (cross-tenant access - PLATFORM ADMIN ONLY)"""
    # SECURITY CHECK: Only platform administrators can access cross-tenant organization data
    if not require_platform_admin_access(token_data):
        raise HTTPException(
            status_code=403,
            detail="Platform administrator access required for cross-tenant operations"
        )

    # For now, org_id is "default" for all tenants
    # In future, we'll have proper org management
    if org_id != "default":
        raise HTTPException(status_code=404, detail="Organization not found")

    # Platform admins can see all tenants, not just user-accessible ones
    all_tenants = db.query(Tenant).filter(
        Tenant.is_active == True
    ).all()

    organizations = []
    for tenant in all_tenants:
        # Get member count for this tenant
        member_count = db.query(UserTenant).filter(
            UserTenant.tenant_id == tenant.id,
            UserTenant.status == "active"
        ).count()

        organizations.append({
            "id": "default",
            "name": tenant.name,
            "domain": tenant.domain,
            "tenant_id": tenant.id,
            "is_default": True,
            "created_at": tenant.created_at.isoformat(),
            "member_count": member_count
        })

    return {
        "organizations": organizations
    }