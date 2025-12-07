"""
Organization Management Module
Handles organization-level operations within the tenant -> organization -> apps hierarchy
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import or_
from sqlalchemy.orm import Session
from typing import List, Dict, Any, Optional
import logging
from datetime import datetime

from shared.database import get_db
from shared.auth import (
    TokenData,
    get_current_token_data,
    require_platform_admin_access,
)
from shared.models import Tenant, UserTenant, TenantAppAccess, AuditLog
from models import Organization, OrganizationAppAccess, OrganizationUserRole
from schemas import (
    OrganizationCreateRequest,
    OrganizationDNSRequest,
    OrganizationListResponse,
    OrganizationResponse,
    TenantDomainCheckRequest,
    TenantDomainCheckResponse,
)
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
    validate_subdomain_candidate,
    slugify,
    generate_domain_suggestions,
    user_has_tenant_admin,
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

DEFAULT_DNS_ZONE = "local.suranku"
APP_DEFAULT_PATHS = {
    "darkhole": "/darkhole/login.html",
    "darkfolio": "/darkfolio/",
    "confiploy": "/confiploy/",
}

def _user_has_tenant_admin_access(user_tenant: Optional[UserTenant]) -> bool:
    return user_has_tenant_admin(user_tenant)

def _serialize_org(org: Organization, tenant: Optional[Tenant] = None) -> Dict[str, Any]:
    return {
        "id": org.id,
        "tenant_id": org.tenant_id,
        "name": org.name,
        "slug": org.slug,
        "description": org.description,
        "dns_subdomain": org.dns_subdomain,
        "dns_zone": org.dns_zone,
        "dns_hostname": org.dns_hostname,
        "dns_status": org.dns_status,
        "status": org.status,
        "is_default": org.is_default,
        "created_at": org.created_at,
        "updated_at": org.updated_at,
    }

def _build_org_hostname(org: Organization) -> str:
    if org.dns_hostname:
        return org.dns_hostname
    zone = org.dns_zone or DEFAULT_DNS_ZONE
    return f"{org.dns_subdomain}.{zone}"

def _grant_org_roles(
    db: Session,
    tenant_id: str,
    org_id: str,
    user_id: str,
    app_roles: Dict[str, List[str]],
    granted_by: Optional[str],
    granted_via: str,
):
    for app_name, roles in app_roles.items():
        normalized = sorted(set(roles))
        entry = db.query(OrganizationUserRole).filter(
            OrganizationUserRole.organization_id == org_id,
            OrganizationUserRole.user_id == user_id,
            OrganizationUserRole.app_name == app_name,
        ).first()
        if normalized:
            if entry:
                entry.roles = normalized
                entry.granted_by = granted_by
                entry.granted_via = granted_via
            else:
                db.add(OrganizationUserRole(
                    tenant_id=tenant_id,
                    organization_id=org_id,
                    user_id=user_id,
                    app_name=app_name,
                    roles=normalized,
                    granted_by=granted_by,
                    granted_via=granted_via,
                ))
        elif entry:
            db.delete(entry)

def _seed_org_birthright_roles(
    db: Session,
    tenant_id: str,
    org_id: str,
    granted_by: Optional[str] = None,
    seed_memberships: Optional[List[UserTenant]] = None,
) -> None:
    if not seed_memberships:
        return

    birthright_apps = {app: ["admin"] for app in APP_CATALOG.keys()}
    for membership in seed_memberships:
        if _user_has_tenant_admin_access(membership):
            _grant_org_roles(
                db,
                tenant_id=tenant_id,
                org_id=org_id,
                user_id=membership.user_id,
                app_roles=birthright_apps,
                granted_by=granted_by,
                granted_via="birthright",
            )

@router.get("/tenants/{tenant_id}/orgs", response_model=OrganizationListResponse)
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

    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    orgs_query = db.query(Organization).filter(
        Organization.tenant_id == tenant_id,
        Organization.deleted_at.is_(None)
    ).order_by(Organization.created_at.asc())

    orgs = orgs_query.all()

    if not require_platform_admin_access(token_data):
        allowed_ids = _user_membership_org_ids(db, user.id)
        orgs = [
            org for org in orgs
            if org.id in allowed_ids or (org.created_by == user.id)
        ]

    payloads = [OrganizationResponse(**_serialize_org(org, tenant)) for org in orgs]
    return OrganizationListResponse(organizations=payloads)

@router.post("/tenants/{tenant_id}/orgs/check-domain", response_model=TenantDomainCheckResponse)
async def check_org_domain(
    tenant_id: str,
    request: TenantDomainCheckRequest,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db)
):
    """Validate whether an organization subdomain is available."""
    user = get_or_create_user_from_token(db, token_data)
    user_tenant = db.query(UserTenant).filter(
        UserTenant.user_id == user.id,
        UserTenant.tenant_id == tenant_id
    ).first()

    if not user_tenant:
        raise HTTPException(status_code=403, detail="Access denied to tenant")

    if not _user_has_tenant_admin_access(user_tenant):
        raise HTTPException(status_code=403, detail="Admin access required to manage organizations")

    sanitized, validation_errors = validate_subdomain_candidate(request.desired_subdomain)
    if validation_errors:
        return TenantDomainCheckResponse(
            available=False,
            sanitized=sanitized or slugify(request.desired_subdomain),
            suggestions=[],
            errors=validation_errors
        )

    tenant_conflict = db.query(Tenant).filter(Tenant.domain == sanitized).first()
    org_conflict = db.query(Organization).filter(Organization.dns_subdomain == sanitized).first()
    available = tenant_conflict is None and org_conflict is None

    suggestions = [] if available else generate_domain_suggestions(db, sanitized)
    errors = [] if available else ["This organization name is already taken"]

    return TenantDomainCheckResponse(
        available=available,
        sanitized=sanitized,
        suggestions=suggestions,
        errors=errors
    )

@router.post("/tenants/{tenant_id}/orgs", response_model=OrganizationResponse)
async def create_organization(
    tenant_id: str,
    request: OrganizationCreateRequest,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db)
):
    """Create a new organization within a tenant."""
    user = get_or_create_user_from_token(db, token_data)
    user_tenant = db.query(UserTenant).filter(
        UserTenant.user_id == user.id,
        UserTenant.tenant_id == tenant_id
    ).first()

    if not user_tenant:
        raise HTTPException(status_code=403, detail="Access denied to tenant")

    if not _user_has_tenant_admin_access(user_tenant):
        raise HTTPException(
            status_code=403,
            detail="Admin access is required to create organizations"
        )

    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    slug_candidate, validation_errors = validate_subdomain_candidate(
        request.desired_subdomain or request.name
    )
    if validation_errors:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=validation_errors)

    # Ensure slug is unique across tenants and organizations
    duplicate_tenant = db.query(Tenant).filter(Tenant.domain == slug_candidate).first()
    duplicate_org = db.query(Organization).filter(
        or_(
            Organization.slug == slug_candidate,
            Organization.dns_subdomain == slug_candidate
        )
    ).first()

    if duplicate_tenant or duplicate_org:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Organization domain is already reserved"
        )

    dns_zone = request.dns_zone or DEFAULT_DNS_ZONE
    organization = Organization(
        tenant_id=tenant_id,
        name=request.name,
        slug=slug_candidate,
        description=request.description,
        dns_subdomain=slug_candidate,
        dns_zone=dns_zone,
        dns_hostname=f"{slug_candidate}.{dns_zone}" if dns_zone else slug_candidate,
        dns_status="reserved",
        created_by=user.id
    )
    db.add(organization)

    audit_log = AuditLog(
        tenant_id=tenant_id,
        user_id=user.id,
        action="organization_created",
        resource_type="organization",
        resource_id=organization.id,
        details={
            "organization_name": organization.name,
            "dns_hostname": organization.dns_hostname,
            "created_by": user.email
        }
    )
    db.add(audit_log)

    # Ensure tenant admins receive birthright org roles
    db.flush()
    _seed_org_birthright_roles(
        db=db,
        tenant_id=tenant_id,
        org_id=organization.id,
        granted_by=user.id,
        seed_memberships=[user_tenant],
    )

    # Initialize Vault directory structure for the organization
    try:
        from shared.credential_manager import initialize_organization_vault_directories
        vault_initialized = await initialize_organization_vault_directories(
            tenant_id, organization.id, organization.name
        )
        if vault_initialized:
            logger.info(f"Vault directories initialized for organization {organization.id}")
        else:
            logger.warning(f"Failed to initialize Vault directories for organization {organization.id}")
    except Exception as e:
        logger.error(f"Error initializing Vault directories for organization {organization.id}: {e}")
        # Don't fail organization creation if Vault initialization fails

    db.commit()
    db.refresh(organization)

    return OrganizationResponse(**_serialize_org(organization, tenant))

@router.post("/tenants/{tenant_id}/orgs/{org_id}/dns/reserve", response_model=OrganizationResponse)
async def reserve_org_dns(
    tenant_id: str,
    org_id: str,
    request: OrganizationDNSRequest,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db)
):
    """Reserve or update the DNS assignment for an organization."""
    user = get_or_create_user_from_token(db, token_data)
    user_tenant = db.query(UserTenant).filter(
        UserTenant.user_id == user.id,
        UserTenant.tenant_id == tenant_id
    ).first()

    if not user_tenant:
        raise HTTPException(status_code=403, detail="Access denied to tenant")

    if not _user_has_tenant_admin_access(user_tenant):
        raise HTTPException(status_code=403, detail="Admin access required to manage DNS")

    organization = db.query(Organization).filter(
        Organization.id == org_id,
        Organization.tenant_id == tenant_id,
        Organization.deleted_at.is_(None)
    ).first()

    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found")

    if not _user_can_manage_org(db, user.id, organization, token_data):
        raise HTTPException(status_code=403, detail="You do not have access to manage this organization")

    slug_candidate, validation_errors = validate_subdomain_candidate(request.desired_subdomain)
    if validation_errors:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=validation_errors)

    duplicate = db.query(Organization).filter(
        Organization.id != org_id,
        or_(
            Organization.slug == slug_candidate,
            Organization.dns_subdomain == slug_candidate
        )
    ).first()

    duplicate_tenant = db.query(Tenant).filter(Tenant.domain == slug_candidate).first()

    if duplicate or duplicate_tenant:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Domain is already assigned to another organization"
        )

    dns_zone = request.dns_zone or organization.dns_zone or DEFAULT_DNS_ZONE
    organization.slug = slug_candidate
    organization.dns_subdomain = slug_candidate
    organization.dns_zone = dns_zone
    organization.dns_hostname = f"{slug_candidate}.{dns_zone}" if dns_zone else slug_candidate
    organization.dns_status = "reserved"
    organization.updated_at = datetime.utcnow()

    audit_log = AuditLog(
        tenant_id=tenant_id,
        user_id=user.id,
        action="organization_dns_reserved",
        resource_type="organization",
        resource_id=org_id,
        details={
            "organization_name": organization.name,
            "dns_hostname": organization.dns_hostname,
            "reserved_by": user.email
        }
    )
    db.add(audit_log)
    db.commit()
    db.refresh(organization)

    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    return OrganizationResponse(**_serialize_org(organization, tenant))

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

    organization = None
    if org_id != "default":
        organization = db.query(Organization).filter(
            Organization.id == org_id,
            Organization.tenant_id == tenant_id,
            Organization.deleted_at.is_(None)
        ).first()
        if not organization:
            raise HTTPException(status_code=404, detail="Organization not found")
        if not _user_can_manage_org(db, user.id, organization, token_data):
            raise HTTPException(status_code=403, detail="You do not have access to manage this organization")

    # Get app access metadata for this tenant
    app_access_records = db.query(TenantAppAccess).filter(
        TenantAppAccess.tenant_id == tenant_id
    ).all()
    enabled_app_ids = {app.app_name for app in app_access_records if app.is_enabled}
    app_access_map = {access.app_name: access for access in app_access_records}

    org_app_map: Dict[str, OrganizationAppAccess] = {}
    if organization:
        org_app_records = db.query(OrganizationAppAccess).filter(
            OrganizationAppAccess.organization_id == organization.id
        ).all()
        org_app_map = {record.app_name: record for record in org_app_records}

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

        org_app_access = org_app_map.get(app_id)
        if org_app_access:
            app_data.update({
                "org_app_enabled": org_app_access.is_enabled,
                "org_ingress_path": org_app_access.ingress_path,
                "org_ingress_hostname": org_app_access.ingress_hostname,
                "org_dns_status": org_app_access.dns_status,
                "org_provisioning_state": org_app_access.provisioning_state,
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

    is_tenant_admin = _user_has_tenant_admin_access(user_tenant)

    # Check if user has admin role in any app within this tenant
    has_app_admin_role = False
    app_role_map = user_tenant.app_roles or {}
    if not is_tenant_admin:
        for app in ["darkhole", "darkfolio", "confiploy"]:
            app_roles = app_role_map.get(app, [])
            if any(role in ["admin", "administrator"] for role in app_roles):
                has_app_admin_role = True
                break

    if not (is_tenant_admin or has_app_admin_role):
        raise HTTPException(status_code=403, detail="Admin, administrator, or tenant_admin role required to manage apps")

    organization = None
    if org_id != "default":
        organization = db.query(Organization).filter(
            Organization.id == org_id,
            Organization.tenant_id == tenant_id,
            Organization.deleted_at.is_(None)
        ).first()
        if not organization:
            raise HTTPException(status_code=404, detail="Organization not found")
        if not _user_can_manage_org(db, user.id, organization, token_data):
            raise HTTPException(status_code=403, detail="You do not have access to manage this organization")

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

    if organization:
        # Clear any tenant-level ingress hostname so provisioning uses org DNS
        app_access.ingress_hostname = None
        logger.info(
            "Enabling app %s for organization %s (tenant=%s, dns=%s)",
            app_id,
            organization.id,
            tenant_id,
            organization.dns_hostname or organization.dns_subdomain,
        )
        org_app_access = db.query(OrganizationAppAccess).filter(
            OrganizationAppAccess.organization_id == organization.id,
            OrganizationAppAccess.app_name == app_id
        ).first()

        if not org_app_access:
            org_app_access = OrganizationAppAccess(
                tenant_id=tenant_id,
                organization_id=organization.id,
                app_name=app_id
            )
            db.add(org_app_access)

        org_app_access.is_enabled = True
        org_app_access.ingress_path = APP_DEFAULT_PATHS.get(app_id, f"/{app_id}/")
        org_app_access.ingress_hostname = _build_org_hostname(organization)
        org_app_access.dns_status = organization.dns_status
        org_app_access.provisioning_state = app_access.provisioning_state
        org_app_access.enabled_at = datetime.utcnow()
        org_app_access.disabled_at = None

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

    org_hostname = organization.dns_hostname if organization else None
    org_subdomain = organization.dns_subdomain if organization else None
    org_zone = organization.dns_zone if organization else None

    logger.info(
        "notify_app_enabled payload: tenant=%s app=%s org=%s hostname=%s subdomain=%s zone=%s",
        tenant_id,
        app_id,
        org_id,
        org_hostname,
        org_subdomain,
        org_zone,
    )

    await notify_app_enabled(
        user_tenant.tenant,
        app_access,
        user.email,
        org_id,
        org_hostname,
        org_subdomain,
        org_zone,
    )

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

    is_tenant_admin = _user_has_tenant_admin_access(user_tenant)

    # Check if user has admin role in any app within this tenant
    has_app_admin_role = False
    app_role_map = user_tenant.app_roles or {}
    if not is_tenant_admin:
        for app in ["darkhole", "darkfolio", "confiploy"]:
            app_roles = app_role_map.get(app, [])
            if any(role in ["admin", "administrator"] for role in app_roles):
                has_app_admin_role = True
                break

    if not (is_tenant_admin or has_app_admin_role):
        raise HTTPException(status_code=403, detail="Admin, administrator, or tenant_admin role required to manage apps")

    organization = None
    if org_id != "default":
        organization = db.query(Organization).filter(
            Organization.id == org_id,
            Organization.tenant_id == tenant_id,
            Organization.deleted_at.is_(None)
        ).first()
        if not organization:
            raise HTTPException(status_code=404, detail="Organization not found")

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

        if organization:
            org_app_access = db.query(OrganizationAppAccess).filter(
                OrganizationAppAccess.organization_id == organization.id,
                OrganizationAppAccess.app_name == app_id
            ).first()
            if org_app_access:
                org_app_access.is_enabled = False
                org_app_access.disabled_at = datetime.utcnow()
                org_app_access.provisioning_state = "disabled"

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
    """Delete (soft delete) an organization."""
    user = get_or_create_user_from_token(db, token_data)
    user_tenant = db.query(UserTenant).filter(
        UserTenant.user_id == user.id,
        UserTenant.tenant_id == tenant_id
    ).first()

    if not user_tenant:
        raise HTTPException(status_code=403, detail="Access denied to tenant")

    if not _user_has_tenant_admin_access(user_tenant):
        raise HTTPException(status_code=403, detail="Admin access required to delete organizations")

    organization = db.query(Organization).filter(
        Organization.id == org_id,
        Organization.tenant_id == tenant_id,
        Organization.deleted_at.is_(None)
    ).first()

    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found")

    if not _user_can_manage_org(db, user.id, organization, token_data):
        raise HTTPException(status_code=403, detail="You do not have access to manage this organization")

    if organization.is_default:
        raise HTTPException(status_code=400, detail="Default organization cannot be deleted")

    organization.status = "deleted"
    organization.deleted_at = datetime.utcnow()

    db.query(OrganizationAppAccess).filter(
        OrganizationAppAccess.organization_id == organization.id
    ).update({
        "is_enabled": False,
        "disabled_at": datetime.utcnow(),
        "provisioning_state": "deleted"
    })

    # Create audit log
    audit_log = AuditLog(
        tenant_id=tenant_id,
        user_id=user.id,
        action="organization_deleted",
        resource_type="organization",
        resource_id=org_id,
        details={
            "organization_name": organization.name,
            "dns_hostname": organization.dns_hostname,
            "deleted_by": user.email
        }
    )
    db.add(audit_log)

    db.commit()

    return {
        "status": "deleted",
        "message": f"Organization '{organization.name}' has been deleted successfully",
        "tenant_id": tenant_id,
        "org_id": org_id
    }

# Cross-tenant organization access routes
@router.get("/orgs/{org_id}", response_model=OrganizationResponse)
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

    organization = db.query(Organization).filter(
        Organization.id == org_id
    ).first()

    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found")

    tenant = db.query(Tenant).filter(Tenant.id == organization.tenant_id).first()
    return OrganizationResponse(**_serialize_org(organization, tenant))
def _user_membership_org_ids(db: Session, user_id: str) -> set[str]:
    """Return organization IDs where the user has explicit membership."""
    rows = (
        db.query(OrganizationUserRole.organization_id)
        .filter(OrganizationUserRole.user_id == user_id)
        .distinct()
        .all()
    )
    org_ids: set[str] = set()
    for row in rows:
        if isinstance(row, tuple):
            org_ids.add(row[0])
        else:
            value = getattr(row, "organization_id", None)
            if value:
                org_ids.add(value)
    return org_ids


def _user_can_manage_org(
    db: Session,
    user_id: str,
    organization: Organization,
    token_data: TokenData,
) -> bool:
    """Determine if caller can manage this organization."""
    if require_platform_admin_access(token_data):
        return True

    if organization.created_by and organization.created_by == user_id:
        return True

    member_ids = _user_membership_org_ids(db, user_id)
    return organization.id in member_ids


@router.get("/tenants/{tenant_id}/orgs/{org_id}/users")
async def list_organization_users(
    tenant_id: str,
    org_id: str,
    include_directory: bool = True,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db),
):
    """
    List all users for an organization, including both platform users and directory users.
    """
    from shared.models import User
    from models import DirectoryUser

    # Verify org access
    organization = db.query(Organization).filter(
        Organization.id == org_id,
        Organization.tenant_id == tenant_id,
        Organization.deleted_at.is_(None)
    ).first()

    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found")

    # TODO: Add proper authorization check
    # For now, allow access if user has tenant access

    users = []

    # Get platform users (invited users with actual user accounts)
    platform_users = db.query(User).join(UserTenant).filter(
        UserTenant.tenant_id == tenant_id
    ).all()

    for user in platform_users:
        # Get user's roles from UserTenant
        user_tenant = db.query(UserTenant).filter(
            UserTenant.user_id == user.id,
            UserTenant.tenant_id == tenant_id
        ).first()

        app_roles = user_tenant.app_roles if user_tenant else {}

        users.append({
            "id": user.id,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "full_name": f"{user.first_name or ''} {user.last_name or ''}".strip() or user.email,
            "source": "platform",
            "status": "active",
            "app_roles": app_roles,
            "created_at": user.created_at.isoformat() if user.created_at else None,
        })

    # Get directory users (Azure AD/LDAP synced users) if requested
    if include_directory:
        directory_users = db.query(DirectoryUser).filter(
            DirectoryUser.organization_id == org_id,
            DirectoryUser.tenant_id == tenant_id
        ).all()

        for dir_user in directory_users:
            # Check if this directory user already exists as a platform user
            existing_platform_user = next(
                (u for u in users if u["email"].lower() == (dir_user.email or "").lower()),
                None
            )

            if not existing_platform_user:
                # Check if this directory user has been synced to platform (has UserTenant record)
                platform_user = db.query(User).filter(
                    User.email.ilike(dir_user.email)
                ).first()

                app_roles = {}
                if platform_user:
                    user_tenant = db.query(UserTenant).filter(
                        UserTenant.user_id == platform_user.id,
                        UserTenant.tenant_id == tenant_id
                    ).first()
                    app_roles = user_tenant.app_roles if user_tenant else {}

                users.append({
                    "id": dir_user.id,  # Use directory user ID for now
                    "email": dir_user.email,
                    "first_name": dir_user.first_name,
                    "last_name": dir_user.last_name,
                    "full_name": dir_user.display_name or f"{dir_user.first_name or ''} {dir_user.last_name or ''}".strip() or dir_user.email,
                    "source": "directory",
                    "provider": dir_user.provider_type,
                    "status": "synced" if app_roles else "directory_only",
                    "app_roles": app_roles,
                    "created_at": dir_user.created_at.isoformat() if dir_user.created_at else None,
                })

    return {
        "users": users,
        "total": len(users),
        "platform_count": len([u for u in users if u.get("source") == "platform"]),
        "directory_count": len([u for u in users if u.get("source") == "directory"]),
    }
