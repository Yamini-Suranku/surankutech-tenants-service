"""
Platform Organization Management Module
Handles organization creation and management for platform users
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Dict, Any, Optional
import logging
from datetime import datetime
import uuid

from shared.database import get_db
from shared.auth import get_current_user
from shared.models import Tenant, User, UserTenant, TenantAppAccess, AuditLog, UserStatus
from models import Organization, OrganizationAppAccess, OrganizationUserRole, TenantSettings
from schemas import (
    OrganizationCreateRequest,
    OrganizationResponse,
    OrganizationListResponse,
)
from modules.tenant_management import (
    slugify,
    validate_subdomain_candidate,
    generate_domain_suggestions,
    seed_app_access_metadata,
    mark_app_for_enable,
    get_trial_features
)

logger = logging.getLogger(__name__)

# Create router for platform organization management endpoints
router = APIRouter(prefix="/api/platform/organizations", tags=["platform-organizations"])

# App catalog - centralized definition
APP_CATALOG = {
    "darkhole": {
        "name": "DarkHole",
        "description": "AI governance & guard rails",
        "version": "v2.1.3",
        "category": "AI Safety",
        "icon": "🔮",
        "default_roles": ["admin", "user"]
    },
    "darkfolio": {
        "name": "DarkFolio",
        "description": "Model cost visibility & analytics",
        "version": "v1.8.2",
        "category": "Analytics",
        "icon": "📊",
        "default_roles": ["admin", "user", "model_engineer", "evaluator", "stuart"]
    },
    "confiploy": {
        "name": "ConfiPloy",
        "description": "Configuration & rollout management",
        "version": "v1.5.1",
        "category": "DevOps",
        "icon": "⚙️",
        "default_roles": ["admin", "user"]
    }
}

DEFAULT_DNS_ZONE = "suranku.net"

def _get_or_create_user_tenant(db: Session, user: User, tenant_name: str = None) -> Tenant:
    """Get user's existing tenant or create new one for their company/workspace"""
    # Check if user already has a tenant (as admin)
    existing_tenant = db.query(Tenant).join(UserTenant).filter(
        UserTenant.user_id == user.id,
        UserTenant.role == "admin",
        UserTenant.status == "active",
        Tenant.status == "active"
    ).first()

    if existing_tenant:
        return existing_tenant

    # Create new tenant for the user's company/workspace
    tenant_name = tenant_name or f"{user.first_name} {user.last_name}'s Workspace"
    tenant = Tenant(
        name=tenant_name,
        slug=slugify(tenant_name),
        description=f"Workspace for {user.email}",
        status="active"
    )
    db.add(tenant)
    db.flush()

    # Create UserTenant relationship with admin privileges
    user_tenant = UserTenant(
        user_id=user.id,
        tenant_id=tenant.id,
        role="admin",
        status="active",
        app_roles={
            "darkhole": ["admin"],
            "darkfolio": ["admin"],
            "confiploy": ["admin"]
        }
    )
    db.add(user_tenant)

    # Create tenant settings
    tenant_settings = TenantSettings(
        tenant_id=tenant.id,
        allow_user_registration=True,
        require_email_verification=True,
        allow_social_login=True
    )
    db.add(tenant_settings)

    # Create tenant app access records
    seed_app_access_metadata(db, tenant.id)

    return tenant

def _check_organization_name_unique(db: Session, name: str, exclude_id: str = None) -> bool:
    """Check if organization name is globally unique"""
    query = db.query(Organization).filter(Organization.name == name)
    if exclude_id:
        query = query.filter(Organization.id != exclude_id)
    return query.first() is None

def _check_subdomain_unique(db: Session, subdomain: str, exclude_id: str = None) -> bool:
    """Check if subdomain is globally unique"""
    query = db.query(Organization).filter(Organization.dns_subdomain == subdomain)
    if exclude_id:
        query = query.filter(Organization.id != exclude_id)
    return query.first() is None

@router.get("/apps")
async def get_available_apps():
    """Get available applications for organizations"""
    return {
        "apps": APP_CATALOG
    }

@router.post("/", response_model=OrganizationResponse)
async def create_organization(
    request: OrganizationCreateRequest,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Create a new organization for a platform user"""
    try:
        # Get user from database
        user = db.query(User).filter(User.id == current_user["id"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Validate organization name is globally unique
        if not _check_organization_name_unique(db, request.name):
            raise HTTPException(
                status_code=400,
                detail=f"Organization name '{request.name}' is already taken"
            )

        # Generate and validate subdomain
        suggested_subdomain = slugify(request.name)
        if not _check_subdomain_unique(db, suggested_subdomain):
            # Generate alternatives
            suggestions = generate_domain_suggestions(suggested_subdomain)
            available_suggestions = [s for s in suggestions if _check_subdomain_unique(db, s)]

            if available_suggestions:
                suggested_subdomain = available_suggestions[0]
            else:
                # Fallback with UUID
                suggested_subdomain = f"{slugify(request.name)}-{str(uuid.uuid4())[:8]}"

        # Validate final subdomain
        if not validate_subdomain_candidate(suggested_subdomain):
            raise HTTPException(
                status_code=400,
                detail="Invalid subdomain format"
            )

        # Get or create user's tenant (workspace)
        tenant = _get_or_create_user_tenant(db, user, request.name)

        # Check if this is the first organization in the tenant
        existing_orgs_count = db.query(Organization).filter(
            Organization.tenant_id == tenant.id,
            Organization.status == "active"
        ).count()
        is_first_org = existing_orgs_count == 0

        # Create organization
        organization = Organization(
            tenant_id=tenant.id,
            name=request.name,
            slug=slugify(request.name),
            description=request.description or f"{request.name} organization",
            dns_subdomain=suggested_subdomain,
            dns_zone=DEFAULT_DNS_ZONE,
            dns_hostname=f"{suggested_subdomain}.{DEFAULT_DNS_ZONE}",
            dns_status="pending",
            status="active",
            is_default=is_first_org,  # First org in tenant is default
            created_by=user.id
        )
        db.add(organization)
        db.flush()

        # Enable selected apps
        enabled_apps = request.enabled_apps or ["darkhole"]  # Default to darkhole

        for app_name in enabled_apps:
            if app_name not in APP_CATALOG:
                logger.warning(f"Unknown app requested: {app_name}")
                continue

            # Create organization app access
            app_access = OrganizationAppAccess(
                tenant_id=tenant.id,
                organization_id=organization.id,
                app_name=app_name,
                is_enabled=True,
                provisioning_state="ready",
                dns_status="pending",
                enabled_at=datetime.utcnow(),
                metadata_json={
                    "created_by": user.id,
                    "app_info": APP_CATALOG[app_name]
                }
            )
            db.add(app_access)

            # Grant admin role to creator for each app
            user_role = OrganizationUserRole(
                tenant_id=tenant.id,
                organization_id=organization.id,
                user_id=user.id,
                app_name=app_name,
                roles=["admin"],
                granted_by=user.id,
                granted_via="system",
                metadata_json={
                    "created_at_org_creation": True
                }
            )
            db.add(user_role)

        # Audit log
        audit_log = AuditLog(
            user_id=user.id,
            tenant_id=tenant.id,
            action="organization_created",
            resource_type="organization",
            resource_id=organization.id,
            details={
                "organization_name": request.name,
                "subdomain": suggested_subdomain,
                "enabled_apps": enabled_apps
            },
            ip_address="unknown",
            user_agent="platform"
        )
        db.add(audit_log)

        db.commit()

        logger.info(f"Platform user {user.email} created organization {request.name} with apps: {enabled_apps}")

        return OrganizationResponse(
            id=organization.id,
            tenant_id=tenant.id,
            name=organization.name,
            slug=organization.slug,
            description=organization.description,
            dns_subdomain=organization.dns_subdomain,
            dns_zone=organization.dns_zone,
            dns_hostname=organization.dns_hostname,
            dns_status=organization.dns_status,
            status=organization.status,
            is_default=organization.is_default,
            created_by=organization.created_by,
            created_at=organization.created_at,
            updated_at=organization.updated_at,
            tenant_name=tenant.name,
            apps_enabled=enabled_apps,
            is_creator=True
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create organization: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create organization: {str(e)}")

@router.get("/", response_model=OrganizationListResponse)
async def list_user_organizations(
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """List organizations where the user has access"""
    try:
        # Get user from database
        user = db.query(User).filter(User.id == current_user["id"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Find organizations where user has roles
        user_orgs = db.query(Organization, OrganizationUserRole, Tenant).join(
            OrganizationUserRole, OrganizationUserRole.organization_id == Organization.id
        ).join(
            Tenant, Tenant.id == Organization.tenant_id
        ).filter(
            OrganizationUserRole.user_id == user.id,
            Organization.deleted_at.is_(None)
        ).distinct().all()

        organizations = []
        for org, role, tenant in user_orgs:
            # Get enabled apps for this org
            enabled_apps = db.query(OrganizationAppAccess).filter(
                OrganizationAppAccess.organization_id == org.id,
                OrganizationAppAccess.is_enabled == True
            ).all()

            organizations.append(OrganizationResponse(
                id=org.id,
                tenant_id=org.tenant_id,
                name=org.name,
                slug=org.slug,
                description=org.description,
                dns_subdomain=org.dns_subdomain,
                dns_zone=org.dns_zone,
                dns_hostname=org.dns_hostname,
                dns_status=org.dns_status,
                status=org.status,
                is_default=org.is_default,
                created_by=org.created_by,
                created_at=org.created_at,
                updated_at=org.updated_at,
                tenant_name=tenant.name,
                apps_enabled=[app.app_name for app in enabled_apps],
                is_creator=org.created_by == user.id
            ))

        return OrganizationListResponse(
            organizations=organizations,
            total_count=len(organizations)
        )

    except Exception as e:
        logger.error(f"Failed to list organizations: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list organizations: {str(e)}")

@router.get("/{organization_id}", response_model=OrganizationResponse)
async def get_organization(
    organization_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get organization details if user has access"""
    try:
        # Check if user has access to this organization
        user_role = db.query(OrganizationUserRole).filter(
            OrganizationUserRole.organization_id == organization_id,
            OrganizationUserRole.user_id == current_user["id"]
        ).first()

        if not user_role:
            raise HTTPException(status_code=403, detail="Access denied to this organization")

        # Get organization with tenant info
        org_query = db.query(Organization, Tenant).join(
            Tenant, Tenant.id == Organization.tenant_id
        ).filter(
            Organization.id == organization_id,
            Organization.deleted_at.is_(None)
        ).first()

        if not org_query:
            raise HTTPException(status_code=404, detail="Organization not found")

        org, tenant = org_query

        # Get enabled apps
        enabled_apps = db.query(OrganizationAppAccess).filter(
            OrganizationAppAccess.organization_id == org.id,
            OrganizationAppAccess.is_enabled == True
        ).all()

        return OrganizationResponse(
            id=org.id,
            tenant_id=org.tenant_id,
            name=org.name,
            slug=org.slug,
            description=org.description,
            dns_subdomain=org.dns_subdomain,
            dns_zone=org.dns_zone,
            dns_hostname=org.dns_hostname,
            dns_status=org.dns_status,
            status=org.status,
            is_default=org.is_default,
            created_by=org.created_by,
            created_at=org.created_at,
            updated_at=org.updated_at,
            tenant_name=tenant.name,
            apps_enabled=[app.app_name for app in enabled_apps],
            is_creator=org.created_by == current_user["id"]
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get organization: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get organization: {str(e)}")
