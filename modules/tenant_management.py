"""
Tenant Management Module
Handles tenant creation, retrieval, and app access management
"""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
import logging
from datetime import datetime, timedelta
import uuid
import re
from typing import Optional, List

from shared.database import get_db
from shared.auth import verify_token, require_tenant_access, TokenData, get_current_token_data
from shared.models import (
    Tenant,
    User,
    UserTenant,
    TenantAppAccess,
    AuditLog,
    FeatureFlag,
)
from models import (
    TenantSettings,
    Invitation,
    Organization,
    OrganizationAppAccess,
)
from schemas import (
    TenantCreateRequest, TenantResponse, UserResponse,
    TenantUpdateRequest, AppAccessResponse,
    TenantQuickCreateRequest, TenantListResponse,
    TenantSummaryResponse, TenantAppSummary,
    TenantAppToggleRequest, TenantDomainCheckRequest,
    TenantDomainCheckResponse
)
from modules.keycloak_client import KeycloakClient
from modules.provisioning_events import (
    emit_app_disabled_event,
    emit_app_enabled_event,
    emit_tenant_created_event,
)

logger = logging.getLogger(__name__)

# Create router for tenant management endpoints (no prefix - Kong strips /api/tenants)
router = APIRouter(tags=["tenant-management"])

APP_CATALOG = {
    "darkhole": {
        "display_name": "DarkHole",
        "description": "AI governance & guard rails",
        "category": "AI Safety",
        "docs_url": "https://docs.suranku.com/darkhole"
    },
    "darkfolio": {
        "display_name": "DarkFolio",
        "description": "Model cost visibility & analytics",
        "category": "Analytics",
        "docs_url": "https://docs.suranku.com/darkfolio"
    },
    "confiploy": {
        "display_name": "ConfiPloy",
        "description": "Configuration & rollout management",
        "category": "DevOps",
        "docs_url": "https://docs.suranku.com/confiploy"
    }
}

DEFAULT_APPS = list(APP_CATALOG.keys())
RESERVED_SUBDOMAINS = {
    "suranku", "surankutech", "surankuservices", "id", "api", "auth", "admin",
    "dashboard", "platform", "console", "kong", "keycloak", "vault", "minio",
    "redis", "postgres", "elasticsearch", "darkhole", "datadance", "confiploy",
    "www", "mail", "ftp", "cdn", "static", "assets", "public", "downloads",
    "dev", "staging", "prod", "test", "demo", "sandbox", "preview", "billing",
    "support", "help", "docs", "status", "monitor", "health", "app",
    "application", "service", "gateway", "proxy", "load-balancer"
}

PROVISIONING_READY_STATES = {"ready", "active", "synced"}
TENANT_ADMIN_ROLES = {"tenant_admin", "administrator", "owner"}

def slugify(value: str) -> str:
    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    value = re.sub(r"-{2,}", "-", value).strip("-")
    if not value:
        value = f"tenant-{uuid.uuid4().hex[:6]}"
    return value[:63]

def ensure_unique_domain(db: Session, desired: str) -> str:
    base = slugify(desired)
    candidate = base
    suffix = 1
    while db.query(Tenant).filter(Tenant.domain == candidate).first():
        candidate = f"{base}-{suffix}"
        suffix += 1
    return candidate

def validate_subdomain_candidate(value: str) -> tuple[str, List[str]]:
    errors: List[str] = []
    if not value:
        errors.append("Organization name is required")
        return "", errors

    name = value.lower().strip()
    if len(name) < 3:
        errors.append("Organization name must be at least 3 characters")
    if len(name) > 63:
        errors.append("Organization name must not exceed 63 characters")
    if not re.match(r"^[a-z][a-z0-9-]*[a-z0-9]$", name):
        errors.append("Organization name must start with a letter and can include lowercase letters, numbers, and hyphens")
    if name in RESERVED_SUBDOMAINS:
        errors.append("This organization name is reserved and cannot be used")
    if "--" in name:
        errors.append("Organization name cannot contain consecutive hyphens")
    if name.startswith("-") or name.endswith("-"):
        errors.append("Organization name cannot start or end with a hyphen")

    sanitized = slugify(name)
    return sanitized, errors

def generate_domain_suggestions(db: Session, base_name: str, limit: int = 3) -> List[str]:
    suggestions: List[str] = []
    suffix = 1
    while len(suggestions) < limit:
        candidate = f"{base_name}-{suffix}"
        suffix += 1
        if db.query(Tenant).filter(Tenant.domain == candidate).first():
            continue
        suggestions.append(candidate)
    return suggestions

def determine_network_tier(plan_id: Optional[str]) -> str:
    tier_map = {
        "free": "shared",
        "trial": "shared",
        "pro": "pro",
        "enterprise": "enterprise"
    }
    return tier_map.get((plan_id or "").lower(), "shared")

def _tenant_hostname_base(tenant: Tenant) -> str:
    if tenant.domain:
        return tenant.domain
    return slugify(tenant.name or "tenant")

def generate_app_hostname(tenant: Tenant, app_name: str, network_tier: Optional[str] = None) -> str:
    base_domain = _tenant_hostname_base(tenant)
    tier = network_tier or determine_network_tier(tenant.plan_id)
    if tier == "enterprise":
        return f"{base_domain}.{app_name}.customers.suranku.net"
    return f"{base_domain}.{app_name}.suranku.net"

def seed_app_access_metadata(app_access: TenantAppAccess, tenant: Tenant, app_name: str):
    network_tier = determine_network_tier(tenant.plan_id)
    app_access.network_tier = network_tier
    if not app_access.ingress_hostname:
        app_access.ingress_hostname = generate_app_hostname(tenant, app_name, network_tier)
    if app_access.is_enabled:
        app_access.provisioning_state = "pending"
        app_access.dns_status = "pending"
    else:
        app_access.provisioning_state = "disabled"
        app_access.dns_status = "not_applicable"
    app_access.provisioning_error = None
    app_access.last_synced_at = None

def user_has_tenant_admin(user_tenant: Optional[UserTenant]) -> bool:
    if not user_tenant or not user_tenant.app_roles:
        return False
    for roles in user_tenant.app_roles.values():
        if any(role in TENANT_ADMIN_ROLES for role in roles):
            return True
    return False

def delete_tenant_records(
    db: Session,
    tenant_id: str,
    requested_by: Optional[str] = None,
) -> None:
    """Remove tenant and all dependent records."""
    db.query(OrganizationAppAccess).filter(
        OrganizationAppAccess.tenant_id == tenant_id
    ).delete(synchronize_session=False)

    db.query(Organization).filter(
        Organization.tenant_id == tenant_id
    ).delete(synchronize_session=False)

    db.query(TenantAppAccess).filter(
        TenantAppAccess.tenant_id == tenant_id
    ).delete(synchronize_session=False)

    db.query(TenantSettings).filter(
        TenantSettings.tenant_id == tenant_id
    ).delete(synchronize_session=False)

    db.query(FeatureFlag).filter(
        FeatureFlag.tenant_id == tenant_id
    ).delete(synchronize_session=False)

    db.query(Invitation).filter(
        Invitation.tenant_id == tenant_id
    ).delete(synchronize_session=False)

    db.query(UserTenant).filter(
        UserTenant.tenant_id == tenant_id
    ).delete(synchronize_session=False)

    db.query(AuditLog).filter(
        AuditLog.tenant_id == tenant_id
    ).delete(synchronize_session=False)

    db.query(Tenant).filter(Tenant.id == tenant_id).delete(synchronize_session=False)

def mark_app_for_enable(app_access: TenantAppAccess, tenant: Tenant, app_name: str):
    network_tier = determine_network_tier(tenant.plan_id)
    app_access.network_tier = network_tier
    if not app_access.ingress_hostname:
        app_access.ingress_hostname = generate_app_hostname(tenant, app_name, network_tier)
    app_access.provisioning_state = "pending"
    app_access.dns_status = "pending"
    app_access.provisioning_error = None
    app_access.last_synced_at = None

def mark_app_for_disable(app_access: TenantAppAccess):
    app_access.provisioning_state = "deprovisioning"
    app_access.dns_status = "pending"
    app_access.provisioning_error = None
    app_access.last_synced_at = None

def ensure_user_has_app_admin(user_tenant: UserTenant, app_name: str) -> bool:
    roles_changed = False
    app_roles = user_tenant.app_roles or {}
    current_roles = app_roles.get(app_name, [])
    if "admin" not in current_roles:
        current_roles = list(set(current_roles + ["admin"]))
        app_roles[app_name] = current_roles
        user_tenant.app_roles = app_roles
        roles_changed = True
    return roles_changed

async def notify_tenant_created(tenant: Tenant, created_by: Optional[str]) -> None:
    await emit_tenant_created_event(
        tenant_id=tenant.id,
        tenant_name=tenant.name,
        domain=tenant.domain,
        plan_id=tenant.plan_id,
        created_by=created_by,
    )

async def notify_app_enabled(
    tenant: Tenant,
    app_access: TenantAppAccess,
    requested_by: Optional[str],
    org_id: str = "default",
    org_hostname: Optional[str] = None,
    org_dns_subdomain: Optional[str] = None,
    org_dns_zone: Optional[str] = None,
) -> None:
    await emit_app_enabled_event(
        tenant_id=tenant.id,
        tenant_domain=tenant.domain,
        plan_id=tenant.plan_id,
        app_name=app_access.app_name,
        org_id=org_id,
        org_hostname=org_hostname,
        org_dns_subdomain=org_dns_subdomain,
        org_dns_zone=org_dns_zone,
        ingress_hostname=app_access.ingress_hostname,
        network_tier=app_access.network_tier,
        provisioning_state=app_access.provisioning_state,
        requested_by=requested_by,
    )

async def notify_app_disabled(
    tenant: Tenant,
    app_name: str,
    requested_by: Optional[str],
    org_id: str = "default",
    org_hostname: Optional[str] = None,
    org_dns_subdomain: Optional[str] = None,
    org_dns_zone: Optional[str] = None,
) -> None:
    await emit_app_disabled_event(
        tenant_id=tenant.id,
        app_name=app_name,
        org_id=org_id,
        requested_by=requested_by,
        org_hostname=org_hostname,
        org_dns_subdomain=org_dns_subdomain,
        org_dns_zone=org_dns_zone,
    )

def get_or_create_user_from_token(db: Session, token_data: TokenData) -> User:
    if not token_data or not token_data.sub:
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    user = db.query(User).filter(User.keycloak_id == token_data.sub).first()
    if not user and token_data.email:
        user = db.query(User).filter(User.email == token_data.email).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found in tenant service")
    return user


@router.get("/tenants", response_model=TenantListResponse)
async def list_user_tenants(
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db)
):
    """Return the list of tenants the authenticated user has access to."""
    user = get_or_create_user_from_token(db, token_data)

    user_tenants = db.query(UserTenant).filter(
        UserTenant.user_id == user.id,
        UserTenant.status != "removed"
    ).all()

    if not user_tenants:
        return TenantListResponse(tenants=[])

    summaries = [
        build_tenant_summary(ut.tenant, ut, db)
        for ut in user_tenants if ut.tenant is not None
    ]

    return TenantListResponse(tenants=summaries)

def build_app_summary(app_name: str, access: Optional[TenantAppAccess]) -> TenantAppSummary:
    metadata = APP_CATALOG.get(app_name, {})
    provisioning_state = access.provisioning_state if access else None
    status = provisioning_state or ("enabled" if access and access.is_enabled else "available")
    launch_url = None
    if access and access.ingress_hostname and provisioning_state in PROVISIONING_READY_STATES:
        launch_url = f"https://{access.ingress_hostname}"
    return TenantAppSummary(
        name=app_name,
        display_name=metadata.get("display_name", app_name.title()),
        description=metadata.get("description"),
        category=metadata.get("category"),
        docs_url=metadata.get("docs_url"),
        is_enabled=access.is_enabled if access else False,
        enabled_features=access.enabled_features if access and access.enabled_features else [],
        launch_url=launch_url,
        status=status,
        ingress_hostname=access.ingress_hostname if access else None,
        network_tier=access.network_tier if access else None,
        provisioning_state=provisioning_state,
        dns_status=access.dns_status if access else None,
        provisioning_error=access.provisioning_error if access else None,
        last_synced_at=access.last_synced_at if access else None
    )

def build_tenant_summary(
    tenant: Tenant,
    user_tenant: UserTenant,
    db: Session
) -> TenantSummaryResponse:
    app_records = {
        record.app_name: record
        for record in db.query(TenantAppAccess).filter(
            TenantAppAccess.tenant_id == tenant.id
        ).all()
    }

    apps = [build_app_summary(app_name, app_records.get(app_name)) for app_name in DEFAULT_APPS]

    roles: List[str] = []
    if user_tenant.app_roles:
        app_roles = user_tenant.app_roles
        if isinstance(app_roles, dict):
            for role_list in app_roles.values():
                if isinstance(role_list, list):
                    roles.extend(role_list)
                elif isinstance(role_list, str):
                    roles.append(role_list)
        elif isinstance(app_roles, list):
            roles.extend([role for role in app_roles if isinstance(role, str)])

    # Calculate member count for this tenant
    member_count = db.query(UserTenant).filter(
        UserTenant.tenant_id == tenant.id,
        UserTenant.status == "active"
    ).count()

    return TenantSummaryResponse(
        id=tenant.id,
        name=tenant.name,
        domain=tenant.domain,
        plan_id=tenant.plan_id,
        subscription_status=tenant.subscription_status,
        trial_expires_at=tenant.trial_expires_at,
        logo_url=tenant.logo_url,
        status="active" if tenant.is_active else "inactive",
        roles=roles,
        apps=apps,
        member_count=member_count,
        created_at=tenant.created_at,
        last_accessed_at=user_tenant.last_accessed_at
    )

@router.post("/tenants", response_model=TenantResponse)
async def create_tenant(
    request: TenantCreateRequest,
    db: Session = Depends(get_db)
):
    """Create new tenant during signup - supports existing users"""
    try:
        keycloak_client = KeycloakClient()

        # Create tenant
        tenant_id = str(uuid.uuid4())
        tenant_domain = ensure_unique_domain(db, request.preferred_domain or request.company_name)
        tenant = Tenant(
            id=tenant_id,
            name=request.company_name,
            domain=tenant_domain,
            subscription_status="trial",
            plan_id="free",
            trial_started_at=datetime.utcnow(),
            trial_expires_at=datetime.utcnow() + timedelta(days=14)
        )
        db.add(tenant)
        db.flush()  # Ensure tenant is written to DB before creating dependent records

        # Check if admin user already exists
        existing_user = db.query(User).filter(User.email == request.admin_email).first()

        if existing_user:
            # User exists - add to new tenant
            logger.info(f"Adding existing user {request.admin_email} to new tenant {tenant_id}")
            user = existing_user

            # Add existing user to new tenant group in Keycloak
            keycloak_user_id = await keycloak_client.add_existing_user_to_tenant(
                user_email=request.admin_email,
                tenant_id=tenant_id,
                app_roles={
                    "darkhole": ["admin"],
                    "darkfolio": ["admin"],
                    "confiploy": ["admin"]
                }
            )

            # Update user's Keycloak ID if not set
            if not user.keycloak_id:
                user.keycloak_id = keycloak_user_id

        else:
            # New user - create invitation instead of requiring password
            logger.info(f"Creating invitation for new admin user {request.admin_email} for tenant {tenant_id}")

            # Create user record with PENDING status
            user = User(
                email=request.admin_email,
                first_name=request.admin_first_name or request.company_name,
                last_name=request.admin_last_name or "Admin",
                status="pending",  # Will be activated when invitation is accepted
                is_email_verified=False  # Will be verified during invitation acceptance
            )
            db.add(user)
            db.flush()  # Get user ID

            # Create invitation for the admin user
            from models import Invitation
            invitation_token = str(uuid.uuid4())
            invitation = Invitation(
                tenant_id=tenant_id,
                email=request.admin_email,
                app_roles={
                    "darkhole": ["admin"],
                    "darkfolio": ["admin"],
                    "confiploy": ["admin"]
                },
                status="pending",
                expires_at=datetime.utcnow() + timedelta(days=7),  # 7 days to accept
                invitation_token=invitation_token
            )
            db.add(invitation)
            db.flush()

            # TODO: Send invitation email with setup link
            logger.info(f"Invitation created for {request.admin_email} with token {invitation_token}")

            # Note: Keycloak user will be created when invitation is accepted

        # Create user-tenant relationship (check for existing first)
        existing_user_tenant = db.query(UserTenant).filter(
            UserTenant.user_id == user.id,
            UserTenant.tenant_id == tenant_id
        ).first()

        if not existing_user_tenant:
            # Set status based on user verification status
            user_tenant_status = "active" if user.is_email_verified else "pending"
            user_tenant_joined_at = datetime.utcnow() if user.is_email_verified else None

            user_tenant = UserTenant(
                user_id=user.id,
                tenant_id=tenant_id,
                app_roles={
                    "darkhole": ["admin"],
                    "darkfolio": ["admin"],
                    "confiploy": ["admin"]
                },
                status=user_tenant_status,  # pending until email verified
                joined_at=user_tenant_joined_at  # Set only after verification
            )
            db.add(user_tenant)
            logger.info(f"Created user-tenant relationship for {user.email} in tenant {tenant_id} with status {user_tenant_status}")
        else:
            # Update existing relationship with admin roles
            existing_user_tenant.app_roles = {
                "darkhole": ["admin"],
                "darkfolio": ["admin"],
                "confiploy": ["admin"]
            }
            existing_user_tenant.status = "active"
            existing_user_tenant.joined_at = datetime.utcnow()
            logger.info(f"Updated existing user-tenant relationship for {user.email} in tenant {tenant_id}")

        created_app_accesses: List[TenantAppAccess] = []
        # Create app access for trial (all 3 apps with all features)
        for app_name in ["darkhole", "darkfolio", "confiploy"]:
            app_access = TenantAppAccess(
                tenant_id=tenant_id,
                app_name=app_name,
                is_enabled=False,  # Changed to False - apps disabled by default
                user_limit=5,  # Trial limit
                current_users=0,  # Changed to 0 since apps are disabled by default
                enabled_features=get_trial_features(app_name)
            )
            seed_app_access_metadata(app_access, tenant, app_name)
            db.add(app_access)
            created_app_accesses.append(app_access)

        # Create tenant settings
        tenant_settings = TenantSettings(
            tenant_id=tenant_id,
            timezone="UTC",
            date_format="YYYY-MM-DD",
            language="en",
            company_size=request.company_size,
            industry=request.industry
        )
        db.add(tenant_settings)

        db.commit()
        db.refresh(tenant)

        # Log audit event
        audit_log = AuditLog(
            tenant_id=tenant_id,
            user_id=user.id,
            action="tenant_created",
            resource_type="tenant",
            resource_id=tenant_id,
            details={"company_name": request.company_name, "admin_email": request.admin_email}
        )
        db.add(audit_log)
        db.commit()

        await notify_tenant_created(tenant, user.email)
        for app_access in created_app_accesses:
            if app_access.is_enabled:
                await notify_app_enabled(tenant, app_access, user.email)

        return TenantResponse(
            id=tenant.id,
            name=tenant.name,
            domain=tenant.domain,
            subscription_status=tenant.subscription_status,
            plan_id=tenant.plan_id,
            trial_expires_at=tenant.trial_expires_at,
            created_at=tenant.created_at,
            admin_user=UserResponse(
                id=user.id,
                email=user.email,
                first_name=user.first_name,
                last_name=user.last_name,
                status=user.status
            )
        )

    except Exception as e:
        logger.error(f"Tenant creation error: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create tenant: {str(e)}")

@router.get("/user/tenants", response_model=TenantListResponse)
async def list_user_tenants(
    db: Session = Depends(get_db)
):
    """List all tenants/organizations for the current user"""
    # TEMPORARY: Return all active tenants for debugging
    # TODO: Restore proper authentication after debugging
    logger.info("Getting all active tenants (temporary - no auth)")

    all_user_tenants = db.query(UserTenant).filter(
        UserTenant.status == "active"
    ).all()

    tenants = []
    for user_tenant in all_user_tenants:
        tenant = db.query(Tenant).filter(Tenant.id == user_tenant.tenant_id).first()
        if tenant and tenant.is_active:
            tenant_summary = build_tenant_summary(tenant, user_tenant, db)
            tenants.append(tenant_summary)

    return TenantListResponse(tenants=tenants)

@router.get("/tenants/by-domain/{slug}", response_model=TenantResponse)
async def get_tenant_by_domain(
    slug: str,
    db: Session = Depends(get_db)
):
    """Get tenant information by domain slug (for app tenant resolution)"""
    # Handle both old domain format and new tenantid/orgid/dns format
    if '.' in slug:
        # New format: tenant.org.local.suranku -> extract tenant part
        domain_parts = slug.split('.')
        if len(domain_parts) >= 1:
            tenant_slug = domain_parts[0]  # First part is tenant identifier
        else:
            tenant_slug = slug
    else:
        # Old format: direct domain slug
        tenant_slug = slug

    # Find tenant by domain slug
    tenant = db.query(Tenant).filter(Tenant.domain == tenant_slug).first()
    if not tenant:
        raise HTTPException(status_code=404, detail=f"Tenant not found for domain: {slug}")

    if not tenant.is_active:
        raise HTTPException(status_code=403, detail="Tenant is not active")

    # Get additional company information from TenantSettings
    tenant_settings = db.query(TenantSettings).filter(
        TenantSettings.tenant_id == tenant.id
    ).first()

    return TenantResponse(
        id=tenant.id,
        name=tenant.name,
        subscription_status=tenant.subscription_status,
        plan_id=tenant.plan_id,
        trial_expires_at=tenant.trial_expires_at,
        created_at=tenant.created_at,
        # Organization information from tenant and settings
        logo_url=tenant.logo_url,
        company_size=tenant_settings.company_size if tenant_settings else None,
        industry=tenant_settings.industry if tenant_settings else None,
        company_website=tenant_settings.company_website if tenant_settings else None,
        company_description=tenant_settings.company_description if tenant_settings else None
    )

@router.get("/tenants/{tenant_id}", response_model=TenantResponse)
async def get_tenant(
    tenant_id: str,
    token: str = Depends(HTTPBearer()),
    db: Session = Depends(get_db)
):
    """Get tenant details with complete organization information"""
    token_data = await verify_token(token.credentials)

    # Temporary: Allow all authenticated users
    # TODO: Restore proper tenant access check after debugging database issues
    logger.info(f"GET tenant {tenant_id} for user {token_data.sub}")

    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    # Get additional company information from TenantSettings
    tenant_settings = db.query(TenantSettings).filter(
        TenantSettings.tenant_id == tenant_id
    ).first()

    return TenantResponse(
        id=tenant.id,
        name=tenant.name,
        subscription_status=tenant.subscription_status,
        plan_id=tenant.plan_id,
        trial_expires_at=tenant.trial_expires_at,
        created_at=tenant.created_at,
        # Organization information from tenant and settings
        logo_url=tenant.logo_url,
        company_size=tenant_settings.company_size if tenant_settings else None,
        industry=tenant_settings.industry if tenant_settings else None,
        company_website=tenant_settings.company_website if tenant_settings else None,
        company_description=tenant_settings.company_description if tenant_settings else None
    )

@router.put("/tenants/{tenant_id}", response_model=TenantResponse)
async def update_tenant(
    tenant_id: str,
    request: TenantUpdateRequest,
    token: str = Depends(HTTPBearer()),
    db: Session = Depends(get_db)
):
    """Update tenant information (admin only)"""
    token_data = await verify_token(token.credentials)

    # Temporary: Allow all authenticated users
    # TODO: Restore proper tenant access check after debugging database issues
    logger.info(f"PUT tenant {tenant_id} for user {token_data.sub}")

    # Verify user exists (still needed for user_id in audit log)
    current_user = db.query(User).filter(User.keycloak_id == token_data.sub).first()
    if not current_user:
        raise HTTPException(status_code=404, detail="User not found")

    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    # Update tenant fields
    if request.name:
        tenant.name = request.name

    # Update tenant settings if provided
    if any([request.company_size, request.industry, request.company_website, request.company_description]):
        tenant_settings = db.query(TenantSettings).filter(
            TenantSettings.tenant_id == tenant_id
        ).first()

        if tenant_settings:
            if request.company_size:
                tenant_settings.company_size = request.company_size
            if request.industry:
                tenant_settings.industry = request.industry
            if request.company_website:
                tenant_settings.company_website = request.company_website
            if request.company_description:
                tenant_settings.company_description = request.company_description

    db.commit()
    db.refresh(tenant)

    # Get updated tenant settings for complete response
    tenant_settings = db.query(TenantSettings).filter(
        TenantSettings.tenant_id == tenant_id
    ).first()

    return TenantResponse(
        id=tenant.id,
        name=tenant.name,
        subscription_status=tenant.subscription_status,
        plan_id=tenant.plan_id,
        trial_expires_at=tenant.trial_expires_at,
        created_at=tenant.created_at,
        # Organization information from tenant and settings
        logo_url=tenant.logo_url,
        company_size=tenant_settings.company_size if tenant_settings else None,
        industry=tenant_settings.industry if tenant_settings else None,
        company_website=tenant_settings.company_website if tenant_settings else None,
        company_description=tenant_settings.company_description if tenant_settings else None
    )

@router.get("/tenants/{tenant_id}/app-access", response_model=list[AppAccessResponse])
async def get_tenant_app_access(
    tenant_id: str,
    token: str = Depends(HTTPBearer()),
    db: Session = Depends(get_db)
):
    """Get app access for tenant"""
    token_data = await verify_token(token.credentials)

    # Check tenant access via database (more reliable than JWT token check)
    current_user = db.query(User).filter(User.keycloak_id == token_data.sub).first()
    if not current_user:
        raise HTTPException(status_code=404, detail="User not found")

    user_tenant = db.query(UserTenant).filter(
        UserTenant.user_id == current_user.id,
        UserTenant.tenant_id == tenant_id
    ).first()

    if not user_tenant:
        raise HTTPException(status_code=403, detail="Access denied to tenant")

    app_access_list = db.query(TenantAppAccess).filter(
        TenantAppAccess.tenant_id == tenant_id
    ).all()

    return [
        AppAccessResponse(
            app_name=access.app_name,
            is_enabled=access.is_enabled,
            user_limit=access.user_limit,
            current_users=access.current_users,
            enabled_features=access.enabled_features,
            ingress_hostname=access.ingress_hostname,
            network_tier=access.network_tier,
            provisioning_state=access.provisioning_state,
            dns_status=access.dns_status,
            provisioning_error=access.provisioning_error,
            last_synced_at=access.last_synced_at
        ) for access in app_access_list
    ]

@router.get("/tenants/me", response_model=TenantListResponse)
async def get_my_tenants(
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db)
):
    user = get_or_create_user_from_token(db, token_data)
    user_tenants = db.query(UserTenant).filter(UserTenant.user_id == user.id).all()
    summaries = [
        build_tenant_summary(tenant_rel.tenant, tenant_rel, db)
        for tenant_rel in user_tenants
    ]
    return TenantListResponse(tenants=summaries)

@router.get("/tenants/{tenant_id}/summary", response_model=TenantSummaryResponse)
async def tenant_summary(
    tenant_id: str,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db)
):
    user = get_or_create_user_from_token(db, token_data)
    user_tenant = db.query(UserTenant).filter(
        UserTenant.user_id == user.id,
        UserTenant.tenant_id == tenant_id
    ).first()
    if not user_tenant:
        raise HTTPException(status_code=403, detail="Access denied to tenant")
    return build_tenant_summary(user_tenant.tenant, user_tenant, db)


@router.patch("/tenants/{tenant_id}/apps/{app_name}", response_model=TenantSummaryResponse)
async def toggle_tenant_app(
    tenant_id: str,
    app_name: str,
    payload: TenantAppToggleRequest,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db)
):
    if app_name not in APP_CATALOG:
        raise HTTPException(status_code=404, detail="Unknown application")

    user = get_or_create_user_from_token(db, token_data)
    user_tenant = db.query(UserTenant).filter(
        UserTenant.user_id == user.id,
        UserTenant.tenant_id == tenant_id
    ).first()
    if not user_tenant:
        raise HTTPException(status_code=403, detail="Access denied to tenant")

    app_access = db.query(TenantAppAccess).filter(
        TenantAppAccess.tenant_id == tenant_id,
        TenantAppAccess.app_name == app_name
    ).first()

    if not app_access:
        app_access = TenantAppAccess(
            tenant_id=tenant_id,
            app_name=app_name,
            is_enabled=payload.is_enabled,
            user_limit=5,
            current_users=1 if payload.is_enabled else 0,
            enabled_features=get_trial_features(app_name)
        )
        seed_app_access_metadata(app_access, user_tenant.tenant, app_name)
        db.add(app_access)
        if payload.is_enabled:
            ensure_user_has_app_admin(user_tenant, app_name)
    else:
        app_access.is_enabled = payload.is_enabled
        if payload.is_enabled:
            mark_app_for_enable(app_access, user_tenant.tenant, app_name)
            ensure_user_has_app_admin(user_tenant, app_name)
        else:
            mark_app_for_disable(app_access)
            app_access.current_users = 0

    user_tenant.last_accessed_at = datetime.utcnow()
    db.commit()

    if payload.is_enabled:
        await notify_app_enabled(user_tenant.tenant, app_access, user.email)
    else:
        await notify_app_disabled(user_tenant.tenant, app_name, user.email)

    return build_tenant_summary(user_tenant.tenant, user_tenant, db)



@router.post("/tenants/check-domain", response_model=TenantDomainCheckResponse)
async def check_tenant_domain(
    request: TenantDomainCheckRequest,
    db: Session = Depends(get_db)
):
    sanitized, validation_errors = validate_subdomain_candidate(request.desired_subdomain)
    if validation_errors:
        return TenantDomainCheckResponse(
            available=False,
            sanitized=sanitized or slugify(request.desired_subdomain),
            suggestions=[],
            errors=validation_errors
        )

    is_available = db.query(Tenant).filter(Tenant.domain == sanitized).first() is None
    suggestions = [] if is_available else generate_domain_suggestions(db, sanitized)
    errors = [] if is_available else ["This organization name is already taken"]

    return TenantDomainCheckResponse(
        available=is_available,
        sanitized=sanitized,
        suggestions=suggestions,
        errors=errors
    )

@router.post("/tenants/quick-create", response_model=TenantResponse)
async def quick_create_tenant(
    request: TenantQuickCreateRequest,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db)
):
    user = get_or_create_user_from_token(db, token_data)
    keycloak_client = KeycloakClient()

    tenant_id = str(uuid.uuid4())
    tenant_domain = ensure_unique_domain(db, request.desired_subdomain or request.company_name)
    tenant_admin_app_roles = {app: ["admin", "tenant_admin"] for app in DEFAULT_APPS}
    tenant = Tenant(
        id=tenant_id,
        name=request.company_name,
        domain=tenant_domain,
        subscription_status="trial",
        plan_id="free",
        trial_started_at=datetime.utcnow(),
        trial_expires_at=datetime.utcnow() + timedelta(days=14),
        is_active=True
    )
    db.add(tenant)
    db.flush()  # ensure tenant row exists for FK references

    await keycloak_client.add_existing_user_to_tenant(
        user_email=user.email,
        tenant_id=tenant_id,
        app_roles=tenant_admin_app_roles
    )

    user_tenant = UserTenant(
        user_id=user.id,
        tenant_id=tenant_id,
        app_roles={app: roles[:] for app, roles in tenant_admin_app_roles.items()},
        status="active",
        joined_at=datetime.utcnow(),
        last_accessed_at=datetime.utcnow()
    )
    db.add(user_tenant)

    apps_to_enable = request.apps or DEFAULT_APPS
    created_app_accesses: List[TenantAppAccess] = []
    for app_name in DEFAULT_APPS:
        app_access = TenantAppAccess(
            tenant_id=tenant_id,
            app_name=app_name,
            is_enabled=app_name in apps_to_enable,
            user_limit=5,
            current_users=1 if app_name in apps_to_enable else 0,
            enabled_features=get_trial_features(app_name)
        )
        seed_app_access_metadata(app_access, tenant, app_name)
        db.add(app_access)
        created_app_accesses.append(app_access)

    tenant_settings = TenantSettings(
        tenant_id=tenant_id,
        timezone="UTC",
        date_format="YYYY-MM-DD",
        language="en",
        company_size=request.company_size,
        industry=request.industry
    )
    db.add(tenant_settings)
    db.flush()

    db.commit()
    db.refresh(tenant)

    audit_log = AuditLog(
        tenant_id=tenant_id,
        user_id=user.id,
        action="tenant_quick_created",
        resource_type="tenant",
        resource_id=tenant_id,
        details={"company_name": request.company_name, "creator": user.email}
    )
    db.add(audit_log)
    db.commit()

    await notify_tenant_created(tenant, user.email)
    for app_access in created_app_accesses:
        if app_access.is_enabled:
            await notify_app_enabled(tenant, app_access, user.email)

    return TenantResponse(
        id=tenant.id,
        name=tenant.name,
        domain=tenant.domain,
        subscription_status=tenant.subscription_status,
        plan_id=tenant.plan_id,
        trial_expires_at=tenant.trial_expires_at,
        created_at=tenant.created_at,
        admin_user=UserResponse(
            id=user.id,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            status=user.status
        ),
        logo_url=tenant.logo_url,
        company_size=request.company_size,
        industry=request.industry
    )


@router.delete("/tenants/{tenant_id}")
async def delete_tenant_account(
    tenant_id: str,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db)
):
    """Delete a tenant and all associated data."""
    user = get_or_create_user_from_token(db, token_data)
    user_tenant = db.query(UserTenant).filter(
        UserTenant.user_id == user.id,
        UserTenant.tenant_id == tenant_id
    ).first()

    if not user_tenant:
        raise HTTPException(status_code=403, detail="Access denied to tenant")

    if not user_has_tenant_admin(user_tenant):
        raise HTTPException(
            status_code=403,
            detail="Administrator access is required to delete a tenant"
        )

    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    tenant_name = tenant.name
    delete_tenant_records(db, tenant_id, requested_by=user.email)
    db.commit()

    return {
        "status": "deleted",
        "tenant_id": tenant_id,
        "message": f"Tenant '{tenant_name}' and all related data have been deleted."
    }

def get_trial_features(app_name: str) -> list[str]:
    """Get trial features for each app (all features unlocked during trial)"""
    trial_features = {
        "darkhole": ["admin", "user", "rag", "tuner", "analytics", "export"],
        "darkfolio": ["admin", "user", "stuart", "analyst", "reports", "integrations"],
        "confiploy": ["admin", "user", "devops-engineer", "release-manager", "pipelines", "monitoring"]
    }
    return trial_features.get(app_name, ["admin", "user"])

def get_app_icon(app_name: str) -> str:
    """Get icon for each app"""
    app_icons = {
        "darkhole": "🔮",
        "darkfolio": "📊",
        "confiploy": "⚙️"
    }
    return app_icons.get(app_name, "📱")

def is_app_available_for_plan(app_name: str, plan_id: str) -> bool:
    """Check if app is available for the given plan"""
    plan_apps = {
        "free": ["darkhole"],
        "trial": ["darkhole", "darkfolio", "confiploy"],  # All apps during trial
        "pro": ["darkhole", "darkfolio"],
        "enterprise": ["darkhole", "darkfolio", "confiploy"]
    }
    return app_name in plan_apps.get(plan_id, ["darkhole"])

def get_app_user_limit(app_name: str, plan_id: str) -> int:
    """Get user limit for app based on plan"""
    plan_limits = {
        "free": {"darkhole": 3, "darkfolio": 0, "confiploy": 0},
        "trial": {"darkhole": 10, "darkfolio": 10, "confiploy": 10},
        "pro": {"darkhole": 25, "darkfolio": 25, "confiploy": 0},
        "enterprise": {"darkhole": 100, "darkfolio": 100, "confiploy": 100}
    }
    return plan_limits.get(plan_id, {}).get(app_name, 5)

def get_app_features(app_name: str, plan_id: str) -> list[str]:
    """Get enabled features for app based on plan"""
    if plan_id == "trial":
        return get_trial_features(app_name)

    plan_features = {
        "free": {
            "darkhole": ["admin", "user"],
            "darkfolio": [],
            "confiploy": []
        },
        "pro": {
            "darkhole": ["admin", "user", "rag", "analytics"],
            "darkfolio": ["admin", "user", "stuart", "analyst"],
            "confiploy": []
        },
        "enterprise": {
            "darkhole": ["admin", "user", "rag", "tuner", "analytics", "export"],
            "darkfolio": ["admin", "user", "stuart", "analyst", "reports", "integrations"],
            "confiploy": ["admin", "user", "devops-engineer", "release-manager", "pipelines", "monitoring"]
        }
    }
    return plan_features.get(plan_id, {}).get(app_name, ["admin", "user"])
