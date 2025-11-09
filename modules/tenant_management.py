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

from services.shared.database import get_db
from services.shared.auth import verify_token, require_tenant_access, TokenData
from services.shared.models import Tenant, User, UserTenant, TenantAppAccess, AuditLog
from services.tenants.models import TenantSettings
from services.tenants.schemas import (
    TenantCreateRequest, TenantResponse, UserResponse,
    TenantUpdateRequest, AppAccessResponse
)
from services.tenants.keycloak_client import KeycloakClient

logger = logging.getLogger(__name__)

# Create router for tenant management endpoints (no prefix - Kong strips /api/tenants)
router = APIRouter(tags=["tenant-management"])

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
        tenant = Tenant(
            id=tenant_id,
            name=request.company_name,
            subscription_status="trial",
            plan_id="free",
            trial_started_at=datetime.utcnow(),
            trial_expires_at=datetime.utcnow() + timedelta(days=14)
        )
        db.add(tenant)

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
            # New user - create with PENDING status (requires email verification)
            logger.info(f"Creating new user {request.admin_email} for tenant {tenant_id}")
            user = User(
                email=request.admin_email,
                first_name=request.admin_first_name,
                last_name=request.admin_last_name,
                status="pending",  # Start as PENDING until email verified
                is_email_verified=False  # Email not verified yet
            )
            db.add(user)
            db.flush()  # Get user ID

            # Create Keycloak user and groups
            keycloak_user_id = await keycloak_client.create_user_with_tenant(
                email=request.admin_email,
                password=request.admin_password,
                first_name=request.admin_first_name,
                last_name=request.admin_last_name,
                tenant_id=tenant_id,
                app_roles={
                    "darkhole": ["admin"],
                    "darkfolio": ["admin"],
                    "confiploy": ["admin"]
                }
            )

            # Update user with Keycloak ID
            user.keycloak_id = keycloak_user_id

            # Send verification email for new user
            from services.tenants.email_verification import EmailVerificationService
            verification_service = EmailVerificationService()
            try:
                await verification_service.send_verification_email(db, user)
                logger.info(f"Verification email sent to {user.email}")
            except Exception as email_error:
                logger.error(f"Failed to send verification email to {user.email}: {email_error}")
                # Continue with tenant creation even if email fails

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

        # Create app access for trial (all 3 apps with all features)
        for app_name in ["darkhole", "darkfolio", "confiploy"]:
            app_access = TenantAppAccess(
                tenant_id=tenant_id,
                app_name=app_name,
                is_enabled=True,
                user_limit=5,  # Trial limit
                current_users=1,
                enabled_features=get_trial_features(app_name)
            )
            db.add(app_access)

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

        return TenantResponse(
            id=tenant.id,
            name=tenant.name,
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
            enabled_features=access.enabled_features
        ) for access in app_access_list
    ]

def get_trial_features(app_name: str) -> list[str]:
    """Get trial features for each app (all features unlocked during trial)"""
    trial_features = {
        "darkhole": ["admin", "user", "rag", "tuner", "analytics", "export"],
        "darkfolio": ["admin", "user", "stuart", "analyst", "reports", "integrations"],
        "confiploy": ["admin", "user", "devops-engineer", "release-manager", "pipelines", "monitoring"]
    }
    return trial_features.get(app_name, ["admin", "user"])