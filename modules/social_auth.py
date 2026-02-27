"""
Social Authentication Module
Handles social login providers (Google, GitHub, Microsoft)
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
import logging
from datetime import datetime
import uuid
import os
from typing import Optional
from jose import jwt

from shared.database import get_db
from shared.models import User, UserTenant
from models import SocialAccount, Organization, TenantLDAPConfig, OrganizationUserRole
from schemas import SocialLoginRequest, SocialLoginResponse
from modules.keycloak_client import KeycloakClient

logger = logging.getLogger(__name__)

# Create router for social authentication endpoints
router = APIRouter(prefix="/auth/social", tags=["social-authentication"])


def _normalize_email(email: Optional[str]) -> str:
    return (email or "").strip().lower()


def _find_platform_user_by_email(db: Session, email: str) -> Optional[User]:
    """
    Resolve users case-insensitively and pick the most useful row first.
    This prevents split identities like User@x.com vs user@x.com.
    """
    normalized = _normalize_email(email)
    if not normalized:
        return None

    candidates = db.query(User).filter(
        func.lower(User.email) == normalized
    ).all()

    if not candidates:
        return None

    candidate_ids = [u.id for u in candidates]
    tenant_links = db.query(UserTenant).filter(UserTenant.user_id.in_(candidate_ids)).all()
    org_roles = db.query(OrganizationUserRole).filter(OrganizationUserRole.user_id.in_(candidate_ids)).all()

    non_platform_role_users = set()
    for ut in tenant_links:
        app_roles = ut.app_roles or {}
        if isinstance(app_roles, dict):
            if any(app != "platform" and roles for app, roles in app_roles.items()):
                non_platform_role_users.add(ut.user_id)

    org_role_users = {r.user_id for r in org_roles}

    # Prefer keycloak-linked identity first, then existing org/app membership context.
    candidates.sort(
        key=lambda u: (
            0 if u.keycloak_id else 1,
            0 if u.id in org_role_users else 1,
            0 if u.id in non_platform_role_users else 1,
            u.created_at or datetime.min,
        )
    )
    return candidates[0]


def _merge_user_access_records(db: Session, source_user: User, target_user: User) -> None:
    """
    Merge tenant/org access from source user into target user.
    Used to heal case-split identities for the same email.
    """
    if source_user.id == target_user.id:
        return

    # Merge tenant memberships
    source_tenants = db.query(UserTenant).filter(UserTenant.user_id == source_user.id).all()
    for src in source_tenants:
        dst = db.query(UserTenant).filter(
            UserTenant.user_id == target_user.id,
            UserTenant.tenant_id == src.tenant_id
        ).first()
        if not dst:
            src.user_id = target_user.id
            continue

        src_roles = src.app_roles or {}
        dst_roles = dst.app_roles or {}
        merged = dict(dst_roles)
        for app, roles in src_roles.items():
            existing = set(merged.get(app, []) or [])
            incoming = set(roles or [])
            merged[app] = sorted(existing.union(incoming))
        dst.app_roles = merged

    # Merge org app roles
    source_org_roles = db.query(OrganizationUserRole).filter(
        OrganizationUserRole.user_id == source_user.id
    ).all()
    for src in source_org_roles:
        dst = db.query(OrganizationUserRole).filter(
            OrganizationUserRole.user_id == target_user.id,
            OrganizationUserRole.organization_id == src.organization_id,
            OrganizationUserRole.app_name == src.app_name
        ).first()
        if not dst:
            src.user_id = target_user.id
            continue

        merged_roles = sorted(set((dst.roles or []) + (src.roles or [])))
        dst.roles = merged_roles
        db.delete(src)


def _merge_duplicate_email_access_into_anchor(db: Session, anchor_user: User, email: str) -> None:
    """
    Merge tenant/org access from same-email duplicate rows into the anchor user.
    This heals case-split identities where access was attached to a non-keycloak row.
    """
    normalized = _normalize_email(email)
    if not normalized or not anchor_user:
        return

    duplicates = db.query(User).filter(
        func.lower(User.email) == normalized,
        User.id != anchor_user.id
    ).all()

    if not duplicates:
        return

    for dup in duplicates:
        _merge_user_access_records(db, source_user=dup, target_user=anchor_user)

    if anchor_user.email != normalized:
        anchor_user.email = normalized


def _frontend_callback_uri() -> str:
    base_url = os.getenv("PLATFORM_FRONTEND_URL", "http://platform.local.suranku").rstrip("/")
    callback_path = os.getenv("SOCIAL_CALLBACK_PATH", "/auth/callback.html")
    if not callback_path.startswith("/"):
        callback_path = f"/{callback_path}"
    return f"{base_url}{callback_path}"

def _build_broker_login_url(
    keycloak_base_url: str,
    realm: str,
    frontend_client_id: str,
    redirect_uri: str,
    idp_alias: str
) -> str:
    return (
        f"{keycloak_base_url}/realms/{realm}/protocol/openid-connect/auth"
        f"?client_id={frontend_client_id}"
        f"&response_type=code"
        f"&scope=openid email profile"
        f"&redirect_uri={redirect_uri}"
        f"&kc_idp_hint={idp_alias}"
    )

def _resolve_org_by_hostname(db: Session, org_hostname: str) -> Optional[Organization]:
    host = (org_hostname or "").strip().lower()
    if not host:
        return None
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0].split(":", 1)[0]
    subdomain = host.split(".", 1)[0] if "." in host else host

    return db.query(Organization).filter(
        Organization.deleted_at.is_(None),
        (
            (Organization.dns_hostname.isnot(None) & (Organization.dns_hostname == host)) |
            (Organization.dns_subdomain.isnot(None) & (Organization.dns_subdomain == subdomain)) |
            (Organization.slug == subdomain)
        )
    ).first()

@router.get("/providers")
async def get_social_providers(
    organization_id: Optional[str] = None,
    org_hostname: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Get available social login providers"""
    import os

    # Get Keycloak URL from environment
    keycloak_base_url = os.getenv("KEYCLOAK_PUBLIC_URL", "http://localhost:8080")
    realm = "suranku-platform"

    # Frontend application client ID for social login
    frontend_client_id = os.getenv("KEYCLOAK_FRONTEND_CLIENT_ID", "platform-frontend")

    # Redirect URI after social login
    redirect_uri = _frontend_callback_uri()

    providers = [
        {
            "id": "google",
            "name": "Google",
            "display_name": "Sign in with Google",
            "icon": "google",
            "enabled": True,
            "login_url": _build_broker_login_url(
                keycloak_base_url,
                realm,
                frontend_client_id,
                redirect_uri,
                "google"
            )
        },
        {
            "id": "github",
            "name": "GitHub",
            "display_name": "Sign in with GitHub",
            "icon": "github",
            "enabled": True,
            "login_url": _build_broker_login_url(
                keycloak_base_url,
                realm,
                frontend_client_id,
                redirect_uri,
                "github"
            )
        }
    ]

    org = None
    if organization_id:
        org = db.query(Organization).filter(
            Organization.id == organization_id,
            Organization.deleted_at.is_(None)
        ).first()
    elif org_hostname:
        org = _resolve_org_by_hostname(db, org_hostname)

    # For organization-scoped login, prefer org-specific Microsoft IdP alias.
    # If alias is missing in Keycloak (e.g., legacy config), fall back to global "microsoft"
    # so login still redirects to Microsoft instead of stopping on Keycloak's local login page.
    if org:
        ldap_config = db.query(TenantLDAPConfig).filter(
            TenantLDAPConfig.tenant_id == org.tenant_id,
            TenantLDAPConfig.organization_id == org.id,
            TenantLDAPConfig.provider_type == "azure_ad_graph",
            TenantLDAPConfig.enabled == True
        ).first()

        if ldap_config:
            keycloak_client = KeycloakClient()
            org_alias = KeycloakClient.get_org_microsoft_idp_alias(org.id)
            effective_alias = org_alias

            # Validate the org-specific IdP alias exists; otherwise fallback to "microsoft".
            org_provider = await keycloak_client.get_social_provider_config(org_alias)
            if not org_provider:
                logger.warning(
                    "Org-specific Microsoft IdP alias missing; falling back to global alias. org_id=%s alias=%s",
                    org.id,
                    org_alias
                )
                global_provider = await keycloak_client.get_social_provider_config("microsoft")
                if global_provider:
                    effective_alias = "microsoft"

            providers.append(
                {
                    "id": "microsoft",
                    "name": "Microsoft",
                    "display_name": "Sign in with Microsoft",
                    "icon": "microsoft",
                    "enabled": True,
                    "org_id": org.id,
                    "idp_alias": effective_alias,
                    "login_url": _build_broker_login_url(
                        keycloak_base_url,
                        realm,
                        frontend_client_id,
                        redirect_uri,
                        effective_alias
                    )
                }
            )

    return {
        "providers": providers
    }

@router.post("/login", response_model=SocialLoginResponse)
async def initiate_social_login(
    request: SocialLoginRequest,
    db: Session = Depends(get_db)
):
    """Initiate social login flow"""
    try:
        keycloak_client = KeycloakClient()

        # Get social provider configuration
        provider_config = await keycloak_client.get_social_provider_config(request.provider)

        if not provider_config:
            raise HTTPException(status_code=400, detail=f"Social provider {request.provider} not configured")

        # Generate state parameter for security
        state = str(uuid.uuid4())

        # Build authorization URL
        auth_url = await keycloak_client.build_social_auth_url(
            provider=request.provider,
            state=state,
            redirect_uri=request.redirect_uri
        )

        return SocialLoginResponse(
            provider=request.provider,
            auth_url=auth_url,
            state=state
        )

    except Exception as e:
        logger.error(f"Social login initiation error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to initiate social login: {str(e)}")

@router.get("/callback")
async def handle_oauth_callback(
    code: str,
    state: str = None,
    redirect_uri: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Handle OAuth callback from Keycloak after social login"""
    try:
        import httpx
        from shared.models import UserStatus

        keycloak_client = KeycloakClient()

        callback_redirect_uri = (redirect_uri or "").strip() or _frontend_callback_uri()

        # Exchange authorization code for access token
        token_url = f"{keycloak_client.base_url}/realms/{keycloak_client.realm}/protocol/openid-connect/token"

        async with httpx.AsyncClient() as client:
            response = await client.post(
                token_url,
                data={
                    "grant_type": "authorization_code",
                    "client_id": os.getenv("KEYCLOAK_FRONTEND_CLIENT_ID", "platform-frontend"),
                    "client_secret": os.getenv("KEYCLOAK_FRONTEND_CLIENT_SECRET"),
                    "code": code,
                    "redirect_uri": callback_redirect_uri
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )

            if response.status_code != 200:
                logger.error(f"Token exchange failed: {response.text}")
                raise HTTPException(status_code=400, detail="Authentication failed")

            token_data = response.json()

        # Get user info from Keycloak using access token
        userinfo_url = f"{keycloak_client.base_url}/realms/{keycloak_client.realm}/protocol/openid-connect/userinfo"

        async with httpx.AsyncClient() as client:
            response = await client.get(
                userinfo_url,
                headers={"Authorization": f"Bearer {token_data['access_token']}"}
            )

            if response.status_code == 200:
                user_info = response.json()
            else:
                logger.warning(
                    "Failed to get user info from userinfo endpoint (status=%s). Falling back to id_token claims.",
                    response.status_code,
                )
                id_token = token_data.get("id_token")
                if not id_token:
                    logger.error(f"Failed to get user info: {response.text}")
                    raise HTTPException(status_code=400, detail="Failed to get user information")
                user_info = jwt.get_unverified_claims(id_token)

        # Ensure required identity fields exist even when using fallback claims
        if not user_info.get("email"):
            raise HTTPException(status_code=400, detail="Social provider did not return email")

        # Check if user exists in our database (case-insensitive)
        user = _find_platform_user_by_email(db, user_info["email"])

        is_new_user = False
        canonical_email = _normalize_email(user_info["email"])
        if not user:
            # Create new platform user (no tenant association)
            user = User(
                email=canonical_email,
                first_name=user_info.get("given_name", ""),
                last_name=user_info.get("family_name", ""),
                status=UserStatus.ACTIVE,  # Social login users are pre-verified
                is_email_verified=True,    # Email verified by social provider
                keycloak_id=user_info.get("sub")  # Keycloak user ID
            )
            db.add(user)
            db.flush()
            is_new_user = True

            logger.info(f"Created new platform user via social login: {user.email}")
        else:
            incoming_sub = user_info.get("sub")
            if incoming_sub:
                # If the subject already belongs to another same-email row, merge access into that row.
                sub_owner = db.query(User).filter(User.keycloak_id == incoming_sub).first()
                if sub_owner and sub_owner.id != user.id:
                    if _normalize_email(sub_owner.email) == canonical_email:
                        _merge_user_access_records(db, source_user=user, target_user=sub_owner)
                        user = sub_owner
                    else:
                        logger.warning(
                            "Incoming social subject is linked to a different email user_id=%s; leaving existing link unchanged",
                            sub_owner.id
                        )

            # Keep canonical lowercase email. If another row already owns it, merge instead of updating into conflict.
            if user.email != canonical_email:
                conflicting = db.query(User).filter(
                    func.lower(User.email) == canonical_email,
                    User.id != user.id
                ).first()
                if conflicting:
                    _merge_user_access_records(db, source_user=user, target_user=conflicting)
                    user = conflicting
                else:
                    user.email = canonical_email

            # Backfill Keycloak subject only after identity conflict resolution.
            if incoming_sub and not user.keycloak_id:
                user.keycloak_id = incoming_sub

        # Ensure any same-email duplicate rows contribute their memberships/roles
        # to the keycloak-linked login identity.
        _merge_duplicate_email_access_into_anchor(db, user, canonical_email)

        # Update last login
        user.last_login = datetime.utcnow()

        # Check if social account link exists
        provider = user_info.get("identity_provider", "unknown")
        if provider != "unknown":
            social_account = db.query(SocialAccount).filter(
                SocialAccount.user_id == user.id,
                SocialAccount.provider == provider
            ).first()

            if not social_account:
                social_account = SocialAccount(
                    user_id=user.id,
                    provider=provider,
                    social_id=user_info.get("sub"),
                    email=user_info["email"],
                    profile_data=user_info,
                    is_verified=True
                )
                db.add(social_account)

        # Create default tenant for new platform users
        if is_new_user:
            try:
                from shared.models import Tenant, UserTenant
                from datetime import timedelta

                # Create default tenant for platform user
                tenant_name = f"{user.first_name} {user.last_name}".strip() or user.email.split('@')[0]
                tenant = Tenant(
                    name=f"{tenant_name}'s Workspace",
                    subscription_status="trial",
                    plan_id="free",
                    trial_started_at=datetime.utcnow(),
                    trial_expires_at=datetime.utcnow() + timedelta(days=14),
                    is_active=True
                )
                db.add(tenant)
                db.flush()

                # Create UserTenant with tenant_admin role
                user_tenant = UserTenant(
                    user_id=user.id,
                    tenant_id=tenant.id,
                    app_roles={"platform": ["tenant_admin"]},
                    status="active",
                    joined_at=datetime.utcnow()
                )
                db.add(user_tenant)

                logger.info(f"Created default tenant '{tenant.name}' for social login user: {user.email}")

            except Exception as e:
                logger.error(f"Failed to create default tenant for social login user: {e}")
                # Don't fail the entire login process
                pass

        db.commit()

        # Return redirect to platform dashboard
        platform_url = os.getenv("PLATFORM_FRONTEND_URL", "http://platform.local.suranku")
        redirect_url = f"{platform_url}/dashboard.html?social_login_success=true&user_id={user.id}"

        return {
            "message": "Authentication successful",
            "redirect_url": redirect_url,
            "user": {
                "id": user.id,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "is_first_login": is_new_user
            },
            "keycloak_token": token_data.get("access_token")  # Pass the original Keycloak token
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"OAuth callback error: {e}")
        raise HTTPException(status_code=500, detail=f"Social login failed: {str(e)}")
