"""
Social Authentication Module
Handles social login providers (Google, GitHub, Microsoft)
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
import logging
from datetime import datetime
import uuid
import os

from shared.database import get_db
from shared.models import User
from models import SocialAccount
from schemas import SocialLoginRequest, SocialLoginResponse
from modules.keycloak_client import KeycloakClient

logger = logging.getLogger(__name__)

# Create router for social authentication endpoints
router = APIRouter(prefix="/auth/social", tags=["social-authentication"])

@router.get("/providers")
async def get_social_providers():
    """Get available social login providers"""
    import os

    # Get Keycloak URL from environment
    keycloak_base_url = os.getenv("KEYCLOAK_PUBLIC_URL", "http://localhost:8080")
    realm = "suranku-platform"

    # Frontend application client ID for social login
    frontend_client_id = os.getenv("KEYCLOAK_FRONTEND_CLIENT_ID", "platform-frontend")

    # Redirect URI after social login
    redirect_uri = os.getenv("PLATFORM_FRONTEND_URL", "http://platform.local.suranku") + "/auth/callback"

    return {
        "providers": [
            {
                "id": "google",
                "name": "Google",
                "display_name": "Sign in with Google",
                "icon": "google",
                "enabled": True,
                "login_url": f"{keycloak_base_url}/realms/{realm}/protocol/openid-connect/auth?client_id={frontend_client_id}&response_type=code&scope=openid email profile&redirect_uri={redirect_uri}&kc_idp_hint=google"
            },
            {
                "id": "microsoft",
                "name": "Microsoft",
                "display_name": "Sign in with Microsoft",
                "icon": "microsoft",
                "enabled": True,
                "login_url": f"{keycloak_base_url}/realms/{realm}/protocol/openid-connect/auth?client_id={frontend_client_id}&response_type=code&scope=openid email profile&redirect_uri={redirect_uri}&kc_idp_hint=microsoft"
            },
            {
                "id": "github",
                "name": "GitHub",
                "display_name": "Sign in with GitHub",
                "icon": "github",
                "enabled": True,
                "login_url": f"{keycloak_base_url}/realms/{realm}/protocol/openid-connect/auth?client_id={frontend_client_id}&response_type=code&scope=openid email profile&redirect_uri={redirect_uri}&kc_idp_hint=github"
            }
        ]
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
    db: Session = Depends(get_db)
):
    """Handle OAuth callback from Keycloak after social login"""
    try:
        import httpx
        from shared.models import UserStatus
        from shared.auth import create_access_token

        keycloak_client = KeycloakClient()

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
                    "redirect_uri": os.getenv("PLATFORM_FRONTEND_URL", "http://platform.local.suranku") + "/auth/callback"
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

            if response.status_code != 200:
                logger.error(f"Failed to get user info: {response.text}")
                raise HTTPException(status_code=400, detail="Failed to get user information")

            user_info = response.json()

        # Check if user exists in our database
        user = db.query(User).filter(User.email == user_info["email"]).first()

        is_new_user = False
        if not user:
            # Create new platform user (no tenant association)
            user = User(
                email=user_info["email"],
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
        redirect_url = f"{platform_url}/dashboard?social_login_success=true&user_id={user.id}"

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

    except Exception as e:
        logger.error(f"OAuth callback error: {e}")
        raise HTTPException(status_code=500, detail=f"Social login failed: {str(e)}")
