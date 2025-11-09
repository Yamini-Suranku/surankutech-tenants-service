"""
Social Authentication Module
Handles social login providers (Google, GitHub, Microsoft)
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
import logging
from datetime import datetime
import uuid

from services.shared.database import get_db
from services.shared.models import User
from services.tenants.models import SocialAccount
from services.tenants.schemas import SocialLoginRequest, SocialLoginResponse
from services.tenants.keycloak_client import KeycloakClient

logger = logging.getLogger(__name__)

# Create router for social authentication endpoints
router = APIRouter(prefix="/auth/social", tags=["social-authentication"])

@router.get("/providers")
async def get_social_providers():
    """Get available social login providers"""
    # Use localhost for browser-accessible URLs
    keycloak_public_url = "http://localhost:8080/auth"

    return {
        "providers": [
            {
                "id": "google",
                "name": "Google",
                "display_name": "Sign in with Google",
                "icon": "google",
                "enabled": True,
                "login_url": f"{keycloak_public_url}/realms/suranku-platform/protocol/openid-connect/auth?client_id=google&response_type=code&scope=openid email profile&redirect_uri={keycloak_public_url}/realms/suranku-platform/broker/google/endpoint"
            },
            {
                "id": "github",
                "name": "GitHub",
                "display_name": "Sign in with GitHub",
                "icon": "github",
                "enabled": True,
                "login_url": f"{keycloak_public_url}/realms/suranku-platform/protocol/openid-connect/auth?client_id=github&response_type=code&scope=user:email&redirect_uri={keycloak_public_url}/realms/suranku-platform/broker/github/endpoint"
            },
            {
                "id": "microsoft",
                "name": "Microsoft",
                "display_name": "Sign in with Microsoft",
                "icon": "microsoft",
                "enabled": True,
                "login_url": f"{keycloak_public_url}/realms/suranku-platform/protocol/openid-connect/auth?client_id=microsoft&response_type=code&scope=openid email profile&redirect_uri={keycloak_public_url}/realms/suranku-platform/broker/microsoft/endpoint"
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

@router.post("/callback")
async def handle_social_callback(
    provider: str,
    code: str,
    state: str,
    db: Session = Depends(get_db)
):
    """Handle social login callback"""
    try:
        keycloak_client = KeycloakClient()

        # Exchange code for tokens
        token_response = await keycloak_client.exchange_social_code(
            provider=provider,
            code=code,
            state=state
        )

        # Get user info from social provider
        user_info = await keycloak_client.get_social_user_info(
            provider=provider,
            access_token=token_response["access_token"]
        )

        # Check if user exists
        user = db.query(User).filter(User.email == user_info["email"]).first()

        if not user:
            # Create new user
            user = User(
                email=user_info["email"],
                first_name=user_info.get("first_name", ""),
                last_name=user_info.get("last_name", ""),
                status="active",
                is_email_verified=True
            )
            db.add(user)
            db.flush()

            # Create user in Keycloak
            keycloak_user_id = await keycloak_client.create_social_user(
                email=user_info["email"],
                first_name=user_info.get("first_name", ""),
                last_name=user_info.get("last_name", ""),
                provider=provider,
                social_id=user_info["id"]
            )
            user.keycloak_id = keycloak_user_id

        # Create or update social account link
        social_account = db.query(SocialAccount).filter(
            SocialAccount.user_id == user.id,
            SocialAccount.provider == provider
        ).first()

        if not social_account:
            social_account = SocialAccount(
                user_id=user.id,
                provider=provider,
                social_id=user_info["id"],
                email=user_info["email"],
                profile_data=user_info
            )
            db.add(social_account)

        # Update last login
        user.last_login = datetime.utcnow()
        db.commit()

        # Generate JWT token
        jwt_token = await keycloak_client.generate_user_token(user.keycloak_id)

        return {
            "access_token": jwt_token,
            "user": {
                "id": user.id,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name
            },
            "social_account": {
                "provider": provider,
                "linked_at": social_account.created_at
            }
        }

    except Exception as e:
        logger.error(f"Social callback error: {e}")
        raise HTTPException(status_code=500, detail=f"Social login failed: {str(e)}")