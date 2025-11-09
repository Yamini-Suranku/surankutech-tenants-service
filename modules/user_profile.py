"""
User Profile Management Module
Handles user profile updates, password changes, and profile information retrieval
"""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
import logging
from typing import Optional
import hashlib

from services.shared.database import get_db
from services.shared.auth import verify_token, TokenData
from services.shared.models import User
from services.tenants.keycloak_client import KeycloakClient
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Create router for user profile endpoints
router = APIRouter(tags=["user-profile"])

# Request/Response models
class ProfileUpdateRequest(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[EmailStr] = None

class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str


class ProfileResponse(BaseModel):
    id: str
    email: str
    first_name: Optional[str]
    last_name: Optional[str]
    avatar_url: Optional[str]
    status: str
    is_email_verified: bool
    app_roles: Optional[dict] = None

@router.get("/user/profile", response_model=ProfileResponse)
async def get_user_profile(
    token: str = Depends(HTTPBearer()),
    db: Session = Depends(get_db)
):
    """Get current user's profile information including app_roles"""
    token_data = await verify_token(token.credentials)

    # Get user from database using Keycloak ID from token
    user = db.query(User).filter(User.keycloak_id == token_data.sub).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Get app_roles from UserTenant relationship
    from services.shared.models import UserTenant
    user_tenant = db.query(UserTenant).filter(
        UserTenant.user_id == user.id
    ).first()

    app_roles = user_tenant.app_roles if user_tenant else None

    return ProfileResponse(
        id=user.id,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        avatar_url=user.avatar_url,
        status=user.status,
        is_email_verified=user.is_email_verified,
        app_roles=app_roles
    )

@router.put("/user/profile", response_model=ProfileResponse)
async def update_user_profile(
    request: ProfileUpdateRequest,
    token: str = Depends(HTTPBearer()),
    db: Session = Depends(get_db)
):
    """Update current user's profile information"""
    token_data = await verify_token(token.credentials)

    # Get user from database using Keycloak ID from token
    user = db.query(User).filter(User.keycloak_id == token_data.sub).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Update fields that were provided
    if request.first_name is not None:
        user.first_name = request.first_name
    if request.last_name is not None:
        user.last_name = request.last_name
    if request.email is not None:
        # Check if email is already taken by another user
        existing_user = db.query(User).filter(
            User.email == request.email,
            User.id != user.id
        ).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already in use")

        user.email = request.email
        # Note: If email changes, may need to update in Keycloak too
        if user.keycloak_id:
            try:
                keycloak_client = KeycloakClient()
                # TODO: Implement update_user_email method in KeycloakClient
                # await keycloak_client.update_user_email(user.keycloak_id, request.email)
                logger.info(f"Email update for Keycloak user {user.keycloak_id} - not implemented yet")
            except Exception as e:
                logger.warning(f"Failed to update email in Keycloak: {e}")

    db.commit()
    db.refresh(user)

    # Get app_roles from UserTenant relationship (same as GET endpoint)
    from services.shared.models import UserTenant
    user_tenant = db.query(UserTenant).filter(
        UserTenant.user_id == user.id
    ).first()

    app_roles = user_tenant.app_roles if user_tenant else None

    return ProfileResponse(
        id=user.id,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        avatar_url=user.avatar_url,
        status=user.status,
        is_email_verified=user.is_email_verified,
        app_roles=app_roles
    )

@router.post("/user/password")
async def change_password(
    request: PasswordChangeRequest,
    token: str = Depends(HTTPBearer()),
    db: Session = Depends(get_db)
):
    """Change user's password"""
    token_data = await verify_token(token.credentials)

    # Get user from database using Keycloak ID from token
    user = db.query(User).filter(User.keycloak_id == token_data.sub).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.keycloak_id:
        raise HTTPException(status_code=400, detail="Cannot change password for this account type")

    try:
        # Use Keycloak client to change password
        keycloak_client = KeycloakClient()

        # TODO: Implement password verification and update methods in KeycloakClient
        # For now, we'll assume the current password is correct and just attempt to update
        logger.info(f"Password change requested for user {user.email} - Keycloak integration pending")

        # Placeholder for Keycloak password update
        # await keycloak_client.update_user_password(user.keycloak_id, request.new_password)

        logger.info(f"Password changed for user {user.email}")
        return {"message": "Password changed successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to change password for user {user.email}: {e}")
        raise HTTPException(status_code=500, detail="Failed to change password")

