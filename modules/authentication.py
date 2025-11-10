
"""
Authentication Module
Handles login, registration, email verification, and social authentication
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
import logging
from datetime import datetime, timedelta
import uuid
from pydantic import BaseModel, EmailStr

from shared.database import get_db
from shared.auth import verify_token, TokenData, get_current_token_data
from shared.models import Tenant, User, UserTenant, TenantAppAccess, AuditLog, UserStatus
from models import TenantSettings, SocialAccount, PasswordResetToken
from schemas import (
    LoginRequest, LoginResponse, TenantInfo, UserMeResponse, UserResponse,
    TenantSwitchRequest, SocialLoginRequest, SocialLoginResponse
)
from keycloak_client import KeycloakClient
import secrets
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)

# Create router for authentication endpoints
router = APIRouter(prefix="/auth", tags=["authentication"])

class UserRegisterRequest(BaseModel):
    email: str
    password: str
    first_name: str
    last_name: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

@router.post("/register")
async def register_user(
    request: UserRegisterRequest,
    db: Session = Depends(get_db)
):
    """Register new user with email verification required"""
    try:
        keycloak_client = KeycloakClient()

        # Check if user already exists
        existing_user = db.query(User).filter(User.email == request.email).first()
        if existing_user:
            if existing_user.is_email_verified:
                raise HTTPException(status_code=400, detail="User with this email already exists")
            else:
                # User exists but not verified - allow resending verification
                from email_verification import EmailVerificationService
                verification_service = EmailVerificationService()
                result = await verification_service.send_verification_email(db, existing_user, resend=True)
                return {
                    "status": "verification_required",
                    "message": "Please verify your email address to complete registration",
                    "verification_status": result["status"],
                    "verification_message": result["message"]
                }

        # Create tenant for the user
        tenant_id = str(uuid.uuid4())
        tenant = Tenant(
            id=tenant_id,
            name=f"{request.first_name} {request.last_name}'s Organization",
            subscription_status="trial",
            plan_id="free",
            trial_started_at=datetime.utcnow(),
            trial_expires_at=datetime.utcnow() + timedelta(days=14)
        )
        db.add(tenant)
        db.flush()  # Flush tenant to ensure it exists in database

        # Create user in PENDING state (requires email verification)
        user = User(
            email=request.email,
            first_name=request.first_name,
            last_name=request.last_name,
            status=UserStatus.PENDING,  # Start as PENDING until email verified
            is_email_verified=False     # Email not verified yet
        )
        db.add(user)
        db.flush()  # Get user ID

        # Create Keycloak user (disabled until email verified)
        keycloak_user_id = await keycloak_client.create_user_with_tenant(
            email=request.email,
            password=request.password,
            first_name=request.first_name,
            last_name=request.last_name,
            tenant_id=tenant_id,
            app_roles={
                "darkhole": ["admin"],
                "darkfolio": ["admin"],
                "confiploy": ["admin"]
            }
        )

        # Update user with Keycloak ID
        user.keycloak_id = keycloak_user_id

        # Create user-tenant relationship (also PENDING)
        user_tenant = UserTenant(
            user_id=user.id,
            tenant_id=tenant_id,
            app_roles={
                "darkhole": ["admin"],
                "darkfolio": ["admin"],
                "confiploy": ["admin"]
            },
            status=UserStatus.PENDING,  # Will be activated after email verification
            joined_at=None              # Will be set after verification
        )
        db.add(user_tenant)

        # Create app access for trial
        for app_name in ["darkhole", "darkfolio", "confiploy"]:
            app_access = TenantAppAccess(
                tenant_id=tenant_id,
                app_name=app_name,
                is_enabled=True,
                user_limit=5,  # Trial limit
                current_users=0,  # Will be incremented after verification
                enabled_features=get_trial_features(app_name)
            )
            db.add(app_access)

        # Create tenant settings
        tenant_settings = TenantSettings(
            tenant_id=tenant_id,
            timezone="UTC",
            date_format="YYYY-MM-DD",
            language="en"
        )
        db.add(tenant_settings)

        db.commit()

        # Send verification email
        from email_verification import EmailVerificationService
        verification_service = EmailVerificationService()
        verification_result = await verification_service.send_verification_email(db, user)

        return {
            "status": "verification_required",
            "message": "Registration successful! Please check your email to verify your account before logging in.",
            "user_id": user.id,
            "email": user.email,
            "verification_status": verification_result["status"],
            "verification_message": verification_result["message"],
            "expires_at": verification_result.get("expires_at")
        }

    except Exception as e:
        logger.error(f"Registration error: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

@router.post("/login", response_model=LoginResponse)
async def login_user(
    request: LoginRequest,
    db: Session = Depends(get_db)
):
    """Authenticate user with email and password"""
    try:
        keycloak_client = KeycloakClient()

        # Authenticate with Keycloak
        auth_result = await keycloak_client.authenticate_user(request.email, request.password)

        # Get user info from Keycloak response
        user_info = auth_result["user_info"]

        # Find user in our database
        user = db.query(User).filter(User.email == request.email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Get all user's active tenant relationships
        user_tenants = db.query(UserTenant).filter(
            UserTenant.user_id == user.id,
            UserTenant.status == "active"
        ).order_by(UserTenant.last_accessed_at.desc().nulls_last()).all()

        if not user_tenants:
            raise HTTPException(status_code=400, detail="User has no active tenant")

        # Determine current tenant using "last used" logic
        current_user_tenant = user_tenants[0]  # First in desc order = most recently accessed

        # Build tenants list with their information
        tenants_info = []
        current_tenant_info = None

        for ut in user_tenants:
            tenant = db.query(Tenant).filter(Tenant.id == ut.tenant_id).first()
            if tenant:
                # Extract roles from app_roles (flatten all app roles into single list)
                roles = []
                if ut.app_roles:
                    for app_name, app_roles in ut.app_roles.items():
                        if isinstance(app_roles, list):
                            roles.extend(app_roles)
                        else:
                            roles.append(str(app_roles))

                tenant_info = {
                    "id": tenant.id,
                    "name": tenant.name,
                    "domain": tenant.domain,
                    "logo_url": tenant.logo_url,
                    "roles": list(set(roles)),  # Remove duplicates
                    "is_active": True
                }
                tenants_info.append(tenant_info)

                # Set current tenant (the first/most recent one)
                if ut == current_user_tenant:
                    current_tenant_info = tenant_info

        # Update last_accessed_at for the current tenant being used
        current_user_tenant.last_accessed_at = datetime.utcnow()
        db.commit()

        # Create audit log
        audit_log = AuditLog(
            action="user_login",
            resource_type="user",
            resource_id=user.id,
            user_id=user.id,
            tenant_id=current_user_tenant.tenant_id,
            details={"login_method": "email_password", "user_agent": "api"},
            created_at=datetime.utcnow()
        )
        db.add(audit_log)
        db.commit()

        # Format user response
        user_response = UserResponse(
            id=user.id,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            status=user.status,
            app_roles=current_user_tenant.app_roles,
            joined_at=current_user_tenant.joined_at,
            last_login=user.last_login
        )

        # Convert tenant info dicts to TenantInfo objects
        tenant_objects = [TenantInfo(**tenant) for tenant in tenants_info]
        current_tenant_object = TenantInfo(**current_tenant_info) if current_tenant_info else None

        return LoginResponse(
            access_token=auth_result["access_token"],
            token_type="bearer",
            expires_in=auth_result["expires_in"],
            user=user_response,
            tenants=tenant_objects,
            current_tenant=current_tenant_object
        )

    except Exception as e:
        logger.error(f"Login error: {e}")
        if "Authentication failed" in str(e):
            raise HTTPException(status_code=401, detail="Invalid email or password")
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")

@router.get("/me", response_model=UserMeResponse)
async def get_current_user(
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db)
):
    """Get current authenticated user info with all tenants"""
    try:
        # Find user in database using Keycloak ID from token
        user = db.query(User).filter(User.keycloak_id == token_data.sub).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Get all user's active tenant relationships
        user_tenants = db.query(UserTenant).filter(
            UserTenant.user_id == user.id,
            UserTenant.status == "active"
        ).order_by(UserTenant.last_accessed_at.desc().nulls_last()).all()

        if not user_tenants:
            raise HTTPException(status_code=400, detail="User has no active tenant")

        # Get current tenant (use most recently accessed - first in ordered list)
        current_user_tenant = user_tenants[0]

        # Build tenants list with their information
        tenants_info = []
        current_tenant_info = None

        for ut in user_tenants:
            tenant = db.query(Tenant).filter(Tenant.id == ut.tenant_id).first()
            if tenant:
                # Extract roles from app_roles
                roles = []
                if ut.app_roles:
                    for app_name, app_roles in ut.app_roles.items():
                        if isinstance(app_roles, list):
                            roles.extend(app_roles)
                        else:
                            roles.append(str(app_roles))

                tenant_info = {
                    "id": tenant.id,
                    "name": tenant.name,
                    "domain": tenant.domain,
                    "logo_url": tenant.logo_url,
                    "roles": list(set(roles)),
                    "is_active": True
                }
                tenants_info.append(tenant_info)

                # Set current tenant
                if ut == current_user_tenant:
                    current_tenant_info = tenant_info

        # Format user response
        user_response = UserResponse(
            id=user.id,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            status=user.status,
            app_roles=current_user_tenant.app_roles,
            joined_at=current_user_tenant.joined_at,
            last_login=user.last_login
        )

        # Convert tenant info dicts to TenantInfo objects
        tenant_objects = [TenantInfo(**tenant) for tenant in tenants_info]
        current_tenant_object = TenantInfo(**current_tenant_info) if current_tenant_info else None

        return UserMeResponse(
            user=user_response,
            tenants=tenant_objects,
            current_tenant=current_tenant_object
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get current user error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get user info")

@router.post("/switch-tenant")
async def switch_tenant(
    request: TenantSwitchRequest,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db)
):
    """Switch active tenant for user"""
    try:
        keycloak_client = KeycloakClient()

        # Verify user has access to target tenant
        user_tenant = db.query(UserTenant).filter(
            UserTenant.user_id == token_data.sub,
            UserTenant.tenant_id == request.tenant_id,
            UserTenant.status == "active"
        ).first()

        if not user_tenant:
            raise HTTPException(status_code=403, detail="Access denied to tenant")

        # Generate new token with updated tenant context
        new_token = await keycloak_client.generate_tenant_token(
            user_id=token_data.sub,
            tenant_id=request.tenant_id,
            app_roles=user_tenant.app_roles
        )

        return {"new_token": new_token, "active_tenant": request.tenant_id}

    except Exception as e:
        logger.error(f"Tenant switch error: {e}")
        raise HTTPException(status_code=500, detail="Failed to switch tenant")

@router.post("/refresh")
async def refresh_token(
    token_data: TokenData = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """Refresh access token"""
    try:
        # For now, this is a placeholder since we're using Keycloak tokens
        # In a full implementation, you'd use the refresh token from Keycloak
        return {"message": "Token refresh not implemented yet"}

    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        raise HTTPException(status_code=500, detail="Token refresh failed")

@router.post("/forgot-password")
async def forgot_password(
    request: ForgotPasswordRequest,
    db: Session = Depends(get_db)
):
    """Send password reset email"""
    try:
        # Find user by email
        user = db.query(User).filter(User.email == request.email).first()

        # Always return success to prevent email enumeration
        if not user:
            logger.warning(f"Password reset requested for non-existent email: {request.email}")
            return {"message": "If an account with that email exists, you will receive a password reset link"}

        if not user.keycloak_id:
            logger.warning(f"Password reset requested for social login user: {request.email}")
            return {"message": "If an account with that email exists, you will receive a password reset link"}

        # Generate reset token
        reset_token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(hours=1)  # 1 hour expiry

        # Invalidate any existing reset tokens for this user
        db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.is_used == False
        ).update({"is_used": True})

        # Create new reset token
        password_reset = PasswordResetToken(
            user_id=user.id,
            token=reset_token,
            email=user.email,
            expires_at=expires_at
        )
        db.add(password_reset)
        db.commit()

        # Send reset email
        await send_password_reset_email(user.email, reset_token, user.first_name)

        logger.info(f"Password reset email sent to {user.email}")
        return {"message": "If an account with that email exists, you will receive a password reset link"}

    except Exception as e:
        logger.error(f"Failed to process forgot password request: {e}")
        # Still return success to prevent email enumeration
        return {"message": "If an account with that email exists, you will receive a password reset link"}

@router.post("/reset-password")
async def reset_password(
    request: ResetPasswordRequest,
    db: Session = Depends(get_db)
):
    """Reset password using token"""
    try:
        # Find valid reset token
        reset_token = db.query(PasswordResetToken).filter(
            PasswordResetToken.token == request.token,
            PasswordResetToken.is_used == False,
            PasswordResetToken.expires_at > datetime.utcnow()
        ).first()

        if not reset_token:
            raise HTTPException(status_code=400, detail="Invalid or expired reset token")

        # Get user
        user = db.query(User).filter(User.id == reset_token.user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        if not user.keycloak_id:
            raise HTTPException(status_code=400, detail="Cannot reset password for this account type")

        # Update password in Keycloak
        keycloak_client = KeycloakClient()
        password_updated = await keycloak_client.update_user_password(user.keycloak_id, request.new_password)

        if not password_updated:
            raise HTTPException(status_code=500, detail="Failed to update password in authentication system")

        # Mark token as used only after successful password update
        reset_token.is_used = True
        reset_token.used_at = datetime.utcnow()
        db.commit()

        logger.info(f"Password reset completed for user {user.email}")
        return {"message": "Password reset successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to reset password: {e}")
        raise HTTPException(status_code=500, detail="Failed to reset password")

async def send_password_reset_email(email: str, token: str, first_name: str = None):
    """Send password reset email using SMTP configuration"""
    try:
        # Get SMTP configuration from environment
        smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        smtp_user = os.getenv("SMTP_USER")
        smtp_password = os.getenv("SMTP_PASSWORD")
        smtp_use_tls = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
        email_from = os.getenv("EMAIL_FROM", smtp_user)

        if not all([smtp_user, smtp_password, email_from]):
            logger.warning("SMTP not configured, skipping password reset email")
            return

        # Create reset URL - assuming frontend is accessible
        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:8000/vanilla")
        reset_url = f"{frontend_url}/pages/reset-password.html?token={token}"

        # Create email content
        display_name = first_name or email.split('@')[0]

        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Reset Your SurankuTech Password"
        msg["From"] = f"SurankuTech <{email_from}>"
        msg["To"] = email

        # HTML email body
        html_body = f"""
        <html>
          <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
              <h1 style="color: #0b80ee; text-align: center;">Reset Your Password</h1>

              <p>Hello {display_name},</p>

              <p>We received a request to reset your password for your SurankuTech account. If you did not make this request, you can safely ignore this email.</p>

              <p>To reset your password, click the button below:</p>

              <div style="text-align: center; margin: 30px 0;">
                <a href="{reset_url}"
                   style="background-color: #0b80ee; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: bold;">
                  Reset Password
                </a>
              </div>

              <p>Or copy and paste this link into your browser:</p>
              <p style="word-break: break-all; background-color: #f5f5f5; padding: 10px; border-radius: 4px;">
                {reset_url}
              </p>

              <p><strong>This link will expire in 1 hour.</strong></p>

              <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">

              <p style="color: #666; font-size: 14px;">
                If you're having trouble with the button above, copy and paste the link into your web browser.
              </p>

              <p style="color: #666; font-size: 14px;">
                Best regards,<br>
                The SurankuTech Team
              </p>
            </div>
          </body>
        </html>
        """

        # Plain text fallback
        text_body = f"""
        Reset Your Password

        Hello {display_name},

        We received a request to reset your password for your SurankuTech account.
        If you did not make this request, you can safely ignore this email.

        To reset your password, visit this link:
        {reset_url}

        This link will expire in 1 hour.

        Best regards,
        The SurankuTech Team
        """

        # Attach parts
        html_part = MIMEText(html_body, "html")
        text_part = MIMEText(text_body, "plain")
        msg.attach(text_part)
        msg.attach(html_part)

        # Send email
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            if smtp_use_tls:
                server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(msg)

        logger.info(f"Password reset email sent successfully to {email}")

    except Exception as e:
        logger.error(f"Failed to send password reset email to {email}: {e}")
        # Don't raise exception - we don't want to expose email sending failures

class ApplicationSelectRequest(BaseModel):
    email: str
    password: str
    application_id: str

@router.post("/select-application")
async def select_application(
    request: ApplicationSelectRequest,
    db: Session = Depends(get_db)
):
    """
    Handle application selection after initial login
    This endpoint allows users to select which application they want to access
    """
    try:
        # First verify the user credentials (similar to login)
        user = db.query(User).filter(User.email == request.email).first()
        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # Get user's Keycloak authentication
        keycloak_client = KeycloakClient()
        keycloak_response = await keycloak_client.authenticate_user(request.email, request.password)

        if not keycloak_response:
            raise HTTPException(status_code=401, detail="Authentication failed")

        # Get user tenants and find the one with access to the requested application
        user_tenants = db.query(UserTenant).filter(
            UserTenant.user_id == user.id,
            UserTenant.status == "active"
        ).order_by(UserTenant.last_accessed_at.desc()).all()

        if not user_tenants:
            raise HTTPException(status_code=403, detail="No active tenants found")

        # Find tenant with access to the requested application
        selected_tenant = None
        has_app_access = False

        for ut in user_tenants:
            if ut.app_roles and request.application_id in ut.app_roles:
                selected_tenant = ut
                has_app_access = True
                break

        if not has_app_access:
            raise HTTPException(status_code=403, detail="You don't have access to this application")

        # Update last accessed time for the selected tenant
        selected_tenant.last_accessed_at = datetime.utcnow()
        db.commit()

        # Get tenant info
        tenant = db.query(Tenant).filter(Tenant.id == selected_tenant.tenant_id).first()

        # Create response similar to login
        user_response = {
            "id": user.id,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "status": user.status.value if hasattr(user.status, 'value') else user.status,
            "avatar_url": user.avatar_url,
            "app_roles": selected_tenant.app_roles,
            "joined_at": user.created_at.isoformat() if user.created_at else None,
            "last_login": user.last_login.isoformat() if user.last_login else None,
            "social_accounts": []
        }

        tenant_info = {
            "id": tenant.id,
            "name": tenant.name,
            "domain": tenant.domain,
            "logo_url": tenant.logo_url,
            "roles": selected_tenant.app_roles.get(request.application_id, []) if selected_tenant.app_roles else [],
            "is_active": True
        }

        return {
            "access_token": keycloak_response["access_token"],
            "token_type": "bearer",
            "expires_in": keycloak_response.get("expires_in", 3600),
            "user": user_response,
            "current_tenant": tenant_info
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Application selection error: {e}")
        raise HTTPException(status_code=500, detail="Application selection failed")

def get_trial_features(app_name: str) -> list[str]:
    """Get trial features for each app (all features unlocked during trial)"""
    trial_features = {
        "darkhole": ["admin", "user", "rag", "tuner", "analytics", "export"],
        "darkfolio": ["admin", "user", "stuart", "analyst", "reports", "integrations"],
        "confiploy": ["admin", "user", "devops-engineer", "release-manager", "pipelines", "monitoring"]
    }
    return trial_features.get(app_name, ["admin", "user"])