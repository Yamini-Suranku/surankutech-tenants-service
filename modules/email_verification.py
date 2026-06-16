"""
Email Verification Module
Handles email verification endpoints and functionality
"""

from fastapi import APIRouter, Depends, HTTPException, Body
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from sqlalchemy import func
import logging
import os

from shared.database import get_db
from shared.models import Tenant, TenantAppAccess, User, UserStatus, UserTenant
from shared.email_verification import EmailVerificationService
from pydantic import BaseModel, EmailStr

logger = logging.getLogger(__name__)

# Create router for email verification endpoints
router = APIRouter(prefix="/api/tenants/auth", tags=["email-verification"])

class VerificationRequest(BaseModel):
    email: EmailStr
    token: str

class ResendVerificationRequest(BaseModel):
    email: EmailStr


def _verification_login_url() -> str:
    explicit_url = str(os.getenv("PLATFORM_LOGIN_URL", "") or "").strip()
    if explicit_url:
        return explicit_url

    keycloak_public_url = str(os.getenv("KEYCLOAK_PUBLIC_URL", "") or "").strip().rstrip("/")
    if keycloak_public_url:
        return f"{keycloak_public_url}/login/index.html"

    return "http://id.local.suranku/login/index.html"


def _enforce_platform_approval_after_verification(db: Session, email: str) -> bool:
    """Keep newly verified tenant signups pending when platform approval is required."""
    user = db.query(User).filter(func.lower(User.email) == email.strip().lower()).first()
    if not user:
        return False

    updated = False
    user_tenants = db.query(UserTenant).filter(UserTenant.user_id == user.id).all()
    for user_tenant in user_tenants:
        tenant = db.query(Tenant).filter(Tenant.id == user_tenant.tenant_id).first()
        tenant_settings = tenant.settings if tenant and isinstance(tenant.settings, dict) else {}
        approval_required = (
            tenant_settings.get("platform_approval_required") is True
            and tenant_settings.get("platform_approval_status") == "pending"
        )
        if not approval_required:
            continue

        was_active = user_tenant.status == UserStatus.ACTIVE or user_tenant.status == "active"
        user_tenant.status = UserStatus.PENDING
        user_tenant.joined_at = None
        updated = True

        if was_active:
            app_access_list = db.query(TenantAppAccess).filter(
                TenantAppAccess.tenant_id == user_tenant.tenant_id
            ).all()
            for app_access in app_access_list:
                app_access.current_users = max((app_access.current_users or 0) - 1, 0)

    if updated:
        db.commit()
        logger.info("Email verified for %s; tenant access remains pending platform approval", email)
    return updated

@router.get("/verify-email")
async def verify_email(
    email: str,
    token: str,
    db: Session = Depends(get_db)
):
    """Verify user email address and activate account"""
    try:
        verification_service = EmailVerificationService()

        result = await verification_service.verify_email(db, email, token)

        if result["status"] == "verified":
            pending_platform_approval = _enforce_platform_approval_after_verification(db, email)
            base_login_url = _verification_login_url()
            query = "verified=true"
            if pending_platform_approval:
                query += "&pending_approval=true"
            login_url = f"{base_login_url}{'&' if '?' in base_login_url else '?'}{query}"
            # Return HTML success page with option to go to login
            message = (
                "Your email address has been verified successfully. Your tenant is waiting for Platform Admin approval before platform access is enabled."
                if pending_platform_approval
                else "Your email address has been verified successfully. You can now login to your account and access all features."
            )
            html_content = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Email Verified Successfully</title>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        min-height: 100vh;
                        margin: 0;
                        background-color: #f5f5f5;
                    }}
                    .container {{
                        text-align: center;
                        background: white;
                        padding: 3rem;
                        border-radius: 10px;
                        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                        max-width: 500px;
                    }}
                    .success-icon {{
                        color: #4CAF50;
                        font-size: 4rem;
                        margin-bottom: 1rem;
                    }}
                    h1 {{
                        color: #333;
                        margin-bottom: 1rem;
                    }}
                    p {{
                        color: #666;
                        margin-bottom: 2rem;
                        line-height: 1.6;
                    }}
                    .login-btn {{
                        background-color: #007bff;
                        color: white;
                        padding: 12px 30px;
                        border: none;
                        border-radius: 5px;
                        font-size: 16px;
                        cursor: pointer;
                        text-decoration: none;
                        display: inline-block;
                        transition: background-color 0.3s;
                    }}
                    .login-btn:hover {{
                        background-color: #0056b3;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="success-icon">✓</div>
                    <h1>Email Verified Successfully!</h1>
                    <p>{message}</p>
                    <a href="{login_url}" class="login-btn">Go to Login Page</a>
                </div>
            </body>
            </html>
            """.format(login_url=login_url, message=message)
            return HTMLResponse(content=html_content, status_code=200)
        else:
            # For error cases, still return JSON for API compatibility
            return {
                "status": result["status"],
                "message": result["message"]
            }

    except Exception as e:
        logger.error(f"Email verification error: {e}")
        raise HTTPException(status_code=500, detail=f"Email verification failed: {str(e)}")

@router.post("/verify-email")
async def verify_email_post(
    payload: VerificationRequest,
    db: Session = Depends(get_db)
):
    """
    JSON-friendly verification endpoint for SPA/static pages.
    Mirrors GET /auth/verify-email but returns JSON always.
    """
    try:
        verification_service = EmailVerificationService()
        result = await verification_service.verify_email(db, payload.email, payload.token)
        if result["status"] == "verified":
            pending_platform_approval = _enforce_platform_approval_after_verification(db, payload.email)
            return {
                "status": "verified",
                "message": "Email verified successfully",
                "pending_platform_approval": pending_platform_approval,
            }
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Email verification error: {e}")
        raise HTTPException(status_code=500, detail=f"Email verification failed: {str(e)}")

@router.post("/resend-verification")
async def resend_verification_email(
    payload: ResendVerificationRequest = Body(...),
    db: Session = Depends(get_db)
):
    """Resend verification email"""
    try:
        # Find user (case-insensitive email)
        user = db.query(User).filter(func.lower(User.email) == payload.email.strip().lower()).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        if user.is_email_verified:
            return {
                "status": "already_verified",
                "message": "Email is already verified. You can login."
            }

        # Send verification email
        verification_service = EmailVerificationService()
        result = await verification_service.send_verification_email(db, user, resend=True)

        return {
            "status": result["status"],
            "message": result["message"]
        }

    except Exception as e:
        logger.error(f"Resend verification error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to resend verification email: {str(e)}")

@router.get("/verification-status")
async def check_verification_status(
    email: str,
    db: Session = Depends(get_db)
):
    """Check email verification status"""
    try:
        verification_service = EmailVerificationService()

        result = await verification_service.check_verification_status(db, email)
        return result

    except Exception as e:
        logger.error(f"Verification status check error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to check verification status: {str(e)}")
