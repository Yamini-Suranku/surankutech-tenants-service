"""
Email Verification Module
Handles email verification endpoints and functionality
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
import logging

from shared.database import get_db

logger = logging.getLogger(__name__)

# Create router for email verification endpoints
router = APIRouter(prefix="/auth", tags=["email-verification"])

@router.get("/verify-email")
async def verify_email(
    email: str,
    token: str,
    db: Session = Depends(get_db)
):
    """Verify user email address and activate account"""
    try:
        from email_verification import EmailVerificationService
        verification_service = EmailVerificationService()

        result = await verification_service.verify_email(db, email, token)

        if result["status"] == "verified":
            return {
                "status": "success",
                "message": "Email verified successfully! You can now login to your account.",
                "redirect_url": "/login?verified=true"
            }
        else:
            return {
                "status": result["status"],
                "message": result["message"]
            }

    except Exception as e:
        logger.error(f"Email verification error: {e}")
        raise HTTPException(status_code=500, detail=f"Email verification failed: {str(e)}")

@router.post("/resend-verification")
async def resend_verification_email(
    email: str,
    db: Session = Depends(get_db)
):
    """Resend verification email"""
    try:
        # Find user
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        if user.is_email_verified:
            return {
                "status": "already_verified",
                "message": "Email is already verified. You can login."
            }

        # Send verification email
        from email_verification import EmailVerificationService
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
        from email_verification import EmailVerificationService
        verification_service = EmailVerificationService()

        result = await verification_service.check_verification_status(db, email)
        return result

    except Exception as e:
        logger.error(f"Verification status check error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to check verification status: {str(e)}")