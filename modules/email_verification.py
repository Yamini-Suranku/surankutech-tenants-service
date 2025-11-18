"""
Email Verification Module
Handles email verification endpoints and functionality
"""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
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
            # Return HTML success page with option to go to login
            html_content = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Email Verified Successfully</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        min-height: 100vh;
                        margin: 0;
                        background-color: #f5f5f5;
                    }
                    .container {
                        text-align: center;
                        background: white;
                        padding: 3rem;
                        border-radius: 10px;
                        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                        max-width: 500px;
                    }
                    .success-icon {
                        color: #4CAF50;
                        font-size: 4rem;
                        margin-bottom: 1rem;
                    }
                    h1 {
                        color: #333;
                        margin-bottom: 1rem;
                    }
                    p {
                        color: #666;
                        margin-bottom: 2rem;
                        line-height: 1.6;
                    }
                    .login-btn {
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
                    }
                    .login-btn:hover {
                        background-color: #0056b3;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="success-icon">✓</div>
                    <h1>Email Verified Successfully!</h1>
                    <p>Your email address has been verified successfully. You can now login to your account and access all features.</p>
                    <a href="/login?verified=true" class="login-btn">Go to Login Page</a>
                </div>
            </body>
            </html>
            """
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