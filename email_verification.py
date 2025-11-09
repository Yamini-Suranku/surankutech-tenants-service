"""
Email Verification Service for Traditional User Registration
Ensures users own their email addresses before account activation
"""

import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Optional
import logging
from sqlalchemy.orm import Session
from services.shared.database import get_db
from services.shared.models import User, UserStatus
from services.shared.email_service import BaseEmailService

logger = logging.getLogger(__name__)

class EmailVerificationService(BaseEmailService):
    """Service for handling email verification in user registration"""

    def __init__(self):
        super().__init__()
        self.verification_expiry_hours = 24
        self.max_resend_attempts = 3
        self.resend_cooldown_minutes = 5

    async def send_verification_email(
        self,
        db: Session,
        user: User,
        resend: bool = False
    ) -> Dict[str, str]:
        """
        Send email verification to user

        Args:
            db: Database session
            user: User object
            resend: Whether this is a resend request

        Returns:
            Dict with status and message
        """
        try:
            # Check if user is already verified
            if user.is_email_verified:
                return {
                    "status": "already_verified",
                    "message": "Email is already verified"
                }

            # For resend requests, check cooldown and attempt limits
            if resend:
                if user.email_verification_sent_at:
                    cooldown_time = user.email_verification_sent_at + timedelta(minutes=self.resend_cooldown_minutes)
                    if datetime.utcnow() < cooldown_time:
                        remaining_minutes = (cooldown_time - datetime.utcnow()).total_seconds() / 60
                        return {
                            "status": "cooldown_active",
                            "message": f"Please wait {int(remaining_minutes)} more minutes before requesting another verification email"
                        }

            # Generate new verification token
            verification_token = self._generate_verification_token(user.email)
            expires_at = datetime.utcnow() + timedelta(hours=self.verification_expiry_hours)

            # Update user with new token
            user.email_verification_token = verification_token
            user.email_verification_sent_at = datetime.utcnow()
            user.email_verification_expires_at = expires_at

            db.commit()

            # Development fallback action: auto-verify user
            async def auto_verify_fallback():
                await self._auto_verify_development_user(user.email, verification_token)

            # Build email content and send using base class
            subject, html_body = self._build_email_content(
                user=user,
                token=verification_token,
                expires_at=expires_at
            )

            # Development info for logging
            development_info = {
                "Verification email sent to": user.email,
                "User name": f"{user.first_name} {user.last_name}".strip() or "User",
                "Token expires": expires_at.isoformat(),
                "Verification URL": self._build_action_url(email=user.email, token=verification_token)
            }

            # Send using base class with development fallback
            result = await self._send_email(
                to_email=user.email,
                subject=subject,
                html_body=html_body,
                development_fallback_action=auto_verify_fallback,
                development_info=development_info,
                email_type="verification",
                db=db,
                context_ids={
                    'user_id': user.id
                }
            )

            # Return result compatible with existing API
            if result["status"] == "development":
                return {
                    "status": "sent",  # Keep existing API compatibility
                    "message": "Verification email sent (development mode)",
                    "expires_at": expires_at.isoformat(),
                    "token": verification_token
                }
            else:
                return {
                    "status": "sent",
                    "message": "Verification email sent. Please check your inbox and spam folder.",
                    "expires_at": expires_at.isoformat(),
                    "token": verification_token  # Remove this in production
                }

        except Exception as e:
            logger.error(f"Email verification sending error: {e}")
            db.rollback()
            raise Exception(f"Failed to send verification email: {str(e)}")

    async def verify_email(
        self,
        db: Session,
        email: str,
        token: str
    ) -> Dict[str, str]:
        """
        Verify email with token and activate user account

        Args:
            db: Database session
            email: User email address
            token: Verification token

        Returns:
            Dict with verification result
        """
        try:
            # Find user with matching email and token
            user = db.query(User).filter(
                User.email == email,
                User.email_verification_token == token
            ).first()

            if not user:
                return {
                    "status": "invalid",
                    "message": "Invalid verification link. Please check your email for the correct link."
                }

            # Check if already verified
            if user.is_email_verified:
                return {
                    "status": "already_verified",
                    "message": "Email is already verified. You can now login."
                }

            # Check token expiry
            if (user.email_verification_expires_at and
                datetime.utcnow() > user.email_verification_expires_at):

                # Clear expired token
                user.email_verification_token = None
                user.email_verification_expires_at = None
                db.commit()

                return {
                    "status": "expired",
                    "message": "Verification link has expired. Please request a new verification email."
                }

            # Activate the user account
            user.is_email_verified = True
            user.status = UserStatus.ACTIVE
            user.email_verification_token = None  # Clear token after use
            user.email_verification_expires_at = None

            # Get user-tenant relationship to check for roles
            from services.shared.models import UserTenant, TenantAppAccess
            user_tenant = db.query(UserTenant).filter(UserTenant.user_id == user.id).first()

            # Also activate the user in Keycloak if they have a keycloak_id
            if user.keycloak_id:
                from services.tenants.keycloak_client import KeycloakClient
                keycloak_client = KeycloakClient()

                # Get app_roles from user_tenant if available (for tenant registration with admin roles)
                app_roles = None
                if user_tenant and user_tenant.app_roles:
                    app_roles = user_tenant.app_roles
                    logger.info(f"Found app_roles for user {email} from database: {app_roles}")

                keycloak_activated = await keycloak_client.activate_user_after_verification(
                    user.keycloak_id,
                    app_roles=app_roles
                )
                if not keycloak_activated:
                    logger.warning(f"Failed to activate Keycloak user {user.keycloak_id} for {email}")

            # Update user-tenant relationship to active and increment app access counts
            if user_tenant:
                user_tenant.status = UserStatus.ACTIVE
                user_tenant.joined_at = datetime.utcnow()

                # Increment app access user counts
                app_access_list = db.query(TenantAppAccess).filter(
                    TenantAppAccess.tenant_id == user_tenant.tenant_id
                ).all()
                for app_access in app_access_list:
                    app_access.current_users += 1

            db.commit()

            logger.info(f"Email verified successfully for user: {email}")

            return {
                "status": "verified",
                "message": "Email verified successfully! Your account is now active. You can login."
            }

        except Exception as e:
            logger.error(f"Email verification error: {e}")
            db.rollback()
            raise Exception(f"Failed to verify email: {str(e)}")

    async def check_verification_status(
        self,
        db: Session,
        email: str
    ) -> Dict[str, any]:
        """
        Check the email verification status for a user

        Args:
            db: Database session
            email: User email address

        Returns:
            Dict with verification status details
        """
        try:
            user = db.query(User).filter(User.email == email).first()

            if not user:
                return {
                    "status": "user_not_found",
                    "message": "User not found"
                }

            if user.is_email_verified:
                return {
                    "status": "verified",
                    "message": "Email is verified",
                    "user_status": user.status,
                    "verified_at": user.updated_at.isoformat() if user.updated_at else None
                }

            # Check if verification is pending
            if user.email_verification_token:
                is_expired = (user.email_verification_expires_at and
                            datetime.utcnow() > user.email_verification_expires_at)

                return {
                    "status": "pending",
                    "message": "Email verification pending",
                    "expired": is_expired,
                    "sent_at": user.email_verification_sent_at.isoformat() if user.email_verification_sent_at else None,
                    "expires_at": user.email_verification_expires_at.isoformat() if user.email_verification_expires_at else None
                }

            return {
                "status": "not_sent",
                "message": "Verification email not sent yet"
            }

        except Exception as e:
            logger.error(f"Verification status check error: {e}")
            raise Exception(f"Failed to check verification status: {str(e)}")

    def _generate_verification_token(self, email: str) -> str:
        """
        Generate cryptographically secure verification token

        Args:
            email: User email for additional entropy

        Returns:
            Secure verification token
        """
        # Generate 32 bytes of random data
        random_bytes = secrets.token_bytes(32)

        # Add email and timestamp for uniqueness
        timestamp = str(datetime.utcnow().timestamp())
        combined_data = random_bytes + email.encode() + timestamp.encode()

        # Return secure hash
        return hashlib.sha256(combined_data).hexdigest()

    async def _send_verification_email(
        self,
        email: str,
        name: str,
        token: str
    ):
        """
        Send the actual verification email

        Args:
            email: Recipient email address
            name: User's name
            token: Verification token
        """
        try:
            # Email configuration matching your existing pattern
            smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
            smtp_port = int(os.getenv("SMTP_PORT", "587"))
            smtp_user = os.getenv("SMTP_USER")  # Match your .env pattern
            smtp_password = os.getenv("SMTP_PASSWORD")
            smtp_use_tls = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
            email_from = os.getenv("EMAIL_FROM", smtp_user)
            email_from_name = os.getenv("EMAIL_FROM_NAME", "SurankuTech")

            if not all([smtp_user, smtp_password, email_from]):
                logger.warning("SMTP configuration incomplete. Please set SMTP_USER, SMTP_PASSWORD, and EMAIL_FROM in .env")
                logger.info(f"Development verification URL for {email}: {self._build_verification_url(email, token)}")
                logger.info("Development mode: Auto-verifying user since SMTP is not configured")

                # In development mode, automatically verify the email since we can't send emails
                await self._auto_verify_development_user(email, token)
                return

            # Build verification URL
            verification_url = self._build_verification_url(email, token)

            # Email content
            subject = "Verify Your Email Address - Suranku Platform"

            html_body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="text-align: center; margin-bottom: 30px;">
                    <h1 style="color: #333; margin-bottom: 10px;">Welcome to Suranku Platform!</h1>
                    <p style="color: #666; font-size: 16px;">Please verify your email address to activate your account</p>
                </div>

                <div style="background-color: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                    <p>Hi {name},</p>
                    <p>Thank you for creating an account with Suranku Platform. To complete your registration and activate your account, please verify your email address.</p>
                </div>

                <div style="text-align: center; margin: 30px 0;">
                    <a href="{verification_url}"
                       style="background-color: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">
                        Verify Email Address
                    </a>
                </div>

                <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <p style="margin: 0; color: #856404;"><strong>Important:</strong></p>
                    <ul style="color: #856404; margin: 10px 0;">
                        <li>This link will expire in 24 hours</li>
                        <li>You cannot login until your email is verified</li>
                        <li>If you didn't create this account, please ignore this email</li>
                    </ul>
                </div>

                <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; text-align: center;">
                    <p style="color: #666; font-size: 14px;">
                        If the button doesn't work, copy and paste this link into your browser:<br>
                        <a href="{verification_url}" style="color: #007bff; word-break: break-all;">{verification_url}</a>
                    </p>
                    <p style="color: #666; font-size: 12px; margin-top: 20px;">
                        Best regards,<br>
                        Suranku Platform Team
                    </p>
                </div>
            </body>
            </html>
            """

            # Create message
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = f"{email_from_name} <{email_from}>"
            msg["To"] = email

            # Add HTML content
            html_part = MIMEText(html_body, "html")
            msg.attach(html_part)

            # Send email
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                if smtp_use_tls:
                    server.starttls()
                server.login(smtp_user, smtp_password)
                server.send_message(msg)

            logger.info(f"Verification email sent to {email}")

        except Exception as e:
            logger.error(f"Email sending error: {e}")
            # Log the verification URL for development
            logger.info(f"Development verification URL for {email}: {self._build_verification_url(email, token)}")
            # Don't fail the registration process if email fails in development
            if not os.getenv("SMTP_USER"):
                logger.warning("Email not sent due to missing SMTP configuration")
            else:
                raise Exception(f"Failed to send verification email: {str(e)}")

    def _build_verification_url(self, email: str, token: str) -> str:
        """
        Build the verification URL

        Args:
            email: User email
            token: Verification token

        Returns:
            Complete verification URL
        """
        base_url = os.getenv("APP_BASE_URL", "http://localhost:8010")
        return f"{base_url}/api/tenants/auth/verify-email?email={email}&token={token}"

    def _build_email_content(self, **kwargs) -> tuple[str, str]:
        """
        Build verification email subject and HTML content

        Returns:
            Tuple of (subject, html_body)
        """
        user = kwargs['user']
        token = kwargs['token']
        expires_at = kwargs['expires_at']

        # Build verification URL
        verification_url = self._build_action_url(email=user.email, token=token)
        name = f"{user.first_name} {user.last_name}".strip() or "User"

        # Email content
        subject = "Verify Your Email Address - Suranku Platform"

        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="text-align: center; margin-bottom: 30px;">
                <h1 style="color: #333; margin-bottom: 10px;">Welcome to Suranku Platform!</h1>
                <p style="color: #666; font-size: 16px;">Please verify your email address to activate your account</p>
            </div>

            <div style="background-color: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                <p>Hi {name},</p>
                <p>Thank you for creating an account with Suranku Platform. To complete your registration and activate your account, please verify your email address.</p>
            </div>

            <div style="text-align: center; margin: 30px 0;">
                <a href="{verification_url}"
                   style="background-color: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">
                    Verify Email Address
                </a>
            </div>

            <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0;">
                <p style="margin: 0; color: #856404;"><strong>Important:</strong></p>
                <ul style="color: #856404; margin: 10px 0;">
                    <li>This link will expire in 24 hours</li>
                    <li>You cannot login until your email is verified</li>
                    <li>If you didn't create this account, please ignore this email</li>
                </ul>
            </div>

            <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; text-align: center;">
                <p style="color: #666; font-size: 14px;">
                    If the button doesn't work, copy and paste this link into your browser:<br>
                    <a href="{verification_url}" style="color: #007bff; word-break: break-all;">{verification_url}</a>
                </p>
                <p style="color: #666; font-size: 12px; margin-top: 20px;">
                    Best regards,<br>
                    Suranku Platform Team
                </p>
            </div>
        </body>
        </html>
        """

        return subject, html_body

    def _build_action_url(self, **kwargs) -> str:
        """
        Build the verification URL

        Returns:
            Complete verification URL
        """
        email = kwargs['email']
        token = kwargs['token']
        config = self._get_smtp_config()
        return f"{config['app_base_url']}/api/tenants/auth/verify-email?email={email}&token={token}"

    async def cleanup_expired_tokens(self, db: Session) -> int:
        """
        Cleanup expired verification tokens
        Should be run periodically as a background task

        Args:
            db: Database session

        Returns:
            Number of tokens cleaned up
        """
        try:
            expired_users = db.query(User).filter(
                User.email_verification_expires_at != None,
                User.email_verification_expires_at < datetime.utcnow(),
                User.is_email_verified == False
            ).all()

            count = 0
            for user in expired_users:
                user.email_verification_token = None
                user.email_verification_expires_at = None
                count += 1

            db.commit()
            logger.info(f"Cleaned up {count} expired verification tokens")
            return count

        except Exception as e:
            logger.error(f"Token cleanup error: {e}")
            db.rollback()
            return 0

    async def _auto_verify_development_user(self, email: str, token: str):
        """
        Automatically verify user in development mode when SMTP is not configured

        Args:
            email: User email address
            token: Verification token that was generated
        """
        try:
            from services.shared.database import get_db

            # Get database session
            db = next(get_db())

            try:
                # Call the verification method directly with the token
                result = await self.verify_email(db, email, token)

                if result["status"] == "verified":
                    logger.info(f"Development mode: Successfully auto-verified user {email}")
                else:
                    logger.warning(f"Development mode: Auto-verification failed for {email}: {result['message']}")

            finally:
                db.close()

        except Exception as e:
            logger.error(f"Development auto-verification error for {email}: {e}")
            # Don't raise the exception - we don't want to fail the registration process