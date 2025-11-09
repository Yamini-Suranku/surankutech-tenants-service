"""
Secure Social Account Linking Service
Prevents account takeover attacks by requiring email verification
"""

import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Optional
import logging
from sqlalchemy.orm import Session
from services.shared.database import get_db
from services.shared.models import User
from services.tenants.models import SocialAccount
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

logger = logging.getLogger(__name__)

class SecureAccountLinking:
    """Secure social account linking with email verification"""

    def __init__(self):
        self.token_expiry_hours = 24

    async def initiate_account_linking(
        self,
        db: Session,
        email: str,
        provider: str,
        social_id: str,
        social_profile: Dict
    ) -> Dict[str, str]:
        """
        Step 1: Initiate secure account linking process
        Returns linking token and instructions
        """
        try:
            # Check if user exists with this email
            existing_user = db.query(User).filter(User.email == email).first()
            if not existing_user:
                raise Exception(f"No account found with email {email}")

            # Check if this social account is already linked
            existing_social = db.query(SocialAccount).filter(
                SocialAccount.user_id == existing_user.id,
                SocialAccount.provider == provider
            ).first()

            if existing_social:
                if existing_social.social_id == social_id:
                    return {"status": "already_linked", "message": "Social account already linked"}
                else:
                    raise Exception(f"Different {provider} account already linked to this user")

            # Check if this social_id is linked to another user
            existing_social_other = db.query(SocialAccount).filter(
                SocialAccount.provider == provider,
                SocialAccount.social_id == social_id
            ).first()

            if existing_social_other:
                raise Exception(f"This {provider} account is already linked to another user")

            # Generate secure verification token
            verification_token = self._generate_verification_token()
            expires_at = datetime.utcnow() + timedelta(hours=self.token_expiry_hours)

            # Create pending social account record
            pending_social = SocialAccount(
                user_id=existing_user.id,
                provider=provider,
                social_id=social_id,
                email=email,
                profile_data=social_profile,
                avatar_url=social_profile.get("avatar_url"),
                profile_url=social_profile.get("profile_url"),
                is_active=False,  # Not active until verified
                is_verified=False,
                verification_token=verification_token,
                verification_sent_at=datetime.utcnow()
            )

            db.add(pending_social)
            db.commit()

            # Send verification email
            await self._send_verification_email(
                email=email,
                name=f"{existing_user.first_name} {existing_user.last_name}".strip(),
                provider=provider,
                token=verification_token
            )

            return {
                "status": "verification_sent",
                "message": f"Please check your email to verify linking your {provider} account",
                "token": verification_token  # For testing purposes - remove in production
            }

        except Exception as e:
            logger.error(f"Account linking initiation error: {e}")
            db.rollback()
            raise Exception(f"Failed to initiate account linking: {str(e)}")

    async def verify_account_linking(
        self,
        db: Session,
        email: str,
        provider: str,
        token: str
    ) -> Dict[str, str]:
        """
        Step 2: Verify email ownership and complete account linking
        """
        try:
            # Find pending social account
            pending_social = db.query(SocialAccount).filter(
                SocialAccount.email == email,
                SocialAccount.provider == provider,
                SocialAccount.verification_token == token,
                SocialAccount.is_verified == False
            ).first()

            if not pending_social:
                raise Exception("Invalid or expired verification token")

            # Check token expiry
            if pending_social.verification_sent_at:
                expiry_time = pending_social.verification_sent_at + timedelta(hours=self.token_expiry_hours)
                if datetime.utcnow() > expiry_time:
                    # Clean up expired token
                    db.delete(pending_social)
                    db.commit()
                    raise Exception("Verification token has expired. Please try linking again.")

            # Activate the social account
            pending_social.is_verified = True
            pending_social.is_active = True
            pending_social.verification_token = None  # Clear token after use

            db.commit()

            return {
                "status": "success",
                "message": f"Successfully linked your {provider} account"
            }

        except Exception as e:
            logger.error(f"Account linking verification error: {e}")
            raise Exception(f"Failed to verify account linking: {str(e)}")

    async def get_linked_accounts(
        self,
        db: Session,
        user_id: str
    ) -> Dict[str, list]:
        """Get all linked social accounts for a user"""
        try:
            social_accounts = db.query(SocialAccount).filter(
                SocialAccount.user_id == user_id,
                SocialAccount.is_active == True,
                SocialAccount.is_verified == True
            ).all()

            linked_accounts = []
            for account in social_accounts:
                linked_accounts.append({
                    "provider": account.provider,
                    "social_id": account.social_id,
                    "profile_url": account.profile_url,
                    "avatar_url": account.avatar_url,
                    "linked_at": account.created_at.isoformat(),
                    "last_login": account.last_login.isoformat() if account.last_login else None
                })

            return {
                "status": "success",
                "linked_accounts": linked_accounts,
                "count": len(linked_accounts)
            }

        except Exception as e:
            logger.error(f"Get linked accounts error: {e}")
            raise Exception(f"Failed to get linked accounts: {str(e)}")

    def _generate_verification_token(self) -> str:
        """Generate cryptographically secure verification token"""
        # Generate 32 bytes of random data
        random_bytes = secrets.token_bytes(32)
        # Hash with current timestamp for uniqueness
        timestamp = str(datetime.utcnow().timestamp())
        combined = random_bytes + timestamp.encode()

        # Return hex digest
        return hashlib.sha256(combined).hexdigest()

    async def _send_verification_email(
        self,
        email: str,
        name: str,
        provider: str,
        token: str
    ):
        """Send verification email for account linking"""
        try:
            # Email configuration from environment
            smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
            smtp_port = int(os.getenv("SMTP_PORT", "587"))
            smtp_username = os.getenv("SMTP_USERNAME")
            smtp_password = os.getenv("SMTP_PASSWORD")
            from_email = os.getenv("FROM_EMAIL", smtp_username)

            if not all([smtp_username, smtp_password]):
                logger.warning("SMTP credentials not configured - email not sent")
                return  # Skip email in development

            # Build verification URL
            base_url = os.getenv("APP_BASE_URL", "http://localhost:8010")
            verify_url = f"{base_url}/api/auth/verify-social-linking?email={email}&provider={provider}&token={token}"

            # Email content
            subject = f"Verify {provider.title()} Account Linking - Suranku Platform"

            html_body = f"""
            <html>
            <body>
                <h2>Verify Account Linking</h2>
                <p>Hi {name},</p>
                <p>You requested to link your <strong>{provider.title()}</strong> account to your Suranku Platform account.</p>
                <p>For security, please verify that you own this email address by clicking the link below:</p>
                <p>
                    <a href="{verify_url}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
                        Verify Account Linking
                    </a>
                </p>
                <p>This link will expire in 24 hours.</p>
                <p>If you didn't request this linking, please ignore this email.</p>
                <br>
                <p>Best regards,<br>Suranku Platform Team</p>
                <hr>
                <small>Verification URL: {verify_url}</small>
            </body>
            </html>
            """

            # Create message
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = from_email
            msg["To"] = email

            # Add HTML content
            html_part = MIMEText(html_body, "html")
            msg.attach(html_part)

            # Send email
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(smtp_username, smtp_password)
                server.send_message(msg)

            logger.info(f"Verification email sent to {email}")

        except Exception as e:
            logger.error(f"Email sending error: {e}")
            # Don't fail the linking process if email fails
            logger.warning(f"Failed to send verification email to {email}: {e}")