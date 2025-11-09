"""
Password Reset Email Service
Handles sending password reset emails to users
"""

import logging
from typing import Dict
from sqlalchemy.orm import Session
from services.shared.models import User
from services.shared.email_service import BaseEmailService
from services.tenants.models import PasswordResetToken

logger = logging.getLogger(__name__)


class PasswordResetEmailService(BaseEmailService):
    """Service for sending password reset emails"""

    def __init__(self):
        super().__init__()

    async def send_reset_email(
        self,
        db: Session,
        user: User,
        reset_token: PasswordResetToken
    ) -> Dict[str, str]:
        """
        Send password reset email to user

        Args:
            db: Database session
            user: User object requesting password reset
            reset_token: Password reset token object

        Returns:
            Dict with status and message
        """
        # Build email content
        subject, html_body = self._build_email_content(
            user=user,
            reset_token=reset_token
        )

        # Prepare development mode info
        development_info = {
            "Password reset email sent to": user.email,
            "User name": f"{user.first_name} {user.last_name}".strip() or "User",
            "Token expires": reset_token.expires_at.isoformat() if reset_token.expires_at else "No expiry",
            "Reset URL": self._build_action_url(user=user, reset_token=reset_token)
        }

        # Use base class email sending with graceful fallback
        return await self._send_email(
            to_email=user.email,
            subject=subject,
            html_body=html_body,
            development_fallback_action=None,  # No auto-action for password reset
            development_info=development_info,
            email_type="password_reset",
            db=db,
            context_ids={
                'user_id': user.id
            }
        )

    def _build_email_content(self, **kwargs) -> tuple[str, str]:
        """
        Build password reset email subject and HTML content

        Returns:
            Tuple of (subject, html_body)
        """
        user = kwargs['user']
        reset_token = kwargs['reset_token']

        # Build reset URL
        reset_url = self._build_action_url(user=user, reset_token=reset_token)
        name = f"{user.first_name} {user.last_name}".strip() or "User"

        # Email content
        subject = "Reset Your Password - Suranku Platform"

        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="text-align: center; margin-bottom: 30px;">
                <h1 style="color: #333; margin-bottom: 10px;">Password Reset Request</h1>
                <p style="color: #666; font-size: 16px;">We received a request to reset your password</p>
            </div>

            <div style="background-color: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                <p>Hi {name},</p>
                <p>Someone requested a password reset for your Suranku Platform account. If this was you, click the button below to set a new password.</p>
                <p>If you didn't request this password reset, you can safely ignore this email.</p>
            </div>

            <div style="text-align: center; margin: 30px 0;">
                <a href="{reset_url}"
                   style="background-color: #dc3545; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">
                    Reset Password
                </a>
            </div>

            <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0;">
                <p style="margin: 0; color: #856404;"><strong>Important:</strong></p>
                <ul style="color: #856404; margin: 10px 0;">
                    <li>This link will expire in 1 hour for security</li>
                    <li>You can only use this link once</li>
                    <li>If you didn't request this, please ignore this email</li>
                    <li>Your password won't change until you complete the reset</li>
                </ul>
            </div>

            <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; text-align: center;">
                <p style="color: #666; font-size: 14px;">
                    If the button doesn't work, copy and paste this link into your browser:<br>
                    <a href="{reset_url}" style="color: #007bff; word-break: break-all;">{reset_url}</a>
                </p>
                <p style="color: #666; font-size: 12px; margin-top: 20px;">
                    For security reasons, this email was sent from an automated system.<br>
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
        Build the password reset URL

        Returns:
            Complete password reset URL
        """
        user = kwargs['user']
        reset_token = kwargs['reset_token']
        config = self._get_smtp_config()
        return f"{config['app_base_url']}/reset-password?token={reset_token.token}&email={user.email}"