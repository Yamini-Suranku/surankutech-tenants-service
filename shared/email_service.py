"""
Shared Email Service Base Class
Consolidates common SMTP functionality used by verification and invitation emails
"""

import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Optional
from abc import ABC, abstractmethod
from sqlalchemy.orm import Session
from datetime import datetime

logger = logging.getLogger(__name__)


class BaseEmailService(ABC):
    """Base email service with shared SMTP functionality"""

    def __init__(self):
        # Don't load config in constructor - load fresh each time
        pass

    def _get_smtp_config(self) -> Dict[str, any]:
        """Get fresh SMTP configuration from environment"""
        return {
            'smtp_host': os.getenv("SMTP_HOST", "smtp.gmail.com"),
            'smtp_port': int(os.getenv("SMTP_PORT", "587")),
            'smtp_user': os.getenv("SMTP_USER"),
            'smtp_password': os.getenv("SMTP_PASSWORD"),
            'smtp_use_tls': os.getenv("SMTP_USE_TLS", "true").lower() == "true",
            'email_from': os.getenv("EMAIL_FROM"),
            'email_from_name': os.getenv("EMAIL_FROM_NAME", "SurankuTech"),
            'app_base_url': os.getenv("APP_BASE_URL", "http://localhost:3000")
        }

    def _is_smtp_configured(self, config: Dict[str, any]) -> bool:
        """Check if SMTP is properly configured"""
        return all([
            config['smtp_user'],
            config['smtp_password']
            # email_from can fallback to smtp_user, so not required
        ])

    async def _send_email(
        self,
        to_email: str,
        subject: str,
        html_body: str,
        development_fallback_action: Optional[callable] = None,
        development_info: Optional[Dict] = None,
        email_type: str = "unknown",
        db: Optional[Session] = None,
        context_ids: Optional[Dict[str, str]] = None
    ) -> Dict[str, str]:
        """
        Core email sending functionality with development fallback

        Args:
            to_email: Recipient email address
            subject: Email subject
            html_body: HTML email content
            development_fallback_action: Action to take in development mode
            development_info: Additional info for development logging

        Returns:
            Dict with status and message
        """
        try:
            config = self._get_smtp_config()

            # Check SMTP configuration
            if not self._is_smtp_configured(config):
                logger.warning("SMTP configuration incomplete. Please set SMTP_USER, SMTP_PASSWORD, and EMAIL_FROM in .env")

                # Development mode logging
                if development_info:
                    for key, value in development_info.items():
                        logger.info(f"Development mode - {key}: {value}")

                # Execute development fallback action if provided
                if development_fallback_action:
                    await development_fallback_action()

                return {
                    "status": "development",
                    "message": "Email logged (SMTP not configured for development)"
                }

            # Ensure email_from is set (fallback to smtp_user)
            if not config['email_from']:
                config['email_from'] = config['smtp_user']

            # Create email message
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = f"{config['email_from_name']} <{config['email_from']}>"
            msg["To"] = to_email

            # Add HTML content
            html_part = MIMEText(html_body, "html")
            msg.attach(html_part)

            # Send email via SMTP
            with smtplib.SMTP(config['smtp_host'], config['smtp_port']) as server:
                if config['smtp_use_tls']:
                    server.starttls()
                server.login(config['smtp_user'], config['smtp_password'])
                server.send_message(msg)

            logger.info(f"Email sent successfully to {to_email}")

            # Log successful email delivery
            await self._log_email(
                db=db,
                email_type=email_type,
                recipient_email=to_email,
                subject=subject,
                status="sent",
                context_ids=context_ids
            )

            return {
                "status": "sent",
                "message": f"Email sent to {to_email}"
            }

        except Exception as e:
            logger.error(f"Email sending error: {e}")

            # In development mode (no SMTP), don't fail
            config = self._get_smtp_config()
            if not self._is_smtp_configured(config):
                logger.warning(f"Development mode: Email to {to_email} logged but not sent")

                # Execute development fallback action if provided
                if development_fallback_action:
                    try:
                        await development_fallback_action()
                    except Exception as fallback_error:
                        logger.error(f"Development fallback action failed: {fallback_error}")

                # Log development mode "delivery"
                await self._log_email(
                    db=db,
                    email_type=email_type,
                    recipient_email=to_email,
                    subject=subject,
                    status="development",
                    context_ids=context_ids
                )

                return {
                    "status": "development",
                    "message": "Email logged (SMTP not configured)"
                }
            else:
                # Log failed email delivery
                await self._log_email(
                    db=db,
                    email_type=email_type,
                    recipient_email=to_email,
                    subject=subject,
                    status="failed",
                    error_message=str(e),
                    context_ids=context_ids
                )

                # In production mode, raise the exception
                raise Exception(f"Failed to send email: {str(e)}")

    async def _log_email(
        self,
        db: Optional[Session],
        email_type: str,
        recipient_email: str,
        subject: str,
        status: str,
        error_message: Optional[str] = None,
        context_ids: Optional[Dict[str, str]] = None
    ):
        """Log email delivery for audit purposes"""
        if not db:
            return  # Skip logging if no database session provided

        try:
            # Import here to avoid circular imports
            from models import EmailLog

            # Extract context IDs
            context_ids = context_ids or {}

            email_log = EmailLog(
                email_type=email_type,
                recipient_email=recipient_email,
                subject=subject,
                status=status,
                error_message=error_message,
                user_id=context_ids.get('user_id'),
                tenant_id=context_ids.get('tenant_id'),
                invitation_id=context_ids.get('invitation_id'),
                delivery_attempts=1,
                last_attempt_at=datetime.utcnow()
            )

            db.add(email_log)
            db.commit()
            logger.info(f"Email delivery logged: {email_type} to {recipient_email} with status {status}")

        except Exception as log_error:
            logger.error(f"Failed to log email delivery: {log_error}")
            # Don't fail the main email operation if logging fails
            if db:
                db.rollback()

    @abstractmethod
    def _build_email_content(self, **kwargs) -> tuple[str, str]:
        """
        Build email subject and HTML content

        Returns:
            Tuple of (subject, html_body)
        """
        pass

    @abstractmethod
    def _build_action_url(self, **kwargs) -> str:
        """
        Build the action URL for the email (verification, invitation, etc.)

        Returns:
            Complete action URL
        """
        pass