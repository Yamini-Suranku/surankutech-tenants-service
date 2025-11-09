"""
Invitation Email Service
Handles sending invitation emails to new users
"""

import logging
from typing import Dict
from sqlalchemy.orm import Session
from services.shared.models import User, Tenant
from services.shared.email_service import BaseEmailService
from services.tenants.models import Invitation

logger = logging.getLogger(__name__)


class InvitationEmailService(BaseEmailService):
    """Service for sending invitation emails to new users"""

    def __init__(self):
        super().__init__()

    async def send_invitation_email(
        self,
        db: Session,
        invitation: Invitation,
        invited_by_user: User,
        tenant: Tenant
    ) -> Dict[str, str]:
        """
        Send invitation email to a new user

        Args:
            db: Database session
            invitation: Invitation object
            invited_by_user: User who sent the invitation
            tenant: Tenant organization

        Returns:
            Dict with status and message
        """
        # Build email content
        subject, html_body = self._build_email_content(
            invitation=invitation,
            invited_by_user=invited_by_user,
            tenant=tenant
        )

        # Prepare development mode info
        development_info = {
            "Invitation sent to": invitation.email,
            "Invited by": f"{invited_by_user.first_name} {invited_by_user.last_name}",
            "Organization": tenant.name,
            "App roles": str(invitation.app_roles),
            "Invitation expires": invitation.expires_at.isoformat() if invitation.expires_at else "No expiry",
            "Invitation URL": self._build_action_url(invitation=invitation)
        }

        # Use base class email sending with graceful fallback
        return await self._send_email(
            to_email=invitation.email,
            subject=subject,
            html_body=html_body,
            development_fallback_action=None,  # No auto-action needed for invitations
            development_info=development_info,
            email_type="invitation",
            db=db,
            context_ids={
                'user_id': invited_by_user.id,
                'tenant_id': tenant.id,
                'invitation_id': invitation.id
            }
        )

    def _build_email_content(self, **kwargs) -> tuple[str, str]:
        """
        Build invitation email subject and HTML content

        Returns:
            Tuple of (subject, html_body)
        """
        invitation = kwargs['invitation']
        invited_by_user = kwargs['invited_by_user']
        tenant = kwargs['tenant']

        # Build invitation acceptance URL
        invitation_url = self._build_action_url(invitation=invitation)

        # Get app names for display
        app_names = self._format_app_roles(invitation.app_roles)

        # Email content
        subject = f"You're invited to join {tenant.name} on Suranku Platform"

        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="text-align: center; margin-bottom: 30px;">
                <h1 style="color: #333; margin-bottom: 10px;">You're Invited!</h1>
                <p style="color: #666; font-size: 16px;">{invited_by_user.first_name} {invited_by_user.last_name} has invited you to join {tenant.name}</p>
            </div>

            <div style="background-color: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                <p>Hi there,</p>
                <p>You've been invited to join <strong>{tenant.name}</strong> on the Suranku Platform by {invited_by_user.first_name} {invited_by_user.last_name}.</p>

                <div style="margin: 15px 0;">
                    <strong>Your access includes:</strong>
                    <ul style="margin: 10px 0; padding-left: 20px;">
                        {app_names}
                    </ul>
                </div>
            </div>

            <div style="text-align: center; margin: 30px 0;">
                <a href="{invitation_url}"
                   style="background-color: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">
                    Accept Invitation
                </a>
            </div>

            <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0;">
                <p style="margin: 0; color: #856404;"><strong>Important:</strong></p>
                <ul style="color: #856404; margin: 10px 0;">
                    <li>This invitation will expire on {invitation.expires_at.strftime('%B %d, %Y at %I:%M %p UTC') if invitation.expires_at else 'No expiry'}</li>
                    <li>You'll need to create an account or login if you already have one</li>
                    <li>If you didn't expect this invitation, you can safely ignore this email</li>
                </ul>
            </div>

            <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; text-align: center;">
                <p style="color: #666; font-size: 14px;">
                    If the button doesn't work, copy and paste this link into your browser:<br>
                    <a href="{invitation_url}" style="color: #007bff; word-break: break-all;">{invitation_url}</a>
                </p>
                <p style="color: #666; font-size: 12px; margin-top: 20px;">
                    Best regards,<br>
                    The Suranku Platform Team
                </p>
            </div>
        </body>
        </html>
        """

        return subject, html_body

    def _build_action_url(self, **kwargs) -> str:
        """
        Build the invitation acceptance URL

        Returns:
            Complete invitation URL
        """
        invitation = kwargs['invitation']
        config = self._get_smtp_config()
        return f"{config['app_base_url']}/vanilla/pages/accept-invitation.html?invitation_id={invitation.id}"

    def _format_app_roles(self, app_roles: dict) -> str:
        """
        Format app roles for display in email

        Args:
            app_roles: Dictionary of app roles

        Returns:
            Formatted HTML list items
        """
        app_display_names = {
            "darkhole": "DarkHole (AI Knowledge Platform)",
            "darkfolio": "DarkFolio (Data Management & Governance)",
            "confiploy": "ConfiPloy (Configuration Management)"
        }

        role_display_names = {
            "admin": "Administrator",
            "user": "User",
            "rag": "RAG Specialist",
            "tuner": "Model Tuner",
            "analytics": "Analytics",
            "stuart": "Stuart",
            "analyst": "Analyst",
            "devops-engineer": "DevOps Engineer",
            "release-manager": "Release Manager"
        }

        items = []
        for app_name, roles in app_roles.items():
            app_display = app_display_names.get(app_name, app_name.title())
            role_names = [role_display_names.get(role, role.title()) for role in roles]
            items.append(f"<li>{app_display}: {', '.join(role_names)}</li>")

        return ''.join(items)