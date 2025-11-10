"""
User Management Module
Handles user listing, invitations, and user-related operations
"""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
import logging
from datetime import datetime, timedelta
import uuid

from shared.database import get_db
from shared.auth import verify_token, require_tenant_access, TokenData
from shared.models import User, UserTenant, TenantAppAccess, AuditLog
from models import Invitation, SocialAccount
from schemas import (
    UserInviteRequest, InvitationResponse, UserResponse, UserUpdateRequest,
    UserListResponse, PaginationInfo, InvitationAcceptRequest
)
from typing import List, Optional
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# Create router for user management endpoints
router = APIRouter(tags=["user-management"])

@router.get("/tenants/{tenant_id}/users", response_model=UserListResponse)
async def list_tenant_users(
    tenant_id: str,
    page: int = 1,
    size: int = 20,
    search: Optional[str] = None,
    status_filter: Optional[str] = None,
    role_filter: Optional[str] = None,
    token: str = Depends(HTTPBearer()),
    db: Session = Depends(get_db)
):
    """List users in tenant with pagination, search and filtering"""
    token_data = await verify_token(token.credentials)

    # Check if current user belongs to this tenant by querying database
    current_user = db.query(User).filter(User.keycloak_id == token_data.sub).first()
    if not current_user:
        raise HTTPException(status_code=404, detail="Current user not found")

    user_tenant = db.query(UserTenant).filter(
        UserTenant.user_id == current_user.id,
        UserTenant.tenant_id == tenant_id
    ).first()

    if not user_tenant:
        raise HTTPException(status_code=403, detail="Access denied to tenant")

    # Build query with joins for better performance
    query = db.query(UserTenant, User).join(
        User, UserTenant.user_id == User.id
    ).filter(UserTenant.tenant_id == tenant_id)

    # Apply filters
    if status_filter and status_filter != "all":
        query = query.filter(UserTenant.status == status_filter)

    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            (User.email.ilike(search_pattern)) |
            (User.first_name.ilike(search_pattern)) |
            (User.last_name.ilike(search_pattern))
        )

    if role_filter and role_filter != "all":
        # Filter by app roles - this is a JSON column search
        query = query.filter(
            UserTenant.app_roles.op('@>')({role_filter: []})
        )

    # Get total count for pagination
    total_count = query.count()

    # Apply pagination
    offset = (page - 1) * size
    user_tenant_pairs = query.order_by(User.created_at.desc()).offset(offset).limit(size).all()

    users = []
    for ut, user in user_tenant_pairs:
        # Get social accounts
        social_accounts = db.query(SocialAccount).filter(
            SocialAccount.user_id == user.id
        ).all()

        users.append(UserResponse(
            id=user.id,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            status=ut.status,
            avatar_url=user.avatar_url,
            app_roles=ut.app_roles,
            joined_at=ut.joined_at,
            last_login=user.last_login,
            social_accounts=[{
                "provider": sa.provider,
                "linked_at": sa.created_at
            } for sa in social_accounts]
        ))

    # Return paginated response
    return UserListResponse(
        users=users,
        pagination=PaginationInfo(
            page=page,
            size=size,
            total=total_count,
            pages=(total_count + size - 1) // size
        )
    )

@router.post("/tenants/{tenant_id}/invitations", response_model=InvitationResponse)
async def invite_user(
    tenant_id: str,
    request: UserInviteRequest,
    token: str = Depends(HTTPBearer()),
    db: Session = Depends(get_db)
):
    """Invite user to tenant"""
    logger.info(f"🔔 INVITE_USER ENDPOINT CALLED for tenant: {tenant_id}, email: {request.email}")
    token_data = await verify_token(token.credentials)
    logger.info(f"🔔 TOKEN VERIFIED for user: {token_data.sub}")

    # Check if current user belongs to this tenant by querying database
    logger.info(f"Looking for user with keycloak_id: {token_data.sub}")
    current_user = db.query(User).filter(User.keycloak_id == token_data.sub).first()
    if not current_user:
        logger.error(f"User not found with keycloak_id: {token_data.sub}")
        raise HTTPException(status_code=404, detail="Current user not found")

    logger.info(f"Found user: {current_user.id}, checking tenant access for tenant: {tenant_id}")
    user_tenant = db.query(UserTenant).filter(
        UserTenant.user_id == current_user.id,
        UserTenant.tenant_id == tenant_id
    ).first()

    if not user_tenant:
        logger.error(f"User {current_user.id} does not have access to tenant {tenant_id}")
        raise HTTPException(status_code=403, detail="Access denied to tenant")

    logger.info(f"User {current_user.id} has access to tenant {tenant_id} with roles: {user_tenant.app_roles}")

    # Check if user is admin in this tenant
    is_admin = any(
        "admin" in user_tenant.app_roles.get(app, [])
        for app in ["darkhole", "darkfolio", "confiploy"]
    )

    if not is_admin:
        raise HTTPException(status_code=403, detail="Admin role required to invite users")

    # Validate app roles and check limits
    for app_name, roles in request.app_roles.items():
        if app_name not in ["darkhole", "darkfolio", "confiploy"]:
            raise HTTPException(status_code=400, detail=f"Invalid app name: {app_name}")

        app_access = db.query(TenantAppAccess).filter(
            TenantAppAccess.tenant_id == tenant_id,
            TenantAppAccess.app_name == app_name
        ).first()

        if not app_access or app_access.current_users >= app_access.user_limit:
            raise HTTPException(
                status_code=400,
                detail=f"User limit exceeded for {app_name} app"
            )

    # Check for existing invitation first
    logger.info(f"Checking for existing invitation: tenant_id={tenant_id}, email={request.email}")
    existing_invitation = db.query(Invitation).filter(
        Invitation.tenant_id == tenant_id,
        Invitation.email == request.email
    ).first()

    logger.info(f"Existing invitation query result: {existing_invitation}")
    if existing_invitation:
        logger.info(f"Found existing invitation: id={existing_invitation.id}, status={existing_invitation.status}")

    if existing_invitation:
        if existing_invitation.status == "pending":
            # Check cooldown for resend (like email verification)
            cooldown_minutes = 5  # Same as email verification
            if existing_invitation.last_sent_at:
                cooldown_time = existing_invitation.last_sent_at + timedelta(minutes=cooldown_minutes)
                if datetime.utcnow() < cooldown_time:
                    remaining_minutes = (cooldown_time - datetime.utcnow()).total_seconds() / 60
                    raise HTTPException(
                        status_code=429,  # Too Many Requests
                        detail=f"Please wait {int(remaining_minutes)} more minutes before resending invitation to {request.email}"
                    )

            # Update existing pending invitation (resend)
            existing_invitation.app_roles = request.app_roles
            existing_invitation.invited_by = current_user.id
            existing_invitation.expires_at = datetime.utcnow() + timedelta(days=7)
            existing_invitation.resent_count = (existing_invitation.resent_count or 0) + 1
            existing_invitation.last_sent_at = datetime.utcnow()
            existing_invitation.updated_at = datetime.utcnow()
            invitation = existing_invitation
            logger.info(f"Resending invitation for {request.email} (attempt #{invitation.resent_count})")
        else:
            raise HTTPException(
                status_code=409,
                detail=f"User {request.email} already has a {existing_invitation.status} invitation"
            )
    else:
        # Create new invitation
        invitation = Invitation(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            email=request.email,
            app_roles=request.app_roles,
            invited_by=current_user.id,
            expires_at=datetime.utcnow() + timedelta(days=7),
            status="pending"
        )
        db.add(invitation)
        logger.info(f"Created new invitation for {request.email}")

    db.commit()

    # Send invitation email
    try:
        from invitation_email_service import InvitationEmailService
        from shared.models import Tenant

        # Get tenant and send email
        tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()

        email_service = InvitationEmailService()
        email_result = await email_service.send_invitation_email(
            db=db,
            invitation=invitation,
            invited_by_user=current_user,
            tenant=tenant
        )
        logger.info(f"Email service result: {email_result}")

    except Exception as email_error:
        logger.warning(f"Failed to send invitation email (invitation still created): {email_error}")
        # Don't fail the invitation creation if email fails

    return InvitationResponse(
        id=invitation.id,
        email=invitation.email,
        app_roles=invitation.app_roles,
        status=invitation.status,
        expires_at=invitation.expires_at,
        created_at=invitation.created_at,
        invited_by=invitation.invited_by,
        resent_count=invitation.resent_count or 0,
        last_sent_at=invitation.last_sent_at or invitation.created_at
    )

@router.put("/tenants/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    request: UserUpdateRequest,
    token: str = Depends(HTTPBearer()),
    db: Session = Depends(get_db)
):
    """Update user profile and app roles"""
    token_data = await verify_token(token.credentials)

    # Get the user to update
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Get current user from token
    current_user = db.query(User).filter(User.keycloak_id == token_data.sub).first()
    if not current_user:
        raise HTTPException(status_code=404, detail="Current user not found")

    # Find the tenant this user belongs to (check permissions)
    user_tenant = db.query(UserTenant).filter(UserTenant.user_id == user_id).first()
    if not user_tenant:
        raise HTTPException(status_code=404, detail="User tenant relationship not found")

    # Verify current user has access to this tenant and is admin
    if not require_tenant_access(token_data, user_tenant.tenant_id):
        raise HTTPException(status_code=403, detail="Access denied to tenant")

    # Check if current user is admin in this tenant
    current_user_tenant = db.query(UserTenant).filter(
        UserTenant.user_id == current_user.id,
        UserTenant.tenant_id == user_tenant.tenant_id
    ).first()

    if not current_user_tenant:
        raise HTTPException(status_code=403, detail="Not a member of this tenant")

    # Check admin role
    is_admin = any(
        "admin" in current_user_tenant.app_roles.get(app, [])
        for app in ["darkhole", "darkfolio", "confiploy"]
    )

    if not is_admin:
        raise HTTPException(status_code=403, detail="Admin role required")

    try:
        # Update user basic information
        if request.first_name is not None:
            user.first_name = request.first_name
        if request.last_name is not None:
            user.last_name = request.last_name

        # Update user-tenant relationship
        if request.app_roles is not None:
            # Validate app roles
            for app_name, roles in request.app_roles.items():
                if app_name not in ["darkhole", "darkfolio", "confiploy"]:
                    raise HTTPException(status_code=400, detail=f"Invalid app name: {app_name}")

            user_tenant.app_roles = request.app_roles

        if request.status is not None:
            if request.status not in ["active", "suspended", "inactive"]:
                raise HTTPException(status_code=400, detail="Invalid status")
            user_tenant.status = request.status

        user.updated_at = datetime.utcnow()
        user_tenant.updated_at = datetime.utcnow()

        db.commit()

        # Create audit log
        audit_log = AuditLog(
            action="user_update",
            resource_type="user",
            resource_id=user.id,
            user_id=current_user.id,
            tenant_id=user_tenant.tenant_id,
            details={
                "updated_fields": {
                    "first_name": request.first_name,
                    "last_name": request.last_name,
                    "app_roles": request.app_roles,
                    "status": request.status
                }
            },
            created_at=datetime.utcnow()
        )
        db.add(audit_log)
        db.commit()

        # Get social accounts for response
        social_accounts = db.query(SocialAccount).filter(
            SocialAccount.user_id == user.id
        ).all()

        return UserResponse(
            id=user.id,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            status=user_tenant.status,
            avatar_url=user.avatar_url,
            app_roles=user_tenant.app_roles,
            joined_at=user_tenant.joined_at,
            last_login=user.last_login,
            social_accounts=[{
                "provider": sa.provider,
                "linked_at": sa.created_at
            } for sa in social_accounts]
        )

    except Exception as e:
        db.rollback()
        logger.error(f"Error updating user {user_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update user: {str(e)}")

@router.put("/users/{user_id}/suspend")
async def suspend_user(
    user_id: str,
    token: str = Depends(HTTPBearer()),
    db: Session = Depends(get_db)
):
    """Suspend a user"""
    token_data = await verify_token(token.credentials)

    # Get the user to suspend
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Get current user from token
    current_user = db.query(User).filter(User.keycloak_id == token_data.sub).first()
    if not current_user:
        raise HTTPException(status_code=404, detail="Current user not found")

    # Find the tenant this user belongs to
    user_tenant = db.query(UserTenant).filter(UserTenant.user_id == user_id).first()
    if not user_tenant:
        raise HTTPException(status_code=404, detail="User tenant relationship not found")

    # Check if current user belongs to the same tenant
    current_user_tenant = db.query(UserTenant).filter(
        UserTenant.user_id == current_user.id,
        UserTenant.tenant_id == user_tenant.tenant_id
    ).first()

    if not current_user_tenant:
        raise HTTPException(status_code=403, detail="Access denied to tenant")

    # Check if current user is admin
    current_user_tenant = db.query(UserTenant).filter(
        UserTenant.user_id == current_user.id,
        UserTenant.tenant_id == user_tenant.tenant_id
    ).first()

    if not current_user_tenant:
        raise HTTPException(status_code=403, detail="Not a member of this tenant")

    is_admin = any(
        "admin" in current_user_tenant.app_roles.get(app, [])
        for app in ["darkhole", "darkfolio", "confiploy"]
    )

    if not is_admin:
        raise HTTPException(status_code=403, detail="Admin role required")

    try:
        # Update user status
        user_tenant.status = "suspended"
        user_tenant.updated_at = datetime.utcnow()

        db.commit()

        # Create audit log
        audit_log = AuditLog(
            action="user_suspend",
            resource_type="user",
            resource_id=user.id,
            user_id=current_user.id,
            tenant_id=user_tenant.tenant_id,
            details={"suspended_user_email": user.email},
            created_at=datetime.utcnow()
        )
        db.add(audit_log)
        db.commit()

        return {"message": "User suspended successfully", "user_id": user_id}

    except Exception as e:
        db.rollback()
        logger.error(f"Error suspending user {user_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to suspend user: {str(e)}")

@router.put("/users/{user_id}/activate")
async def activate_user(
    user_id: str,
    token: str = Depends(HTTPBearer()),
    db: Session = Depends(get_db)
):
    """Activate/reactivate a user"""
    token_data = await verify_token(token.credentials)

    # Get the user to activate
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Get current user from token
    current_user = db.query(User).filter(User.keycloak_id == token_data.sub).first()
    if not current_user:
        raise HTTPException(status_code=404, detail="Current user not found")

    # Find the tenant this user belongs to
    user_tenant = db.query(UserTenant).filter(UserTenant.user_id == user_id).first()
    if not user_tenant:
        raise HTTPException(status_code=404, detail="User tenant relationship not found")

    # Verify permissions
    if not require_tenant_access(token_data, user_tenant.tenant_id):
        raise HTTPException(status_code=403, detail="Access denied to tenant")

    # Check if current user is admin
    current_user_tenant = db.query(UserTenant).filter(
        UserTenant.user_id == current_user.id,
        UserTenant.tenant_id == user_tenant.tenant_id
    ).first()

    if not current_user_tenant:
        raise HTTPException(status_code=403, detail="Not a member of this tenant")

    is_admin = any(
        "admin" in current_user_tenant.app_roles.get(app, [])
        for app in ["darkhole", "darkfolio", "confiploy"]
    )

    if not is_admin:
        raise HTTPException(status_code=403, detail="Admin role required")

    try:
        # Update user status
        user_tenant.status = "active"
        user_tenant.updated_at = datetime.utcnow()

        db.commit()

        # Create audit log
        audit_log = AuditLog(
            action="user_activate",
            resource_type="user",
            resource_id=user.id,
            user_id=current_user.id,
            tenant_id=user_tenant.tenant_id,
            details={"activated_user_email": user.email},
            created_at=datetime.utcnow()
        )
        db.add(audit_log)
        db.commit()

        return {"message": "User activated successfully", "user_id": user_id}

    except Exception as e:
        db.rollback()
        logger.error(f"Error activating user {user_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to activate user: {str(e)}")



@router.post("/users/bulk-action")
async def bulk_user_action(
    action_request: dict,
    token: str = Depends(HTTPBearer()),
    db: Session = Depends(get_db)
):
    """Perform bulk actions on users (suspend, activate)"""
    token_data = await verify_token(token.credentials)

    # Validate request structure
    if "action" not in action_request or "user_ids" not in action_request:
        raise HTTPException(status_code=400, detail="Missing 'action' or 'user_ids' in request")

    action = action_request["action"]
    user_ids = action_request["user_ids"]

    if action not in ["suspend", "activate"]:
        raise HTTPException(status_code=400, detail="Invalid action. Must be 'suspend' or 'activate'")

    if not isinstance(user_ids, list) or len(user_ids) == 0:
        raise HTTPException(status_code=400, detail="user_ids must be a non-empty list")

    # Get current user
    current_user = db.query(User).filter(User.keycloak_id == token_data.sub).first()
    if not current_user:
        raise HTTPException(status_code=404, detail="Current user not found")

    results = {"success": [], "failed": []}

    try:
        for user_id in user_ids:
            try:
                # Get user and tenant relationship
                user = db.query(User).filter(User.id == user_id).first()
                if not user:
                    results["failed"].append({"user_id": user_id, "reason": "User not found"})
                    continue

                user_tenant = db.query(UserTenant).filter(UserTenant.user_id == user_id).first()
                if not user_tenant:
                    results["failed"].append({"user_id": user_id, "reason": "User tenant relationship not found"})
                    continue

                # Verify permissions for this tenant
                if not require_tenant_access(token_data, user_tenant.tenant_id):
                    results["failed"].append({"user_id": user_id, "reason": "Access denied to tenant"})
                    continue

                # Check if current user is admin in this tenant
                current_user_tenant = db.query(UserTenant).filter(
                    UserTenant.user_id == current_user.id,
                    UserTenant.tenant_id == user_tenant.tenant_id
                ).first()

                if not current_user_tenant:
                    results["failed"].append({"user_id": user_id, "reason": "Not a member of this tenant"})
                    continue

                is_admin = any(
                    "admin" in current_user_tenant.app_roles.get(app, [])
                    for app in ["darkhole", "darkfolio", "confiploy"]
                )

                if not is_admin:
                    results["failed"].append({"user_id": user_id, "reason": "Admin role required"})
                    continue

                # Perform the action
                new_status = "suspended" if action == "suspend" else "active"
                user_tenant.status = new_status
                user_tenant.updated_at = datetime.utcnow()

                # Create audit log
                audit_log = AuditLog(
                    action=f"user_{action}",
                    resource_type="user",
                    resource_id=user.id,
                    user_id=current_user.id,
                    tenant_id=user_tenant.tenant_id,
                    details={
                        "bulk_action": True,
                        "user_email": user.email,
                        "new_status": new_status
                    },
                    created_at=datetime.utcnow()
                )
                db.add(audit_log)

                results["success"].append({"user_id": user_id, "email": user.email})

            except Exception as e:
                logger.error(f"Error processing user {user_id} in bulk action: {e}")
                results["failed"].append({"user_id": user_id, "reason": str(e)})

        db.commit()

        return {
            "action": action,
            "results": results,
            "summary": {
                "total": len(user_ids),
                "success": len(results["success"]),
                "failed": len(results["failed"])
            }
        }

    except Exception as e:
        db.rollback()
        logger.error(f"Error in bulk user action: {e}")
        raise HTTPException(status_code=500, detail=f"Bulk action failed: {str(e)}")

@router.get("/tenants/{tenant_id}/invitations", response_model=list[InvitationResponse])
async def list_tenant_invitations(
    tenant_id: str,
    token: str = Depends(HTTPBearer()),
    db: Session = Depends(get_db)
):
    """List all invitations for a tenant"""
    token_data = await verify_token(token.credentials)

    # Use the same database-based authorization as the invitation creation endpoint
    current_user = db.query(User).filter(User.keycloak_id == token_data.sub).first()
    if not current_user:
        raise HTTPException(status_code=404, detail="Current user not found")

    user_tenant = db.query(UserTenant).filter(
        UserTenant.user_id == current_user.id,
        UserTenant.tenant_id == tenant_id
    ).first()

    if not user_tenant:
        raise HTTPException(status_code=403, detail="Access denied to tenant")

    # Get all invitations for this tenant
    invitations = db.query(Invitation).filter(
        Invitation.tenant_id == tenant_id
    ).order_by(Invitation.created_at.desc()).all()

    return [
        InvitationResponse(
            id=inv.id,
            email=inv.email,
            app_roles=inv.app_roles,
            status=inv.status,
            expires_at=inv.expires_at,
            created_at=inv.created_at,
            invited_by=inv.invited_by,
            resent_count=inv.resent_count or 0,
            last_sent_at=inv.last_sent_at or inv.created_at
        )
        for inv in invitations
    ]

@router.post("/tenants/invitations/{invitation_id}/resend")
async def resend_invitation(
    invitation_id: str,
    token: str = Depends(HTTPBearer()),
    db: Session = Depends(get_db)
):
    """Resend an existing invitation"""
    try:
        token_data = await verify_token(token.credentials)

        # Get current user
        current_user = db.query(User).filter(User.keycloak_id == token_data.sub).first()
        if not current_user:
            raise HTTPException(status_code=404, detail="Current user not found")

        # Find the invitation
        invitation = db.query(Invitation).filter(Invitation.id == invitation_id).first()
        if not invitation:
            raise HTTPException(status_code=404, detail="Invitation not found")

        # Check if user has access to this tenant using database-based authorization
        # (same method as list_tenant_invitations which works)
        user_tenant = db.query(UserTenant).filter(
            UserTenant.user_id == current_user.id,
            UserTenant.tenant_id == invitation.tenant_id
        ).first()
        if not user_tenant:
            raise HTTPException(status_code=403, detail="Access denied to tenant")

        # Check if invitation is still valid
        if invitation.status != "pending":
            raise HTTPException(
                status_code=400,
                detail=f"Cannot resend invitation with status: {invitation.status}"
            )

        # Check if invitation has expired
        if invitation.expires_at and datetime.utcnow() > invitation.expires_at:
            raise HTTPException(status_code=400, detail="Invitation has expired")

        # Update invitation with resend info
        invitation.resent_count = (invitation.resent_count or 0) + 1
        invitation.last_sent_at = datetime.utcnow()

        # Extend expiry by 7 more days
        invitation.expires_at = datetime.utcnow() + timedelta(days=7)

        db.commit()

        # Send invitation email
        try:
            from invitation_email_service import InvitationEmailService
            from shared.models import Tenant

            # Get tenant and send email
            tenant = db.query(Tenant).filter(Tenant.id == invitation.tenant_id).first()

            email_service = InvitationEmailService()
            email_result = await email_service.send_invitation_email(
                db=db,
                invitation=invitation,
                invited_by_user=current_user,
                tenant=tenant
            )
            logger.info(f"Resend email service result: {email_result}")

        except Exception as email_error:
            logger.warning(f"Failed to resend invitation email: {email_error}")
            # Don't fail the resend if email fails

        return {
            "status": "success",
            "message": f"Invitation resent to {invitation.email}",
            "invitation_id": invitation.id,
            "resent_count": invitation.resent_count,
            "new_expiry": invitation.expires_at.isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Error resending invitation: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to resend invitation: {str(e)}")

class BulkInviteRequest(BaseModel):
    invitations: List[UserInviteRequest]

class BulkInviteResponse(BaseModel):
    total_sent: int
    successful: List[InvitationResponse]
    failed: List[dict]

@router.post("/tenants/{tenant_id}/users/bulk-invite", response_model=BulkInviteResponse)
async def bulk_invite_users(
    tenant_id: str,
    request: BulkInviteRequest,
    token: str = Depends(HTTPBearer()),
    db: Session = Depends(get_db)
):
    """Bulk invite multiple users to tenant"""
    token_data = await verify_token(token.credentials)

    # Check if current user belongs to this tenant by querying database
    current_user = db.query(User).filter(User.keycloak_id == token_data.sub).first()
    if not current_user:
        raise HTTPException(status_code=404, detail="Current user not found")

    user_tenant = db.query(UserTenant).filter(
        UserTenant.user_id == current_user.id,
        UserTenant.tenant_id == tenant_id
    ).first()

    if not user_tenant:
        raise HTTPException(status_code=403, detail="Access denied to tenant")

    # Check if user is admin in this tenant
    is_admin = any(
        "admin" in user_tenant.app_roles.get(app, [])
        for app in ["darkhole", "darkfolio", "confiploy"]
    )

    if not is_admin:
        raise HTTPException(status_code=403, detail="Admin role required to invite users")

    results = {"successful": [], "failed": []}

    try:
        for invite_request in request.invitations:
            try:
                # Check if email already invited or exists
                existing_invitation = db.query(Invitation).filter(
                    Invitation.tenant_id == tenant_id,
                    Invitation.email == invite_request.email,
                    Invitation.status.in_(["pending", "sent"])
                ).first()

                if existing_invitation:
                    results["failed"].append({
                        "email": invite_request.email,
                        "reason": "Already has pending invitation"
                    })
                    continue

                # Check if user already exists in tenant
                existing_user = db.query(User).filter(User.email == invite_request.email).first()
                if existing_user:
                    existing_user_tenant = db.query(UserTenant).filter(
                        UserTenant.user_id == existing_user.id,
                        UserTenant.tenant_id == tenant_id
                    ).first()

                    if existing_user_tenant:
                        results["failed"].append({
                            "email": invite_request.email,
                            "reason": "User already exists in tenant"
                        })
                        continue

                # Validate app roles and check limits
                for app_name, roles in invite_request.app_roles.items():
                    if app_name not in ["darkhole", "darkfolio", "confiploy"]:
                        results["failed"].append({
                            "email": invite_request.email,
                            "reason": f"Invalid app name: {app_name}"
                        })
                        continue

                    app_access = db.query(TenantAppAccess).filter(
                        TenantAppAccess.tenant_id == tenant_id,
                        TenantAppAccess.app_name == app_name
                    ).first()

                    if not app_access or app_access.current_users >= app_access.user_limit:
                        results["failed"].append({
                            "email": invite_request.email,
                            "reason": f"User limit exceeded for {app_name} app"
                        })
                        continue

                # Create invitation
                invitation = Invitation(
                    id=str(uuid.uuid4()),
                    tenant_id=tenant_id,
                    email=invite_request.email,
                    app_roles=invite_request.app_roles,
                    invited_by=current_user.id,
                    expires_at=datetime.utcnow() + timedelta(days=7),
                    status="pending"
                )
                db.add(invitation)

                # Send invitation email
                try:
                    from invitation_email_service import InvitationEmailService
                    from shared.models import Tenant

                    # Get tenant and send email
                    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()

                    email_service = InvitationEmailService()
                    email_result = await email_service.send_invitation_email(
                        db=db,
                        invitation=invitation,
                        invited_by_user=current_user,
                        tenant=tenant
                    )
                    logger.info(f"Bulk email service result for {invitation.email}: {email_result}")

                except Exception as email_error:
                    logger.warning(f"Failed to send bulk invitation email to {invitation.email}: {email_error}")
                    # Don't fail the invitation creation if email fails

                invitation_response = InvitationResponse(
                    id=invitation.id,
                    email=invitation.email,
                    app_roles=invitation.app_roles,
                    status=invitation.status,
                    expires_at=invitation.expires_at,
                    created_at=invitation.created_at,
                    invited_by=invitation.invited_by,
                    resent_count=0,
                    last_sent_at=invitation.created_at
                )

                results["successful"].append(invitation_response)

            except Exception as e:
                logger.error(f"Error creating invitation for {invite_request.email}: {e}")
                results["failed"].append({
                    "email": invite_request.email,
                    "reason": f"Internal error: {str(e)}"
                })

        db.commit()

        # TODO: Send bulk invitation emails
        # await send_bulk_invitation_emails(results["successful"])

        return BulkInviteResponse(
            total_sent=len(results["successful"]),
            successful=results["successful"],
            failed=results["failed"]
        )

    except Exception as e:
        db.rollback()
        logger.error(f"Error in bulk invite: {e}")
        raise HTTPException(status_code=500, detail=f"Bulk invite failed: {str(e)}")


@router.delete("/tenants/invitations/{invitation_id}")
async def cancel_invitation(
    invitation_id: str,
    token: str = Depends(HTTPBearer()),
    db: Session = Depends(get_db)
):
    """Cancel an invitation"""
    token_data = await verify_token(token.credentials)

    # Get the invitation
    invitation = db.query(Invitation).filter(Invitation.id == invitation_id).first()
    if not invitation:
        raise HTTPException(status_code=404, detail="Invitation not found")

    # Check tenant access
    if not require_tenant_access(token_data, invitation.tenant_id):
        raise HTTPException(status_code=403, detail="Access denied to tenant")

    # Check if user is admin
    user_roles = token_data.resource_access.get("darkhole-client", {}).get("roles", [])
    if "admin" not in user_roles:
        raise HTTPException(status_code=403, detail="Admin role required")

    try:
        # Update invitation status
        invitation.status = "cancelled"
        invitation.updated_at = datetime.utcnow()

        db.commit()

        return {
            "message": "Invitation cancelled successfully",
            "invitation_id": invitation_id
        }

    except Exception as e:
        db.rollback()
        logger.error(f"Error cancelling invitation {invitation_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to cancel invitation: {str(e)}")


@router.get("/tenants/accept-invitation/{invitation_id}")
async def get_invitation_info(
    invitation_id: str,
    db: Session = Depends(get_db)
):
    """Get invitation information for display on acceptance page"""
    try:
        # Find the invitation by ID
        invitation = db.query(Invitation).filter(Invitation.id == invitation_id).first()
        if not invitation:
            raise HTTPException(status_code=404, detail="Invitation not found")

        # Check if invitation has expired
        if invitation.expires_at and datetime.utcnow() > invitation.expires_at:
            return {
                "status": "expired",
                "message": "This invitation has expired"
            }

        # Check if invitation is still valid
        if invitation.status != "pending":
            return {
                "status": "used",
                "message": f"This invitation has already been {invitation.status}"
            }

        # Get tenant and inviter information
        from shared.models import Tenant
        tenant = db.query(Tenant).filter(Tenant.id == invitation.tenant_id).first()
        inviter = db.query(User).filter(User.id == invitation.invited_by).first()

        return {
            "status": "valid",
            "invitation_id": invitation_id,
            "email": invitation.email,
            "tenant_name": tenant.name if tenant else "Unknown Organization",
            "inviter_name": f"{inviter.first_name} {inviter.last_name}" if inviter else "Admin",
            "app_roles": invitation.app_roles,
            "expires_at": invitation.expires_at.isoformat() if invitation.expires_at else None,
            "message": "Invitation is valid and ready to accept"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting invitation info {invitation_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get invitation info: {str(e)}")

@router.post("/tenants/accept-invitation/{invitation_id}")
async def accept_invitation(
    invitation_id: str,
    request: InvitationAcceptRequest,
    db: Session = Depends(get_db)
):
    """Accept an invitation and create/link user account"""
    try:
        # Find the invitation by ID
        invitation = db.query(Invitation).filter(Invitation.id == invitation_id).first()
        if not invitation:
            raise HTTPException(status_code=404, detail="Invitation not found")

        # Check if invitation is still valid
        if invitation.status != "pending":
            raise HTTPException(
                status_code=400,
                detail=f"Invitation is no longer valid. Status: {invitation.status}"
            )

        # Check if invitation has expired
        if invitation.expires_at and datetime.utcnow() > invitation.expires_at:
            raise HTTPException(status_code=400, detail="Invitation has expired")

        # Check if user with this email already exists
        existing_user = db.query(User).filter(User.email == invitation.email).first()

        if existing_user:
            # User exists, check if already in tenant
            existing_user_tenant = db.query(UserTenant).filter(
                UserTenant.user_id == existing_user.id,
                UserTenant.tenant_id == invitation.tenant_id
            ).first()

            if existing_user_tenant:
                # Update invitation status anyway
                invitation.status = "accepted"
                invitation.accepted_at = datetime.utcnow()
                db.commit()

                return {
                    "status": "already_member",
                    "message": "You are already a member of this organization",
                    "redirect_url": "/login"
                }
            else:
                # Add existing user to tenant
                user_tenant = UserTenant(
                    user_id=existing_user.id,
                    tenant_id=invitation.tenant_id,
                    app_roles=invitation.app_roles,
                    status="active",
                    joined_at=datetime.utcnow()
                )
                db.add(user_tenant)

                # Update invitation status
                invitation.status = "accepted"
                invitation.accepted_at = datetime.utcnow()

                db.commit()

                return {
                    "status": "success",
                    "message": "Successfully joined organization! You can now login.",
                    "user_id": existing_user.id,
                    "tenant_id": invitation.tenant_id,
                    "redirect_url": "/login"
                }

        # User doesn't exist - create new user account
        from keycloak_client import KeycloakClient
        import uuid

        # Create user in database (no password stored here)
        from shared.models import UserStatus

        new_user = User(
            id=str(uuid.uuid4()),
            email=invitation.email,
            first_name=request.first_name,
            last_name=request.last_name,
            is_email_verified=True,  # Skip email verification for invited users
            status=UserStatus.ACTIVE  # Use status field with UserStatus.ACTIVE instead of is_active
        )
        db.add(new_user)
        db.flush()  # Flush to get the user ID

        # Create user in Keycloak with password
        try:
            keycloak_client = KeycloakClient()
            keycloak_user_id = await keycloak_client.create_user_with_tenant(
                email=invitation.email,
                password=request.password,
                first_name=request.first_name,
                last_name=request.last_name,
                tenant_id=invitation.tenant_id,
                app_roles=invitation.app_roles
            )

            # Update user with Keycloak ID
            new_user.keycloak_id = keycloak_user_id

            # Enable the Keycloak user immediately for invited users (skip email verification)
            await keycloak_client.activate_user_after_verification(keycloak_user_id)

        except Exception as keycloak_error:
            # If Keycloak creation fails, we still want to create the local user
            # for invitation acceptance, but log the error
            logger.warning(f"Keycloak user creation failed for {invitation.email}: {keycloak_error}")
            # Continue without Keycloak ID

        # Add user to tenant with invitation roles
        user_tenant = UserTenant(
            user_id=new_user.id,
            tenant_id=invitation.tenant_id,
            app_roles=invitation.app_roles,
            status="active",
            joined_at=datetime.utcnow()
        )
        db.add(user_tenant)

        # Update invitation status
        invitation.status = "accepted"
        invitation.accepted_at = datetime.utcnow()

        db.commit()

        return {
            "status": "success",
            "message": "Account created successfully! You can now login with your credentials.",
            "user_id": new_user.id,
            "tenant_id": invitation.tenant_id,
            "redirect_url": "/login"
        }

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Error accepting invitation {invitation_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to accept invitation: {str(e)}")