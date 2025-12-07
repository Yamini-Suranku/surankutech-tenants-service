"""
Organization Groups Management Module
Handles manual groups created for organizations (email-invited users).
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
import logging
from datetime import datetime
import uuid

from shared.database import get_db
from shared.auth import get_current_user
from shared.models import User
from models import (
    OrganizationGroup,
    OrganizationGroupMembership,
    Organization,
    DirectoryGroup,
    DirectoryGroupMembership,
    TenantLDAPConfig,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/platform/organizations", tags=["organization-groups"])


# Pydantic models for API requests/responses
class OrganizationGroupCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="Group name")
    display_name: Optional[str] = Field(None, max_length=255, description="Display name")
    description: Optional[str] = Field(None, description="Group description")
    color: Optional[str] = Field("#6366f1", pattern=r"^#[0-9A-Fa-f]{6}$", description="Hex color code")


class OrganizationGroupUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    display_name: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = Field(None)
    color: Optional[str] = Field(None, pattern=r"^#[0-9A-Fa-f]{6}$")
    app_role_mappings: Optional[Dict[str, List[str]]] = Field(None, description="App role mappings")


class OrganizationGroupResponse(BaseModel):
    id: str
    name: str
    display_name: Optional[str]
    description: Optional[str]
    color: str
    source_type: str
    app_role_mappings: Dict[str, List[str]]
    member_count: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class GroupMembershipUpdate(BaseModel):
    user_ids: List[str] = Field(..., description="List of user IDs to set as group members")


def _require_org_admin_access(db: Session, user_id: str, org: Organization):
    """Check if user has admin access to the organization."""
    # This should match the logic from organization_azure_ad.py
    # For now, we'll implement basic checks
    pass  # TODO: Implement proper admin access check


@router.get("/{organization_id}/groups")
async def get_organization_groups(
    organization_id: str,
    include_directory: bool = True,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> List[OrganizationGroupResponse]:
    """Get all groups for an organization (manual + directory groups)."""
    try:
        org = db.query(Organization).filter(
            Organization.id == organization_id,
            Organization.deleted_at.is_(None)
        ).first()
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        _require_org_admin_access(db, current_user.user_id, org)

        # Get manual groups
        manual_groups = db.query(OrganizationGroup).filter(
            OrganizationGroup.organization_id == organization_id
        ).all()

        groups_data = []

        # Add manual groups
        for group in manual_groups:
            # Count members
            member_count = db.query(OrganizationGroupMembership).filter(
                OrganizationGroupMembership.organization_group_id == group.id
            ).count()

            groups_data.append(OrganizationGroupResponse(
                id=group.id,
                name=group.name,
                display_name=group.display_name,
                description=group.description,
                color=group.color,
                source_type=group.source_type,
                app_role_mappings=group.app_role_mappings or {},
                member_count=member_count,
                created_at=group.created_at,
                updated_at=group.updated_at
            ))

        # Add directory groups if requested
        if include_directory:
            directory_groups = db.query(DirectoryGroup).filter(
                DirectoryGroup.organization_id == organization_id,
                DirectoryGroup.provider_type.in_(["azure_ad_graph", "ldap"])
            ).all()

            # Get LDAP config to check for group role mappings
            ldap_config = db.query(TenantLDAPConfig).filter(
                TenantLDAPConfig.tenant_id == org.tenant_id,
                TenantLDAPConfig.organization_id == organization_id,
                TenantLDAPConfig.provider_type.in_(["azure_ad_graph", "ldap"])
            ).first()

            group_role_mappings = ldap_config.group_role_mappings if ldap_config else {}

            for group in directory_groups:
                # Get role mappings for this group
                group_roles = group_role_mappings.get(group.external_id, {})

                # Count directory group members
                directory_member_count = db.query(DirectoryGroupMembership).filter(
                    DirectoryGroupMembership.directory_group_id == group.id
                ).count()

                groups_data.append(OrganizationGroupResponse(
                    id=group.external_id,  # Use external_id as the ID for directory groups
                    name=group.display_name or group.name,
                    display_name=group.display_name,
                    description=group.description,
                    color="#9333ea",  # Purple for Azure AD groups, Green for LDAP
                    source_type=group.provider_type,
                    app_role_mappings=group_roles,
                    member_count=directory_member_count,
                    created_at=group.created_at,
                    updated_at=group.updated_at
                ))

        return groups_data

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get organization groups: {e}")
        raise HTTPException(status_code=500, detail="Failed to get organization groups")


@router.post("/{organization_id}/groups")
async def create_organization_group(
    organization_id: str,
    group_data: OrganizationGroupCreate,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> OrganizationGroupResponse:
    """Create a new manual group for the organization."""
    try:
        org = db.query(Organization).filter(
            Organization.id == organization_id,
            Organization.deleted_at.is_(None)
        ).first()
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        _require_org_admin_access(db, current_user.user_id, org)

        # Check if group name already exists
        existing_group = db.query(OrganizationGroup).filter(
            and_(
                OrganizationGroup.organization_id == organization_id,
                OrganizationGroup.name == group_data.name
            )
        ).first()
        if existing_group:
            raise HTTPException(
                status_code=400,
                detail=f"Group '{group_data.name}' already exists in this organization"
            )

        # Find the database user ID using the Keycloak ID from current_user
        db_user = db.query(User).filter(User.keycloak_id == current_user.user_id).first()
        created_by_id = db_user.id if db_user else None

        # Create new group
        new_group = OrganizationGroup(
            tenant_id=org.tenant_id,
            organization_id=organization_id,
            name=group_data.name,
            display_name=group_data.display_name,
            description=group_data.description,
            color=group_data.color or "#6366f1",
            created_by=created_by_id,
            app_role_mappings={}
        )

        db.add(new_group)
        db.commit()
        db.refresh(new_group)

        return OrganizationGroupResponse(
            id=new_group.id,
            name=new_group.name,
            display_name=new_group.display_name,
            description=new_group.description,
            color=new_group.color,
            source_type=new_group.source_type,
            app_role_mappings=new_group.app_role_mappings or {},
            member_count=0,
            created_at=new_group.created_at,
            updated_at=new_group.updated_at
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create organization group: {e}")
        raise HTTPException(status_code=500, detail="Failed to create organization group")


@router.put("/{organization_id}/groups/{group_id}")
async def update_organization_group(
    organization_id: str,
    group_id: str,
    group_data: OrganizationGroupUpdate,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> OrganizationGroupResponse:
    """Update an existing manual group."""
    try:
        org = db.query(Organization).filter(
            Organization.id == organization_id,
            Organization.deleted_at.is_(None)
        ).first()
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        _require_org_admin_access(db, current_user.user_id, org)

        # Get the group
        group = db.query(OrganizationGroup).filter(
            and_(
                OrganizationGroup.id == group_id,
                OrganizationGroup.organization_id == organization_id
            )
        ).first()
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")

        # Update fields if provided
        if group_data.name is not None:
            # Check if new name conflicts
            existing_group = db.query(OrganizationGroup).filter(
                and_(
                    OrganizationGroup.organization_id == organization_id,
                    OrganizationGroup.name == group_data.name,
                    OrganizationGroup.id != group_id
                )
            ).first()
            if existing_group:
                raise HTTPException(
                    status_code=400,
                    detail=f"Group '{group_data.name}' already exists in this organization"
                )
            group.name = group_data.name

        if group_data.display_name is not None:
            group.display_name = group_data.display_name
        if group_data.description is not None:
            group.description = group_data.description
        if group_data.color is not None:
            group.color = group_data.color
        if group_data.app_role_mappings is not None:
            group.app_role_mappings = group_data.app_role_mappings

        group.updated_at = datetime.utcnow()

        db.commit()
        db.refresh(group)

        # Get member count
        member_count = db.query(OrganizationGroupMembership).filter(
            OrganizationGroupMembership.organization_group_id == group.id
        ).count()

        return OrganizationGroupResponse(
            id=group.id,
            name=group.name,
            display_name=group.display_name,
            description=group.description,
            color=group.color,
            source_type=group.source_type,
            app_role_mappings=group.app_role_mappings or {},
            member_count=member_count,
            created_at=group.created_at,
            updated_at=group.updated_at
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update organization group: {e}")
        raise HTTPException(status_code=500, detail="Failed to update organization group")


@router.delete("/{organization_id}/groups/{group_id}")
async def delete_organization_group(
    organization_id: str,
    group_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Delete a manual group and all its memberships."""
    try:
        org = db.query(Organization).filter(
            Organization.id == organization_id,
            Organization.deleted_at.is_(None)
        ).first()
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        _require_org_admin_access(db, current_user.user_id, org)

        # Get the group
        group = db.query(OrganizationGroup).filter(
            and_(
                OrganizationGroup.id == group_id,
                OrganizationGroup.organization_id == organization_id
            )
        ).first()
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")

        # Delete the group (memberships will cascade)
        db.delete(group)
        db.commit()

        return {"message": "Group deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete organization group: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete organization group")


@router.get("/{organization_id}/groups/{group_id}/members")
async def get_group_members(
    organization_id: str,
    group_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get members of a manual group."""
    try:
        org = db.query(Organization).filter(
            Organization.id == organization_id,
            Organization.deleted_at.is_(None)
        ).first()
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        _require_org_admin_access(db, current_user.user_id, org)

        # Get group memberships with user details
        memberships = db.query(OrganizationGroupMembership, User).join(
            User, OrganizationGroupMembership.user_id == User.id
        ).filter(
            OrganizationGroupMembership.organization_group_id == group_id
        ).all()

        members_data = []
        for membership, user in memberships:
            members_data.append({
                "user_id": user.id,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "full_name": f"{user.first_name or ''} {user.last_name or ''}".strip(),
                "joined_at": membership.created_at.isoformat()
            })

        return {"members": members_data}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get group members: {e}")
        raise HTTPException(status_code=500, detail="Failed to get group members")


@router.put("/{organization_id}/groups/{group_id}/members")
async def update_group_members(
    organization_id: str,
    group_id: str,
    membership_data: GroupMembershipUpdate,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Update group membership (replace all members)."""
    try:
        org = db.query(Organization).filter(
            Organization.id == organization_id,
            Organization.deleted_at.is_(None)
        ).first()
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        _require_org_admin_access(db, current_user.user_id, org)

        # Verify group exists
        group = db.query(OrganizationGroup).filter(
            and_(
                OrganizationGroup.id == group_id,
                OrganizationGroup.organization_id == organization_id
            )
        ).first()
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")

        # Verify all user IDs exist and belong to this tenant
        if membership_data.user_ids:
            valid_users = db.query(User).filter(
                User.id.in_(membership_data.user_ids)
            ).all()
            if len(valid_users) != len(membership_data.user_ids):
                invalid_ids = set(membership_data.user_ids) - {u.id for u in valid_users}
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid user IDs: {list(invalid_ids)}"
                )

        # Remove all existing memberships
        db.query(OrganizationGroupMembership).filter(
            OrganizationGroupMembership.organization_group_id == group_id
        ).delete()

        # Find the database user ID using the Keycloak ID from current_user
        db_user = db.query(User).filter(User.keycloak_id == current_user.user_id).first()
        created_by_id = db_user.id if db_user else None

        # Add new memberships
        for user_id in membership_data.user_ids:
            membership = OrganizationGroupMembership(
                organization_group_id=group_id,
                user_id=user_id,
                created_by=created_by_id
            )
            db.add(membership)

        db.commit()

        return {"message": f"Group membership updated. {len(membership_data.user_ids)} members assigned."}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update group members: {e}")
        raise HTTPException(status_code=500, detail="Failed to update group members")