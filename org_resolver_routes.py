"""
Organization Resolution API Routes
Provides DNS-based organization resolution for multi-tenant authentication
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from typing import Dict, Any, Optional, List
from pydantic import BaseModel
import logging
from sqlalchemy.orm import Session
from sqlalchemy import and_

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from shared.database import get_db
from shared.auth import get_current_token_data, TokenData, require_platform_admin_access, extract_subdomain_from_hostname
from modules.tenant_management import get_or_create_user_from_token
from models import Organization, OrganizationAppAccess, OrganizationUserRole
from shared.models import Tenant, User

router = APIRouter()
logger = logging.getLogger(__name__)

class OrganizationContext(BaseModel):
    """Organization context response model"""
    org_id: str
    org_slug: str
    tenant_id: str
    hostname: str
    dns_subdomain: str
    dns_status: str
    status: str
    is_default: bool
    name: str
    description: Optional[str]
    app_access: Dict[str, Dict[str, Any]]
    metadata: Optional[Dict[str, Any]]

class UserOrgRole(BaseModel):
    """User organization role model"""
    user_id: str
    app_name: str
    roles: List[str]
    granted_via: str
    granted_at: str

class OrgMembershipResponse(BaseModel):
    """Authenticated user's organization membership"""
    org_id: str
    org_slug: str
    org_name: str
    tenant_id: str
    dns_subdomain: str
    dns_hostname: Optional[str]
    status: str
    app_roles: Dict[str, List[str]]
    is_default: bool

@router.get("/api/organizations/by-hostname/{hostname}")
async def resolve_organization_by_hostname(
    hostname: str,
    db: Session = Depends(get_db)
):
    """
    Resolve organization context by hostname for DNS-based routing.

    This endpoint is used by services to resolve organization context
    from subdomain hostnames (e.g., acme.darkhole.suranku.net -> acme org)

    Args:
        hostname: Full hostname (e.g., "acme.darkhole.suranku.net")

    Returns:
        Organization context with app access details
    """
    try:
        logger.info(f"🔍 Resolving organization for hostname: {hostname}")

        # Extract organization slug from hostname
        org_slug = extract_subdomain_from_hostname(hostname)
        if not org_slug:
            logger.warning(f"❌ No organization subdomain found in hostname: {hostname}")
            raise HTTPException(
                status_code=400,
                detail=f"Invalid hostname: No organization subdomain found in '{hostname}'"
            )

        # Find organization by slug
        org = db.query(Organization).filter(
            Organization.slug == org_slug,
            Organization.status == "active"
        ).first()

        if not org:
            logger.warning(f"❌ Organization '{org_slug}' not found or inactive")
            raise HTTPException(
                status_code=404,
                detail=f"Organization '{org_slug}' not found"
            )

        # Get organization app access details
        app_access_records = db.query(OrganizationAppAccess).filter(
            OrganizationAppAccess.organization_id == org.id,
            OrganizationAppAccess.is_enabled == True
        ).all()

        app_access = {}
        for access in app_access_records:
            app_access[access.app_name] = {
                "enabled": access.is_enabled,
                "ingress_hostname": access.ingress_hostname,
                "provisioning_state": access.provisioning_state,
                "dns_status": access.dns_status,
                "enabled_features": access.enabled_features or [],
                "last_synced_at": access.last_synced_at.isoformat() if access.last_synced_at else None
            }

        # Build organization context
        org_context = OrganizationContext(
            org_id=org.id,
            org_slug=org.slug,
            tenant_id=org.tenant_id,
            hostname=hostname,
            dns_subdomain=org.dns_subdomain,
            dns_status=org.dns_status,
            status=org.status,
            is_default=org.is_default,
            name=org.name,
            description=org.description,
            app_access=app_access,
            metadata=org.metadata_json or {}
        )

        logger.info(f"✅ Resolved organization: {org_slug} (ID: {org.id})")
        return org_context

    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"❌ Error resolving organization by hostname: {e}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error during organization resolution"
        )

@router.get("/api/organizations/{org_slug}/users/{user_keycloak_id}/roles")
async def get_user_organization_roles(
    org_slug: str,
    user_keycloak_id: str,
    request: Request,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db)
):
    """
    Get user's app-specific roles within an organization.

    This endpoint is used to validate what roles a user has for
    specific apps within a given organization.

    Args:
        org_slug: Organization slug (e.g., "acme", "dnstest")
        user_keycloak_id: User's Keycloak UUID

    Returns:
        User's roles for each app in the organization
    """
    try:
        logger.info(f"🔍 Getting user roles: user={user_keycloak_id}, org={org_slug}")

        # Find organization
        org = db.query(Organization).filter(
            Organization.slug == org_slug,
            Organization.status == "active"
        ).first()

        if not org:
            raise HTTPException(
                status_code=404,
                detail=f"Organization '{org_slug}' not found"
            )

        # Find user
        user = db.query(User).filter(User.keycloak_id == user_keycloak_id).first()
        if not user:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )

        # Security check: Users can only view their own roles unless they're admin
        requesting_user_id = getattr(token_data, 'sub', None)
        if requesting_user_id != user_keycloak_id:
            # Check if requesting user has admin access to this org
            hostname = f"{org_slug}.platform.suranku.net"  # Generic hostname for admin check
            if not require_platform_admin_access(token_data):
                raise HTTPException(
                    status_code=403,
                    detail="Access denied: Can only view your own roles"
                )

        # Get user's organization roles
        org_user_roles = db.query(OrganizationUserRole).filter(
            OrganizationUserRole.organization_id == org.id,
            OrganizationUserRole.user_id == user.id
        ).all()

        # Build roles response
        user_roles = {}
        for role_record in org_user_roles:
            user_roles[role_record.app_name] = {
                "roles": role_record.roles or [],
                "granted_via": role_record.granted_via,
                "granted_at": role_record.created_at.isoformat(),
                "last_updated": role_record.updated_at.isoformat()
            }

        logger.info(f"✅ Retrieved user roles for {user_keycloak_id} in {org_slug}")
        return {
            "user_id": user_keycloak_id,
            "organization": {
                "id": org.id,
                "slug": org_slug,
                "name": org.name
            },
            "app_roles": user_roles
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error getting user organization roles: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/api/organizations/memberships/me", response_model=List[OrgMembershipResponse])
async def get_my_org_memberships(
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db)
):
    """Return organization memberships for the authenticated user."""
    try:
        user = get_or_create_user_from_token(db, token_data)
        logger.info(f"🔍 Loading org memberships for user {user.email} ({user.id})")

        role_rows = (
            db.query(OrganizationUserRole, Organization)
            .join(Organization, Organization.id == OrganizationUserRole.organization_id)
            .filter(OrganizationUserRole.user_id == user.id)
            .all()
        )

        memberships: Dict[str, OrgMembershipResponse] = {}

        for role_entry, org in role_rows:
            membership = memberships.get(org.id)
            if not membership:
                membership = OrgMembershipResponse(
                    org_id=org.id,
                    org_slug=org.slug,
                    org_name=org.name,
                    tenant_id=org.tenant_id,
                    dns_subdomain=org.dns_subdomain,
                    dns_hostname=org.dns_hostname,
                    status=org.status,
                    app_roles={},
                    is_default=bool(org.is_default),
                )
                memberships[org.id] = membership

            current_roles = membership.app_roles.setdefault(role_entry.app_name, [])
            for role in (role_entry.roles or []):
                if role not in current_roles:
                    current_roles.append(role)

        logger.info(f"✅ Found {len(memberships)} org memberships for user {user.email}")
        return list(memberships.values())

    except Exception as e:
        logger.error(f"❌ Error loading org memberships: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to load organization memberships"
        )


@router.get("/organizations/memberships/me", response_model=List[OrgMembershipResponse])
async def get_my_org_memberships_alias(
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db)
):
    """Alias endpoint for Kong path (/api/tenants-service/... routes)."""
    return await get_my_org_memberships(token_data, db)

@router.post("/api/organizations/{org_slug}/users/{user_keycloak_id}/roles")
async def assign_user_organization_roles(
    org_slug: str,
    user_keycloak_id: str,
    role_assignment: Dict[str, list],  # {"darkhole": ["admin", "consumer"], "darkfolio": ["user"]}
    request: Request,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db)
):
    """
    Assign app-specific roles to user within an organization.

    This endpoint allows admins to grant/modify user roles for specific
    apps within an organization (e.g., admin for darkhole, user for darkfolio).

    Args:
        org_slug: Organization slug
        user_keycloak_id: User's Keycloak UUID
        role_assignment: Dict mapping app names to role lists

    Returns:
        Updated user role assignments
    """
    try:
        logger.info(f"🔐 Assigning user roles: user={user_keycloak_id}, org={org_slug}")

        # Security check: Only platform admins can assign roles
        if not require_platform_admin_access(token_data):
            raise HTTPException(
                status_code=403,
                detail="Access denied: Platform admin role required"
            )

        # Find organization
        org = db.query(Organization).filter(
            Organization.slug == org_slug,
            Organization.status == "active"
        ).first()

        if not org:
            raise HTTPException(
                status_code=404,
                detail=f"Organization '{org_slug}' not found"
            )

        # Find user
        user = db.query(User).filter(User.keycloak_id == user_keycloak_id).first()
        if not user:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )

        # Validate app access is enabled for this org
        enabled_apps = db.query(OrganizationAppAccess).filter(
            OrganizationAppAccess.organization_id == org.id,
            OrganizationAppAccess.is_enabled == True
        ).all()

        enabled_app_names = {app.app_name for app in enabled_apps}

        # Process role assignments
        granter_user_id = getattr(token_data, 'sub', 'system')

        for app_name, roles in role_assignment.items():
            if app_name not in enabled_app_names:
                logger.warning(f"⚠️ App '{app_name}' not enabled for org '{org_slug}', skipping")
                continue

            # Find or create organization user role record
            org_user_role = db.query(OrganizationUserRole).filter(
                OrganizationUserRole.organization_id == org.id,
                OrganizationUserRole.user_id == user.id,
                OrganizationUserRole.app_name == app_name
            ).first()

            if org_user_role:
                # Update existing roles
                org_user_role.roles = roles
                org_user_role.granted_by = granter_user_id
                org_user_role.granted_via = "api_assignment"
            else:
                # Create new role assignment
                org_user_role = OrganizationUserRole(
                    organization_id=org.id,
                    user_id=user.id,
                    app_name=app_name,
                    roles=roles,
                    granted_by=granter_user_id,
                    granted_via="api_assignment",
                    tenant_id=org.tenant_id
                )
                db.add(org_user_role)

        db.commit()

        logger.info(f"✅ Assigned roles to user {user_keycloak_id} in org {org_slug}")

        # Return updated roles (reuse get endpoint logic)
        return await get_user_organization_roles(org_slug, user_keycloak_id, request, token_data, db)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error assigning user organization roles: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/api/organizations/{org_slug}/validate-access")
async def validate_organization_access(
    org_slug: str,
    app_name: Optional[str] = None,
    required_role: Optional[str] = None,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db)
):
    """
    Validate if current user has access to organization and optionally specific app/role.

    This endpoint is used by services to validate user access without needing
    to implement the full database lookup logic.

    Args:
        org_slug: Organization slug to validate
        app_name: Optional app name to check (e.g., "darkhole")
        required_role: Optional role to validate (e.g., "admin")

    Returns:
        Access validation result with user's roles
    """
    try:
        user_keycloak_id = getattr(token_data, 'sub', None)
        if not user_keycloak_id:
            raise HTTPException(status_code=401, detail="Invalid token")

        logger.info(f"🔐 Validating access: user={user_keycloak_id}, org={org_slug}, app={app_name}, role={required_role}")

        # Find organization
        org = db.query(Organization).filter(
            Organization.slug == org_slug,
            Organization.status == "active"
        ).first()

        if not org:
            return {
                "has_access": False,
                "reason": f"Organization '{org_slug}' not found or inactive"
            }

        # Find user
        user = db.query(User).filter(User.keycloak_id == user_keycloak_id).first()
        if not user:
            return {
                "has_access": False,
                "reason": "User not found in system"
            }

        # Check organization access
        if app_name:
            # Check specific app access
            org_user_role = db.query(OrganizationUserRole).filter(
                OrganizationUserRole.organization_id == org.id,
                OrganizationUserRole.user_id == user.id,
                OrganizationUserRole.app_name == app_name
            ).first()

            if not org_user_role:
                return {
                    "has_access": False,
                    "reason": f"User has no access to {app_name} in organization {org_slug}"
                }

            user_roles = org_user_role.roles or []

            # Check specific role if required
            if required_role and required_role not in user_roles:
                return {
                    "has_access": False,
                    "reason": f"User lacks required role '{required_role}' for {app_name}",
                    "user_roles": user_roles
                }

            return {
                "has_access": True,
                "organization": {
                    "id": org.id,
                    "slug": org_slug,
                    "name": org.name
                },
                "app_name": app_name,
                "user_roles": user_roles
            }
        else:
            # Check general organization access
            org_access = db.query(OrganizationUserRole).filter(
                OrganizationUserRole.organization_id == org.id,
                OrganizationUserRole.user_id == user.id
            ).first()

            if not org_access:
                return {
                    "has_access": False,
                    "reason": f"User has no access to organization {org_slug}"
                }

            return {
                "has_access": True,
                "organization": {
                    "id": org.id,
                    "slug": org_slug,
                    "name": org.name
                },
                "message": "User has access to organization"
            }

    except Exception as e:
        logger.error(f"❌ Error validating organization access: {e}")
        return {
            "has_access": False,
            "reason": "Internal server error during validation"
        }
class OrgMembershipResponse(BaseModel):
    org_id: str
    org_slug: str
    org_name: str
    tenant_id: str
    dns_subdomain: str
    dns_hostname: Optional[str]
    status: str
    app_roles: Dict[str, List[str]]
    is_default: bool
