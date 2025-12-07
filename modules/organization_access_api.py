"""
Organization Access API Module
Provides endpoints for checking and managing organization access
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Path
from sqlalchemy.orm import Session
from typing import List, Dict, Any, Optional
import logging

from shared.database import get_db
from shared.auth import get_current_user
from modules.organization_access_control import OrganizationAccessControl
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# Create router for organization access endpoints
router = APIRouter(prefix="/api/access", tags=["organization-access"])

# Response models
class OrganizationAccessResponse(BaseModel):
    has_access: bool
    roles: List[str]
    organization: Optional[Dict[str, Any]] = None
    reason: Optional[str] = None
    granted_via: Optional[str] = None

class UserOrganizationsResponse(BaseModel):
    total_organizations: int
    organizations: List[Dict[str, Any]]

class AccessSummaryResponse(BaseModel):
    total_organizations: int
    organizations: List[Dict[str, Any]]
    apps_by_org: Dict[str, Any]
    all_accessible_apps: List[str]

@router.get("/check/{org_subdomain}/{app_name}", response_model=OrganizationAccessResponse)
async def check_organization_app_access(
    org_subdomain: str = Path(..., description="Organization subdomain"),
    app_name: str = Path(..., description="Application name"),
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Check if current user has access to specific app in organization"""
    try:
        access_result = OrganizationAccessControl.check_org_app_access_by_subdomain(
            db, current_user["id"], org_subdomain, app_name
        )

        return OrganizationAccessResponse(**access_result)

    except Exception as e:
        logger.error(f"Error checking organization access: {e}")
        raise HTTPException(status_code=500, detail=f"Access check failed: {str(e)}")

@router.get("/organizations", response_model=UserOrganizationsResponse)
async def get_user_organizations(
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get all organizations where user has access"""
    try:
        organizations = OrganizationAccessControl.get_user_organizations(
            db, current_user["id"]
        )

        return UserOrganizationsResponse(
            total_organizations=len(organizations),
            organizations=organizations
        )

    except Exception as e:
        logger.error(f"Error getting user organizations: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get organizations: {str(e)}")

@router.get("/summary", response_model=AccessSummaryResponse)
async def get_user_access_summary(
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get complete summary of user's access across all organizations"""
    try:
        summary = OrganizationAccessControl.get_user_app_access_summary(
            db, current_user["id"]
        )

        return AccessSummaryResponse(**summary)

    except Exception as e:
        logger.error(f"Error getting access summary: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get access summary: {str(e)}")

@router.post("/validate")
async def validate_organization_access(
    org_subdomain: str,
    app_name: str,
    required_roles: Optional[List[str]] = None,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Validate access and raise exception if denied (for middleware use)"""
    try:
        access_result = OrganizationAccessControl.require_org_app_access(
            db, current_user["id"], org_subdomain, app_name, required_roles
        )

        return {
            "access_granted": True,
            "organization": access_result["organization"],
            "roles": access_result["roles"],
            "message": "Access validated successfully"
        }

    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        logger.error(f"Error validating access: {e}")
        raise HTTPException(status_code=500, detail=f"Access validation failed: {str(e)}")

@router.get("/apps/{org_subdomain}")
async def get_organization_accessible_apps(
    org_subdomain: str = Path(..., description="Organization subdomain"),
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get all apps user can access in specific organization"""
    try:
        # Get organization
        org = OrganizationAccessControl.get_organization_by_subdomain(db, org_subdomain)
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        # Get user's app access in this organization
        access_summary = OrganizationAccessControl.get_user_app_access_summary(
            db, current_user["id"]
        )

        org_apps = access_summary["apps_by_org"].get(org.id, {}).get("apps", {})

        return {
            "organization": {
                "id": org.id,
                "name": org.name,
                "subdomain": org.dns_subdomain,
                "hostname": org.dns_hostname
            },
            "accessible_apps": org_apps,
            "total_apps": len(org_apps)
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting organization apps: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get organization apps: {str(e)}")

# Health check endpoint for access control system
@router.get("/health")
async def access_control_health():
    """Health check for access control system"""
    return {
        "status": "healthy",
        "service": "organization_access_control",
        "features": {
            "organization_isolation": True,
            "app_level_access": True,
            "role_based_access": True,
            "dns_based_routing": True
        }
    }