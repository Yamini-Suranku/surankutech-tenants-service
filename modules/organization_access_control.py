"""
Organization Access Control Module
Handles access isolation and entitlement checking for organization-scoped apps
"""

from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from typing import Optional, List, Dict, Any
import logging

from shared.database import get_db
from shared.models import User, UserTenant
from models import Organization, OrganizationUserRole, OrganizationAppAccess

logger = logging.getLogger(__name__)

class OrganizationAccessControl:
    """Manages access control and isolation for organizations"""

    @staticmethod
    def get_organization_by_subdomain(db: Session, subdomain: str) -> Optional[Organization]:
        """Get organization by DNS subdomain"""
        return db.query(Organization).filter(
            Organization.dns_subdomain == subdomain,
            Organization.status == "active",
            Organization.deleted_at.is_(None)
        ).first()

    @staticmethod
    def check_user_org_app_access(
        db: Session,
        user_id: str,
        organization_id: str,
        app_name: str
    ) -> Dict[str, Any]:
        """
        Check if user has access to specific app in organization
        Returns access details including roles
        """
        try:
            # Check if user has roles in this organization for this app
            user_role = db.query(OrganizationUserRole).filter(
                OrganizationUserRole.organization_id == organization_id,
                OrganizationUserRole.user_id == user_id,
                OrganizationUserRole.app_name == app_name
            ).first()

            if not user_role or not user_role.roles:
                return {
                    "has_access": False,
                    "roles": [],
                    "reason": "No roles assigned for this app"
                }

            # Check if app is enabled for this organization
            app_access = db.query(OrganizationAppAccess).filter(
                OrganizationAppAccess.organization_id == organization_id,
                OrganizationAppAccess.app_name == app_name,
                OrganizationAppAccess.is_enabled == True
            ).first()

            if not app_access:
                return {
                    "has_access": False,
                    "roles": user_role.roles,
                    "reason": "App not enabled for this organization"
                }

            return {
                "has_access": True,
                "roles": user_role.roles,
                "app_access_id": app_access.id,
                "granted_via": user_role.granted_via,
                "metadata": user_role.metadata_json
            }

        except Exception as e:
            logger.error(f"Error checking user org app access: {e}")
            return {
                "has_access": False,
                "roles": [],
                "reason": f"Access check failed: {str(e)}"
            }

    @staticmethod
    def check_org_app_access_by_subdomain(
        db: Session,
        user_id: str,
        org_subdomain: str,
        app_name: str
    ) -> Dict[str, Any]:
        """
        Check access using organization subdomain (for DNS-based routing)
        """
        # Get organization by subdomain
        org = OrganizationAccessControl.get_organization_by_subdomain(db, org_subdomain)
        if not org:
            return {
                "has_access": False,
                "roles": [],
                "organization": None,
                "reason": f"Organization with subdomain '{org_subdomain}' not found"
            }

        # Check user access
        access_result = OrganizationAccessControl.check_user_org_app_access(
            db, user_id, org.id, app_name
        )

        # Add organization info to result
        access_result["organization"] = {
            "id": org.id,
            "name": org.name,
            "subdomain": org.dns_subdomain,
            "hostname": org.dns_hostname,
            "tenant_id": org.tenant_id
        }

        return access_result

    @staticmethod
    def get_user_organizations(db: Session, user_id: str) -> List[Dict[str, Any]]:
        """Get all organizations where user has any access"""
        try:
            # Find all organizations where user has roles
            user_orgs = db.query(
                Organization,
                OrganizationUserRole
            ).join(
                OrganizationUserRole,
                OrganizationUserRole.organization_id == Organization.id
            ).filter(
                OrganizationUserRole.user_id == user_id,
                Organization.status == "active",
                Organization.deleted_at.is_(None)
            ).distinct().all()

            organizations = []
            for org, role in user_orgs:
                # Get user's apps in this org
                user_apps = db.query(OrganizationUserRole).filter(
                    OrganizationUserRole.organization_id == org.id,
                    OrganizationUserRole.user_id == user_id
                ).all()

                app_access = {}
                for app_role in user_apps:
                    app_access[app_role.app_name] = app_role.roles

                organizations.append({
                    "id": org.id,
                    "name": org.name,
                    "subdomain": org.dns_subdomain,
                    "hostname": org.dns_hostname,
                    "tenant_id": org.tenant_id,
                    "app_access": app_access,
                    "is_creator": org.created_by == user_id
                })

            return organizations

        except Exception as e:
            logger.error(f"Error getting user organizations: {e}")
            return []

    @staticmethod
    def require_org_app_access(
        db: Session,
        user_id: str,
        org_subdomain: str,
        app_name: str,
        required_roles: List[str] = None
    ) -> Dict[str, Any]:
        """
        Require access to organization app, raise HTTPException if denied
        Returns access info if successful
        """
        access_result = OrganizationAccessControl.check_org_app_access_by_subdomain(
            db, user_id, org_subdomain, app_name
        )

        if not access_result["has_access"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: {access_result['reason']}"
            )

        # Check specific role requirements
        if required_roles:
            user_roles = access_result.get("roles", [])
            if not any(role in user_roles for role in required_roles):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient privileges. Required roles: {required_roles}"
                )

        return access_result

    @staticmethod
    def get_user_app_access_summary(db: Session, user_id: str) -> Dict[str, Any]:
        """Get complete summary of user's app access across all organizations"""
        try:
            user_orgs = OrganizationAccessControl.get_user_organizations(db, user_id)

            summary = {
                "total_organizations": len(user_orgs),
                "organizations": user_orgs,
                "apps_by_org": {},
                "all_accessible_apps": set()
            }

            for org in user_orgs:
                org_id = org["id"]
                summary["apps_by_org"][org_id] = {
                    "org_name": org["name"],
                    "org_subdomain": org["subdomain"],
                    "apps": org["app_access"]
                }

                # Add to global accessible apps set
                for app_name in org["app_access"].keys():
                    summary["all_accessible_apps"].add(app_name)

            # Convert set to list for JSON serialization
            summary["all_accessible_apps"] = list(summary["all_accessible_apps"])

            return summary

        except Exception as e:
            logger.error(f"Error getting user app access summary: {e}")
            return {
                "total_organizations": 0,
                "organizations": [],
                "apps_by_org": {},
                "all_accessible_apps": [],
                "error": str(e)
            }

    @staticmethod
    def check_cross_org_access_violation(
        db: Session,
        user_id: str,
        requested_org_subdomain: str,
        app_name: str,
        user_context_org: str = None
    ) -> Dict[str, Any]:
        """
        Check if user is trying to access an app in a different organization
        than their current context (useful for detecting access violations)
        """
        if not user_context_org or user_context_org == requested_org_subdomain:
            return {"violation": False}

        # Check if user has access to both organizations
        user_orgs = OrganizationAccessControl.get_user_organizations(db, user_id)

        accessible_subdomains = {org["subdomain"] for org in user_orgs}

        has_context_access = user_context_org in accessible_subdomains
        has_requested_access = requested_org_subdomain in accessible_subdomains

        return {
            "violation": True,
            "context_org": user_context_org,
            "requested_org": requested_org_subdomain,
            "has_context_access": has_context_access,
            "has_requested_access": has_requested_access,
            "reason": f"Cross-organization access attempt: {user_context_org} -> {requested_org_subdomain}"
        }


def create_org_access_middleware():
    """
    Factory function to create organization access middleware
    This can be used as FastAPI dependency or middleware
    """

    def check_organization_access(
        org_subdomain: str,
        app_name: str,
        user_id: str,
        required_roles: List[str] = None,
        db: Session = None
    ) -> Dict[str, Any]:
        """Middleware function to check organization access"""
        if not db:
            db = next(get_db())

        return OrganizationAccessControl.require_org_app_access(
            db, user_id, org_subdomain, app_name, required_roles
        )

    return check_organization_access

# Export the main class and utility function
__all__ = ["OrganizationAccessControl", "create_org_access_middleware"]