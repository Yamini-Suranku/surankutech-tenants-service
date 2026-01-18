"""
JWT Token Enhancement Service
Provides organization membership data for JWT token claims
"""

import json
import logging
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import and_

from shared.database import get_db_session
from shared.models import User, UserTenant, Tenant
from models import Organization, OrganizationUserRole

logger = logging.getLogger(__name__)

class JWTTokenEnhancer:
    """Service to enhance JWT tokens with organization membership data"""

    def __init__(self):
        pass

    async def get_user_org_memberships(self, user_keycloak_id: str) -> List[Dict[str, Any]]:
        """
        Get user's organization memberships with app roles for JWT token
        Returns array of org memberships in the format:
        [
            {
                "tenant_id": "uuid",
                "org_id": "uuid",
                "org_slug": "acme-corp",
                "org_name": "ACME Corp",
                "app_roles": {
                    "darkhole": ["admin", "user"],
                    "darkfolio": ["user"]
                }
            }
        ]
        """
        try:
            with get_db_session() as db:
                return self._query_user_org_memberships(db, user_keycloak_id)
        except Exception as e:
            logger.error(f"Error getting org memberships for user {user_keycloak_id}: {e}")
            return []

    def _query_user_org_memberships(self, db: Session, user_keycloak_id: str) -> List[Dict[str, Any]]:
        """Query database for user's organization memberships"""

        # Get user from database
        user = db.query(User).filter(User.keycloak_id == user_keycloak_id).first()
        if not user:
            logger.warning(f"User not found for keycloak_id: {user_keycloak_id}")
            return []

        # Get user's organization memberships with roles
        org_memberships = []

        # Query user's organization roles
        org_roles = (
            db.query(OrganizationUserRole, Organization, Tenant)
            .join(Organization, OrganizationUserRole.organization_id == Organization.id)
            .join(Tenant, Organization.tenant_id == Tenant.id)
            .filter(OrganizationUserRole.user_id == user.id)
            .all()
        )

        # Group by organization
        org_data = {}
        for org_role, org, tenant in org_roles:

            org_key = str(org.id)
            if org_key not in org_data:
                org_data[org_key] = {
                    "tenant_id": str(tenant.id),
                    "org_id": str(org.id),
                    "org_slug": org.dns_subdomain,
                    "org_name": org.name,
                    "app_roles": {}
                }

            # Add app-specific roles
            if org_role.roles:
                app_name = org_role.app_name
                if app_name not in org_data[org_key]["app_roles"]:
                    org_data[org_key]["app_roles"][app_name] = []

                # Merge roles and deduplicate
                existing_roles = set(org_data[org_key]["app_roles"][app_name])
                new_roles = set(org_role.roles) if isinstance(org_role.roles, list) else {org_role.roles}
                org_data[org_key]["app_roles"][app_name] = list(existing_roles | new_roles)

        # Also include tenant-level app roles for organizations
        user_tenants = (
            db.query(UserTenant)
            .join(Tenant, UserTenant.tenant_id == Tenant.id)
            .filter(UserTenant.user_id == user.id)
            .all()
        )

        for user_tenant in user_tenants:
            tenant = user_tenant.tenant

            # Get organizations for this tenant where user doesn't have specific org roles
            tenant_orgs = (
                db.query(Organization)
                .filter(Organization.tenant_id == tenant.id)
                .all()
            )

            for org in tenant_orgs:
                org_key = str(org.id)

                # If user doesn't have specific org roles, use tenant-level app roles
                if org_key not in org_data and user_tenant.app_roles:
                    org_data[org_key] = {
                        "tenant_id": str(tenant.id),
                        "org_id": str(org.id),
                        "org_slug": org.dns_subdomain,
                        "org_name": org.name,
                        "app_roles": dict(user_tenant.app_roles)  # Copy tenant app roles
                    }
                elif org_key in org_data:
                    # Merge tenant-level app roles with org-specific roles
                    if user_tenant.app_roles:
                        for app_name, roles in user_tenant.app_roles.items():
                            if app_name not in org_data[org_key]["app_roles"]:
                                org_data[org_key]["app_roles"][app_name] = []

                            # Merge roles
                            existing_roles = set(org_data[org_key]["app_roles"][app_name])
                            tenant_roles = set(roles) if isinstance(roles, list) else {roles}
                            org_data[org_key]["app_roles"][app_name] = list(existing_roles | tenant_roles)

        org_memberships = list(org_data.values())

        logger.info(f"Found {len(org_memberships)} organization memberships for user {user.email}")
        for membership in org_memberships:
            logger.info(f"  - Org: {membership['org_name']} ({membership['org_slug']}) - Apps: {list(membership['app_roles'].keys())}")

        return org_memberships

    async def get_user_enhanced_token_data(self, user_keycloak_id: str) -> Dict[str, Any]:
        """
        Get enhanced token data for a user including org memberships
        """
        try:
            org_memberships = await self.get_user_org_memberships(user_keycloak_id)

            # Get additional user data
            with get_db_session() as db:
                user = db.query(User).filter(User.keycloak_id == user_keycloak_id).first()
                if not user:
                    return {"org_memberships": org_memberships}

                # Get tenant information
                user_tenants = (
                    db.query(UserTenant)
                    .join(Tenant, UserTenant.tenant_id == Tenant.id)
                    .filter(UserTenant.user_id == user.id)
                    .all()
                )

                all_tenants = [str(ut.tenant_id) for ut in user_tenants]
                active_tenant = all_tenants[0] if all_tenants else None

                # Get consolidated app roles across all tenants
                consolidated_app_roles = {}
                for user_tenant in user_tenants:
                    if user_tenant.app_roles:
                        for app_name, roles in user_tenant.app_roles.items():
                            if app_name not in consolidated_app_roles:
                                consolidated_app_roles[app_name] = []

                            # Merge roles
                            existing_roles = set(consolidated_app_roles[app_name])
                            new_roles = set(roles) if isinstance(roles, list) else {roles}
                            consolidated_app_roles[app_name] = list(existing_roles | new_roles)

                return {
                    "org_memberships": org_memberships,
                    "tenant_id": active_tenant,
                    "all_tenants": all_tenants,
                    "app_roles": consolidated_app_roles
                }

        except Exception as e:
            logger.error(f"Error getting enhanced token data for user {user_keycloak_id}: {e}")
            return {"org_memberships": []}

# Global instance
jwt_enhancer = JWTTokenEnhancer()
