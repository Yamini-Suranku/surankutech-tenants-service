"""
User Attribute Synchronization Service
Synchronizes user attributes in Keycloak with organization membership data
"""

import json
import logging
import asyncio
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from shared.database import get_db_session
from modules.keycloak_client import KeycloakClient
from modules.jwt_token_enhancer import jwt_enhancer

logger = logging.getLogger(__name__)

class UserAttributeSyncService:
    """Service to sync user attributes with Keycloak for JWT enhancement"""

    def __init__(self):
        self.keycloak_client = KeycloakClient()

    async def sync_user_org_memberships(self, user_keycloak_id: str) -> bool:
        """
        Sync user's organization memberships and tenant data to Keycloak user attributes
        This enables protocol mappers to include all JWT enhancement claims
        """
        try:
            logger.info(f"Syncing enhanced token data for user: {user_keycloak_id}")

            # Get enhanced token data including all JWT claims
            enhanced_data = await jwt_enhancer.get_user_enhanced_token_data(user_keycloak_id)

            # Extract individual claims
            org_memberships = enhanced_data.get("org_memberships", [])
            token_org_memberships = self._build_token_org_memberships(org_memberships)
            tenant_id = enhanced_data.get("tenant_id")
            all_tenants = enhanced_data.get("all_tenants", [])
            app_roles = enhanced_data.get("app_roles", {})
            org_app_roles = self._build_org_app_roles(org_memberships)
            current_org = self._derive_current_org_slug(org_memberships)

            # Get user data for bulk update
            user_data = await self.keycloak_client.get_user_by_id(user_keycloak_id)
            if not user_data:
                logger.error(f"User {user_keycloak_id} not found in Keycloak")
                return False

            # Prepare all attributes for bulk update
            attributes = user_data.get("attributes", {})

            # Sync org_memberships
            attributes["org_memberships"] = [json.dumps(token_org_memberships, separators=(',', ':'))]

            # Sync tenant claims
            if tenant_id:
                attributes["tenant_id"] = [str(tenant_id)]
                attributes["active_tenant"] = [str(tenant_id)]  # For compatibility

            attributes["all_tenants"] = [json.dumps(all_tenants, separators=(',', ':'))]

            # Sync app_roles
            attributes["app_roles"] = [json.dumps(app_roles, separators=(',', ':'))]

            # Sync org-scoped app roles (for org-specific access checks)
            if org_app_roles is not None:
                attributes["org_app_roles"] = [json.dumps(org_app_roles, separators=(',', ':'))]

            # Sync current org slug if determinable
            if current_org:
                attributes["current_org"] = [current_org]

            # Bulk update user attributes in Keycloak.
            # Some legacy users can fail full attribute updates in Keycloak with 400.
            # In that case, fall back to per-attribute updates so critical claims still land.
            update_data = {"attributes": attributes}
            success = await self.keycloak_client.update_user(user_keycloak_id, update_data)
            if not success:
                logger.warning(
                    "Bulk attribute sync failed for user %s; attempting per-attribute fallback",
                    user_keycloak_id,
                )
                success = await self._sync_user_attributes_individually(user_keycloak_id, attributes)

            if success:
                logger.info(f"Successfully synced enhanced token data for user {user_keycloak_id}")
                logger.info(f"  - Tenant ID: {tenant_id}")
                logger.info(f"  - All tenants: {all_tenants}")
                logger.info(f"  - App roles: {list(app_roles.keys())}")
                logger.info(f"  - Org memberships: {len(token_org_memberships)}")
                if current_org:
                    logger.info(f"  - Current org: {current_org}")
                return True
            else:
                logger.error(f"Failed to sync enhanced token data for user {user_keycloak_id}")
                return False

        except Exception as e:
            logger.error(f"Error syncing enhanced token data for {user_keycloak_id}: {e}")
            return False

    async def _update_user_attribute(self, user_keycloak_id: str, attribute_name: str, attribute_value: str) -> bool:
        """Update a single user attribute in Keycloak"""
        try:
            # Get user from Keycloak
            user_data = await self.keycloak_client.get_user_by_id(user_keycloak_id)
            if not user_data:
                logger.error(f"User {user_keycloak_id} not found in Keycloak")
                return False

            # Update user attributes
            attributes = user_data.get("attributes", {})
            attributes[attribute_name] = [attribute_value]  # Keycloak expects array for attributes

            # Update user in Keycloak
            update_data = {
                "attributes": attributes
            }

            success = await self.keycloak_client.update_user(user_keycloak_id, update_data)
            if success:
                logger.info(f"Updated {attribute_name} attribute for user {user_keycloak_id}")
                return True
            else:
                logger.error(f"Failed to update {attribute_name} attribute for user {user_keycloak_id}")
                return False

        except Exception as e:
            logger.error(f"Error updating user attribute {attribute_name} for {user_keycloak_id}: {e}")
            return False

    async def _sync_user_attributes_individually(
        self,
        user_keycloak_id: str,
        attributes: Dict[str, List[str]],
    ) -> bool:
        """
        Fallback synchronization path for Keycloak users that reject bulk attribute updates.
        Returns True when critical org claims are applied.
        """
        # Apply critical claims first so downstream org authorization can succeed.
        ordered_keys = [
            "org_memberships",
            "current_org",
            "app_roles",
            "org_app_roles",
            "tenant_id",
            "active_tenant",
            "all_tenants",
        ]

        applied = set()
        for key in ordered_keys:
            values = attributes.get(key)
            if not values:
                continue
            value = values[0]
            ok = await self._update_user_attribute(user_keycloak_id, key, value)
            if ok:
                applied.add(key)
            else:
                logger.warning(
                    "Per-attribute sync failed for user %s attribute %s",
                    user_keycloak_id,
                    key,
                )

        # Treat as success if core org claims are present.
        critical = {"org_memberships", "current_org", "app_roles"}
        return critical.issubset(applied)

    @staticmethod
    def _build_org_app_roles(org_memberships: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build org_app_roles claim from org memberships."""
        org_app_roles = []
        for membership in org_memberships or []:
            org_slug = membership.get("org_slug") or membership.get("dns_subdomain")
            app_roles = membership.get("app_roles") or {}
            if not org_slug or not app_roles:
                continue
            for app_name, roles in app_roles.items():
                org_app_roles.append({
                    "org_slug": org_slug,
                    "app": app_name,
                    "roles": roles or []
                })
        return org_app_roles

    @staticmethod
    def _build_token_org_memberships(org_memberships: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Build compact org_memberships payload for JWT attribute storage.
        Keep only fields needed for org resolution to avoid Keycloak attribute size issues.
        """
        compact = []
        for membership in org_memberships or []:
            org_slug = membership.get("org_slug") or membership.get("dns_subdomain")
            if not org_slug:
                continue
            compact.append(
                {
                    "tenant_id": membership.get("tenant_id"),
                    "org_id": membership.get("org_id"),
                    "org_slug": org_slug,
                }
            )
        return compact

    @staticmethod
    def _derive_current_org_slug(org_memberships: List[Dict[str, Any]]) -> Optional[str]:
        """Pick a stable org slug for current_org when available."""
        if not org_memberships:
            return None
        membership = org_memberships[0]
        return membership.get("org_slug") or membership.get("dns_subdomain")

    async def sync_all_users_org_memberships(self) -> Dict[str, Any]:
        """
        Sync organization memberships for all users with active tenants
        This is a bulk operation for initial setup or periodic sync
        """
        try:
            logger.info("Starting bulk sync of user organization memberships")

            stats = {
                "total_users": 0,
                "successful_syncs": 0,
                "failed_syncs": 0,
                "errors": []
            }

            with get_db_session() as db:
                # Get all users with Keycloak IDs
                from shared.models import User
                users = db.query(User).filter(User.keycloak_id.isnot(None)).all()

                stats["total_users"] = len(users)
                logger.info(f"Found {len(users)} users to sync")

                for user in users:
                    try:
                        success = await self.sync_user_org_memberships(user.keycloak_id)
                        if success:
                            stats["successful_syncs"] += 1
                        else:
                            stats["failed_syncs"] += 1
                            stats["errors"].append(f"Failed to sync user {user.email}")

                    except Exception as e:
                        stats["failed_syncs"] += 1
                        error_msg = f"Error syncing user {user.email}: {str(e)}"
                        stats["errors"].append(error_msg)
                        logger.error(error_msg)

                    # Small delay to avoid overwhelming Keycloak
                    await asyncio.sleep(0.1)

            logger.info(f"Bulk sync completed: {stats['successful_syncs']}/{stats['total_users']} successful")
            return stats

        except Exception as e:
            logger.error(f"Error in bulk sync: {e}")
            return {"error": str(e)}

    async def sync_user_on_org_change(self, user_id: str, organization_id: str) -> bool:
        """
        Sync user attributes when organization membership changes
        Called after organization role assignments or removals
        """
        try:
            with get_db_session() as db:
                from shared.models import User
                user = db.query(User).filter(User.id == user_id).first()
                if not user or not user.keycloak_id:
                    logger.error(f"User {user_id} not found or missing Keycloak ID")
                    return False

                logger.info(f"Syncing org memberships for user {user.email} after org {organization_id} change")
                return await self.sync_user_org_memberships(user.keycloak_id)

        except Exception as e:
            logger.error(f"Error syncing user on org change: {e}")
            return False

# Global instance
user_attribute_sync = UserAttributeSyncService()
