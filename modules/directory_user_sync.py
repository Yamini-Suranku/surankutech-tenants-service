"""
Directory to Platform Sync Service
Syncs directory users and groups (Azure AD/LDAP) to platform users/groups with role mappings
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import and_, func, select
from typing import List, Dict, Any, Optional
import logging
import uuid
from datetime import datetime

from shared.database import get_db
from shared.auth import get_current_user
from shared.models import User, UserTenant
from models import (
    DirectoryUser,
    DirectoryGroup,
    DirectoryGroupMembership,
    Organization,
    OrganizationUserRole,
    OrganizationGroup,
    OrganizationGroupMembership,
    TenantLDAPConfig,
    TenantLDAPSyncHistory,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/platform/organizations", tags=["directory-to-platform-sync"])


class DirectoryToPlatformSyncService:
    """Service to sync directory users and groups to platform users/groups with role mappings"""

    def __init__(self, db: Session):
        self.db = db

    def _find_platform_user_by_email(self, email: str, tenant_id: str) -> Optional[User]:
        """
        Resolve case-insensitive email collisions deterministically.
        Prefer user already in target tenant, then one linked to Keycloak.
        """
        normalized = (email or "").strip().lower()
        if not normalized:
            return None

        candidates = self.db.query(User).filter(
            func.lower(User.email) == normalized
        ).all()

        if not candidates:
            return None
        if len(candidates) == 1:
            return candidates[0]

        candidate_ids = [u.id for u in candidates]
        tenant_members = {
            ut.user_id
            for ut in self.db.query(UserTenant).filter(
                UserTenant.tenant_id == tenant_id,
                UserTenant.user_id.in_(candidate_ids)
            ).all()
        }

        def rank(u: User):
            return (
                0 if u.id in tenant_members else 1,
                0 if u.keycloak_id else 1,
                u.created_at or datetime.min,
            )

        candidates.sort(key=rank)
        winner = candidates[0]
        logger.warning(
            "Found %d platform users for email %s; selected user_id=%s",
            len(candidates), normalized, winner.id
        )
        return winner

    async def sync_directory_to_platform(
        self,
        organization_id: str,
        tenant_id: str,
        sync_users: bool = True,
        sync_groups: bool = True,
        triggered_by_user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Sync directory users and groups to platform with role mappings.
        Creates platform User records and OrganizationGroup records with proper role mappings.
        """
        try:
            results = {
                "success": True,
                "users": {"synced": 0, "skipped": 0, "errors": 0},
                "groups": {"synced": 0, "skipped": 0, "errors": 0},
                "errors": [],
                "message": ""
            }

            # Ensure there is an LDAP/Azure configuration to anchor the batch history
            ldap_config = self.db.query(TenantLDAPConfig).filter(
                and_(
                    TenantLDAPConfig.tenant_id == tenant_id,
                    TenantLDAPConfig.organization_id == organization_id
                )
            ).first()

            if not ldap_config:
                raise HTTPException(status_code=400, detail="Directory sync configuration not found for this organization")

            # Track this run in tenant_ldap_sync_history so we can surface Source/Batch metadata
            sync_history = TenantLDAPSyncHistory(
                tenant_id=tenant_id,
                organization_id=organization_id,
                ldap_config_id=ldap_config.id,
                sync_type="directory_to_platform",
                sync_status="in_progress",
                started_at=datetime.utcnow(),
                triggered_by=triggered_by_user_id
            )
            self.db.add(sync_history)
            self.db.flush()
            active_sync_batch_id = sync_history.id

            # Sync users if requested
            if sync_users:
                user_result = await self._sync_directory_users(
                    organization_id,
                    tenant_id,
                    sync_batch_id=active_sync_batch_id
                )
                results["users"] = user_result

            # Sync groups if requested
            if sync_groups:
                group_result = await self._sync_directory_groups(organization_id, tenant_id)
                results["groups"] = group_result

            # Apply group-to-role mappings
            if sync_groups:
                mapping_result = await self._apply_group_role_mappings(organization_id, tenant_id)
                if mapping_result.get("errors"):
                    results["errors"].extend(mapping_result["errors"])

            # Commit all changes and record batch metadata
            completion_time = datetime.utcnow()
            sync_history.sync_status = "success"
            sync_history.users_added = results["users"]["synced"] if sync_users else 0
            sync_history.users_updated = results["users"]["skipped"] if sync_users else 0
            sync_history.groups_added = results["groups"]["synced"] if sync_groups else 0
            sync_history.groups_updated = results["groups"]["skipped"] if sync_groups else 0
            sync_history.completed_at = completion_time
            sync_history.duration_seconds = int((completion_time - sync_history.started_at).total_seconds())

            results["sync_batch_id"] = active_sync_batch_id

            # Commit all changes
            self.db.commit()

            # Sync directory users' Keycloak attributes after role changes
            # This ensures JWT tokens include updated organization app roles
            try:
                from modules.user_attribute_sync import user_attribute_sync

                # Get all users who had roles synced in this batch
                synced_users = self.db.query(OrganizationUserRole).filter(
                    OrganizationUserRole.sync_batch_id == active_sync_batch_id
                ).all()

                # Get unique users and sync their Keycloak attributes
                user_ids = set(role_entry.user_id for role_entry in synced_users)
                synced_user_count = 0

                import asyncio
                for user_id in user_ids:
                    try:
                        user = self.db.query(User).filter(User.id == user_id).first()
                        if user and user.keycloak_id:
                            # Background task to sync attributes
                            asyncio.create_task(
                                user_attribute_sync.sync_user_org_memberships(user.keycloak_id)
                            )
                            synced_user_count += 1
                            logger.info(f"Queued Keycloak attribute sync for directory user {user.email}")
                    except Exception as e:
                        logger.warning(f"Failed to queue Keycloak sync for user {user_id}: {e}")

                if synced_user_count > 0:
                    logger.info(f"Queued Keycloak attribute sync for {synced_user_count} directory users")

            except Exception as e:
                logger.warning(f"Failed to sync directory users to Keycloak: {e}")

            # Build summary message
            message_parts = []
            if sync_users:
                message_parts.append(f"Users: {results['users']['synced']} synced, {results['users']['skipped']} skipped, {results['users']['errors']} errors")
            if sync_groups:
                message_parts.append(f"Groups: {results['groups']['synced']} synced, {results['groups']['skipped']} skipped, {results['groups']['errors']} errors")

            results["message"] = "Directory to platform sync completed. " + "; ".join(message_parts)
            return results

        except HTTPException:
            self.db.rollback()
            raise
        except Exception as e:
            self.db.rollback()
            logger.error(f"Directory to platform sync failed for org {organization_id}: {e}")
            raise HTTPException(status_code=500, detail=f"Directory to platform sync failed: {str(e)}")

    async def _sync_single_directory_user(
        self,
        dir_user: DirectoryUser,
        tenant_id: str,
        organization_id: str,
        sync_batch_id: Optional[str] = None
    ) -> Dict[str, str]:
        """Sync a single directory user to a platform user"""

        logger.info(f"Starting sync for directory user: {dir_user.email} (ID: {dir_user.id})")

        if not dir_user.email:
            logger.warning(f"Skipping directory user {dir_user.id}: No email address")
            return {"action": "skipped", "reason": "No email address"}

        # Check if platform user already exists with this email
        existing_user = self._find_platform_user_by_email(dir_user.email, tenant_id)

        if existing_user:
            logger.info(f"Platform user already exists for {dir_user.email} (User ID: {existing_user.id})")
            # User already exists, ensure they have tenant access
            await self._ensure_user_tenant_access(existing_user, tenant_id, organization_id, sync_batch_id=sync_batch_id)
            return {"action": "skipped", "reason": "User already exists"}

        logger.info(f"Creating new platform user for directory user: {dir_user.email}")

        # Create new platform user from directory user
        new_user = User(
            id=str(uuid.uuid4()),
            email=dir_user.email,
            first_name=dir_user.first_name,
            last_name=dir_user.last_name,
            is_email_verified=True,  # Directory users are pre-verified
            status="active",  # Directory users start as active
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )

        try:
            self.db.add(new_user)
            self.db.flush()  # Get the user ID
            logger.info(f"Successfully added platform user to database: {new_user.email} (ID: {new_user.id})")

            # Create tenant association
            await self._ensure_user_tenant_access(new_user, tenant_id, organization_id, sync_batch_id=sync_batch_id)

            logger.info(f"Successfully created platform user for directory user: {dir_user.email}")
            return {"action": "created", "user_id": new_user.id}
        except Exception as e:
            logger.error(f"Failed to create platform user for {dir_user.email}: {e}")
            self.db.rollback()
            raise e

    async def _ensure_user_tenant_access(
        self,
        user: User,
        tenant_id: str,
        organization_id: str,
        sync_batch_id: Optional[str] = None
    ):
        """Ensure user has access to the tenant with proper roles from directory group mappings"""
        logger.info(f"Ensuring tenant access for user {user.email} (ID: {user.id}) in tenant {tenant_id}")

        existing_tenant_access = self.db.query(UserTenant).filter(
            and_(
                UserTenant.user_id == user.id,
                UserTenant.tenant_id == tenant_id
            )
        ).first()

        # Calculate roles based on directory group memberships
        calculated_roles = await self._calculate_user_roles_from_directory_groups(user.email, tenant_id)

        if not existing_tenant_access:
            logger.info(f"Creating new tenant access for user {user.email} in tenant {tenant_id}")
            user_tenant = UserTenant(
                user_id=user.id,
                tenant_id=tenant_id,
                app_roles=calculated_roles,  # Use calculated roles from group mappings
                created_at=datetime.utcnow()
            )
            self.db.add(user_tenant)
            logger.info(f"Created tenant access for user {user.email} with roles: {calculated_roles}")
        else:
            # Update existing user's roles based on current group memberships
            logger.info(f"Updating existing tenant access roles for user {user.email}")
            existing_roles = existing_tenant_access.app_roles or {}
            merged_roles = dict(existing_roles)
            managed_apps = {k for k in calculated_roles.keys() if k}

            # Update directory-managed app entries
            for app_name, roles in calculated_roles.items():
                merged_roles[app_name] = roles

            # Preserve elevated existing platform role when present
            existing_platform = set(existing_roles.get("platform", []) or [])
            new_platform = set(merged_roles.get("platform", []) or [])
            if "tenant_admin" in existing_platform:
                new_platform.add("tenant_admin")
            if new_platform:
                merged_roles["platform"] = sorted(new_platform)

            existing_tenant_access.app_roles = merged_roles
            logger.info(
                f"Updated roles for user {user.email}: calculated={calculated_roles}, merged={merged_roles}, managed_apps={sorted(managed_apps)}"
            )

        # Sync roles to OrganizationUserRole table for organization members UI
        await self._sync_roles_to_organization_user_role_table(
            user,
            tenant_id,
            organization_id,
            calculated_roles,
            sync_batch_id=sync_batch_id
        )

    async def _sync_directory_users(self, organization_id: str, tenant_id: str, sync_batch_id: Optional[str] = None) -> Dict[str, int]:
        """Sync all directory users for an organization to platform users."""
        logger.info(f"Starting directory users sync for organization {organization_id}, tenant {tenant_id}")

        # Get all directory users for this organization
        directory_users = self.db.query(DirectoryUser).filter(
            and_(
                DirectoryUser.organization_id == organization_id,
                DirectoryUser.tenant_id == tenant_id
            )
        ).all()

        logger.info(f"Found {len(directory_users)} directory users to sync")
        for i, dir_user in enumerate(directory_users):
            logger.info(f"Directory user {i+1}: {dir_user.email} (ID: {dir_user.id}, Provider: {dir_user.provider_type})")

        synced_count = 0
        skipped_count = 0
        error_count = 0

        for dir_user in directory_users:
            try:
                result = await self._sync_single_directory_user(
                    dir_user,
                    tenant_id,
                    organization_id,
                    sync_batch_id=sync_batch_id
                )
                logger.info(f"Sync result for {dir_user.email}: {result}")
                if result["action"] == "created":
                    synced_count += 1
                elif result["action"] == "skipped":
                    skipped_count += 1
            except Exception as e:
                error_count += 1
                logger.error(f"Failed to sync directory user {dir_user.email}: {e}")

        logger.info(f"Directory users sync completed: {synced_count} synced, {skipped_count} skipped, {error_count} errors")
        return {"synced": synced_count, "skipped": skipped_count, "errors": error_count}

    async def _sync_directory_groups(self, organization_id: str, tenant_id: str) -> Dict[str, int]:
        """Sync directory groups to platform organization groups."""
        # Get all directory groups for this organization
        directory_groups = self.db.query(DirectoryGroup).filter(
            and_(
                DirectoryGroup.organization_id == organization_id,
                DirectoryGroup.tenant_id == tenant_id
            )
        ).all()

        synced_count = 0
        skipped_count = 0
        error_count = 0

        for dir_group in directory_groups:
            try:
                result = await self._sync_single_directory_group(dir_group, organization_id, tenant_id)
                if result["action"] == "created":
                    synced_count += 1
                elif result["action"] == "skipped":
                    skipped_count += 1
            except Exception as e:
                error_count += 1
                logger.error(f"Failed to sync directory group {dir_group.display_name}: {e}")

        return {"synced": synced_count, "skipped": skipped_count, "errors": error_count}

    async def _sync_single_directory_group(self, dir_group: DirectoryGroup, organization_id: str, tenant_id: str) -> Dict[str, str]:
        """Sync a single directory group to a platform organization group."""
        if not dir_group.display_name and not dir_group.name:
            return {"action": "skipped", "reason": "No group name"}

        group_name = dir_group.display_name or dir_group.name

        # Check if platform group already exists with this name
        existing_group = self.db.query(OrganizationGroup).filter(
            and_(
                OrganizationGroup.organization_id == organization_id,
                OrganizationGroup.name == group_name,
                OrganizationGroup.source_type.in_(["azure_ad_graph", "ldap"])
            )
        ).first()

        if existing_group:
            return {"action": "skipped", "reason": "Group already exists"}

        # Create new platform group from directory group
        new_group = OrganizationGroup(
            tenant_id=tenant_id,
            organization_id=organization_id,
            name=group_name,
            display_name=dir_group.display_name,
            description=dir_group.description,
            color="#9333ea" if dir_group.provider_type == "azure_ad_graph" else "#10b981",
            source_type=dir_group.provider_type,
            app_role_mappings={},
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )

        self.db.add(new_group)
        self.db.flush()  # Get the group ID

        logger.info(f"Created platform group for directory group: {group_name}")
        return {"action": "created", "group_id": new_group.id}

    async def _apply_group_role_mappings(self, organization_id: str, tenant_id: str) -> Dict[str, Any]:
        """Apply group-to-role mappings from LDAP config to platform groups."""
        errors = []

        try:
            # Get LDAP config for group role mappings
            ldap_config = self.db.query(TenantLDAPConfig).filter(
                and_(
                    TenantLDAPConfig.tenant_id == tenant_id,
                    TenantLDAPConfig.organization_id == organization_id
                )
            ).first()

            if not ldap_config or not ldap_config.group_role_mappings:
                return {"applied": 0, "errors": []}

            applied_count = 0
            for group_external_id, role_mappings in ldap_config.group_role_mappings.items():
                try:
                    # Find the directory group
                    dir_group = self.db.query(DirectoryGroup).filter(
                        and_(
                            DirectoryGroup.external_id == group_external_id,
                            DirectoryGroup.organization_id == organization_id,
                            DirectoryGroup.tenant_id == tenant_id
                        )
                    ).first()

                    if not dir_group:
                        continue

                    # Find corresponding platform group
                    platform_group = self.db.query(OrganizationGroup).filter(
                        and_(
                            OrganizationGroup.organization_id == organization_id,
                            OrganizationGroup.name == (dir_group.display_name or dir_group.name),
                            OrganizationGroup.source_type == dir_group.provider_type
                        )
                    ).first()

                    if platform_group:
                        platform_group.app_role_mappings = role_mappings
                        platform_group.updated_at = datetime.utcnow()
                        applied_count += 1
                        logger.info(f"Applied role mappings to group {platform_group.name}")

                except Exception as e:
                    errors.append(f"Failed to apply role mapping for group {group_external_id}: {str(e)}")
                    logger.error(f"Failed to apply role mapping for group {group_external_id}: {e}")

            return {"applied": applied_count, "errors": errors}

        except Exception as e:
            errors.append(f"Failed to apply group role mappings: {str(e)}")
            logger.error(f"Failed to apply group role mappings: {e}")
            return {"applied": 0, "errors": errors}

    async def _calculate_user_roles_from_directory_groups(self, user_email: str, tenant_id: str) -> Dict[str, List[str]]:
        """Calculate user roles based on their directory group memberships and group-to-role mappings."""
        try:
            logger.info(f"Calculating roles for user {user_email} in tenant {tenant_id}")

            # Find the directory user by email
            directory_user = self.db.query(DirectoryUser).filter(
                and_(
                    DirectoryUser.email.ilike(user_email),
                    DirectoryUser.tenant_id == tenant_id
                )
            ).first()

            if not directory_user:
                logger.info(f"No directory user found for email {user_email}")
                return {"platform": ["user"]}  # Default platform user role

            logger.info(f"Found directory user: {directory_user.id} for email {user_email}")

            # Get all directory groups this user belongs to
            user_group_memberships = self.db.query(DirectoryGroupMembership).join(
                DirectoryGroup, DirectoryGroupMembership.directory_group_id == DirectoryGroup.id
            ).filter(
                and_(
                    DirectoryGroupMembership.directory_user_id == directory_user.id,
                    DirectoryGroup.tenant_id == tenant_id
                )
            ).all()

            if not user_group_memberships:
                logger.info(f"No group memberships found for user {user_email}")
                return {"platform": ["user"]}  # Default platform user role

            logger.info(f"Found {len(user_group_memberships)} group memberships for user {user_email}")

            # Get the organization from the directory user
            organization_id = directory_user.organization_id

            # Get Azure AD/LDAP config for group role mappings
            ldap_config = self.db.query(TenantLDAPConfig).filter(
                and_(
                    TenantLDAPConfig.tenant_id == tenant_id,
                    TenantLDAPConfig.organization_id == organization_id
                )
            ).first()

            if not ldap_config or not ldap_config.group_role_mappings:
                logger.info(f"No group role mappings found for organization {organization_id}")
                return {"platform": ["user"]}  # Default platform user role

            logger.info(f"Found group role mappings: {ldap_config.group_role_mappings}")

            # Combine roles from all groups the user belongs to
            combined_roles = {}

            for membership in user_group_memberships:
                # Get the directory group
                directory_group = self.db.query(DirectoryGroup).filter(
                    DirectoryGroup.id == membership.directory_group_id
                ).first()

                if not directory_group:
                    continue

                logger.info(f"Processing group: {directory_group.display_name or directory_group.name} (external_id: {directory_group.external_id})")

                # Get role mappings for this group
                group_role_mappings = ldap_config.group_role_mappings.get(directory_group.external_id)

                if not group_role_mappings:
                    logger.info(f"No role mappings found for group {directory_group.external_id}")
                    continue

                logger.info(f"Found role mappings for group {directory_group.external_id}: {group_role_mappings}")

                # Add roles to combined roles
                for app_name, roles in group_role_mappings.items():
                    if app_name not in combined_roles:
                        combined_roles[app_name] = set()

                    if isinstance(roles, list):
                        combined_roles[app_name].update(roles)
                    elif isinstance(roles, str):
                        combined_roles[app_name].add(roles)

            # Convert sets back to lists
            final_roles = {app: list(roles) for app, roles in combined_roles.items()}

            # Ensure platform user role is always present
            if "platform" not in final_roles:
                final_roles["platform"] = ["user"]
            elif "user" not in final_roles["platform"]:
                final_roles["platform"].append("user")

            logger.info(f"Calculated roles for user {user_email}: {final_roles}")
            return final_roles

        except Exception as e:
            logger.error(f"Failed to calculate user roles for {user_email}: {e}")
            return {"platform": ["user"]}  # Default platform user role

    async def _sync_roles_to_organization_user_role_table(
        self,
        user: User,
        tenant_id: str,
        organization_id: str,
        app_roles: Dict[str, List[str]],
        sync_batch_id: Optional[str] = None
    ):
        """Sync user roles to OrganizationUserRole table to maintain consistency with UI"""
        logger.info(f"ENTERING _sync_roles_to_organization_user_role_table for user {user.email}")
        try:
            logger.info(f"Syncing roles to OrganizationUserRole table for user {user.email} in org {organization_id}")
            logger.info(f"DEBUG: app_roles parameter = {app_roles}")

            # Clear only directory-managed roles; preserve invitation/manual/birthright roles.
            self.db.query(OrganizationUserRole).filter(
                and_(
                    OrganizationUserRole.user_id == user.id,
                    OrganizationUserRole.organization_id == organization_id,
                    OrganizationUserRole.granted_via == "directory_sync"
                )
            ).delete()

            # Add new roles (excluding platform role)
            for app_name, roles in app_roles.items():
                if app_name != "platform" and roles:  # Skip platform role
                    logger.info(f"Creating OrganizationUserRole for {user.email}: app={app_name}, roles={roles}")
                    org_role = OrganizationUserRole(
                        tenant_id=tenant_id,
                        user_id=user.id,
                        organization_id=organization_id,
                        app_name=app_name,
                        roles=roles,
                        granted_via="directory_sync",
                        granted_by=None,
                        sync_batch_id=sync_batch_id
                    )
                    self.db.add(org_role)
                    logger.info(f"Added OrganizationUserRole for {user.email}: {app_name} = {roles}")

        except Exception as e:
            logger.error(f"Failed to sync roles to OrganizationUserRole table for {user.email}: {e}")


@router.post("/{organization_id}/sync-directory-to-platform")
async def sync_directory_to_platform_endpoint(
    organization_id: str,
    sync_users: bool = True,
    sync_groups: bool = True,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Sync directory users and groups to platform with role mappings.
    Creates platform User and OrganizationGroup records with proper role mappings.
    """
    try:
        # Verify organization exists and get tenant_id
        org = db.query(Organization).filter(
            Organization.id == organization_id,
            Organization.deleted_at.is_(None)
        ).first()

        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        # TODO: Add proper authorization check
        # For now, allow if user has access to the organization

        # Resolve the DB user ID so we can stamp the sync batch
        triggered_by_user_id: Optional[str] = None
        possible_ids: List[Optional[str]] = []

        if hasattr(current_user, "id"):
            possible_ids.append(getattr(current_user, "id"))
        if isinstance(current_user, dict):
            possible_ids.append(current_user.get("id"))

        keycloak_id = getattr(current_user, "user_id", None)
        if isinstance(current_user, dict) and not keycloak_id:
            keycloak_id = current_user.get("user_id") or current_user.get("sub")

        for candidate in possible_ids:
            if candidate:
                local = db.query(User).filter(User.id == candidate).first()
                if local:
                    triggered_by_user_id = local.id
                    break

        if not triggered_by_user_id and keycloak_id:
            local = db.query(User).filter(User.keycloak_id == keycloak_id).first()
            if local:
                triggered_by_user_id = local.id

        # Create sync service and perform sync
        sync_service = DirectoryToPlatformSyncService(db)
        result = await sync_service.sync_directory_to_platform(
            organization_id=organization_id,
            tenant_id=org.tenant_id,
            sync_users=sync_users,
            sync_groups=sync_groups,
            triggered_by_user_id=triggered_by_user_id
        )

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Directory to platform sync endpoint failed: {e}")
        raise HTTPException(status_code=500, detail="Directory to platform sync failed")


@router.get("/{organization_id}/directory-to-platform-status")
async def get_directory_to_platform_status(
    organization_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get the status of directory to platform sync for an organization.
    Shows counts of directory users/groups vs synced platform users/groups.
    """
    try:
        # Verify organization exists
        org = db.query(Organization).filter(
            Organization.id == organization_id,
            Organization.deleted_at.is_(None)
        ).first()

        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        # Count unique directory user emails (case-insensitive) for sync status.
        # This avoids false "pending" counts caused by casing differences.
        directory_email_subquery = (
            db.query(func.lower(DirectoryUser.email).label("email"))
            .filter(
                and_(
                    DirectoryUser.organization_id == organization_id,
                    DirectoryUser.tenant_id == org.tenant_id,
                    DirectoryUser.email.isnot(None)
                )
            )
            .distinct()
            .subquery()
        )

        directory_user_count = (
            db.query(func.count())
            .select_from(directory_email_subquery)
            .scalar()
            or 0
        )

        # Count directory groups
        directory_group_count = db.query(DirectoryGroup).filter(
            and_(
                DirectoryGroup.organization_id == organization_id,
                DirectoryGroup.tenant_id == org.tenant_id
            )
        ).count()

        # Count unique platform users in this tenant with case-insensitive email
        # match against directory users.
        synced_platform_users = (
            db.query(func.count(func.distinct(func.lower(User.email))))
            .join(UserTenant)
            .filter(
                and_(
                    UserTenant.tenant_id == org.tenant_id,
                    func.lower(User.email).in_(select(directory_email_subquery.c.email))
                )
            )
            .scalar()
            or 0
        )

        # Count platform groups with source_type from directory
        synced_platform_groups = db.query(OrganizationGroup).filter(
            and_(
                OrganizationGroup.organization_id == organization_id,
                OrganizationGroup.source_type.in_(["azure_ad_graph", "ldap"])
            )
        ).count()

        pending_user_sync = max(0, directory_user_count - synced_platform_users)
        pending_group_sync = max(0, directory_group_count - synced_platform_groups)

        return {
            "org_id": organization_id,
            "users": {
                "directory_count": directory_user_count,
                "synced_platform_count": synced_platform_users,
                "pending_sync_count": pending_user_sync,
                "sync_percentage": (synced_platform_users / directory_user_count * 100) if directory_user_count > 0 else 0
            },
            "groups": {
                "directory_count": directory_group_count,
                "synced_platform_count": synced_platform_groups,
                "pending_sync_count": pending_group_sync,
                "sync_percentage": (synced_platform_groups / directory_group_count * 100) if directory_group_count > 0 else 0
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Directory to platform status endpoint failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to get directory to platform status")
