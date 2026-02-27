"""
Organization Azure AD Integration Module
Handles organization-scoped Azure AD/EntraID Graph integration for user sync and role mapping
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import or_
from typing import List, Dict, Any, Optional, Tuple
import logging
from datetime import datetime, timezone
import uuid
import requests
import httpx

from shared.database import get_db
from shared.auth import get_current_user
from shared.credential_manager import get_credential_manager
from modules.keycloak_client import KeycloakClient
from models import (
    TenantLDAPConfig,
    TenantLDAPSyncHistory,
    Organization,
    OrganizationUserRole,
    OrganizationAppAccess,
    DirectoryUser,
    DirectoryGroup,
    DirectoryGroupMembership
)
from shared.models import User, UserTenant
from pydantic import BaseModel, Field
from modules.tenant_management import user_has_tenant_admin

logger = logging.getLogger(__name__)

# Create router for organization Azure AD endpoints
router = APIRouter(prefix="/platform/organizations", tags=["organization-azure-ad"])

class OrganizationAzureADConfigRequest(BaseModel):
    """Organization-specific Azure AD configuration"""
    tenant_id: str = Field(..., description="Azure AD Tenant ID")
    client_id: str = Field(..., description="Azure AD Application Client ID")
    client_secret: Optional[str] = Field(
        None, description="Azure AD Application Client Secret"
    )
    enabled: bool = Field(default=True, description="Enable Azure AD sync")
    sync_users: bool = Field(default=True, description="Sync users from Azure AD")
    sync_groups: bool = Field(default=True, description="Sync groups from Azure AD")
    group_role_mappings: Dict[str, Dict[str, List[str]]] = Field(
        default_factory=dict,
        description="Mapping of Azure AD groups to organization app roles"
    )
    user_filter: Optional[str] = Field(None, description="Filter users (e.g., department='Engineering')")
    group_filter: Optional[str] = Field(None, description="Filter groups")

class OrganizationAzureADConfigResponse(BaseModel):
    """Azure AD configuration response"""
    id: Optional[str] = None
    organization_id: str
    tenant_id: str
    client_id: str
    enabled: bool
    sync_users: bool
    sync_groups: bool
    group_role_mappings: Dict[str, Any]
    last_sync_at: Optional[datetime] = None
    last_sync_status: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class AzureADSyncRequest(BaseModel):
    """Azure AD sync trigger request"""
    sync_type: str = Field(default="incremental", pattern="^(full|incremental|test)$")
    dry_run: bool = Field(default=False, description="Perform dry run without making changes")

class AzureADTestConnectionRequest(BaseModel):
    """Payload for testing Azure AD client credentials"""
    tenant_id: str
    client_id: str
    client_secret: str

async def _store_client_secret(org: Organization, client_secret: Optional[str]):
    """Store Azure AD client secret using organization-scoped directory structure"""
    if not client_secret:
        return
    try:
        credential_manager = get_credential_manager()
        await credential_manager.store_secret(
            org.tenant_id,
            f"organizations/{org.id}/azure_ad",
            "client_secret",
            {"client_secret": client_secret}
        )
        logger.info(f"Successfully stored Azure AD client secret for organization {org.id}")
    except Exception as e:
        logger.error(f"Failed to store Azure AD client secret for organization {org.id}: {e}")
        # For development environments where credential manager isn't available,
        # we'll log the issue but allow the config update to proceed
        # In production, you might want to raise an HTTPException here
        logger.warning("Proceeding with config update despite credential storage failure (development mode)")

async def _get_client_secret(org: Organization) -> Optional[str]:
    """Get Azure AD client secret using organization-scoped directory structure"""
    try:
        credential_manager = get_credential_manager()
        secret = await credential_manager.get_secret(
            org.tenant_id,
            f"organizations/{org.id}/azure_ad",
            "client_secret"
        )
        return secret.get("client_secret") if secret else None
    except Exception as e:
        logger.error(f"Failed to retrieve Azure AD client secret: {e}")
        return None

async def _delete_client_secret(org: Organization):
    """Delete Azure AD client secret using organization-scoped directory structure"""
    try:
        credential_manager = get_credential_manager()
        await credential_manager.delete_secret(
            org.tenant_id,
            f"organizations/{org.id}/azure_ad",
            "client_secret"
        )
        logger.info(f"Successfully deleted Azure AD client secret for organization {org.id}")
    except Exception as e:
        logger.error(f"Failed to delete Azure AD client secret for organization {org.id}: {e}")
        # Continue with deletion even if credential cleanup fails

def _get_graph_token(tenant_id: str, client_id: str, client_secret: str) -> Tuple[str, Optional[int]]:
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    form = {
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials",
    }
    response = requests.post(token_url, data=form, timeout=15)
    if response.status_code != 200:
        detail = response.json().get("error_description", response.text)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Azure AD connection failed: {detail}"
        )
    payload = response.json()
    access_token = payload.get("access_token")
    if not access_token:
        raise HTTPException(status_code=500, detail="Azure AD response missing access token")
    return access_token, payload.get("expires_in")

def _fetch_graph_resource(access_token: str, resource: str) -> List[Dict[str, Any]]:
    headers = {"Authorization": f"Bearer {access_token}"}
    url = f"https://graph.microsoft.com/v1.0/{resource}"
    response = requests.get(url, headers=headers, timeout=20)
    if response.status_code != 200:
        detail = response.json().get("error", {}).get("message", response.text)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to query Microsoft Graph: {detail}"
        )
    data = response.json()
    return data.get("value", [])

def _get_org_and_config(db: Session, organization_id: str) -> Tuple[Organization, TenantLDAPConfig]:
    org = db.query(Organization).filter(
        Organization.id == organization_id,
        Organization.deleted_at.is_(None)
    ).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    config = db.query(TenantLDAPConfig).filter(
        TenantLDAPConfig.tenant_id == org.tenant_id,
        TenantLDAPConfig.organization_id == organization_id,
        TenantLDAPConfig.provider_type == "azure_ad_graph"
    ).first()
    if not config:
        raise HTTPException(status_code=404, detail="Azure AD configuration not found")

    return org, config

def _require_org_admin_access(db: Session, user_id: str, organization: Organization) -> User:
    """Allow tenant admins or org-scoped app admins to manage directory settings."""
    if not organization:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")

    user = db.query(User).filter(
        or_(User.id == user_id, User.keycloak_id == user_id)
    ).first()
    if not user:
        logger.warning(f"User not found for ID: {user_id}")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    logger.debug(f"Found user: {user.email} (ID: {user.id}, Keycloak ID: {user.keycloak_id}) for organization {organization.id}")

    membership = db.query(UserTenant).filter(
        UserTenant.user_id == user.id,
        UserTenant.tenant_id == organization.tenant_id,
        UserTenant.status == "active"
    ).first()
    if not membership:
        logger.warning(f"No active tenant membership found for user {user.email} in tenant {organization.tenant_id}")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied to tenant")

    logger.debug(f"Found tenant membership for {user.email}: app_roles = {membership.app_roles}")

    if user_has_tenant_admin(membership):
        logger.debug(f"User {user.email} has tenant admin access")
        return user

    role_entries = db.query(OrganizationUserRole).filter(
        OrganizationUserRole.organization_id == organization.id,
        OrganizationUserRole.user_id == user.id
    ).all()

    logger.debug(f"Found {len(role_entries)} organization role entries for user {user.email}")
    for entry in role_entries:
        logger.debug(f"Organization role entry: {entry.roles}")
        if any(role in {"admin", "administrator"} for role in (entry.roles or [])):
            logger.debug(f"User {user.email} has organization admin access")
            return user

    logger.warning(f"User {user.email} lacks required admin access for organization {organization.id}")
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Organization admin access required"
    )

@router.post("/{organization_id}/azure-ad/config", response_model=OrganizationAzureADConfigResponse)
async def create_azure_ad_config(
    organization_id: str,
    config: OrganizationAzureADConfigRequest,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Create Azure AD configuration for organization"""
    try:
        # Check organization exists and user has access
        org = db.query(Organization).filter(
            Organization.id == organization_id,
            Organization.deleted_at.is_(None)
        ).first()

        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        user = _require_org_admin_access(db, current_user.user_id, org)

        if not config.client_secret:
            raise HTTPException(
                status_code=400,
                detail="Client secret is required when creating Azure Entra configuration"
            )

        # Check if config already exists
        existing_config = db.query(TenantLDAPConfig).filter(
            TenantLDAPConfig.tenant_id == org.tenant_id,
            TenantLDAPConfig.organization_id == organization_id,
            TenantLDAPConfig.provider_type == "azure_ad_graph"
        ).first()

        if existing_config:
            raise HTTPException(
                status_code=400,
                detail="Azure AD configuration already exists for this organization"
            )

        # Create LDAP config for Azure AD
        ldap_config = TenantLDAPConfig(
            tenant_id=org.tenant_id,
            organization_id=organization_id,
            enabled=config.enabled,
            provider_type="azure_ad_graph",

            # Azure AD Graph configuration
            graph_tenant_id=config.tenant_id,
            graph_client_id=config.client_id,

            # Sync settings
            sync_registrations=config.sync_users,
            import_enabled=config.sync_users,
            edit_mode="READ_ONLY",

            # Store group role mappings
            group_role_mappings=config.group_role_mappings,
            last_sync_status="not_started",
            created_by=user.id if user else None
        )

        db.add(ldap_config)
        db.flush()

        # Store client secret securely
        await _store_client_secret(org, config.client_secret)
        # Keep Keycloak Microsoft IdP org-scoped and in sync with this org's Entra config.
        try:
            keycloak_client = KeycloakClient()
            await keycloak_client.upsert_org_microsoft_idp(
                org_id=org.id,
                client_id=config.client_id,
                client_secret=config.client_secret or "",
                tenant_id=config.tenant_id
            )
        except Exception as idp_error:
            logger.warning(f"Failed to upsert org-scoped Microsoft IdP for org {org.id}: {idp_error}")

        db.commit()

        return OrganizationAzureADConfigResponse(
            id=ldap_config.id,
            organization_id=organization_id,
            tenant_id=config.tenant_id,
            client_id=config.client_id,
            enabled=config.enabled,
            sync_users=config.sync_users,
            sync_groups=config.sync_groups,
            group_role_mappings=config.group_role_mappings,
            last_sync_at=ldap_config.last_sync_at,
            last_sync_status=ldap_config.last_sync_status,
            created_at=ldap_config.created_at,
            updated_at=ldap_config.updated_at
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create Azure AD config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create Azure AD configuration: {str(e)}")

@router.get("/{organization_id}/azure-ad/config", response_model=OrganizationAzureADConfigResponse)
async def get_azure_ad_config(
    organization_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get Azure AD configuration for organization"""
    try:
        # Check organization exists and user has access
        org = db.query(Organization).filter(
            Organization.id == organization_id,
            Organization.deleted_at.is_(None)
        ).first()

        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        _require_org_admin_access(db, current_user.user_id, org)

        # Get Azure AD config
        config = db.query(TenantLDAPConfig).filter(
            TenantLDAPConfig.tenant_id == org.tenant_id,
            TenantLDAPConfig.organization_id == organization_id,
            TenantLDAPConfig.provider_type == "azure_ad_graph"
        ).first()

        if not config:
            return OrganizationAzureADConfigResponse(
                id=None,
                organization_id=organization_id,
                tenant_id=org.tenant_id,
                client_id="",
                enabled=False,
                sync_users=True,
                sync_groups=True,
                group_role_mappings={},
                last_sync_at=None,
                last_sync_status=None,
                created_at=None,
                updated_at=None
            )

        # Load group role mappings from database
        group_role_mappings = config.group_role_mappings or {}

        return OrganizationAzureADConfigResponse(
            id=config.id,
            organization_id=organization_id,
            tenant_id=config.graph_tenant_id,
            client_id=config.graph_client_id,
            enabled=config.enabled,
            sync_users=config.sync_registrations,
            sync_groups=config.import_enabled,
            group_role_mappings=group_role_mappings,
            last_sync_at=config.last_sync_at,
            last_sync_status=config.last_sync_status,
            created_at=config.created_at,
            updated_at=config.updated_at
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get Azure AD config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get Azure AD configuration: {str(e)}")

@router.put("/{organization_id}/azure-ad/config", response_model=OrganizationAzureADConfigResponse)
async def update_azure_ad_config(
    organization_id: str,
    config_update: OrganizationAzureADConfigRequest,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Update Azure AD configuration for organization"""
    try:
        # Check organization exists and user has access
        org = db.query(Organization).filter(
            Organization.id == organization_id,
            Organization.deleted_at.is_(None)
        ).first()

        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        _require_org_admin_access(db, current_user.user_id, org)

        # Get existing config
        ldap_config = db.query(TenantLDAPConfig).filter(
            TenantLDAPConfig.tenant_id == org.tenant_id,
            TenantLDAPConfig.organization_id == organization_id,
            TenantLDAPConfig.provider_type == "azure_ad_graph"
        ).first()

        if not ldap_config:
            raise HTTPException(status_code=404, detail="Azure AD configuration not found")

        # Update configuration
        ldap_config.graph_tenant_id = config_update.tenant_id
        ldap_config.graph_client_id = config_update.client_id
        ldap_config.enabled = config_update.enabled
        ldap_config.sync_registrations = config_update.sync_users
        ldap_config.import_enabled = config_update.sync_users
        ldap_config.group_role_mappings = config_update.group_role_mappings
        ldap_config.updated_at = datetime.utcnow()

        if config_update.client_secret:
            await _store_client_secret(org, config_update.client_secret)
            client_secret_for_idp = config_update.client_secret
        else:
            existing_secret = await _get_client_secret(org)
            client_secret_for_idp = existing_secret
            if not existing_secret:
                # For group role mapping updates, we don't require the client secret
                # since we're not making API calls to Azure AD, just updating local mappings
                logger.warning(f"No client secret found for organization {organization_id}, but allowing group role mapping update")
                # Only fail if we need the secret for actual Azure AD operations (sync operations)
                # For configuration updates (especially group role mappings), we can proceed without it

        # Sync org-scoped Microsoft IdP if we have credentials.
        if client_secret_for_idp:
            try:
                keycloak_client = KeycloakClient()
                await keycloak_client.upsert_org_microsoft_idp(
                    org_id=org.id,
                    client_id=config_update.client_id,
                    client_secret=client_secret_for_idp,
                    tenant_id=config_update.tenant_id
                )
            except Exception as idp_error:
                logger.warning(f"Failed to upsert org-scoped Microsoft IdP for org {org.id}: {idp_error}")

        db.commit()

        return OrganizationAzureADConfigResponse(
            id=ldap_config.id,
            organization_id=organization_id,
            tenant_id=ldap_config.graph_tenant_id,
            client_id=ldap_config.graph_client_id,
            enabled=ldap_config.enabled,
            sync_users=ldap_config.sync_registrations,
            sync_groups=ldap_config.import_enabled,
            group_role_mappings=config_update.group_role_mappings,
            last_sync_at=ldap_config.last_sync_at,
            last_sync_status=ldap_config.last_sync_status,
            created_at=ldap_config.created_at,
            updated_at=ldap_config.updated_at
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update Azure AD config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update Azure AD configuration: {str(e)}")

@router.post("/{organization_id}/azure-ad/sync")
async def trigger_azure_ad_sync(
    organization_id: str,
    sync_request: AzureADSyncRequest,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Trigger Azure AD user and group sync for organization"""
    try:
        # Check organization exists and user has access
        org = db.query(Organization).filter(
            Organization.id == organization_id,
            Organization.deleted_at.is_(None)
        ).first()

        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        _require_org_admin_access(db, current_user.user_id, org)

        # Get Azure AD config
        config = db.query(TenantLDAPConfig).filter(
            TenantLDAPConfig.tenant_id == org.tenant_id,
            TenantLDAPConfig.organization_id == organization_id,
            TenantLDAPConfig.provider_type == "azure_ad_graph"
        ).first()

        if not config:
            raise HTTPException(status_code=404, detail="Azure AD configuration not found")

        if not config.enabled:
            raise HTTPException(status_code=400, detail="Azure AD sync is disabled")

        client_secret = await _get_client_secret(org)
        if not client_secret:
            # Return appropriate response for development when credentials aren't available
            logger.warning(f"Azure AD client secret not available for organization {organization_id}")
            return {"status": "error", "message": "Azure AD credentials not configured or not available in current environment"}

        access_token, _ = _get_graph_token(
            config.graph_tenant_id,
            config.graph_client_id,
            client_secret
        )

        # Get user database ID from Keycloak ID for foreign key constraint
        # current_user.user_id contains the Keycloak ID, but foreign key needs database User.id
        local_user = db.query(User).filter(User.keycloak_id == current_user.user_id).first()
        triggered_by_user_id = None

        if local_user:
            triggered_by_user_id = local_user.id  # Use database ID, not Keycloak ID
            logger.debug(f"Found local user {local_user.id} for Keycloak ID {current_user.user_id}")
        else:
            # User may not exist in local database yet (external users, etc.)
            logger.warning(f"User with Keycloak ID {current_user.user_id} not found in local users table")

        # Create sync history record
        sync_history = TenantLDAPSyncHistory(
            tenant_id=org.tenant_id,
            organization_id=organization_id,
            ldap_config_id=config.id,
            sync_type=sync_request.sync_type,
            sync_status="in_progress",
            started_at=datetime.utcnow(),
            triggered_by=triggered_by_user_id
        )
        db.add(sync_history)
        db.flush()

        users = []
        groups = []
        try:
            groups = _fetch_graph_resource(
                access_token,
                "groups?$top=50&$select=id,displayName,mail,description,securityEnabled,groupTypes"
            )
            users = _fetch_graph_resource(
                access_token,
                "users?$top=50&$select=id,displayName,mail,userPrincipalName,accountEnabled,userType"
            )
            logger.info(f"Fetched {len(users)} users from Azure AD for organization {organization_id}")
            for i, user in enumerate(users):
                user_type = user.get('userType', 'Unknown')
                account_enabled = user.get('accountEnabled', 'Unknown')
                email = user.get('mail') or user.get('userPrincipalName', 'No email')
                display_name = user.get('displayName', 'No name')
                logger.info(f"User {i+1}: {display_name} ({email}) - Type: {user_type}, Enabled: {account_enabled}")
        except HTTPException as graph_error:
            sync_history.sync_status = "failed"
            sync_history.completed_at = datetime.utcnow()
            sync_history.error_message = graph_error.detail
            config.last_sync_at = sync_history.completed_at
            config.last_sync_status = sync_history.sync_status
            db.commit()
            raise

        # Persist users and groups to database (unless dry_run)
        users_added = 0
        users_updated = 0
        groups_added = 0
        groups_updated = 0

        if not sync_request.dry_run:
            # Sync users to database
            for user_data in users:
                existing_user = db.query(DirectoryUser).filter(
                    DirectoryUser.ldap_config_id == config.id,
                    DirectoryUser.external_id == user_data.get('id')
                ).first()

                if existing_user:
                    # Update existing user
                    existing_user.display_name = user_data.get('displayName')
                    existing_user.email = user_data.get('mail') or user_data.get('userPrincipalName')
                    existing_user.username = user_data.get('userPrincipalName')
                    existing_user.enabled = user_data.get('accountEnabled', True)
                    existing_user.last_synced_at = datetime.utcnow()
                    existing_user.attributes = user_data
                    users_updated += 1
                else:
                    # Create new user
                    new_user = DirectoryUser(
                        tenant_id=org.tenant_id,
                        organization_id=organization_id,
                        ldap_config_id=config.id,
                        external_id=user_data.get('id'),
                        provider_type="azure_ad_graph",
                        display_name=user_data.get('displayName'),
                        email=user_data.get('mail') or user_data.get('userPrincipalName'),
                        username=user_data.get('userPrincipalName'),
                        enabled=user_data.get('accountEnabled', True),
                        attributes=user_data,
                        last_synced_at=datetime.utcnow()
                    )
                    db.add(new_user)
                    users_added += 1

            # Sync groups to database
            for group_data in groups:
                existing_group = db.query(DirectoryGroup).filter(
                    DirectoryGroup.ldap_config_id == config.id,
                    DirectoryGroup.external_id == group_data.get('id')
                ).first()

                if existing_group:
                    # Update existing group
                    existing_group.display_name = group_data.get('displayName')
                    existing_group.name = group_data.get('displayName')
                    existing_group.description = group_data.get('description')
                    existing_group.email = group_data.get('mail')
                    existing_group.security_enabled = group_data.get('securityEnabled', True)
                    existing_group.last_synced_at = datetime.utcnow()
                    existing_group.attributes = group_data
                    groups_updated += 1
                else:
                    # Create new group
                    new_group = DirectoryGroup(
                        tenant_id=org.tenant_id,
                        organization_id=organization_id,
                        ldap_config_id=config.id,
                        external_id=group_data.get('id'),
                        provider_type="azure_ad_graph",
                        name=group_data.get('displayName'),
                        display_name=group_data.get('displayName'),
                        description=group_data.get('description'),
                        email=group_data.get('mail'),
                        security_enabled=group_data.get('securityEnabled', True),
                        attributes=group_data,
                        last_synced_at=datetime.utcnow()
                    )
                    db.add(new_group)
                    groups_added += 1

        # Sync group memberships
        memberships_added = 0
        memberships_removed = 0
        if not sync_request.dry_run:
            logger.info(f"Syncing group memberships for {len(groups)} groups")

            # Clear existing memberships for this config to handle removals
            # Get group IDs first, then delete memberships
            group_ids = db.query(DirectoryGroup.id).filter(
                DirectoryGroup.ldap_config_id == config.id,
                DirectoryGroup.provider_type == "azure_ad_graph"
            ).all()
            group_ids = [g.id for g in group_ids]

            if group_ids:
                db.query(DirectoryGroupMembership).filter(
                    DirectoryGroupMembership.directory_group_id.in_(group_ids)
                ).delete(synchronize_session=False)

            for group_data in groups:
                group_id = group_data.get('id')
                if not group_id:
                    continue

                # Find the group in our database
                directory_group = db.query(DirectoryGroup).filter(
                    DirectoryGroup.ldap_config_id == config.id,
                    DirectoryGroup.external_id == group_id
                ).first()

                if not directory_group:
                    continue

                try:
                    # Fetch group members from Azure AD
                    group_members = _fetch_graph_resource(
                        access_token,
                        f"groups/{group_id}/members?$select=id,displayName,userPrincipalName"
                    )

                    logger.info(f"Group {group_data.get('displayName')} has {len(group_members)} members")

                    for member_data in group_members:
                        member_id = member_data.get('id')
                        if not member_id:
                            continue

                        # Find the user in our database
                        directory_user = db.query(DirectoryUser).filter(
                            DirectoryUser.ldap_config_id == config.id,
                            DirectoryUser.external_id == member_id
                        ).first()

                        if directory_user:
                            # Create group membership
                            membership = DirectoryGroupMembership(
                                directory_group_id=directory_group.id,
                                directory_user_id=directory_user.id,
                                created_at=datetime.utcnow(),
                                last_synced_at=datetime.utcnow()
                            )
                            db.add(membership)
                            memberships_added += 1

                except Exception as e:
                    logger.warning(f"Failed to sync members for group {group_data.get('displayName')}: {e}")
                    continue

            logger.info(f"Group membership sync completed: {memberships_added} memberships added")

        # Sync users and groups to Keycloak with role assignments
        keycloak_sync_results = {"users_synced": 0, "errors": []}
        if not sync_request.dry_run:
            try:
                keycloak_sync_results = await _sync_to_keycloak(
                    config, org, users
                )
            except Exception as e:
                logger.error(f"Keycloak sync failed: {e}")
                keycloak_sync_results["errors"].append(str(e))

        sync_history.users_added = users_added
        sync_history.groups_added = groups_added
        sync_history.users_updated = users_updated
        sync_history.sync_status = "success"
        sync_history.completed_at = datetime.utcnow()
        sync_history.details = {
            "message": "Azure Entra sync completed",
            "dry_run": sync_request.dry_run,
            "users_processed": len(users),
            "groups_processed": len(groups),
            "memberships_added": memberships_added,
            "users_added": users_added,
            "users_updated": users_updated,
            "groups_added": groups_added,
            "groups_updated": groups_updated,
            "preview_users": users[:5],
            "preview_groups": groups[:5],
            "keycloak_sync": keycloak_sync_results
        }

        # Update config with last sync info
        config.last_sync_at = sync_history.completed_at
        config.last_sync_status = sync_history.sync_status

        db.commit()

        return {
            "sync_id": sync_history.id,
            "status": sync_history.sync_status,
            "started_at": sync_history.started_at,
            "completed_at": sync_history.completed_at,
            "sync_type": sync_request.sync_type,
            "dry_run": sync_request.dry_run,
            "results": {
                "users_added": sync_history.users_added,
                "users_updated": sync_history.users_updated,
                "groups_added": sync_history.groups_added
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to trigger Azure AD sync: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to trigger Azure AD sync: {str(e)}")

@router.get("/{organization_id}/azure-ad/groups")
async def list_azure_ad_groups(
    organization_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """List Azure AD groups for an organization."""
    try:
        org = db.query(Organization).filter(
            Organization.id == organization_id,
            Organization.deleted_at.is_(None)
        ).first()
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        _require_org_admin_access(db, current_user.user_id, org)
        config = db.query(TenantLDAPConfig).filter(
            TenantLDAPConfig.tenant_id == org.tenant_id,
            TenantLDAPConfig.organization_id == organization_id,
            TenantLDAPConfig.provider_type == "azure_ad_graph"
        ).first()
        if not config or not config.enabled:
            return {"groups": []}

        client_secret = await _get_client_secret(org)
        if not client_secret:
            # Return empty groups in development when credentials aren't available
            logger.warning(f"Azure AD client secret not available for organization {organization_id}")
            return {"groups": []}

        # Get cached groups from database instead of live API call
        try:
            cached_groups = db.query(DirectoryGroup).filter(
                DirectoryGroup.ldap_config_id == config.id,
                DirectoryGroup.provider_type == "azure_ad_graph"
            ).order_by(DirectoryGroup.display_name).all()

            # Convert to API format
            groups = []
            for group in cached_groups:
                groups.append({
                    "id": group.external_id,
                    "displayName": group.display_name,
                    "mail": group.email,
                    "description": group.description,
                    "securityEnabled": group.security_enabled,
                    **(group.attributes or {})  # Include any additional attributes stored
                })

            return {"groups": groups}
        except Exception as e:
            logger.error(f"Failed to fetch cached Azure AD groups: {e}")
            return {"groups": []}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to list Azure AD groups: {e}")
        raise HTTPException(status_code=500, detail="Failed to load Azure AD groups")

@router.get("/{organization_id}/azure-ad/users")
async def list_azure_ad_users(
    organization_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """List Azure AD users for an organization."""
    try:
        org = db.query(Organization).filter(
            Organization.id == organization_id,
            Organization.deleted_at.is_(None)
        ).first()
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        _require_org_admin_access(db, current_user.user_id, org)
        config = db.query(TenantLDAPConfig).filter(
            TenantLDAPConfig.tenant_id == org.tenant_id,
            TenantLDAPConfig.organization_id == organization_id,
            TenantLDAPConfig.provider_type == "azure_ad_graph"
        ).first()
        if not config or not config.enabled:
            return {"users": []}

        client_secret = await _get_client_secret(org)
        if not client_secret:
            # Return empty users in development when credentials aren't available
            logger.warning(f"Azure AD client secret not available for organization {organization_id}")
            return {"users": []}

        # Get cached users from database instead of live API call
        try:
            cached_users = db.query(DirectoryUser).filter(
                DirectoryUser.ldap_config_id == config.id,
                DirectoryUser.provider_type == "azure_ad_graph"
            ).order_by(DirectoryUser.display_name).all()

            # Convert to API format
            users = []
            for user in cached_users:
                users.append({
                    "id": user.external_id,
                    "displayName": user.display_name,
                    "mail": user.email,
                    "userPrincipalName": user.username,
                    "accountEnabled": user.enabled,
                    **(user.attributes or {})  # Include any additional attributes stored
                })

            return {"users": users}
        except Exception as e:
            logger.error(f"Failed to fetch cached Azure AD users: {e}")
            return {"users": []}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to list Azure AD users: {e}")
        raise HTTPException(status_code=500, detail="Failed to load Azure AD users")

@router.get("/{organization_id}/azure-ad/status")
async def get_azure_ad_status(
    organization_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get Azure AD directory status with database counts for metrics."""
    try:
        org = db.query(Organization).filter(
            Organization.id == organization_id,
            Organization.deleted_at.is_(None)
        ).first()
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        _require_org_admin_access(db, current_user.user_id, org)
        config = db.query(TenantLDAPConfig).filter(
            TenantLDAPConfig.tenant_id == org.tenant_id,
            TenantLDAPConfig.organization_id == organization_id,
            TenantLDAPConfig.provider_type == "azure_ad_graph"
        ).first()

        if not config or not config.enabled:
            return {
                "enabled": False,
                "status": "not_connected",
                "configured": False,
                "provider_type": "azure_ad_graph",
                "mapped_group_count": 0,
                "directory_user_count": 0,
                "last_sync_at": None
            }

        # Get counts from database
        group_count = db.query(DirectoryGroup).filter(
            DirectoryGroup.ldap_config_id == config.id,
            DirectoryGroup.provider_type == "azure_ad_graph"
        ).count()

        user_count = db.query(DirectoryUser).filter(
            DirectoryUser.ldap_config_id == config.id,
            DirectoryUser.provider_type == "azure_ad_graph"
        ).count()

        logger.info(f"Azure AD status for org {organization_id}: config_id={config.id}, user_count={user_count}, group_count={group_count}")

        # Debug: Check if users exist with different config IDs
        total_users = db.query(DirectoryUser).filter(
            DirectoryUser.organization_id == organization_id,
            DirectoryUser.provider_type == "azure_ad_graph"
        ).count()
        logger.info(f"Total DirectoryUsers for org {organization_id}: {total_users}")

        # Count mapped groups (groups that have role mappings)
        mapped_group_count = 0
        if config.group_role_mappings:
            mapped_group_count = len(config.group_role_mappings)

        return {
            "enabled": config.enabled,
            "status": "configured" if config.enabled else "not_connected",
            "configured": config.enabled,
            "provider_type": "azure_ad_graph",
            "mapped_group_count": mapped_group_count,
            "directory_user_count": user_count,
            "directory_group_count": group_count,
            "last_sync_at": config.last_sync_at.isoformat() if config.last_sync_at else None
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get Azure AD status: {e}")
        raise HTTPException(status_code=500, detail="Failed to get Azure AD status")

@router.get("/{organization_id}/directory-users")
async def get_directory_users(
    organization_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get cached directory users for organization members display."""
    try:
        org = db.query(Organization).filter(
            Organization.id == organization_id,
            Organization.deleted_at.is_(None)
        ).first()
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        _require_org_admin_access(db, current_user.user_id, org)

        # Get all directory users for this organization
        directory_users = db.query(DirectoryUser).filter(
            DirectoryUser.organization_id == organization_id,
            DirectoryUser.provider_type.in_(["azure_ad_graph", "ldap"])
        ).all()

        # Format users for frontend display
        users_data = []
        for user in directory_users:
            users_data.append({
                "id": user.external_id,
                "email": user.email,
                "displayName": user.display_name,
                "firstName": user.first_name,
                "lastName": user.last_name,
                "enabled": user.enabled,
                "providerType": user.provider_type,
                "directorySource": "Azure Entra ID" if user.provider_type == "azure_ad_graph" else "LDAP",
                "lastSyncedAt": user.last_synced_at.isoformat() if user.last_synced_at else None
            })

        return {"users": users_data}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get directory users: {e}")
        raise HTTPException(status_code=500, detail="Failed to get directory users")

@router.get("/{organization_id}/directory-groups")
async def get_directory_groups(
    organization_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get cached directory groups for organization groups display."""
    try:
        org = db.query(Organization).filter(
            Organization.id == organization_id,
            Organization.deleted_at.is_(None)
        ).first()
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        _require_org_admin_access(db, current_user.user_id, org)

        # Get all directory groups for this organization
        directory_groups = db.query(DirectoryGroup).filter(
            DirectoryGroup.organization_id == organization_id,
            DirectoryGroup.provider_type.in_(["azure_ad_graph", "ldap"])
        ).all()

        # Format groups for frontend display
        groups_data = []
        for group in directory_groups:
            groups_data.append({
                "id": group.external_id,
                "displayName": group.display_name or group.name,
                "name": group.name,
                "description": group.description,
                "email": group.email,
                "securityEnabled": group.security_enabled,
                "providerType": group.provider_type,
                "directorySource": "Azure Entra ID" if group.provider_type == "azure_ad_graph" else "LDAP",
                "lastSyncedAt": group.last_synced_at.isoformat() if group.last_synced_at else None
            })

        return {"groups": groups_data}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get directory groups: {e}")
        raise HTTPException(status_code=500, detail="Failed to get directory groups")

@router.post("/{organization_id}/azure-ad/test-connection")
async def test_azure_ad_connection(
    organization_id: str,
    request: AzureADTestConnectionRequest,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Test Azure Entra ID client credentials by performing a token exchange.
    """
    try:
        org = db.query(Organization).filter(
            Organization.id == organization_id,
            Organization.deleted_at.is_(None)
        ).first()
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        _require_org_admin_access(db, current_user.user_id, org)

        _, expires_in = _get_graph_token(
            request.tenant_id,
            request.client_id,
            request.client_secret
        )

        return {
            "status": "success",
            "message": "Azure Entra ID credentials validated successfully.",
            "expires_in": expires_in,
        }

    except HTTPException:
        raise
    except requests.RequestException as e:
        logger.error(f"Network error during Azure AD test connection: {e}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to reach Azure AD. Check network connectivity.",
        )
    except Exception as e:
        logger.error(f"Unexpected error during Azure AD test connection: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to test Azure AD connection: {str(e)}",
        )

@router.get("/{organization_id}/azure-ad/sync/history")
async def get_sync_history(
    organization_id: str,
    limit: int = 10,
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get Azure AD sync history for organization"""
    try:
        # Check organization exists and user has access
        org = db.query(Organization).filter(
            Organization.id == organization_id,
            Organization.deleted_at.is_(None)
        ).first()

        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        _require_org_admin_access(db, current_user.user_id, org)

        # Get sync history
        history = db.query(TenantLDAPSyncHistory).filter(
            TenantLDAPSyncHistory.tenant_id == org.tenant_id,
            TenantLDAPSyncHistory.organization_id == organization_id
        ).order_by(
            TenantLDAPSyncHistory.started_at.desc()
        ).offset(offset).limit(limit).all()

        return {
            "history": [
                {
                    "id": h.id,
                    "sync_type": h.sync_type,
                    "sync_status": h.sync_status,
                    "started_at": h.started_at,
                    "completed_at": h.completed_at,
                    "duration_seconds": h.duration_seconds,
                    "users_added": h.users_added,
                    "users_updated": h.users_updated,
                    "users_removed": h.users_removed,
                    "groups_added": h.groups_added,
                    "groups_updated": h.groups_updated,
                    "error_message": h.error_message,
                    "details": h.details
                }
                for h in history
            ],
            "total": len(history),
            "limit": limit,
            "offset": offset
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get sync history: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get sync history: {str(e)}")

@router.delete("/{organization_id}/azure-ad/config")
async def delete_azure_ad_config(
    organization_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Delete Azure AD configuration for organization"""
    try:
        # Check organization exists and user has access
        org = db.query(Organization).filter(
            Organization.id == organization_id,
            Organization.deleted_at.is_(None)
        ).first()

        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        _require_org_admin_access(db, current_user.user_id, org)

        # Get and delete config
        config = db.query(TenantLDAPConfig).filter(
            TenantLDAPConfig.tenant_id == org.tenant_id,
            TenantLDAPConfig.organization_id == organization_id,
            TenantLDAPConfig.provider_type == "azure_ad_graph"
        ).first()

        if not config:
            raise HTTPException(status_code=404, detail="Azure AD configuration not found")

        # TODO: Clean up stored credentials and role mappings

        db.delete(config)
        await _delete_client_secret(org)
        try:
            keycloak_client = KeycloakClient()
            await keycloak_client.delete_org_microsoft_idp(org.id)
        except Exception as idp_error:
            logger.warning(f"Failed to delete org-scoped Microsoft IdP for org {org.id}: {idp_error}")
        db.commit()

        return {"message": "Azure AD configuration deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete Azure AD config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete Azure AD configuration: {str(e)}")


async def _sync_to_keycloak(
    config: TenantLDAPConfig,
    org: Organization,
    users: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Sync Azure AD users and groups to Keycloak with proper role assignments
    """
    keycloak_client = KeycloakClient()
    results = {
        "users_synced": 0,
        "users_created": 0,
        "users_updated": 0,
        "roles_assigned": 0,
        "errors": []
    }

    try:
        # Get group role mappings from config
        group_role_mappings = config.group_role_mappings or {}

        # Process each user from Azure AD
        for user_data in users:
            try:
                external_id = user_data.get('id')
                email = user_data.get('mail') or user_data.get('userPrincipalName')
                display_name = user_data.get('displayName', '')
                first_name = display_name.split(' ')[0] if display_name else ''
                last_name = ' '.join(display_name.split(' ')[1:]) if len(display_name.split(' ')) > 1 else ''
                enabled = user_data.get('accountEnabled', True)

                if not email:
                    logger.warning(f"Skipping user {external_id}: no email address")
                    continue

                # Check if user already exists in Keycloak
                token = await keycloak_client.get_admin_token()
                async with httpx.AsyncClient() as client:
                    existing_user = await keycloak_client._get_user_by_email(
                        email,
                        token,
                        client
                    )

                # Find user groups from Azure AD and map to roles
                user_groups = []
                app_roles = {}

                # Get user's actual group memberships from Azure AD
                try:
                    # Fetch user's group memberships using Microsoft Graph API
                    client_secret = await _get_client_secret(org)
                    if client_secret:
                        access_token, _ = _get_graph_token(
                            config.graph_tenant_id,
                            config.graph_client_id,
                            client_secret
                        )

                        # Get user's group memberships
                        user_groups_response = _fetch_graph_resource(
                            access_token,
                            f"users/{external_id}/memberOf?$select=id,displayName,securityEnabled"
                        )

                        # Filter for security-enabled groups that are in our role mappings
                        for group_data in user_groups_response:
                            group_id = group_data.get('id')
                            group_name = group_data.get('displayName')

                            if (group_data.get('securityEnabled', True) and
                                group_id in group_role_mappings):
                                user_groups.append({
                                    'id': group_id,
                                    'name': group_name,
                                    'roles': group_role_mappings[group_id]
                                })

                except Exception as e:
                    logger.warning(f"Could not fetch group memberships for user {email}: {e}")
                    # Fallback: if we can't fetch memberships, skip role assignment for this user

                # Build app roles from group mappings
                for user_group in user_groups:
                    for app_name, roles in user_group['roles'].items():
                        if app_name not in app_roles:
                            app_roles[app_name] = []
                        app_roles[app_name].extend(roles)

                # Remove duplicates
                for app_name in app_roles:
                    app_roles[app_name] = list(set(app_roles[app_name]))

                if existing_user:
                    # Update existing user
                    user_id = existing_user['id']

                    # Update user attributes with Azure AD info
                    update_data = {
                        "firstName": first_name,
                        "lastName": last_name,
                        "enabled": enabled,
                        "attributes": {
                            "azure_ad_external_id": [external_id],
                            "azure_ad_provider": ["azure_ad_graph"],
                            "tenant_id": [org.tenant_id],
                            "organization_id": [org.id],
                            "last_azure_sync": [datetime.now(timezone.utc).isoformat()]
                        }
                    }

                    success = await keycloak_client.update_user(user_id, update_data)
                    if success:
                        results["users_updated"] += 1
                        logger.info(f"Updated Keycloak user: {email}")
                    else:
                        results["errors"].append(f"Failed to update user {email}")
                        continue

                else:
                    # Create new user in Keycloak
                    try:
                        user_id = await keycloak_client.create_user_with_tenant(
                            email=email,
                            password=str(uuid.uuid4()),  # Random password - user will reset
                            first_name=first_name,
                            last_name=last_name,
                            tenant_id=org.tenant_id,
                            app_roles={},  # Will assign roles separately
                            org_app_roles=None
                        )

                        # Add Azure AD specific attributes
                        await keycloak_client._update_user_attributes(
                            user_id,
                            {
                                "azure_ad_external_id": [external_id],
                                "azure_ad_provider": ["azure_ad_graph"],
                                "organization_id": [org.id],
                                "last_azure_sync": [datetime.now(timezone.utc).isoformat()],
                                "requires_password_reset": ["true"]  # Force password reset on first login
                            }
                        )

                        results["users_created"] += 1
                        logger.info(f"Created Keycloak user: {email}")

                    except Exception as e:
                        if "already exists" in str(e):
                            logger.warning(f"User {email} already exists, skipping creation")
                            continue
                        else:
                            results["errors"].append(f"Failed to create user {email}: {str(e)}")
                            continue

                # Reconcile app roles (add new + remove stale) for managed apps
                try:
                    token = await keycloak_client.get_admin_token()
                    async with httpx.AsyncClient() as role_client:
                        managed_apps = set()
                        for mapping in (group_role_mappings or {}).values():
                            if isinstance(mapping, dict):
                                managed_apps.update(mapping.keys())
                        # Keep known org-scoped apps under reconciliation to avoid stale role drift.
                        managed_apps.update({"darkhole", "darkfolio", "confiploy"})

                        await keycloak_client._sync_app_roles(
                            user_id=user_id,
                            desired_app_roles=app_roles,
                            managed_apps=list(managed_apps),
                            token=token,
                            client=role_client
                        )

                    results["roles_assigned"] += len([role for roles in app_roles.values() for role in roles])
                    logger.info(f"Synced roles for {email}: {app_roles}")

                except Exception as e:
                    results["errors"].append(f"Failed to sync roles for {email}: {str(e)}")

                results["users_synced"] += 1

            except Exception as e:
                logger.error(f"Failed to sync user {user_data.get('id', 'unknown')}: {e}")
                results["errors"].append(f"User sync error: {str(e)}")

        return results

    except Exception as e:
        logger.error(f"Keycloak sync failed: {e}")
        results["errors"].append(f"General sync error: {str(e)}")
        return results
