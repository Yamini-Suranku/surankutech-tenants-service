from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import logging
import uuid

from shared.database import get_db
from models import TenantLDAPConfig, TenantLDAPSyncHistory
from schemas import (
    LDAPConfigCreateRequest,
    LDAPConfigUpdateRequest,
    LDAPConfigResponse,
    LDAPTestConnectionRequest,
    LDAPTestConnectionResponse,
    LDAPSyncTriggerRequest,
    LDAPSyncStatusResponse,
    LDAPSyncHistoryResponse,
    LDAPSyncHistoryListResponse,
    LDAPUserPreviewResponse,
    PaginationInfo
)
from keycloak_client import KeycloakClient
from shared.auth import get_current_user
from shared.credential_manager import get_credential_manager

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/tenants/{tenant_id}/ldap/config", response_model=LDAPConfigResponse)
async def create_ldap_config(
    tenant_id: str,
    config: LDAPConfigCreateRequest,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Create LDAP configuration for tenant"""
    try:
        # Check if LDAP config already exists for this tenant
        existing_config = db.query(TenantLDAPConfig).filter(
            TenantLDAPConfig.tenant_id == tenant_id
        ).first()

        if existing_config:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="LDAP configuration already exists for this tenant. Use PUT to update."
            )

        # Store LDAP credentials in Vault (NOT in database)
        logger.info(f"Storing LDAP credentials in Vault for tenant {tenant_id}")
        credential_manager = get_credential_manager()

        credentials = {
            "bind_dn": config.bind_dn,
            "bind_credential": config.bind_credential
        }

        await credential_manager.store_secret(
            tenant_id=tenant_id,
            service="ldap",
            key_name="credentials",
            secret_data=credentials,
            metadata={
                "configured_at": datetime.utcnow().isoformat(),
                "connection_url": config.connection_url
            }
        )
        logger.info(f"✅ LDAP credentials stored in Vault for tenant {tenant_id}")

        # Create LDAP config in database (without credentials)
        ldap_config = TenantLDAPConfig(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            enabled=config.enabled,
            connection_url=config.connection_url,
            bind_dn=config.bind_dn,  # Store bind_dn for reference, but credential is in Vault
            connection_timeout=config.connection_timeout,
            read_timeout=config.read_timeout,
            use_truststore_spi=config.use_truststore_spi,
            users_dn=config.users_dn,
            user_object_class=config.user_object_class,
            username_ldap_attribute=config.username_ldap_attribute,
            rdn_ldap_attribute=config.rdn_ldap_attribute,
            uuid_ldap_attribute=config.uuid_ldap_attribute,
            user_ldap_filter=config.user_ldap_filter,
            search_scope=config.search_scope,
            email_ldap_attribute=config.email_ldap_attribute,
            first_name_ldap_attribute=config.first_name_ldap_attribute,
            last_name_ldap_attribute=config.last_name_ldap_attribute,
            groups_dn=config.groups_dn,
            group_object_class=config.group_object_class,
            group_name_ldap_attribute=config.group_name_ldap_attribute,
            group_membership_attribute=config.group_membership_attribute,
            group_membership_type=config.group_membership_type,
            sync_registrations=config.sync_registrations,
            import_enabled=config.import_enabled,
            edit_mode=config.edit_mode,
            vendor=config.vendor,
            full_sync_period=config.full_sync_period,
            changed_sync_period=config.changed_sync_period,
            batch_size=config.batch_size,
            created_by=current_user.get("user_id")
        )

        db.add(ldap_config)
        db.flush()

        # Create LDAP federation in Keycloak if enabled
        if config.enabled:
            try:
                keycloak_client = KeycloakClient()

                # Prepare config for Keycloak (with credentials from request)
                config_dict = config.model_dump()

                federation_id, group_mapper_id = await keycloak_client.create_ldap_federation(
                    tenant_id=tenant_id,
                    ldap_config=config_dict
                )

                ldap_config.keycloak_federation_id = federation_id
                ldap_config.keycloak_group_mapper_id = group_mapper_id

                logger.info(f"Created Keycloak LDAP federation {federation_id} for tenant {tenant_id}")

            except Exception as e:
                logger.error(f"Failed to create Keycloak LDAP federation: {e}")
                # Delete credentials from Vault if Keycloak creation fails
                await credential_manager.delete_secret(tenant_id, "ldap", "credentials")
                db.rollback()
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to create LDAP federation in Keycloak: {str(e)}"
                )

        db.commit()
        db.refresh(ldap_config)

        return ldap_config

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"LDAP config creation error: {e}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create LDAP configuration: {str(e)}"
        )


@router.get("/tenants/{tenant_id}/ldap/config", response_model=LDAPConfigResponse)
async def get_ldap_config(
    tenant_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get LDAP configuration for tenant"""
    ldap_config = db.query(TenantLDAPConfig).filter(
        TenantLDAPConfig.tenant_id == tenant_id
    ).first()

    if not ldap_config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="LDAP configuration not found for this tenant"
        )

    return ldap_config


@router.get("/tenants/{tenant_id}/ldap/status")
async def get_ldap_status(
    tenant_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get LDAP/AD authentication status for tenant"""
    ldap_config = db.query(TenantLDAPConfig).filter(
        TenantLDAPConfig.tenant_id == tenant_id
    ).first()

    if not ldap_config:
        # No LDAP configured
        return {
            "type": "ldap",
            "configured": False,
            "enabled": False,
            "status": "not_configured",
            "message": "LDAP/Active Directory not configured"
        }

    # Check if credentials exist in Vault
    credential_manager = get_credential_manager()
    vault_creds = await credential_manager.get_secret(tenant_id, "ldap", "credentials")

    return {
        "type": "ldap",
        "configured": True,
        "enabled": ldap_config.enabled,
        "status": "active" if ldap_config.enabled else "disabled",
        "connection_url": ldap_config.connection_url,
        "bind_dn": ldap_config.bind_dn,
        "users_dn": ldap_config.users_dn,
        "groups_dn": ldap_config.groups_dn,
        "credentials_in_vault": vault_creds is not None,
        "keycloak_federation_id": ldap_config.keycloak_federation_id,
        "last_sync_at": ldap_config.last_sync_at.isoformat() if ldap_config.last_sync_at else None,
        "last_sync_status": ldap_config.last_sync_status,
        "last_sync_users_count": ldap_config.last_sync_users_count,
        "last_sync_groups_count": ldap_config.last_sync_groups_count,
        "last_sync_error": ldap_config.last_sync_error,
        "vendor": ldap_config.vendor,
        "edit_mode": ldap_config.edit_mode,
        "sync_registrations": ldap_config.sync_registrations,
        "import_enabled": ldap_config.import_enabled,
        "created_at": ldap_config.created_at.isoformat() if ldap_config.created_at else None,
        "updated_at": ldap_config.updated_at.isoformat() if ldap_config.updated_at else None
    }


@router.put("/tenants/{tenant_id}/ldap/config", response_model=LDAPConfigResponse)
async def update_ldap_config(
    tenant_id: str,
    config: LDAPConfigUpdateRequest,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Update LDAP configuration for tenant"""
    try:
        ldap_config = db.query(TenantLDAPConfig).filter(
            TenantLDAPConfig.tenant_id == tenant_id
        ).first()

        if not ldap_config:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="LDAP configuration not found for this tenant"
            )

        # Update fields
        update_data = config.model_dump(exclude_unset=True)

        # Update credentials in Vault if provided
        credential_manager = get_credential_manager()
        if "bind_credential" in update_data or "bind_dn" in update_data:
            # Fetch existing credentials from Vault
            existing_vault_creds = await credential_manager.get_secret(tenant_id, "ldap", "credentials") or {}

            # Update with new values
            if "bind_dn" in update_data:
                existing_vault_creds["bind_dn"] = update_data["bind_dn"]
            if "bind_credential" in update_data:
                existing_vault_creds["bind_credential"] = update_data["bind_credential"]

            # Store back to Vault
            await credential_manager.store_secret(
                tenant_id=tenant_id,
                service="ldap",
                key_name="credentials",
                secret_data=existing_vault_creds,
                metadata={
                    "updated_at": datetime.utcnow().isoformat(),
                    "connection_url": ldap_config.connection_url
                }
            )
            logger.info(f"✅ Updated LDAP credentials in Vault for tenant {tenant_id}")

            # Remove credentials from update_data (not stored in database)
            update_data.pop("bind_credential", None)

        # Update database fields (excluding credentials)
        for key, value in update_data.items():
            if key != "bind_credential":  # Don't set credential in database
                setattr(ldap_config, key, value)

        ldap_config.updated_at = datetime.utcnow()

        # Update Keycloak federation if it exists
        if ldap_config.keycloak_federation_id:
            try:
                keycloak_client = KeycloakClient()

                # Get credentials from Vault for Keycloak update
                vault_creds = await credential_manager.get_secret(tenant_id, "ldap", "credentials")
                if vault_creds and "bind_credential" in vault_creds:
                    update_data["bind_credential"] = vault_creds["bind_credential"]

                await keycloak_client.update_ldap_federation(
                    federation_id=ldap_config.keycloak_federation_id,
                    ldap_config=update_data
                )

                logger.info(f"Updated Keycloak LDAP federation {ldap_config.keycloak_federation_id}")

            except Exception as e:
                logger.error(f"Failed to update Keycloak LDAP federation: {e}")
                # Continue with database update even if Keycloak update fails

        db.commit()
        db.refresh(ldap_config)

        return ldap_config

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"LDAP config update error: {e}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update LDAP configuration: {str(e)}"
        )


@router.delete("/tenants/{tenant_id}/ldap/config")
async def delete_ldap_config(
    tenant_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Delete LDAP configuration for tenant"""
    try:
        ldap_config = db.query(TenantLDAPConfig).filter(
            TenantLDAPConfig.tenant_id == tenant_id
        ).first()

        if not ldap_config:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="LDAP configuration not found for this tenant"
            )

        # Delete from Keycloak first
        if ldap_config.keycloak_federation_id:
            try:
                keycloak_client = KeycloakClient()
                await keycloak_client.delete_ldap_federation(
                    federation_id=ldap_config.keycloak_federation_id
                )
                logger.info(f"Deleted Keycloak LDAP federation {ldap_config.keycloak_federation_id}")

            except Exception as e:
                logger.error(f"Failed to delete Keycloak LDAP federation: {e}")
                # Continue with deletions even if Keycloak deletion fails

        # Delete credentials from Vault
        try:
            credential_manager = get_credential_manager()
            await credential_manager.delete_secret(tenant_id, "ldap", "credentials")
            logger.info(f"✅ Deleted LDAP credentials from Vault for tenant {tenant_id}")
        except Exception as e:
            logger.error(f"Failed to delete LDAP credentials from Vault: {e}")
            # Continue with database deletion even if Vault deletion fails

        # Delete from database
        db.delete(ldap_config)
        db.commit()

        return {"message": "LDAP configuration deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"LDAP config deletion error: {e}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete LDAP configuration: {str(e)}"
        )


@router.post("/tenants/{tenant_id}/ldap/test-connection", response_model=LDAPTestConnectionResponse)
async def test_ldap_connection(
    tenant_id: str,
    request: LDAPTestConnectionRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Test LDAP connection without saving configuration"""
    try:
        keycloak_client = KeycloakClient()
        result = await keycloak_client.test_ldap_connection(
            connection_url=request.connection_url,
            bind_dn=request.bind_dn,
            bind_credential=request.bind_credential,
            connection_timeout=request.connection_timeout
        )

        return result

    except Exception as e:
        logger.error(f"LDAP connection test error: {e}")
        return LDAPTestConnectionResponse(
            success=False,
            message=f"Connection test failed: {str(e)}",
            details={"error": str(e)}
        )


@router.post("/tenants/{tenant_id}/ldap/sync", response_model=LDAPSyncHistoryResponse)
async def trigger_ldap_sync(
    tenant_id: str,
    request: LDAPSyncTriggerRequest,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Trigger manual LDAP synchronization"""
    try:
        ldap_config = db.query(TenantLDAPConfig).filter(
            TenantLDAPConfig.tenant_id == tenant_id
        ).first()

        if not ldap_config:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="LDAP configuration not found for this tenant"
            )

        if not ldap_config.enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="LDAP sync is disabled for this tenant"
            )

        if not ldap_config.keycloak_federation_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No Keycloak federation configured"
            )

        # Check if sync is not forced and recently synced
        if not request.force and ldap_config.last_sync_at:
            time_since_sync = datetime.utcnow() - ldap_config.last_sync_at
            if time_since_sync < timedelta(minutes=5):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Sync was performed {int(time_since_sync.total_seconds())} seconds ago. Wait or use force=true."
                )

        # Create sync history entry
        sync_history = TenantLDAPSyncHistory(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            ldap_config_id=ldap_config.id,
            sync_type="manual_" + request.sync_type,
            sync_status="in_progress",
            started_at=datetime.utcnow(),
            triggered_by=current_user.get("user_id")
        )

        db.add(sync_history)
        db.commit()

        # Trigger sync in Keycloak
        try:
            keycloak_client = KeycloakClient()
            sync_type = "triggerFullSync" if request.sync_type == "full" else "triggerChangedUsersSync"

            sync_result = await keycloak_client.trigger_ldap_sync(
                federation_id=ldap_config.keycloak_federation_id,
                sync_type=sync_type
            )

            # Update sync history with results
            sync_history.sync_status = sync_result.get("status", "success")
            sync_history.users_added = sync_result.get("added", 0)
            sync_history.users_updated = sync_result.get("updated", 0)
            sync_history.users_removed = sync_result.get("removed", 0)
            sync_history.completed_at = datetime.utcnow()
            sync_history.duration_seconds = int((sync_history.completed_at - sync_history.started_at).total_seconds())

            # Update LDAP config with last sync info
            ldap_config.last_sync_at = datetime.utcnow()
            ldap_config.last_sync_status = sync_history.sync_status
            ldap_config.last_sync_users_count = sync_result.get("added", 0) + sync_result.get("updated", 0)
            ldap_config.last_sync_error = None

            db.commit()
            db.refresh(sync_history)

            return sync_history

        except Exception as e:
            logger.error(f"LDAP sync failed: {e}")

            # Update sync history with error
            sync_history.sync_status = "failed"
            sync_history.error_message = str(e)
            sync_history.completed_at = datetime.utcnow()
            sync_history.duration_seconds = int((sync_history.completed_at - sync_history.started_at).total_seconds())

            # Update LDAP config
            ldap_config.last_sync_at = datetime.utcnow()
            ldap_config.last_sync_status = "failed"
            ldap_config.last_sync_error = str(e)

            db.commit()
            db.refresh(sync_history)

            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"LDAP sync failed: {str(e)}"
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"LDAP sync trigger error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to trigger LDAP sync: {str(e)}"
        )


@router.get("/tenants/{tenant_id}/ldap/sync/status", response_model=LDAPSyncStatusResponse)
async def get_ldap_sync_status(
    tenant_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get current LDAP sync status"""
    ldap_config = db.query(TenantLDAPConfig).filter(
        TenantLDAPConfig.tenant_id == tenant_id
    ).first()

    if not ldap_config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="LDAP configuration not found for this tenant"
        )

    # Calculate next sync times
    next_full_sync = None
    next_incremental_sync = None

    if ldap_config.last_sync_at:
        next_full_sync = ldap_config.last_sync_at + timedelta(seconds=ldap_config.full_sync_period)
        next_incremental_sync = ldap_config.last_sync_at + timedelta(seconds=ldap_config.changed_sync_period)

    return LDAPSyncStatusResponse(
        is_syncing=False,  # TODO: Implement actual sync status check
        last_sync_at=ldap_config.last_sync_at,
        last_sync_status=ldap_config.last_sync_status,
        last_sync_users_count=ldap_config.last_sync_users_count,
        last_sync_groups_count=ldap_config.last_sync_groups_count,
        last_sync_error=ldap_config.last_sync_error,
        next_full_sync_at=next_full_sync,
        next_incremental_sync_at=next_incremental_sync
    )


@router.get("/tenants/{tenant_id}/ldap/sync/history", response_model=LDAPSyncHistoryListResponse)
async def get_ldap_sync_history(
    tenant_id: str,
    page: int = 1,
    size: int = 20,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get LDAP sync history"""
    ldap_config = db.query(TenantLDAPConfig).filter(
        TenantLDAPConfig.tenant_id == tenant_id
    ).first()

    if not ldap_config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="LDAP configuration not found for this tenant"
        )

    # Get total count
    total = db.query(TenantLDAPSyncHistory).filter(
        TenantLDAPSyncHistory.tenant_id == tenant_id
    ).count()

    # Get paginated history
    history = db.query(TenantLDAPSyncHistory).filter(
        TenantLDAPSyncHistory.tenant_id == tenant_id
    ).order_by(
        TenantLDAPSyncHistory.started_at.desc()
    ).offset((page - 1) * size).limit(size).all()

    return LDAPSyncHistoryListResponse(
        history=history,
        pagination=PaginationInfo(
            page=page,
            size=size,
            total=total,
            pages=(total + size - 1) // size
        )
    )
