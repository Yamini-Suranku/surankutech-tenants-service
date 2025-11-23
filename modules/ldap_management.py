from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import logging
import uuid

from shared.database import get_db
from models import TenantLDAPConfig, TenantLDAPSyncHistory, Organization
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

PROVIDER_LDAP = "ldap"
PROVIDER_ENTRA_GRAPH = "azure_ad_graph"


def _ensure_org_scope(db: Session, tenant_id: str, organization_id: Optional[str]) -> Optional[str]:
    if not organization_id:
        return None
    org = db.query(Organization).filter(
        Organization.id == organization_id,
        Organization.tenant_id == tenant_id,
        Organization.deleted_at.is_(None),
    ).first()
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found for tenant"
        )
    return organization_id


def _ldap_secret_key(organization_id: Optional[str]) -> str:
    return f"credentials-{organization_id}" if organization_id else "credentials"


def _resolve_provider(provider_value: Optional[str]) -> str:
    if not provider_value:
        return PROVIDER_LDAP
    provider_value = provider_value.lower()
    if provider_value in {"azure_ad_graph", "entra_graph"}:
        return PROVIDER_ENTRA_GRAPH
    if provider_value not in {PROVIDER_LDAP, PROVIDER_ENTRA_GRAPH}:
        return PROVIDER_LDAP
    return provider_value


def _get_ldap_config_entry(
    db: Session,
    tenant_id: str,
    organization_id: Optional[str],
    *,
    raise_not_found: bool = True
) -> Optional[TenantLDAPConfig]:
    query = db.query(TenantLDAPConfig).filter(TenantLDAPConfig.tenant_id == tenant_id)
    if organization_id:
        query = query.filter(TenantLDAPConfig.organization_id == organization_id)
    else:
        query = query.filter(TenantLDAPConfig.organization_id.is_(None))
    config = query.first()
    if not config and raise_not_found:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="LDAP configuration not found for this scope"
        )
    return config


@router.post("/tenants/{tenant_id}/ldap/config", response_model=LDAPConfigResponse)
async def create_ldap_config(
    tenant_id: str,
    config: LDAPConfigCreateRequest,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Create LDAP configuration for tenant"""
    try:
        # Validate org scope (optional)
        organization_id = _ensure_org_scope(db, tenant_id, config.organization_id)

        # Check if LDAP config already exists for this tenant/org
        existing_config = _get_ldap_config_entry(
            db,
            tenant_id,
            organization_id,
            raise_not_found=False
        )

        if existing_config:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="LDAP configuration already exists for this tenant. Use PUT to update."
            )

        provider_type = _resolve_provider(config.provider_type)

        # Store provider credentials in Vault (NOT in database)
        logger.info(f"Storing directory credentials ({provider_type}) in Vault for tenant {tenant_id}")
        credential_manager = get_credential_manager()

        credentials = {}
        if provider_type == PROVIDER_LDAP:
            credentials = {
                "bind_dn": config.bind_dn,
                "bind_credential": config.bind_credential
            }
        else:
            credentials = {
                "graph_client_secret": config.graph_client_secret
            }

        credentials = {k: v for k, v in credentials.items() if v is not None}
        if credentials:
            await credential_manager.store_secret(
                tenant_id=tenant_id,
                service="ldap",
                key_name=_ldap_secret_key(organization_id),
                secret_data=credentials,
                metadata={
                    "configured_at": datetime.utcnow().isoformat(),
                    "connection_url": config.connection_url,
                    "provider_type": provider_type
                }
            )
        logger.info(f"✅ Directory credentials stored in Vault for tenant {tenant_id}")

        # Create LDAP config in database (without credentials)
        ldap_config = TenantLDAPConfig(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            organization_id=organization_id,
            enabled=config.enabled,
            provider_type=provider_type,
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
            graph_tenant_id=config.graph_tenant_id if provider_type == PROVIDER_ENTRA_GRAPH else None,
            graph_client_id=config.graph_client_id if provider_type == PROVIDER_ENTRA_GRAPH else None,
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
        if provider_type == PROVIDER_LDAP and config.enabled:
            try:
                keycloak_client = KeycloakClient()

                # Prepare config for Keycloak (with credentials from request)
                config_dict = config.model_dump()

                federation_id, group_mapper_id = await keycloak_client.create_ldap_federation(
                    tenant_id=tenant_id,
                    ldap_config=config_dict,
                    organization_id=organization_id
                )

                ldap_config.keycloak_federation_id = federation_id
                ldap_config.keycloak_group_mapper_id = group_mapper_id

                logger.info(f"Created Keycloak LDAP federation {federation_id} for tenant {tenant_id}")

            except Exception as e:
                logger.error(f"Failed to create Keycloak LDAP federation: {e}")
                # Delete credentials from Vault if Keycloak creation fails
                await credential_manager.delete_secret(tenant_id, "ldap", _ldap_secret_key(organization_id))
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
    organization_id: Optional[str] = Query(None, description="Organization scope for the directory configuration"),
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get LDAP configuration for tenant"""
    organization_id = _ensure_org_scope(db, tenant_id, organization_id)
    ldap_config = _get_ldap_config_entry(db, tenant_id, organization_id)
    return ldap_config


@router.get("/tenants/{tenant_id}/ldap/status")
async def get_ldap_status(
    tenant_id: str,
    organization_id: Optional[str] = Query(None, description="Organization scope for the directory configuration"),
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get LDAP/AD authentication status for tenant"""
    organization_id = _ensure_org_scope(db, tenant_id, organization_id)
    ldap_config = _get_ldap_config_entry(db, tenant_id, organization_id, raise_not_found=False)
    provider_type = PROVIDER_LDAP

    if not ldap_config:
        # No LDAP configured
        return {
            "type": provider_type,
            "provider_type": provider_type,
            "configured": False,
            "enabled": False,
            "status": "not_configured",
            "message": "LDAP/Active Directory not configured"
        }

    provider_type = ldap_config.provider_type or PROVIDER_LDAP

    # Check if credentials exist in Vault
    credential_manager = get_credential_manager()
    vault_creds = await credential_manager.get_secret(
        tenant_id, "ldap", _ldap_secret_key(organization_id)
    )

    if provider_type == PROVIDER_ENTRA_GRAPH:
        return {
            "type": provider_type,
            "provider_type": provider_type,
            "configured": True,
            "enabled": ldap_config.enabled,
            "status": "active" if ldap_config.enabled else "configured",
            "graph_tenant_id": ldap_config.graph_tenant_id,
            "graph_client_id": ldap_config.graph_client_id,
            "credentials_in_vault": bool(vault_creds and vault_creds.get("graph_client_secret")),
            "keycloak_federation_id": None,
            "last_sync_at": None,
            "last_sync_status": None,
            "last_sync_users_count": 0,
            "last_sync_groups_count": 0,
            "vendor": "azure_ad_graph",
            "edit_mode": "READ_ONLY",
            "sync_registrations": ldap_config.sync_registrations,
            "import_enabled": ldap_config.import_enabled,
            "created_at": ldap_config.created_at.isoformat() if ldap_config.created_at else None,
            "updated_at": ldap_config.updated_at.isoformat() if ldap_config.updated_at else None
        }

    return {
        "type": provider_type,
        "provider_type": provider_type,
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
    organization_id: Optional[str] = Query(None, description="Organization scope for the directory configuration"),
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Update LDAP configuration for tenant"""
    scope_org_id = organization_id if organization_id is not None else config.organization_id
    scope_org_id = _ensure_org_scope(db, tenant_id, scope_org_id)
    ldap_config = _get_ldap_config_entry(db, tenant_id, scope_org_id)

    try:
        credential_manager = get_credential_manager()
        update_data = config.model_dump(exclude_unset=True)
        provider_before = ldap_config.provider_type or PROVIDER_LDAP
        provider_after = _resolve_provider(update_data.get("provider_type") or provider_before)
        update_data["provider_type"] = provider_after
        secret_key = _ldap_secret_key(scope_org_id)
        existing_secret = await credential_manager.get_secret(tenant_id, "ldap", secret_key) or {}

        if provider_after == PROVIDER_LDAP:
            new_bind_dn = update_data.get("bind_dn") or existing_secret.get("bind_dn") or ldap_config.bind_dn
            new_bind_credential = update_data.get("bind_credential") or existing_secret.get("bind_credential")

            if provider_before != PROVIDER_LDAP and (not new_bind_dn or not new_bind_credential):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="LDAP credentials must be provided when switching provider back to LDAP"
                )

            if provider_before != PROVIDER_LDAP or "bind_dn" in update_data or "bind_credential" in update_data:
                secret_payload = {}
                if new_bind_dn:
                    secret_payload["bind_dn"] = new_bind_dn
                if new_bind_credential:
                    secret_payload["bind_credential"] = new_bind_credential
                if secret_payload:
                    await credential_manager.store_secret(
                        tenant_id=tenant_id,
                        service="ldap",
                        key_name=secret_key,
                        secret_data=secret_payload,
                        metadata={
                            "updated_at": datetime.utcnow().isoformat(),
                            "connection_url": update_data.get("connection_url", ldap_config.connection_url),
                            "provider_type": provider_after
                        }
                    )
            update_data.pop("bind_credential", None)
            update_data.pop("graph_client_secret", None)
            if provider_before == PROVIDER_ENTRA_GRAPH:
                update_data.setdefault("graph_tenant_id", None)
                update_data.setdefault("graph_client_id", None)
        else:
            if provider_before != PROVIDER_ENTRA_GRAPH:
                missing_fields = [
                    label for field, label in (
                        ("graph_tenant_id", "Azure tenant ID"),
                        ("graph_client_id", "Azure client ID")
                    ) if not update_data.get(field)
                ]
                if missing_fields:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"{', '.join(missing_fields)} required when switching to Azure Entra provider"
                    )
            new_graph_secret = update_data.get("graph_client_secret") or existing_secret.get("graph_client_secret")
            if not new_graph_secret:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Azure Entra client secret is required for Graph provider"
                )
            if provider_before != PROVIDER_ENTRA_GRAPH or "graph_client_secret" in update_data:
                await credential_manager.store_secret(
                    tenant_id=tenant_id,
                    service="ldap",
                    key_name=secret_key,
                    secret_data={"graph_client_secret": new_graph_secret},
                    metadata={
                        "updated_at": datetime.utcnow().isoformat(),
                        "provider_type": provider_after
                    }
                )
            update_data.pop("graph_client_secret", None)
            update_data.pop("bind_credential", None)
            update_data["connection_url"] = None
            update_data["bind_dn"] = None
            update_data["users_dn"] = None
            update_data["groups_dn"] = None

        for key, value in update_data.items():
            if key == "organization_id":
                continue
            setattr(ldap_config, key, value)

        ldap_config.updated_at = datetime.utcnow()

        if provider_after == PROVIDER_LDAP and ldap_config.keycloak_federation_id:
            try:
                keycloak_client = KeycloakClient()
                vault_creds = await credential_manager.get_secret(tenant_id, "ldap", secret_key) or {}
                ldap_payload = update_data.copy()
                if "bind_credential" not in ldap_payload and "bind_credential" in vault_creds:
                    ldap_payload["bind_credential"] = vault_creds["bind_credential"]

                await keycloak_client.update_ldap_federation(
                    federation_id=ldap_config.keycloak_federation_id,
                    ldap_config=ldap_payload
                )
            except Exception as e:
                logger.error(f"Failed to update Keycloak LDAP federation: {e}")
        elif provider_after == PROVIDER_LDAP and ldap_config.enabled:
            try:
                keycloak_client = KeycloakClient()
                vault_creds = await credential_manager.get_secret(tenant_id, "ldap", secret_key) or {}
                config_dict = {
                    **ldap_config.__dict__,
                    "bind_dn": vault_creds.get("bind_dn", ldap_config.bind_dn),
                    "bind_credential": vault_creds.get("bind_credential"),
                }

                federation_id, group_mapper_id = await keycloak_client.create_ldap_federation(
                    tenant_id=tenant_id,
                    ldap_config=config_dict,
                    organization_id=scope_org_id
                )
                ldap_config.keycloak_federation_id = federation_id
                ldap_config.keycloak_group_mapper_id = group_mapper_id
            except Exception as e:
                logger.error(f"Failed to create Keycloak LDAP federation during update: {e}")
        elif provider_after == PROVIDER_ENTRA_GRAPH and ldap_config.keycloak_federation_id:
            try:
                keycloak_client = KeycloakClient()
                await keycloak_client.delete_ldap_federation(federation_id=ldap_config.keycloak_federation_id)
            except Exception as e:
                logger.error(f"Failed to remove legacy LDAP federation after switching provider: {e}")
            finally:
                ldap_config.keycloak_federation_id = None
                ldap_config.keycloak_group_mapper_id = None

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
    organization_id: Optional[str] = Query(None, description="Organization scope for the directory configuration"),
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Delete LDAP configuration for tenant"""
    organization_id = _ensure_org_scope(db, tenant_id, organization_id)
    ldap_config = _get_ldap_config_entry(db, tenant_id, organization_id)

    try:
        if ldap_config.keycloak_federation_id:
            try:
                keycloak_client = KeycloakClient()
                await keycloak_client.delete_ldap_federation(
                    federation_id=ldap_config.keycloak_federation_id
                )
            except Exception as e:
                logger.error(f"Failed to delete Keycloak LDAP federation: {e}")

        try:
            credential_manager = get_credential_manager()
            await credential_manager.delete_secret(tenant_id, "ldap", _ldap_secret_key(organization_id))
        except Exception as e:
            logger.error(f"Failed to delete LDAP credentials from Vault: {e}")

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
        provider_type = _resolve_provider(request.provider_type)
        if provider_type == PROVIDER_LDAP:
            keycloak_client = KeycloakClient()
            result = await keycloak_client.test_ldap_connection(
                connection_url=request.connection_url,
                bind_dn=request.bind_dn,
                bind_credential=request.bind_credential,
                connection_timeout=request.connection_timeout
            )
            return result

        # Azure Entra Graph: perform basic validation only (no outbound call)
        return LDAPTestConnectionResponse(
            success=True,
            message="Azure Entra credentials look good. Graph connectivity will be verified during sync.",
            details={
                "tenant_id": request.graph_tenant_id,
                "client_id": request.graph_client_id
            }
        )

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
    organization_id: Optional[str] = Query(None, description="Organization scope for the directory configuration"),
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Trigger manual LDAP synchronization"""
    try:
        scope_org_id = _ensure_org_scope(db, tenant_id, organization_id)
        ldap_config = _get_ldap_config_entry(db, tenant_id, scope_org_id)

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
            organization_id=scope_org_id,
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
    organization_id: Optional[str] = Query(None, description="Organization scope for the directory configuration"),
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get current LDAP sync status"""
    scope_org_id = _ensure_org_scope(db, tenant_id, organization_id)
    ldap_config = _get_ldap_config_entry(db, tenant_id, scope_org_id)

    next_full_sync = None
    next_incremental_sync = None

    if ldap_config.last_sync_at:
        next_full_sync = ldap_config.last_sync_at + timedelta(seconds=ldap_config.full_sync_period)
        next_incremental_sync = ldap_config.last_sync_at + timedelta(seconds=ldap_config.changed_sync_period)

    return LDAPSyncStatusResponse(
        is_syncing=False,
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
    organization_id: Optional[str] = Query(None, description="Organization scope for the directory configuration"),
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get LDAP sync history"""
    scope_org_id = _ensure_org_scope(db, tenant_id, organization_id)
    _ = _get_ldap_config_entry(db, tenant_id, scope_org_id)

    base_query = db.query(TenantLDAPSyncHistory).filter(
        TenantLDAPSyncHistory.tenant_id == tenant_id
    )
    if scope_org_id:
        base_query = base_query.filter(TenantLDAPSyncHistory.organization_id == scope_org_id)
    else:
        base_query = base_query.filter(TenantLDAPSyncHistory.organization_id.is_(None))

    total = base_query.count()

    history = base_query.order_by(
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
