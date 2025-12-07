"""Organization user role management endpoints"""
from __future__ import annotations

from typing import List, Dict, Optional, Any
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import and_
from datetime import datetime
import logging

from shared.database import get_db
from shared.auth import TokenData, get_current_token_data
from shared.models import User, UserTenant
from modules.tenant_management import get_or_create_user_from_token
from modules.organization_management import APP_CATALOG, _user_has_tenant_admin_access
from models import Organization, OrganizationUserRole, TenantLDAPSyncHistory

router = APIRouter(tags=["organization-roles"])
logger = logging.getLogger(__name__)

class DirectorySyncBatchInfo(BaseModel):
    id: str
    sync_type: Optional[str] = None
    provider: Optional[str] = None
    synced_at: Optional[str] = None
    total_users: Optional[int] = None
    total_groups: Optional[int] = None

class OrgUserRolePayload(BaseModel):
    user_id: str
    email: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    app_roles: Dict[str, List[str]] = Field(default_factory=dict)
    birthright_admin: bool = False
    membership_source: str = Field(default="manual")
    directory_synced: bool = False
    last_sync_batch: Optional[DirectorySyncBatchInfo] = None

class OrgRoleListResponse(BaseModel):
    organization_id: str
    tenant_id: str
    users: List[OrgUserRolePayload]
    available_apps: List[str]

class OrgRoleUpdateRequest(BaseModel):
    app_roles: Dict[str, List[str]]
    granted_via: Optional[str] = Field(default="manual")


def _history_sort_key(history: Optional[TenantLDAPSyncHistory]) -> datetime:
    if not history:
        return datetime.min
    return history.completed_at or history.started_at or datetime.min


def _to_batch_info(history: Optional[TenantLDAPSyncHistory]) -> Optional[DirectorySyncBatchInfo]:
    if not history:
        return None
    return DirectorySyncBatchInfo(
        id=history.id,
        sync_type=history.sync_type,
        status=history.sync_status,
        started_at=history.started_at,
        completed_at=history.completed_at,
    )


def _require_tenant_admin(db: Session, tenant_id: str, token_data: TokenData) -> UserTenant:
    user = get_or_create_user_from_token(db, token_data)
    user_tenant = db.query(UserTenant).filter(
        UserTenant.user_id == user.id,
        UserTenant.tenant_id == tenant_id,
    ).first()
    if not user_tenant or not _user_has_tenant_admin_access(user_tenant):
        raise HTTPException(status_code=403, detail="Tenant admin access required")
    return user_tenant

@router.get("/tenants/{tenant_id}/orgs/{org_id}/roles", response_model=OrgRoleListResponse)
async def list_org_roles(
    tenant_id: str,
    org_id: str,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db),
):
    _require_tenant_admin(db, tenant_id, token_data)

    org = db.query(Organization).filter(
        Organization.id == org_id,
        Organization.tenant_id == tenant_id,
        Organization.deleted_at.is_(None),
    ).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    tenant_users = db.query(User, UserTenant).join(
        UserTenant, UserTenant.user_id == User.id
    ).filter(
        UserTenant.tenant_id == tenant_id,
    ).all()

    role_entries = db.query(OrganizationUserRole).filter(
        OrganizationUserRole.organization_id == org_id,
    ).all()

    role_map: Dict[str, Dict[str, List[str]]] = {}
    user_meta: Dict[str, Dict[str, Any]] = {}

    batch_ids = {entry.sync_batch_id for entry in role_entries if entry.sync_batch_id}
    history_map: Dict[str, TenantLDAPSyncHistory] = {}
    if batch_ids:
        histories = db.query(TenantLDAPSyncHistory).filter(
            TenantLDAPSyncHistory.id.in_(batch_ids)
        ).all()
        history_map = {history.id: history for history in histories}

    for entry in role_entries:
        role_map.setdefault(entry.user_id, {})[entry.app_name] = entry.roles or []

        meta = user_meta.setdefault(entry.user_id, {
            "directory_synced": False,
            "membership_source": "manual",
            "latest_history": None,
        })

        entry_source = entry.granted_via or "manual"
        if entry_source in {"directory_sync", "directory_to_platform"}:
            meta["directory_synced"] = True
            meta["membership_source"] = "directory_sync"
        elif meta["membership_source"] != "directory_sync":
            meta["membership_source"] = entry_source

        if entry.sync_batch_id:
            history = history_map.get(entry.sync_batch_id)
            if history:
                existing = meta.get("latest_history")
                if not existing or _history_sort_key(history) >= _history_sort_key(existing):
                    meta["latest_history"] = history

    payloads: List[OrgUserRolePayload] = []
    for user, user_tenant in tenant_users:
        entry_roles = role_map.get(user.id, {})
        meta = user_meta.get(user.id, {
            "directory_synced": False,
            "membership_source": "manual",
            "latest_history": None,
        })
        payloads.append(
            OrgUserRolePayload(
                user_id=user.id,
                email=user.email,
                first_name=user.first_name,
                last_name= user.last_name,
                app_roles=entry_roles,
                birthright_admin=_user_has_tenant_admin_access(user_tenant),
                membership_source=meta.get("membership_source") or "manual",
                directory_synced=bool(meta.get("directory_synced")),
                last_sync_batch=_to_batch_info(meta.get("latest_history")),
            )
        )

    return OrgRoleListResponse(
        organization_id=org_id,
        tenant_id=tenant_id,
        users=payloads,
        available_apps=list(APP_CATALOG.keys()),
    )

@router.put("/tenants/{tenant_id}/orgs/{org_id}/users/{target_user_id}/roles", response_model=OrgUserRolePayload)
async def update_org_roles(
    tenant_id: str,
    org_id: str,
    target_user_id: str,
    payload: OrgRoleUpdateRequest,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db),
):
    actor = _require_tenant_admin(db, tenant_id, token_data)

    org = db.query(Organization).filter(
        Organization.id == org_id,
        Organization.tenant_id == tenant_id,
        Organization.deleted_at.is_(None),
    ).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    target_user = db.query(User).filter(User.id == target_user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    target_membership = db.query(UserTenant).filter(
        UserTenant.user_id == target_user_id,
        UserTenant.tenant_id == tenant_id,
    ).first()
    if not target_membership:
        raise HTTPException(status_code=400, detail="User does not belong to tenant")

    valid_apps = set(APP_CATALOG.keys())
    for app in payload.app_roles.keys():
        if app not in valid_apps:
            raise HTTPException(status_code=400, detail=f"Unsupported app: {app}")

    existing = db.query(OrganizationUserRole).filter(
        OrganizationUserRole.organization_id == org_id,
        OrganizationUserRole.user_id == target_user_id,
    ).all()
    existing_map = {(entry.app_name): entry for entry in existing}

    for app_name, roles in payload.app_roles.items():
        normalized_roles = sorted(set(roles))
        entry = existing_map.get(app_name)
        if normalized_roles:
            if entry:
                entry.roles = normalized_roles
                entry.granted_by = actor.user_id
                entry.granted_via = payload.granted_via or entry.granted_via
                if (payload.granted_via or "manual") != "directory_sync":
                    entry.sync_batch_id = None
            else:
                db.add(OrganizationUserRole(
                    tenant_id=tenant_id,
                    organization_id=org_id,
                    user_id=target_user_id,
                    app_name=app_name,
                    roles=normalized_roles,
                    granted_by=actor.user_id,
                    granted_via=payload.granted_via or "manual",
                    sync_batch_id=None,
                ))
        elif entry:
            db.delete(entry)

    db.commit()

    new_roles = db.query(OrganizationUserRole).filter(
        OrganizationUserRole.organization_id == org_id,
        OrganizationUserRole.user_id == target_user_id,
    ).all()
    app_roles = {entry.app_name: (entry.roles or []) for entry in new_roles}

    directory_synced = any(
        (entry.granted_via or "").startswith("directory")
        for entry in new_roles
    )
    membership_source = "directory_sync" if directory_synced else (payload.granted_via or "manual")

    batch_ids = {entry.sync_batch_id for entry in new_roles if entry.sync_batch_id}
    last_sync_batch = None
    if batch_ids:
        histories = db.query(TenantLDAPSyncHistory).filter(
            TenantLDAPSyncHistory.id.in_(batch_ids)
        ).all()
        if histories:
            latest = max(histories, key=_history_sort_key)
            last_sync_batch = _to_batch_info(latest)

    return OrgUserRolePayload(
        user_id=target_user_id,
        email=target_user.email,
        first_name=target_user.first_name,
        last_name=target_user.last_name,
        app_roles=app_roles,
        birthright_admin=_user_has_tenant_admin_access(target_membership),
        membership_source=membership_source,
        directory_synced=directory_synced,
        last_sync_batch=last_sync_batch,
    )


@router.get("/auth/user-org-roles")
async def get_user_org_roles_for_keycloak(
    user_email: str,
    org_subdomain: str,
    tenant_id: str,
    db: Session = Depends(get_db),
):
    """
    Get user's org-scoped roles for Keycloak token generation.
    Called by Keycloak mappers to populate org-specific app_roles in JWT.

    Example: palls.local.suranku → only roles for 'palls' organization
    """
    try:
        # Find user by email
        user = db.query(User).filter(User.email == user_email).first()
        if not user:
            return {"app_roles": {}, "error": "User not found"}

        # Find organization by subdomain and tenant
        organization = db.query(Organization).filter(
            and_(
                Organization.dns_subdomain == org_subdomain,
                Organization.tenant_id == tenant_id,
                Organization.deleted_at.is_(None)
            )
        ).first()

        if not organization:
            return {"app_roles": {}, "error": "Organization not found"}

        # Get user's roles for this specific organization
        org_roles = db.query(OrganizationUserRole).filter(
            and_(
                OrganizationUserRole.user_id == user.id,
                OrganizationUserRole.organization_id == organization.id
            )
        ).all()

        # Build app_roles dict for this org only
        app_roles = {}
        for role_entry in org_roles:
            app_roles[role_entry.app_name] = role_entry.roles or []

        # Always include platform role for basic access
        if "platform" not in app_roles:
            app_roles["platform"] = ["user"]

        # Check if user has tenant admin access (for birthright admin)
        user_tenant = db.query(UserTenant).filter(
            and_(
                UserTenant.user_id == user.id,
                UserTenant.tenant_id == tenant_id
            )
        ).first()

        # Add tenant_admin role if user has birthright admin AND non-directory roles
        has_invited_roles = any(
            entry.granted_via in ["invitation", "manual", "birthright"]
            for entry in org_roles
        )

        if (has_invited_roles and
            user_tenant and
            _user_has_tenant_admin_access(user_tenant)):
            app_roles["platform"] = list(set(app_roles.get("platform", []) + ["tenant_admin"]))

        return {
            "app_roles": app_roles,
            "organization_id": organization.id,
            "organization_name": organization.name,
            "dns_subdomain": org_subdomain
        }

    except Exception as e:
        logger.error(f"Error getting org roles for {user_email} in {org_subdomain}: {e}")
        return {"app_roles": {"platform": ["user"]}, "error": str(e)}
