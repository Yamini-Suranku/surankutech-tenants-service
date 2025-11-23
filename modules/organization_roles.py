"""Organization user role management endpoints"""
from __future__ import annotations

from typing import List, Dict
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from shared.database import get_db
from shared.auth import TokenData, get_current_token_data
from shared.models import User, UserTenant
from modules.tenant_management import get_or_create_user_from_token
from modules.organization_management import APP_CATALOG, _user_has_tenant_admin_access
from models import Organization, OrganizationUserRole

router = APIRouter(tags=["organization-roles"])

class OrgUserRolePayload(BaseModel):
    user_id: str
    email: str
    first_name: str | None = None
    last_name: str | None = None
    app_roles: Dict[str, List[str]] = Field(default_factory=dict)
    birthright_admin: bool = False

class OrgRoleListResponse(BaseModel):
    organization_id: str
    tenant_id: str
    users: List[OrgUserRolePayload]
    available_apps: List[str]

class OrgRoleUpdateRequest(BaseModel):
    app_roles: Dict[str, List[str]]
    granted_via: str | None = Field(default="manual")


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
    for entry in role_entries:
        role_map.setdefault(entry.user_id, {})[entry.app_name] = entry.roles or []

    payloads: List[OrgUserRolePayload] = []
    for user, user_tenant in tenant_users:
        entry_roles = role_map.get(user.id, {})
        payloads.append(
            OrgUserRolePayload(
                user_id=user.id,
                email=user.email,
                first_name=user.first_name,
                last_name= user.last_name,
                app_roles=entry_roles,
                birthright_admin=_user_has_tenant_admin_access(user_tenant),
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
            else:
                db.add(OrganizationUserRole(
                    tenant_id=tenant_id,
                    organization_id=org_id,
                    user_id=target_user_id,
                    app_name=app_name,
                    roles=normalized_roles,
                    granted_by=actor.user_id,
                    granted_via=payload.granted_via or "manual",
                ))
        elif entry:
            db.delete(entry)

    db.commit()

    new_roles = db.query(OrganizationUserRole).filter(
        OrganizationUserRole.organization_id == org_id,
        OrganizationUserRole.user_id == target_user_id,
    ).all()
    app_roles = {entry.app_name: entry.roles for entry in new_roles}

    return OrgUserRolePayload(
        user_id=target_user_id,
        email=target_user.email,
        first_name=target_user.first_name,
        last_name=target_user.last_name,
        app_roles=app_roles,
        birthright_admin=_user_has_tenant_admin_access(target_membership),
    )
