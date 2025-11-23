"""
DarkHole Proxy Module
Exposes DarkHole management endpoints (roles, permissions) through tenants-service
so tenant admins can manage org-level settings from the platform.
"""
from __future__ import annotations

import os
import logging
from typing import Dict, Any, Optional, List

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from shared.database import get_db
from shared.auth import TokenData, get_current_token_data
from shared.models import UserTenant
from modules.tenant_management import get_or_create_user_from_token
from modules.organization_management import DEFAULT_DNS_ZONE
from models import Organization, Tenant

logger = logging.getLogger(__name__)

router = APIRouter(tags=["darkhole-management"])

DARKHOLE_SERVICE_URL = os.getenv(
    "DARKHOLE_SERVICE_URL",
    "http://darkhole-api.darkhole.svc.cluster.local"
).rstrip("/")


class RoleCreateRequest(BaseModel):
    name: str
    description: Optional[str] = None
    permissions: Optional[List[str]] = []


class RolePermissionsRequest(BaseModel):
    permissions: Dict[str, Any]


class OrgInviteRequest(BaseModel):
    email: str
    full_name: Optional[str] = None
    message: Optional[str] = None
    app_roles: Dict[str, Any]
    metadata: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"


@router.get("/tenants/{tenant_id}/orgs/{org_id}/apps/darkhole/roles")
async def list_darkhole_roles(
    tenant_id: str,
    org_id: str,
    request: Request,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db),
):
    org, _ = _validate_access(db, tenant_id, org_id, token_data)
    return await _proxy_darkhole(org, request, "GET", "/roles")


@router.post("/tenants/{tenant_id}/orgs/{org_id}/apps/darkhole/roles")
async def create_darkhole_role(
    tenant_id: str,
    org_id: str,
    payload: RoleCreateRequest,
    request: Request,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db),
):
    org, _ = _validate_access(db, tenant_id, org_id, token_data, require_admin=True)
    return await _proxy_darkhole(org, request, "POST", "/roles", json=payload.dict())


@router.put("/tenants/{tenant_id}/orgs/{org_id}/apps/darkhole/roles/{role_id}/permissions")
async def update_darkhole_role_permissions(
    tenant_id: str,
    org_id: str,
    role_id: str,
    payload: RolePermissionsRequest,
    request: Request,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db),
):
    org, _ = _validate_access(db, tenant_id, org_id, token_data, require_admin=True)
    path = f"/roles/{role_id}/permissions"
    return await _proxy_darkhole(org, request, "PUT", path, json=payload.dict())


@router.get("/tenants/{tenant_id}/orgs/{org_id}/apps/darkhole/users")
async def list_darkhole_users(
    tenant_id: str,
    org_id: str,
    request: Request,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db),
):
    """List DarkHole users for an org through tenants-service."""
    org, _ = _validate_access(db, tenant_id, org_id, token_data, require_admin=True)
    return await _proxy_darkhole(org, request, "GET", "/org-admin/users")


@router.get("/tenants/{tenant_id}/orgs/{org_id}/apps/darkhole/invitations")
async def list_darkhole_invitations(
    tenant_id: str,
    org_id: str,
    request: Request,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db),
):
    org, _ = _validate_access(db, tenant_id, org_id, token_data, require_admin=True)
    return await _proxy_darkhole(org, request, "GET", "/org-admin/invitations")


@router.post("/tenants/{tenant_id}/orgs/{org_id}/apps/darkhole/invitations")
async def create_darkhole_invitation(
    tenant_id: str,
    org_id: str,
    payload: OrgInviteRequest,
    request: Request,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db),
):
    org, _ = _validate_access(db, tenant_id, org_id, token_data, require_admin=True)
    return await _proxy_darkhole(
        org,
        request,
        "POST",
        "/org-admin/invitations",
        json=payload.dict(exclude_none=True),
    )


@router.post("/tenants/{tenant_id}/orgs/{org_id}/apps/darkhole/invitations/{invitation_id}/resend")
async def resend_darkhole_invitation(
    tenant_id: str,
    org_id: str,
    invitation_id: str,
    request: Request,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db),
):
    org, _ = _validate_access(db, tenant_id, org_id, token_data, require_admin=True)
    path = f"/org-admin/invitations/{invitation_id}/resend"
    return await _proxy_darkhole(org, request, "POST", path)


@router.delete("/tenants/{tenant_id}/orgs/{org_id}/apps/darkhole/invitations/{invitation_id}")
async def cancel_darkhole_invitation(
    tenant_id: str,
    org_id: str,
    invitation_id: str,
    request: Request,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db),
):
    org, _ = _validate_access(db, tenant_id, org_id, token_data, require_admin=True)
    path = f"/org-admin/invitations/{invitation_id}"
    return await _proxy_darkhole(org, request, "DELETE", path)


def _validate_access(
    db: Session,
    tenant_id: str,
    org_id: str,
    token_data: TokenData,
    require_admin: bool = False,
) -> tuple[Organization, UserTenant]:
    """Ensure user belongs to tenant/org and (optionally) has admin role."""
    user = get_or_create_user_from_token(db, token_data)
    user_tenant = db.query(UserTenant).filter(
        UserTenant.user_id == user.id,
        UserTenant.tenant_id == tenant_id,
    ).first()
    if not user_tenant:
        raise HTTPException(status_code=403, detail="Access denied to tenant")

    org = db.query(Organization).filter(
        Organization.id == org_id,
        Organization.tenant_id == tenant_id,
        Organization.deleted_at.is_(None),
    ).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    if require_admin and not _has_darkhole_admin(user_tenant):
        raise HTTPException(status_code=403, detail="DarkHole admin role required")

    return org, user_tenant


def _has_darkhole_admin(user_tenant: UserTenant) -> bool:
    roles = (user_tenant.app_roles or {}).get("darkhole", [])
    return any(role in {"admin", "administrator"} for role in roles)


def _build_org_hostname(org: Organization) -> str:
    if org.dns_hostname:
        return org.dns_hostname
    zone = org.dns_zone or DEFAULT_DNS_ZONE
    if org.dns_subdomain:
        return f"{org.dns_subdomain}.{zone}"
    # Fallback to slug if subdomain missing
    return f"{org.slug}.{zone}"


async def _proxy_darkhole(
    org: Organization,
    request: Request,
    method: str,
    path: str,
    json: Optional[Dict[str, Any]] = None,
    params: Optional[Dict[str, Any]] = None,
) -> Any:
    """Forward request to DarkHole service with org-specific Host header."""
    url = f"{DARKHOLE_SERVICE_URL}{path}"
    headers = {}
    auth_header = request.headers.get("Authorization")
    if auth_header:
        headers["Authorization"] = auth_header
    headers["Host"] = _build_org_hostname(org)

    logger.debug("Proxying DarkHole request %s %s for host %s", method, path, headers["Host"])

    try:
        query_params = params if params is not None else dict(request.query_params)
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.request(
                method,
                url,
                headers=headers,
                json=json,
                params=query_params or None,
            )
    except Exception as exc:
        logger.error("DarkHole proxy error: %s", exc)
        raise HTTPException(status_code=502, detail="DarkHole service unreachable")

    if response.status_code >= 400:
        logger.warning(
            "DarkHole proxy %s %s failed [%s]: %s",
            method,
            path,
            response.status_code,
            response.text,
        )
        raise HTTPException(status_code=response.status_code, detail=response.text)

    # Return JSON content if available, else raw text
    if response.headers.get("content-type", "").startswith("application/json"):
        return response.json()
    return response.text
