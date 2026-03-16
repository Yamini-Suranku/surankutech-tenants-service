"""
Audit event ingestion endpoints.
Accepts authenticated app/user events and persists to shared audit_logs in tenant-service DB.
"""

from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from shared.auth import TokenData, get_current_token_data
from shared.database import get_db
from shared.models import AuditLog, Tenant, User
from models import Organization
from schemas import AuditLogResponse, AuditLogSearchRequest

import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/audit", tags=["audit-events"])


class AuditEventIngestRequest(BaseModel):
    action: str = Field(..., min_length=1, max_length=100)
    resource_type: str = Field(..., min_length=1, max_length=50)
    resource_id: Optional[str] = Field(None, max_length=64)
    app_name: Optional[str] = Field(None, max_length=50)
    tenant_id: Optional[str] = Field(None, max_length=36)
    org_id: Optional[str] = Field(None, max_length=36)
    org_slug: Optional[str] = Field(None, max_length=255)
    details: Dict[str, Any] = Field(default_factory=dict)
    ip_address: Optional[str] = Field(None, max_length=64)
    user_agent: Optional[str] = None


class AuditEventIngestResponse(BaseModel):
    success: bool
    audit_log_id: str
    tenant_id: str
    organization_id: Optional[str] = None
    user_id: str
    created_at: datetime


def _token_has_org_access(token_data: TokenData, org_id: str) -> bool:
    current_org = getattr(token_data, "current_org", None)
    if isinstance(current_org, dict):
        current_org_id = current_org.get("org_id") or current_org.get("organization_id") or current_org.get("id")
        if current_org_id and str(current_org_id) == str(org_id):
            return True

    memberships = getattr(token_data, "org_memberships", None) or []
    if isinstance(memberships, list):
        for membership in memberships:
            if not isinstance(membership, dict):
                continue
            membership_org_id = membership.get("org_id") or membership.get("organization_id") or membership.get("id")
            if membership_org_id and str(membership_org_id) == str(org_id):
                return True
    return False


def _serialize_audit_log(row: AuditLog, db: Session) -> AuditLogResponse:
    user_email = ""
    if row.user_id:
        user = db.query(User).filter(User.id == row.user_id).first()
        if user and user.email:
            user_email = user.email
    return AuditLogResponse(
        id=row.id,
        organization_id=row.organization_id,
        action=row.action,
        resource_type=row.resource_type or "",
        resource_id=row.resource_id or "",
        user_id=row.user_id or "",
        user_email=user_email,
        ip_address=row.ip_address,
        user_agent=row.user_agent,
        details=row.details or {},
        created_at=row.created_at,
    )


def _resolve_tenant_id(
    db: Session,
    token_data: TokenData,
    req: AuditEventIngestRequest,
) -> str:
    if req.tenant_id:
        tenant = db.query(Tenant).filter(Tenant.id == req.tenant_id).first()
        if tenant:
            return tenant.id

    if req.org_id:
        org = db.query(Organization).filter(Organization.id == req.org_id).first()
        if org and org.tenant_id:
            return org.tenant_id

    if req.org_slug:
        org = db.query(Organization).filter(Organization.slug == req.org_slug).first()
        if org and org.tenant_id:
            return org.tenant_id

    current_org = getattr(token_data, "current_org", None)
    if isinstance(current_org, dict):
        tenant_id = current_org.get("tenant_id") or current_org.get("tenantId")
        if tenant_id:
            tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
            if tenant:
                return tenant.id

    memberships = getattr(token_data, "org_memberships", None) or []
    if isinstance(memberships, list):
        for membership in memberships:
            if not isinstance(membership, dict):
                continue
            tenant_id = membership.get("tenant_id") or membership.get("tenantId")
            if not tenant_id:
                continue
            tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
            if tenant:
                return tenant.id

    raise HTTPException(status_code=400, detail="Unable to resolve tenant_id for audit event")


def _resolve_user(db: Session, token_data: TokenData) -> User:
    user = db.query(User).filter(User.keycloak_id == token_data.sub).first()
    if not user and token_data.email:
        user = db.query(User).filter(
            func.lower(User.email) == token_data.email.strip().lower()
        ).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found in tenant service")
    return user


@router.post("/events", response_model=AuditEventIngestResponse)
async def ingest_audit_event(
    request: AuditEventIngestRequest,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db),
):
    """
    Ingest an authenticated audit event.
    Source services should forward end-user bearer token for accurate user attribution.
    """
    user = _resolve_user(db, token_data)
    tenant_id = _resolve_tenant_id(db, token_data, request)

    audit_log = AuditLog(
        tenant_id=tenant_id,
        organization_id=request.org_id,
        user_id=user.id,
        action=request.action,
        resource_type=request.resource_type,
        resource_id=request.resource_id,
        app_name=request.app_name,
        ip_address=request.ip_address,
        user_agent=request.user_agent,
        details=request.details or {},
    )

    db.add(audit_log)
    db.commit()
    db.refresh(audit_log)

    logger.info(
        "Audit event ingested action=%s app=%s tenant=%s user=%s",
        request.action,
        request.app_name,
        tenant_id,
        user.id,
    )

    return AuditEventIngestResponse(
        success=True,
        audit_log_id=audit_log.id,
        tenant_id=tenant_id,
        organization_id=audit_log.organization_id,
        user_id=user.id,
        created_at=audit_log.created_at,
    )


@router.get("/events", response_model=list[AuditLogResponse])
async def list_audit_events(
    tenant_id: str = Query(..., max_length=36),
    organization_id: Optional[str] = Query(None, max_length=36),
    action: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None, max_length=36),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db),
):
    _ = _resolve_user(db, token_data)

    if organization_id and not _token_has_org_access(token_data, organization_id):
        raise HTTPException(status_code=403, detail="Access denied for organization audit logs")

    query = db.query(AuditLog).filter(AuditLog.tenant_id == tenant_id)
    if organization_id:
        query = query.filter(AuditLog.organization_id == organization_id)
    if action:
        query = query.filter(AuditLog.action == action)
    if resource_type:
        query = query.filter(AuditLog.resource_type == resource_type)
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)

    rows = (
        query.order_by(AuditLog.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [_serialize_audit_log(row, db) for row in rows]


@router.post("/search", response_model=list[AuditLogResponse])
async def search_audit_events(
    request: AuditLogSearchRequest,
    tenant_id: str = Query(..., max_length=36),
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db),
):
    _ = _resolve_user(db, token_data)

    if request.organization_id and not _token_has_org_access(token_data, request.organization_id):
        raise HTTPException(status_code=403, detail="Access denied for organization audit logs")

    query = db.query(AuditLog).filter(AuditLog.tenant_id == tenant_id)
    if request.organization_id:
        query = query.filter(AuditLog.organization_id == request.organization_id)
    if request.start_date:
        query = query.filter(AuditLog.created_at >= request.start_date)
    if request.end_date:
        query = query.filter(AuditLog.created_at <= request.end_date)
    if request.action:
        query = query.filter(AuditLog.action == request.action)
    if request.resource_type:
        query = query.filter(AuditLog.resource_type == request.resource_type)
    if request.user_id:
        query = query.filter(AuditLog.user_id == request.user_id)

    rows = (
        query.order_by(AuditLog.created_at.desc())
        .offset(request.offset or 0)
        .limit(request.limit or 50)
        .all()
    )
    return [_serialize_audit_log(row, db) for row in rows]
