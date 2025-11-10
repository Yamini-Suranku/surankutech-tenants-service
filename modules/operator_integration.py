"""
Operator Integration Module
Integrates the existing tenant service with the Kubernetes tenant bootstrap operator
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
import logging
import asyncio
import aiohttp
import json
from datetime import datetime
from typing import Dict, Any, Optional
from pydantic import BaseModel

from shared.database import get_db
from shared.auth import verify_token, TokenData, get_current_token_data
from shared.models import Tenant, User, UserTenant, AuditLog
from schemas import TenantResponse
import os

logger = logging.getLogger(__name__)

# Create router for operator integration endpoints
router = APIRouter(prefix="/operator", tags=["operator-integration"])

# Configuration from environment
OPERATOR_WEBHOOK_URL = os.getenv("OPERATOR_WEBHOOK_URL", "http://tenant-bootstrap-operator.tenant-operator-system.svc.cluster.local:8080/webhook")
OPERATOR_API_KEY = os.getenv("OPERATOR_API_KEY", "operator-api-key-12345")
KUBERNETES_NAMESPACE = os.getenv("KUBERNETES_NAMESPACE", "default")

class TenantProvisioningRequest(BaseModel):
    tenant_id: str
    tenant_name: str
    tier: str
    applications: list[str]
    domain: Optional[str] = None
    admin_user_id: str
    features: list[str] = []

class TenantProvisioningResponse(BaseModel):
    status: str
    message: str
    tenant_id: str
    operator_resource_name: Optional[str] = None
    estimated_completion_time: Optional[str] = None

class ProvisioningStatus(BaseModel):
    tenant_id: str
    status: str  # pending, provisioning, active, failed
    phase: str   # current phase of provisioning
    progress: int  # percentage complete
    message: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

async def send_operator_webhook(event_type: str, tenant_data: Dict[str, Any]) -> bool:
    """Send webhook to the tenant bootstrap operator"""
    try:
        webhook_url = f"{OPERATOR_WEBHOOK_URL}/{event_type}"

        headers = {
            "Content-Type": "application/json",
            "X-API-Key": OPERATOR_API_KEY,
            "User-Agent": "Suranku-Tenant-Service/1.0"
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                webhook_url,
                json=tenant_data,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:

                if response.status == 200:
                    logger.info(f"Successfully sent {event_type} webhook for tenant {tenant_data.get('tenant_id')}")
                    return True
                else:
                    logger.error(f"Webhook failed with status {response.status}: {await response.text()}")
                    return False

    except Exception as e:
        logger.error(f"Failed to send operator webhook: {e}")
        return False

async def create_kubernetes_tenant_resource(tenant: Tenant, admin_user: User) -> Dict[str, Any]:
    """Create Kubernetes Tenant custom resource"""

    # Determine tier based on subscription
    tier_mapping = {
        "free": "basic",
        "pro": "standard",
        "enterprise": "enterprise"
    }
    tier = tier_mapping.get(tenant.plan_id, "basic")

    # Determine applications based on plan
    if tier == "basic":
        applications = ["darkhole"]
    elif tier == "standard":
        applications = ["darkhole", "darkfolio"]
    else:
        applications = ["darkhole", "darkfolio", "confiploy"]

    # Determine features based on tier
    features = ["core"]
    if tier in ["standard", "professional", "enterprise"]:
        features.append("analytics")
    if tier in ["professional", "enterprise"]:
        features.append("integrations")
    if tier == "enterprise":
        features.extend(["advanced_security", "custom_branding"])

    # Create Kubernetes resource definition
    k8s_resource = {
        "apiVersion": "suranku.io/v1",
        "kind": "Tenant",
        "metadata": {
            "name": tenant.id,
            "namespace": KUBERNETES_NAMESPACE,
            "labels": {
                "suranku.io/tenant": tenant.id,
                "suranku.io/tier": tier,
                "suranku.io/managed-by": "tenant-service"
            },
            "annotations": {
                "suranku.io/tenant-name": tenant.name,
                "suranku.io/created-by": admin_user.email,
                "suranku.io/subscription-status": tenant.subscription_status
            }
        },
        "spec": {
            "tenantId": tenant.id,
            "tenantName": tenant.name,
            "tier": tier,
            "domain": tenant.domain or f"{tenant.id}.local.suranku.net",
            "applications": applications,
            "features": features,
            "resources": {
                "cpuLimit": get_cpu_limit_for_tier(tier),
                "memoryLimit": get_memory_limit_for_tier(tier),
                "storageSize": get_storage_size_for_tier(tier)
            }
        }
    }

    return k8s_resource

def get_cpu_limit_for_tier(tier: str) -> str:
    """Get CPU limit based on tier"""
    limits = {
        "basic": "1",
        "standard": "2",
        "professional": "4",
        "enterprise": "8"
    }
    return limits.get(tier, "1")

def get_memory_limit_for_tier(tier: str) -> str:
    """Get memory limit based on tier"""
    limits = {
        "basic": "2Gi",
        "standard": "4Gi",
        "professional": "8Gi",
        "enterprise": "16Gi"
    }
    return limits.get(tier, "2Gi")

def get_storage_size_for_tier(tier: str) -> str:
    """Get storage size based on tier"""
    sizes = {
        "basic": "10Gi",
        "standard": "50Gi",
        "professional": "100Gi",
        "enterprise": "500Gi"
    }
    return sizes.get(tier, "10Gi")

@router.post("/provision-tenant", response_model=TenantProvisioningResponse)
async def provision_tenant(
    request: TenantProvisioningRequest,
    background_tasks: BackgroundTasks,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db)
):
    """Provision tenant infrastructure through the operator"""
    try:
        # Get tenant and admin user
        tenant = db.query(Tenant).filter(Tenant.id == request.tenant_id).first()
        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant not found")

        admin_user = db.query(User).filter(User.id == request.admin_user_id).first()
        if not admin_user:
            raise HTTPException(status_code=404, detail="Admin user not found")

        # Create Kubernetes tenant resource
        k8s_resource = await create_kubernetes_tenant_resource(tenant, admin_user)

        # Send to operator via webhook
        webhook_data = {
            "event": "tenant_created",
            "tenant_id": request.tenant_id,
            "kubernetes_resource": k8s_resource,
            "timestamp": datetime.utcnow().isoformat()
        }

        # Schedule background task to send webhook
        background_tasks.add_task(send_operator_webhook, "tenant-created", webhook_data)

        # Create audit log
        audit_log = AuditLog(
            action="tenant_provisioning_requested",
            resource_type="tenant",
            resource_id=request.tenant_id,
            user_id=request.admin_user_id,
            tenant_id=request.tenant_id,
            details={
                "provisioning_request": request.dict(),
                "k8s_resource_name": k8s_resource["metadata"]["name"]
            },
            created_at=datetime.utcnow()
        )
        db.add(audit_log)
        db.commit()

        logger.info(f"Tenant provisioning requested for {request.tenant_id}")

        return TenantProvisioningResponse(
            status="accepted",
            message="Tenant provisioning request submitted to operator",
            tenant_id=request.tenant_id,
            operator_resource_name=k8s_resource["metadata"]["name"],
            estimated_completion_time="5-10 minutes"
        )

    except Exception as e:
        logger.error(f"Failed to request tenant provisioning: {e}")
        raise HTTPException(status_code=500, detail=f"Provisioning request failed: {str(e)}")

@router.get("/provisioning-status/{tenant_id}", response_model=ProvisioningStatus)
async def get_provisioning_status(
    tenant_id: str,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db)
):
    """Get tenant provisioning status from the operator"""
    try:
        # Verify access to tenant
        user = db.query(User).filter(User.keycloak_id == token_data.sub).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user_tenant = db.query(UserTenant).filter(
            UserTenant.user_id == user.id,
            UserTenant.tenant_id == tenant_id
        ).first()

        if not user_tenant:
            raise HTTPException(status_code=403, detail="Access denied to tenant")

        # Query operator for status (this would typically be done via Kubernetes API)
        # For now, we'll return a mock status based on tenant state
        tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
        if not tenant:
            raise HTTPException(status_code=404, detail="Tenant not found")

        # Determine status based on subscription status
        if tenant.subscription_status == "trial":
            status = "provisioning"
            phase = "setting_up_infrastructure"
            progress = 75
            message = "Setting up tenant infrastructure components"
        elif tenant.subscription_status == "active":
            status = "active"
            phase = "completed"
            progress = 100
            message = "Tenant infrastructure is fully provisioned and active"
        else:
            status = "pending"
            phase = "waiting_for_approval"
            progress = 0
            message = "Waiting for tenant approval and payment"

        return ProvisioningStatus(
            tenant_id=tenant_id,
            status=status,
            phase=phase,
            progress=progress,
            message=message,
            started_at=tenant.created_at,
            completed_at=tenant.created_at if status == "active" else None
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get provisioning status: {e}")
        raise HTTPException(status_code=500, detail="Failed to get provisioning status")

@router.post("/webhook/operator-status")
async def operator_status_webhook(
    payload: Dict[str, Any],
    db: Session = Depends(get_db)
):
    """Webhook endpoint for receiving status updates from the operator"""
    try:
        # Verify webhook signature/API key
        # This would typically include signature verification

        tenant_id = payload.get("tenant_id")
        status = payload.get("status")
        phase = payload.get("phase")
        message = payload.get("message")

        if not tenant_id:
            raise HTTPException(status_code=400, detail="Missing tenant_id in payload")

        # Update tenant status based on operator feedback
        tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
        if tenant:
            # Update tenant based on operator status
            if status == "active":
                tenant.subscription_status = "active"
            elif status == "failed":
                tenant.subscription_status = "suspended"

            db.commit()

            # Create audit log
            audit_log = AuditLog(
                action="operator_status_update",
                resource_type="tenant",
                resource_id=tenant_id,
                tenant_id=tenant_id,
                details={
                    "operator_status": status,
                    "operator_phase": phase,
                    "operator_message": message,
                    "webhook_payload": payload
                },
                created_at=datetime.utcnow()
            )
            db.add(audit_log)
            db.commit()

            logger.info(f"Updated tenant {tenant_id} status from operator: {status}")

        return {"status": "received", "tenant_id": tenant_id}

    except Exception as e:
        logger.error(f"Failed to process operator webhook: {e}")
        raise HTTPException(status_code=500, detail="Failed to process webhook")

@router.delete("/deprovision-tenant/{tenant_id}")
async def deprovision_tenant(
    tenant_id: str,
    background_tasks: BackgroundTasks,
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db)
):
    """Deprovision tenant infrastructure through the operator"""
    try:
        # Verify access and admin role
        user = db.query(User).filter(User.keycloak_id == token_data.sub).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user_tenant = db.query(UserTenant).filter(
            UserTenant.user_id == user.id,
            UserTenant.tenant_id == tenant_id
        ).first()

        if not user_tenant:
            raise HTTPException(status_code=403, detail="Access denied to tenant")

        # Check admin role
        is_admin = any(
            "admin" in user_tenant.app_roles.get(app, [])
            for app in ["darkhole", "darkfolio", "confiploy"]
        )

        if not is_admin:
            raise HTTPException(status_code=403, detail="Admin role required")

        # Send deprovisioning webhook
        webhook_data = {
            "event": "tenant_deleted",
            "tenant_id": tenant_id,
            "requested_by": user.email,
            "timestamp": datetime.utcnow().isoformat()
        }

        background_tasks.add_task(send_operator_webhook, "tenant-deleted", webhook_data)

        # Create audit log
        audit_log = AuditLog(
            action="tenant_deprovisioning_requested",
            resource_type="tenant",
            resource_id=tenant_id,
            user_id=user.id,
            tenant_id=tenant_id,
            details={
                "requested_by": user.email,
                "deprovision_request": True
            },
            created_at=datetime.utcnow()
        )
        db.add(audit_log)
        db.commit()

        logger.info(f"Tenant deprovisioning requested for {tenant_id} by {user.email}")

        return {
            "status": "accepted",
            "message": "Tenant deprovisioning request submitted to operator",
            "tenant_id": tenant_id
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to request tenant deprovisioning: {e}")
        raise HTTPException(status_code=500, detail="Deprovisioning request failed")

@router.get("/operator-health")
async def check_operator_health():
    """Check if the tenant bootstrap operator is healthy"""
    try:
        health_url = f"{OPERATOR_WEBHOOK_URL.replace('/webhook', '')}/healthz"

        async with aiohttp.ClientSession() as session:
            async with session.get(
                health_url,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:

                if response.status == 200:
                    return {
                        "status": "healthy",
                        "operator_url": OPERATOR_WEBHOOK_URL,
                        "response_time_ms": "< 10000"
                    }
                else:
                    return {
                        "status": "unhealthy",
                        "operator_url": OPERATOR_WEBHOOK_URL,
                        "error": f"HTTP {response.status}"
                    }

    except Exception as e:
        return {
            "status": "unreachable",
            "operator_url": OPERATOR_WEBHOOK_URL,
            "error": str(e)
        }

# Helper function to trigger automatic provisioning on tenant creation
async def trigger_automatic_provisioning(tenant: Tenant, admin_user: User, db: Session):
    """Automatically trigger provisioning for new tenants"""
    try:
        # Create provisioning request
        request = TenantProvisioningRequest(
            tenant_id=tenant.id,
            tenant_name=tenant.name,
            tier=tenant.plan_id,
            applications=["darkhole"],  # Default application
            domain=tenant.domain,
            admin_user_id=admin_user.id,
            features=["core"]
        )

        # Create Kubernetes resource
        k8s_resource = await create_kubernetes_tenant_resource(tenant, admin_user)

        # Send webhook
        webhook_data = {
            "event": "tenant_created",
            "tenant_id": tenant.id,
            "kubernetes_resource": k8s_resource,
            "auto_triggered": True,
            "timestamp": datetime.utcnow().isoformat()
        }

        success = await send_operator_webhook("tenant-created", webhook_data)

        if success:
            logger.info(f"Automatic provisioning triggered for tenant {tenant.id}")
        else:
            logger.warning(f"Failed to trigger automatic provisioning for tenant {tenant.id}")

    except Exception as e:
        logger.error(f"Failed to trigger automatic provisioning for tenant {tenant.id}: {e}")

# Integration points for existing tenant management
async def on_tenant_created(tenant: Tenant, admin_user: User, db: Session):
    """Called when a new tenant is created"""
    await trigger_automatic_provisioning(tenant, admin_user, db)

async def on_tenant_updated(tenant: Tenant, db: Session):
    """Called when a tenant is updated"""
    webhook_data = {
        "event": "tenant_updated",
        "tenant_id": tenant.id,
        "subscription_status": tenant.subscription_status,
        "plan_id": tenant.plan_id,
        "timestamp": datetime.utcnow().isoformat()
    }

    await send_operator_webhook("tenant-updated", webhook_data)

async def on_tenant_deleted(tenant_id: str, db: Session):
    """Called when a tenant is deleted"""
    webhook_data = {
        "event": "tenant_deleted",
        "tenant_id": tenant_id,
        "timestamp": datetime.utcnow().isoformat()
    }

    await send_operator_webhook("tenant-deleted", webhook_data)