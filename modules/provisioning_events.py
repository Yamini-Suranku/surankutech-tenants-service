"""
Event helpers for provisioning workflows.
Encapsulates payload structures for tenant + app lifecycle events.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from modules.kafka_publisher import emit_kafka_event

logger = logging.getLogger(__name__)


async def emit_tenant_created_event(
    *,
    tenant_id: str,
    tenant_name: str,
    domain: Optional[str],
    plan_id: str,
    created_by: Optional[str],
) -> None:
    payload = {
        "tenant_id": tenant_id,
        "tenant_name": tenant_name,
        "domain": domain,
        "plan_id": plan_id,
        "created_by": created_by,
    }
    await emit_kafka_event("tenant.created", payload)


async def emit_app_enabled_event(
    *,
    tenant_id: str,
    tenant_domain: Optional[str],
    plan_id: str,
    app_name: str,
    org_id: str,
    org_hostname: Optional[str],
    org_dns_subdomain: Optional[str],
    org_dns_zone: Optional[str],
    ingress_hostname: Optional[str],
    network_tier: Optional[str],
    provisioning_state: Optional[str],
    requested_by: Optional[str],
) -> None:
    payload = {
        "tenant_id": tenant_id,
        "tenant_domain": tenant_domain,
        "plan_id": plan_id,
        "app_name": app_name,
        "organization_id": org_id,
        "organization_hostname": org_hostname,
        "organization_dns_subdomain": org_dns_subdomain,
        "organization_dns_zone": org_dns_zone,
        "ingress_hostname": ingress_hostname,
        "network_tier": network_tier,
        "provisioning_state": provisioning_state,
        "requested_by": requested_by,
    }
    logger.info(
        "emit_app_enabled_event: tenant=%s app=%s org=%s host=%s subdomain=%s zone=%s",
        tenant_id,
        app_name,
        org_id,
        org_hostname,
        org_dns_subdomain,
        org_dns_zone,
    )
    await emit_kafka_event("tenant.app.enabled", payload)


async def emit_app_disabled_event(
    *,
    tenant_id: str,
    app_name: str,
    org_id: str,
    requested_by: Optional[str],
    org_hostname: Optional[str] = None,
    org_dns_subdomain: Optional[str] = None,
    org_dns_zone: Optional[str] = None,
) -> None:
    payload = {
        "tenant_id": tenant_id,
        "app_name": app_name,
        "organization_id": org_id,
        "organization_hostname": org_hostname,
        "organization_dns_subdomain": org_dns_subdomain,
        "organization_dns_zone": org_dns_zone,
        "requested_by": requested_by,
        "timestamp": datetime.utcnow().isoformat(),
    }
    await emit_kafka_event("tenant.app.disabled", payload)
