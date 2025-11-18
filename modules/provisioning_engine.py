"""
Provisioning engine for tenant applications.

This module encapsulates provisioning steps such as creating ingress records,
ensuring namespaces, and coordinating DNS/Kong updates. The implementation is
designed to work incrementally – shared-tier tenants reuse the shared DarkHole
deployment, while pro/enterprise tiers can be extended to deploy isolated
workloads per tenant.
"""

from __future__ import annotations

import logging
import os
import subprocess
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from shared.models import TenantAppAccess

logger = logging.getLogger(__name__)


def _kubectl(cmd: list[str], payload: Optional[str] = None) -> subprocess.CompletedProcess:
    """Run kubectl command, raising on failure."""
    kubectl_bin = os.getenv("KUBECTL_BIN", "kubectl")
    full_cmd = [kubectl_bin] + cmd
    logger.debug("Running command: %s", " ".join(full_cmd))
    return subprocess.run(
        full_cmd,
        input=payload.encode("utf-8") if payload else None,
        capture_output=True,
        check=True,
    )


def _slugify(value: str) -> str:
    """Simple slugify helper for names/hosts."""
    import re

    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    value = re.sub(r"-{2,}", "-", value).strip("-")
    return value or "tenant"


@dataclass
class ProvisioningContext:
    tenant_id: str
    tenant_domain: Optional[str]
    plan_id: Optional[str]
    app_name: str
    ingress_hostname: Optional[str]
    network_tier: str


class ProvisioningEngine:
    """Executes provisioning steps for tenant applications."""

    def __init__(self) -> None:
        self.environment = os.getenv("ENVIRONMENT", "local")
        self.shared_namespace = os.getenv("PROVISIONING_SHARED_NAMESPACE", "darkhole")
        self.shared_service = os.getenv("PROVISIONING_SHARED_SERVICE", "darkhole-api")
        self.shared_service_port = int(os.getenv("PROVISIONING_SHARED_SERVICE_PORT", "80"))
        self.ingress_class = os.getenv("PROVISIONING_INGRESS_CLASS", "nginx")
        self.cert_manager_cluster_issuer = os.getenv("CERT_MANAGER_CLUSTER_ISSUER", "")
        self.namespace_prefix = os.getenv("PROVISIONING_NAMESPACE_PREFIX", "tenant")
        self.data_plane_domain = os.getenv("DATA_PLANE_DOMAIN", "suranku.net")
        self.local_data_plane_domain = os.getenv("LOCAL_DATA_PLANE_DOMAIN", "local.suranku")

    def provision_app(
        self,
        db: Session,
        app_access: TenantAppAccess,
        context: ProvisioningContext,
    ) -> None:
        """Provision an app based on network tier."""
        hostname = self._resolve_hostname(context)
        app_access.ingress_hostname = hostname
        app_access.provisioning_state = "provisioning"
        app_access.dns_status = "pending"
        app_access.provisioning_error = None
        app_access.last_synced_at = datetime.utcnow()
        db.flush()

        try:
            if context.network_tier in ("shared", "trial", "free", ""):
                self._provision_shared_app(context, hostname)
            else:
                self._provision_isolated_app(context, hostname)

            app_access.provisioning_state = "ready"
            app_access.dns_status = "ready"
            app_access.last_synced_at = datetime.utcnow()
            db.flush()
        except subprocess.CalledProcessError as exc:
            logger.error("Provisioning command failed: %s %s", exc, exc.stderr.decode())
            app_access.provisioning_state = "error"
            app_access.dns_status = "failed"
            app_access.provisioning_error = exc.stderr.decode() or str(exc)
            app_access.last_synced_at = datetime.utcnow()
            db.flush()
            raise
        except Exception as exc:
            logger.exception("Provisioning failed: %s", exc)
            app_access.provisioning_state = "error"
            app_access.dns_status = "failed"
            app_access.provisioning_error = str(exc)
            app_access.last_synced_at = datetime.utcnow()
            db.flush()
            raise

    def deprovision_app(
        self,
        db: Session,
        app_access: TenantAppAccess,
        context: ProvisioningContext,
    ) -> None:
        """Tear down ingress resources for disabled apps."""
        hostname = app_access.ingress_hostname or self._resolve_hostname(context)
        try:
            ingress_name = self._ingress_name(context, hostname)
            namespace = self.shared_namespace if self._is_shared(context) else self._tenant_namespace(context)
            _kubectl(["delete", "ingress", ingress_name, "-n", namespace, "--ignore-not-found"])
        except subprocess.CalledProcessError as exc:
            logger.warning("Failed to delete ingress: %s", exc.stderr.decode())

        app_access.provisioning_state = "disabled"
        app_access.dns_status = "removed"
        app_access.last_synced_at = datetime.utcnow()
        db.flush()

    def _provision_shared_app(self, context: ProvisioningContext, hostname: str) -> None:
        """Shared-tier tenants reuse the shared DarkHole deployment via dedicated ingress."""
        ingress_manifest = self._build_ingress_yaml(
            name=self._ingress_name(context, hostname),
            namespace=self.shared_namespace,
            hostname=hostname,
            service_name=self.shared_service,
            service_port=self.shared_service_port,
            path_prefix=f"/{context.app_name}"
        )
        _kubectl(["apply", "-f", "-"], payload=ingress_manifest)

    def _provision_isolated_app(self, context: ProvisioningContext, hostname: str) -> None:
        """Placeholder for pro/enterprise isolation - ensure namespace and ingress."""
        namespace = self._tenant_namespace(context)
        self._ensure_namespace(namespace)

        ingress_manifest = self._build_ingress_yaml(
            name=self._ingress_name(context, hostname),
            namespace=namespace,
            hostname=hostname,
            service_name=f"{context.app_name}-svc",
            service_port=self.shared_service_port,
            path_prefix=f"/{context.app_name}"
        )
        _kubectl(["apply", "-f", "-"], payload=ingress_manifest)

    def _ensure_namespace(self, namespace: str) -> None:
        try:
            _kubectl(["get", "namespace", namespace])
        except subprocess.CalledProcessError:
            _kubectl(["create", "namespace", namespace])

    def _resolve_hostname(self, context: ProvisioningContext) -> str:
        tenant_slug = _slugify(context.tenant_domain or context.tenant_id[:8])
        suffix = self.local_data_plane_domain if self.environment in ("local", "development") else self.data_plane_domain
        return f"{tenant_slug}.{suffix}"

    def _tenant_namespace(self, context: ProvisioningContext) -> str:
        tenant_slug = _slugify(context.tenant_domain or context.tenant_id[:8])
        return f"{self.namespace_prefix}-{tenant_slug}"

    def _is_shared(self, context: ProvisioningContext) -> bool:
        tier = (context.network_tier or "").lower()
        return tier in ("shared", "free", "trial", "")

    def _ingress_name(self, context: ProvisioningContext, hostname: str) -> str:
        host_slug = _slugify(hostname.replace(".", "-"))
        return f"ingress-{context.app_name}-{host_slug[:32]}"

    def _build_ingress_yaml(
        self,
        name: str,
        namespace: str,
        hostname: str,
        service_name: str,
        service_port: int,
        path_prefix: str = "/",
    ) -> str:
        cert_block = ""
        if self.cert_manager_cluster_issuer:
            cert_block = f"""
  tls:
  - hosts:
      - {hostname}
    secretName: tls-{name}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: cert-{name}
  namespace: {namespace}
spec:
  secretName: tls-{name}
  dnsNames:
    - {hostname}
  issuerRef:
    kind: ClusterIssuer
    name: {self.cert_manager_cluster_issuer}
"""

        return f"""
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {name}
  namespace: {namespace}
  annotations:
    kubernetes.io/ingress.class: {self.ingress_class}
    external-dns.alpha.kubernetes.io/hostname: {hostname}
    external-dns.alpha.kubernetes.io/ttl: "300"
spec:
  rules:
  - host: {hostname}
    http:
      paths:
      - path: {path_prefix.rstrip('/') or '/'}
        pathType: Prefix
        backend:
          service:
            name: {service_name}
            port:
              number: {service_port}
{cert_block or ''}
"""
