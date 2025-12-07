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
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from shared.models import TenantAppAccess

logger = logging.getLogger(__name__)


def _kubectl(cmd: list[str], payload: Optional[str] = None) -> subprocess.CompletedProcess:
    """Run kubectl command with structured logging."""
    kubectl_bin = os.getenv("KUBECTL_BIN", "kubectl")
    full_cmd = [kubectl_bin] + cmd
    logger.info("kubectl exec: %s", " ".join(full_cmd))
    try:
        result = subprocess.run(
            full_cmd,
            input=payload.encode("utf-8") if payload else None,
            capture_output=True,
            check=True,
        )
        stdout = result.stdout.decode().strip() if result.stdout else ""
        stderr = result.stderr.decode().strip() if result.stderr else ""
        if stdout:
            logger.debug("kubectl stdout: %s", stdout)
        if stderr:
            logger.debug("kubectl stderr: %s", stderr)
        return result
    except subprocess.CalledProcessError as exc:
        err_out = exc.stderr.decode().strip() if exc.stderr else ""
        logger.error("kubectl command failed (%s): %s", " ".join(full_cmd), err_out or exc)
        raise


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
    organization_id: Optional[str] = None
    organization_hostname: Optional[str] = None
    organization_dns_subdomain: Optional[str] = None
    organization_dns_zone: Optional[str] = None


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
        self.shared_static_mode = os.getenv("PROVISIONING_SHARED_STATIC_MODE", "false").lower() == "true"
        self.static_apps_prefix = os.getenv("PROVISIONING_STATIC_APPS_PREFIX", "/platform-apps/apps")
        self.api_proxy_enabled = os.getenv("PROVISIONING_API_PROXY_ENABLED", "true").lower() == "true"
        self.api_proxy_service = os.getenv("PROVISIONING_API_PROXY_SERVICE", "kong-gateway").strip()
        self.api_proxy_port = int(os.getenv("PROVISIONING_API_PROXY_PORT", "80"))
        self.api_path_prefix = os.getenv("PROVISIONING_API_PATH_PREFIX", "/api")
        self.shared_assets_enabled = os.getenv("PROVISIONING_SHARED_ASSETS_ENABLED", "true").lower() == "true"
        self.shared_assets_service = os.getenv(
            "PROVISIONING_SHARED_ASSETS_SERVICE",
            self.api_proxy_service,
        ).strip()
        self.shared_assets_port = int(
            os.getenv("PROVISIONING_SHARED_ASSETS_PORT", str(self.api_proxy_port))
        )
        self.shared_assets_path_prefix = os.getenv("PROVISIONING_SHARED_ASSETS_PATH", "/shared")

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
        namespace = self.shared_namespace if self._is_shared(context) else self._tenant_namespace(context)
        ingress_name = self._ingress_name(context, hostname)
        resolved_host = self._resolve_hostname(context)
        resolved_name = self._ingress_name(context, resolved_host)

        # Use the same cleanup helper that the enable path uses
        seen: set[str] = set()
        for base in (ingress_name, resolved_name):
            if base not in seen:
                self._cleanup_existing_ingress(namespace, base)
                seen.add(base)

        app_access.provisioning_state = "disabled"
        app_access.dns_status = "removed"
        app_access.last_synced_at = datetime.utcnow()
        db.flush()

    def _provision_shared_app(self, context: ProvisioningContext, hostname: str) -> None:
        """Shared-tier tenants reuse the shared DarkHole deployment via dedicated ingress."""
        logger.info(
            "Provisioning shared ingress (app=%s host=%s namespace=%s)",
            context.app_name,
            hostname,
            self.shared_namespace,
        )
        base_name = self._ingress_name(context, hostname)
        self._cleanup_existing_ingress(self.shared_namespace, base_name)
        if self.shared_static_mode:
            manifests = []
            path_expr = f"/{context.app_name}/(.*)"
            rewrite_target = f"{self.static_apps_prefix.rstrip('/')}/{context.app_name}/$1"
            manifests.append(self._build_ingress_yaml(
                name=base_name,
                namespace=self.shared_namespace,
                hostname=hostname,
                service_name=self.shared_service,
                service_port=self.shared_service_port,
                path_prefix=path_expr,
                use_regex=True,
                rewrite_target=rewrite_target,
            ))
            index_target = f"{self.static_apps_prefix.rstrip('/')}/{context.app_name}/index.html"
            manifests.append(self._build_ingress_yaml(
                name=f"{base_name}-root",
                namespace=self.shared_namespace,
                hostname=hostname,
                service_name=self.shared_service,
                service_port=self.shared_service_port,
                path_prefix=f"/{context.app_name}",
                path_type="Exact",
                rewrite_target=index_target,
            ))
            for manifest in manifests:
                logger.debug("Applying ingress manifest:\n%s", manifest)
                _kubectl(["apply", "-f", "-"], payload=manifest)
            self._apply_api_proxy_ingress(
                context,
                hostname,
                namespace=self.shared_namespace,
                base_name=base_name,
            )
            return
        else:
            ingress_manifest = self._build_ingress_yaml(
                name=base_name,
                namespace=self.shared_namespace,
                hostname=hostname,
                service_name=self.shared_service,
                service_port=self.shared_service_port,
                path_prefix=f"/{context.app_name}"
            )
        logger.debug("Applying ingress manifest:\n%s", ingress_manifest)
        _kubectl(["apply", "-f", "-"], payload=ingress_manifest)
        self._apply_api_proxy_ingress(
            context,
            hostname,
            namespace=self.shared_namespace,
            base_name=base_name,
        )
        self._apply_shared_assets_ingress(
            context,
            hostname,
            namespace=self.shared_namespace,
            base_name=base_name,
        )

    def _provision_isolated_app(self, context: ProvisioningContext, hostname: str) -> None:
        """Placeholder for pro/enterprise isolation - ensure namespace and ingress."""
        namespace = self._tenant_namespace(context)
        logger.info(
            "Provisioning isolated ingress (app=%s host=%s namespace=%s)",
            context.app_name,
            hostname,
            namespace,
        )
        self._ensure_namespace(namespace)

        base_name = self._ingress_name(context, hostname)
        self._cleanup_existing_ingress(namespace, base_name)
        ingress_manifest = self._build_ingress_yaml(
            name=base_name,
            namespace=namespace,
            hostname=hostname,
            service_name=f"{context.app_name}-svc",
            service_port=self.shared_service_port,
            path_prefix=f"/{context.app_name}"
        )
        logger.debug("Applying ingress manifest:\n%s", ingress_manifest)
        _kubectl(["apply", "-f", "-"], payload=ingress_manifest)
        self._apply_api_proxy_ingress(
            context,
            hostname,
            namespace=namespace,
            base_name=base_name,
        )
        self._apply_shared_assets_ingress(
            context,
            hostname,
            namespace=namespace,
            base_name=base_name,
        )

    def _ensure_namespace(self, namespace: str) -> None:
        try:
            _kubectl(["get", "namespace", namespace])
        except subprocess.CalledProcessError:
            _kubectl(["create", "namespace", namespace])

    def _resolve_hostname(self, context: ProvisioningContext) -> str:
        if context.ingress_hostname:
            return context.ingress_hostname
        if context.organization_hostname:
            return context.organization_hostname
        if context.organization_dns_subdomain:
            zone = context.organization_dns_zone or (
                self.local_data_plane_domain if self.environment in ("local", "development") else self.data_plane_domain
            )
            return f"{context.organization_dns_subdomain}.{zone}"
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
        use_regex: bool = False,
        rewrite_target: Optional[str] = None,
        extra_annotations: Optional[dict[str, str]] = None,
        path_type: Optional[str] = None,
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

        path_value = path_prefix if use_regex else (path_prefix.rstrip('/') or "/")
        effective_path_type = "ImplementationSpecific" if use_regex else (path_type or "Prefix")

        annotations = {
            "kubernetes.io/ingress.class": self.ingress_class,
            "external-dns.alpha.kubernetes.io/hostname": hostname,
            "external-dns.alpha.kubernetes.io/ttl": '"300"',
        }
        if use_regex:
            annotations["nginx.ingress.kubernetes.io/use-regex"] = '"true"'
        if rewrite_target:
            annotations["nginx.ingress.kubernetes.io/rewrite-target"] = rewrite_target
        if extra_annotations:
            annotations.update(extra_annotations)
        formatted_annotations = []
        for key, value in annotations.items():
            if "\n" in value:
                indented = "\n      ".join(value.splitlines())
                formatted_annotations.append(f"{key}: |\n      {indented}")
            else:
                formatted_annotations.append(f"{key}: {value}")
        annotations_block = "\n    ".join(formatted_annotations)

        labels_block = """  labels:
    app.kubernetes.io/managed-by: tenants-provisioning-worker
    suranku.com/provisioned-by: tenant-services
"""

        return f"""
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {name}
  namespace: {namespace}
{labels_block}  annotations:
    {annotations_block}
spec:
  rules:
  - host: {hostname}
    http:
      paths:
      - path: {path_value}
        pathType: {effective_path_type}
        backend:
          service:
            name: {service_name}
            port:
              number: {service_port}
{cert_block or ''}
"""

    def _ingress_name_variants(self, base_name: str) -> list[str]:
        variants = [base_name]
        if self.shared_static_mode:
            variants.extend([
                f"{base_name}-root",
                f"{base_name}-root-slash",
            ])
        if self._api_proxy_active():
            variants.append(f"{base_name}-api")
        if self._shared_assets_active():
            variants.append(f"{base_name}-shared")
        return variants

    def _cleanup_existing_ingress(self, namespace: str, base_name: str) -> None:
        """Ensure no stale ingress objects conflict with the target host/path."""
        variants = self._ingress_name_variants(base_name)
        for name in variants:
            try:
                _kubectl(["delete", "ingress", name, "-n", namespace, "--ignore-not-found"])
            except subprocess.CalledProcessError as exc:
                logger.warning("Failed to delete existing ingress %s: %s", name, exc.stderr.decode())
        self._wait_for_ingress_absence(namespace, variants)

    def _wait_for_ingress_absence(self, namespace: str, names: list[str], timeout: int = 30) -> None:
        """Wait for nginx webhook to observe ingress deletions before recreating."""
        pending = set(names)
        deadline = time.time() + timeout
        while pending and time.time() < deadline:
            completed = set()
            for name in list(pending):
                try:
                    _kubectl(["get", "ingress", name, "-n", namespace])
                except subprocess.CalledProcessError as exc:
                    err = exc.stderr.decode()
                    if "NotFound" in err or "not found" in err.lower():
                        completed.add(name)
                    else:
                        logger.warning("Unexpected error checking ingress %s: %s", name, err)
                        completed.add(name)
                else:
                    # Still exists; keep waiting
                    continue
            pending -= completed
            if pending:
                time.sleep(1)
        if pending:
            logger.warning("Timed out waiting for ingress cleanup: %s", ", ".join(sorted(pending)))

    def _apply_api_proxy_ingress(
        self,
        context: ProvisioningContext,
        hostname: str,
        namespace: str,
        base_name: Optional[str] = None,
    ) -> None:
        if not self._api_proxy_active():
            return
        ingress_base = base_name or self._ingress_name(context, hostname)
        ingress_manifest = self._build_ingress_yaml(
            name=f"{ingress_base}-api",
            namespace=namespace,
            hostname=hostname,
            service_name=self.api_proxy_service,
            service_port=self.api_proxy_port,
            path_prefix=self.api_path_prefix,
            path_type="Prefix",
        )
        logger.debug("Applying API proxy ingress manifest:\n%s", ingress_manifest)
        _kubectl(["apply", "-f", "-"], payload=ingress_manifest)

    def _api_proxy_active(self) -> bool:
        return self.api_proxy_enabled and bool(self.api_proxy_service)

    def _apply_shared_assets_ingress(
        self,
        context: ProvisioningContext,
        hostname: str,
        namespace: str,
        base_name: Optional[str] = None,
    ) -> None:
        if not self._shared_assets_active():
            return
        ingress_base = base_name or self._ingress_name(context, hostname)
        ingress_manifest = self._build_ingress_yaml(
            name=f"{ingress_base}-shared",
            namespace=namespace,
            hostname=hostname,
            service_name=self.shared_assets_service,
            service_port=self.shared_assets_port,
            path_prefix=self.shared_assets_path_prefix,
            path_type="Prefix",
        )
        logger.debug("Applying shared assets ingress manifest:\n%s", ingress_manifest)
        _kubectl(["apply", "-f", "-"], payload=ingress_manifest)

    def _shared_assets_active(self) -> bool:
        return self.shared_assets_enabled and bool(self.shared_assets_service) and bool(
            self.shared_assets_path_prefix
        )
