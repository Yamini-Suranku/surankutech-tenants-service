#!/usr/bin/env bash
set -euo pipefail

CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-v1.15.1}"
CERT_MANAGER_NAMESPACE="${CERT_MANAGER_NAMESPACE:-cert-manager}"
RELEASE_NAME="${CERT_MANAGER_RELEASE_NAME:-cert-manager}"

if ! command -v kubectl >/dev/null 2>&1; then
  echo "[install-cert-manager] kubectl is required on PATH" >&2
  exit 1
fi

if ! command -v helm >/dev/null 2>&1; then
  echo "[install-cert-manager] helm is required on PATH" >&2
  exit 1
fi

CRD_URL="https://github.com/cert-manager/cert-manager/releases/download/${CERT_MANAGER_VERSION}/cert-manager.crds.yaml"
echo "[install-cert-manager] Applying cert-manager CRDs from ${CRD_URL}"
kubectl apply -f "${CRD_URL}"

echo "[install-cert-manager] Ensuring jetstack Helm repo is present"
if ! helm repo list | awk '{print $1}' | grep -qx "jetstack"; then
  helm repo add jetstack https://charts.jetstack.io
fi
helm repo update jetstack >/dev/null

CHART_VERSION="${CERT_MANAGER_VERSION#v}"
echo "[install-cert-manager] Installing chart jetstack/cert-manager (${CHART_VERSION}) into namespace ${CERT_MANAGER_NAMESPACE}"
helm upgrade --install "${RELEASE_NAME}" jetstack/cert-manager \
  --namespace "${CERT_MANAGER_NAMESPACE}" \
  --create-namespace \
  --version "${CHART_VERSION}" \
  --set installCRDs=false

echo "[install-cert-manager] Done. Check status with:"
echo "  kubectl get pods -n ${CERT_MANAGER_NAMESPACE}"
