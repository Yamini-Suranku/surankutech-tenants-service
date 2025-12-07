#!/bin/bash

# Setup Vault access for Tenants Service
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

VAULT_POD_NAME="suranku-vault"
VAULT_NAMESPACE="shared-services"
VAULT_ADDR="http://127.0.0.1:8200"  # Internal pod communication
VAULT_ROOT_TOKEN="root"

echo "🔐 Setting up Vault access for Tenants Service..."

# Copy policy file to Vault pod
echo "📁 Copying policy file to Vault pod..."
VAULT_POD_FULL=$(kubectl get pods -n ${VAULT_NAMESPACE} -l app=suranku-vault -o jsonpath='{.items[0].metadata.name}')
kubectl cp "${REPO_ROOT}/vault-policies/tenants-service-policy.hcl" "${VAULT_NAMESPACE}/${VAULT_POD_FULL}:/tmp/tenants-service-policy.hcl"

# Create the policy in Vault
echo "📝 Creating tenants-service policy in Vault..."
kubectl exec -n ${VAULT_NAMESPACE} deployment/${VAULT_POD_NAME} -- \
  env VAULT_ADDR=${VAULT_ADDR} VAULT_TOKEN=${VAULT_ROOT_TOKEN} \
  vault policy write tenants-service /tmp/tenants-service-policy.hcl

# Create a new token with the policy
echo "🔑 Creating new service token..."
NEW_TOKEN=$(kubectl exec -n ${VAULT_NAMESPACE} deployment/${VAULT_POD_NAME} -- \
  env VAULT_ADDR=${VAULT_ADDR} VAULT_TOKEN=${VAULT_ROOT_TOKEN} \
  vault token create -policy=tenants-service -display-name="tenants-service" -ttl=720h -format=json | \
  jq -r '.auth.client_token')

echo "✅ Created new token: ${NEW_TOKEN}"

# Update the Kubernetes secret with the new token
echo "🔄 Updating tenants-secrets with new Vault token..."
NEW_TOKEN_B64=$(echo -n "${NEW_TOKEN}" | base64)

kubectl patch secret tenants-secrets -n tenant-services --type='json' -p="[{
  \"op\": \"replace\",
  \"path\": \"/data/vault-token\",
  \"value\": \"${NEW_TOKEN_B64}\"
}]"

# Restart the tenants service to pick up the new token
echo "🔄 Restarting tenants service deployment..."
kubectl rollout restart deployment/tenants-service -n tenant-services

echo "⏳ Waiting for rollout to complete..."
kubectl rollout status deployment/tenants-service -n tenant-services

echo "✅ Vault access setup complete!"
echo "🧪 Testing token validity..."

# Test the new token
kubectl exec -n tenant-services deployment/tenants-service -- \
  curl -s -H "X-Vault-Token: ${NEW_TOKEN}" \
  https://suranku-vault.shared-services.svc.cluster.local:8200/v1/auth/token/lookup-self \
  | jq -r '.data.display_name // "Token validation failed"'

echo "✅ Tenants Service now has proper Vault access!"
