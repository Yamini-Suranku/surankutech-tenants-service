#!/bin/bash
# Script to regenerate Vault Agent Injector certificates after HTTPS migration
set -e

echo "🔐 Regenerating Vault Agent Injector certificates for HTTPS..."

# Delete existing certificate generation job if it exists
echo "🧹 Cleaning up existing certificate job..."
kubectl delete job vault-cert-generator -n shared-services --ignore-not-found=true

# Apply the certificate generation job
echo "🛠️ Applying certificate generation job..."
kubectl apply -f /Users/pallava/Documents/RND/gitrepos/surankutech/surankutech-shared-services/k8s/base/vault/vault-certs-job.yaml

# Wait for the job to complete
echo "⏳ Waiting for certificate generation to complete..."
kubectl wait --for=condition=complete job/vault-cert-generator -n shared-services --timeout=120s

# Check job logs
echo "📋 Certificate generation logs:"
kubectl logs job/vault-cert-generator -n shared-services

# Restart vault-agent-injector to pick up new certificates
echo "🔄 Restarting vault-agent-injector deployment..."
kubectl rollout restart deployment/vault-agent-injector -n shared-services

# Wait for rollout to complete
echo "⏳ Waiting for vault-agent-injector rollout..."
kubectl rollout status deployment/vault-agent-injector -n shared-services

# Restart tenants-service to test vault injection
echo "🔄 Restarting tenants-service deployment..."
kubectl rollout restart deployment/tenants-service -n tenant-services

# Wait for rollout to complete
echo "⏳ Waiting for tenants-service rollout..."
kubectl rollout status deployment/tenants-service -n tenant-services

echo "✅ Vault certificates regenerated successfully!"
echo "🧪 Verifying new pods have vault-agent containers..."

# Check that new pods have 3/3 containers (including vault-agent)
sleep 10
kubectl get pods -n tenant-services -l app=tenants-service

echo "✅ Done! Tenants service should now connect to Vault properly."