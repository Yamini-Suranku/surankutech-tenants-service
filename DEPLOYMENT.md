# Deployment Guide - Development Environment Only

## 🔐 GitHub Secrets Setup

### Step 1: Create Development Environment in GitHub

1. Go to your repository: `https://github.com/Yamini-Suranku/surankutech-tenants-service`
2. Navigate to: **Settings** → **Environments**
3. Click **New environment**
4. Name: `development`
5. Click **Configure environment**

### Step 2: Add Required Secrets

In the `development` environment, add these secrets:

| Secret Name | Value | Description |
|-------------|-------|-------------|
| `AWS_ACCESS_KEY_ID` | `AKIAXXXXXXXXXXXXXXXXX` | AWS IAM Access Key |
| `AWS_SECRET_ACCESS_KEY` | `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` | AWS IAM Secret Key |

### Step 3: AWS IAM User Permissions

Create an IAM user with these policies:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "eks:DescribeCluster",
                "eks:DescribeNodegroup",
                "eks:ListClusters"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

## 🚀 Deployment Process

### Automatic Deployment
- **Push to `develop` branch**: Deploys to development
- **Push to `main` branch**: Deploys to development

### Manual Deployment
```bash
# Clone the repository
git clone https://github.com/Yamini-Suranku/surankutech-tenants-service.git
cd surankutech-tenants-service

# Configure AWS CLI
aws configure

# Update kubeconfig
aws eks update-kubeconfig --region us-east-1 --name suranku-development-cluster

# Deploy to development
kubectl apply -k k8s/overlays/development

# Check deployment status
kubectl get pods -n development
kubectl logs -f deployment/tenants-service -n development
```

## 📝 Configuration Updates

### Database Connection
Update `k8s/overlays/development/secret-patch.yaml`:
```yaml
data:
  database-url: <base64-encoded-postgresql-connection-string>
```

### Storage Configuration
Update `k8s/overlays/development/configmap-patch.yaml`:
```yaml
data:
  storage-bucket-name: "your-s3-bucket-name"
  storage-region: "us-east-1"
```

## 🔍 Monitoring

### Health Check
```bash
kubectl port-forward service/tenants-service 8080:80 -n development
curl http://localhost:8080/health
```

### Logs
```bash
kubectl logs -f deployment/tenants-service -n development
```

### Scaling
```bash
kubectl scale deployment tenants-service --replicas=3 -n development
```

## 🛠 Troubleshooting

### Common Issues

1. **Image Pull Errors**
   ```bash
   kubectl describe pod <pod-name> -n development
   ```

2. **Database Connection Issues**
   ```bash
   kubectl exec -it deployment/tenants-service -n development -- env | grep DATABASE
   ```

3. **Service Discovery Issues**
   ```bash
   kubectl get svc -n development
   kubectl get endpoints -n development
   ```

### Debug Commands
```bash
# Check all resources
kubectl get all -n development

# Describe deployment
kubectl describe deployment tenants-service -n development

# Get events
kubectl get events -n development --sort-by='.lastTimestamp'
```