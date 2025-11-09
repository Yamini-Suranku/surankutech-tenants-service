# SurankuTech Tenants Service

Multi-tenant management microservice for the SurankuTech platform. Cloud-agnostic design supports deployment on AWS, GCP, Azure, or any Kubernetes cluster.

## Architecture

- **Framework**: FastAPI with uvicorn
- **Database**: PostgreSQL (cloud-agnostic: RDS, CloudSQL, Azure Database)
- **Storage**: S3-compatible object storage (AWS S3, GCS, Azure Blob, MinIO)
- **Cache**: Redis (cloud-agnostic: ElastiCache, Memorystore, Azure Cache)
- **Authentication**: Keycloak integration with JWT tokens
- **Containerization**: Docker with multi-stage builds
- **Orchestration**: Kubernetes with Kustomize for environment management

## Cloud Provider Support

| Provider | Database | Storage | Cache |
|----------|----------|---------|-------|
| AWS | RDS PostgreSQL | S3 | ElastiCache Redis |
| GCP | Cloud SQL PostgreSQL | Cloud Storage | Memorystore Redis |
| Azure | Azure Database PostgreSQL | Blob Storage | Azure Cache Redis |
| On-Premise | PostgreSQL | MinIO | Redis |

## Environment Configuration

### Development (Cost-Optimized)
```bash
# Deploy to development
kubectl apply -k k8s/overlays/development
```

**Note**: Only development environment is configured to minimize AWS costs. Staging and production environments can be added later when needed.

## Configuration

Update the following files for your environment:

1. **Storage Configuration** (`k8s/overlays/{env}/configmap-patch.yaml`):
   - `storage-type`: s3, gcs, azure, minio
   - `storage-endpoint`: Leave empty for AWS S3, set for other providers
   - `storage-bucket-name`: Your bucket/container name
   - `storage-region`: Your region

2. **Database Configuration** (`k8s/overlays/{env}/secret-patch.yaml`):
   - `database-url`: PostgreSQL connection string
   - `redis-url`: Redis connection string
   - `storage-access-key`: Access key for storage
   - `storage-secret-key`: Secret key for storage

## Local Development

```bash
# Run with Docker Compose (development dependencies)
docker-compose up -d

# Or run locally
pip install -r requirements.txt
uvicorn main:app --reload
```

## CI/CD

The repository includes GitHub Actions workflows for:
- Building Docker images
- Deploying to development environment only (cost-optimized)

### Required GitHub Environment Secrets (development environment):
- `AWS_ACCESS_KEY_ID` - AWS IAM access key with EKS permissions
- `AWS_SECRET_ACCESS_KEY` - AWS IAM secret key

### Setup Instructions:
1. Go to GitHub repo → Settings → Environments
2. Create `development` environment
3. Add the required secrets
4. See `DEPLOYMENT.md` for detailed setup instructions

## Health Checks

- Health endpoint: `/health`
- Kubernetes liveness probe: `/health`
- Kubernetes readiness probe: `/health`

## Security

- Non-root container user
- Minimal base image (python:3.11-slim)
- Security contexts in Kubernetes
- Secrets management via Kubernetes secrets