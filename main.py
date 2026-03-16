"""
Tenant Service Main Application
Clean, modular FastAPI application using organized modules
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os
import logging
from datetime import datetime
from prometheus_fastapi_instrumentator import Instrumentator
from shared.database import get_db, SessionLocal

# Import all module routers
from modules.tenant_management import router as tenant_router
from modules.organization_management import router as org_router
from modules.organization_roles import router as org_roles_router
from modules.platform_organization_management import router as platform_org_router
from modules.authentication import router as auth_router
from modules.email_verification import router as email_router
from modules.user_management import router as user_router
from modules.user_profile import router as profile_router
from modules.social_auth import router as social_router
from modules.file_upload import router as upload_router
from modules.admin_info import router as admin_router
from modules.operator_integration import router as operator_router
from modules.ldap_management import router as ldap_router
from modules.darkhole_proxy import router as darkhole_proxy_router
from modules.organization_access_api import router as org_access_router
from modules.organization_azure_ad import router as org_azure_ad_router
from modules.organization_groups import router as org_groups_router
from modules.directory_user_sync import router as directory_sync_router
from modules.token_enhancement_api import router as token_enhancement_router
from modules.audit_events import router as audit_events_router

# Import organization resolver routes for DNS-based org resolution
from org_resolver_routes import router as org_resolver_router

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI application
app = FastAPI(
    title="Tenants Service",
    description="Multi-tenant user and organization management service",
    version="2.0.1",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Prometheus metrics instrumentation
Instrumentator().instrument(app).expose(app)

# CORS middleware for frontend access
default_allowed_origins = [
    "http://localhost:3000",
    "http://localhost:3001",
    "http://localhost:3002",
    "http://localhost:8000",  # Kong Gateway frontend access
    "http://127.0.0.1:3000",
    "http://127.0.0.1:3001",
    "http://127.0.0.1:3002",
    "http://127.0.0.1:8000",  # Kong Gateway frontend access
    "https://home.local.suranku",
    "https://id.local.suranku",
    "https://api.local.suranku",
    "https://palls.local.suranku",
]

additional_origins = os.getenv("CORS_ALLOW_ORIGINS")
if additional_origins:
    default_allowed_origins.extend(
        origin.strip() for origin in additional_origins.split(",") if origin.strip()
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=default_allowed_origins,
    # Allow dynamic org data-plane and control-plane subdomains.
    # Example: https://acme.suranku.net, https://platform.suranku.com
    allow_origin_regex=r"^https:\/\/([a-z0-9-]+\.)*suranku\.(net|com)$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["*"],
)

# Health check endpoint
@app.get("/health")
async def health_check():
    """Service health check endpoint"""
    return {
        "status": "healthy",
        "service": "tenants",
        "version": "2.0.1",
        "timestamp": datetime.utcnow().isoformat()
    }

KEYCLOAK_ORG_MAPPER_CLIENTS = [
    "platform-frontend",
    "darkhole-client",
    "darkfolio-client",
    "confiploy-client",
]


@app.post("/api/admin/setup-org-mappers")
async def setup_org_mappers_endpoint():
    """
    Manually trigger setup of organization-scoped protocol mappers
    Use this endpoint if automatic startup setup failed
    """
    try:
        from modules.keycloak_client import KeycloakClient

        keycloak_client = KeycloakClient()
        configured = {}
        for client_id in KEYCLOAK_ORG_MAPPER_CLIENTS:
            configured[client_id] = await keycloak_client.ensure_client_org_mappers(client_id)

        configured_count = sum(1 for m in configured.values() if m)
        if configured_count:
            return {
                "status": "success",
                "message": "Organization-scoped mappers configured successfully",
                "clients": configured,
            }
        else:
            return {
                "status": "warning",
                "message": "No mappers were created (they may already exist)",
                "clients": configured,
            }

    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to setup organization mappers: {str(e)}",
                "suggestion": "Check Keycloak connectivity and configured clients exist"
        }

# Include all module routers
app.include_router(tenant_router)           # /tenants/*
app.include_router(org_router)              # /tenants/{id}/orgs/* and /orgs/* (organization management)
app.include_router(org_roles_router)        # /tenants/{id}/orgs/{id}/roles/*
app.include_router(platform_org_router)     # /api/platform/organizations/* (platform user org management)
app.include_router(user_router)             # /tenants/{id}/users, etc. (must come after org_router to avoid conflicts)
app.include_router(auth_router)             # /auth/*
app.include_router(email_router)            # /auth/verify-email, etc.
app.include_router(profile_router)          # /user/profile, /user/password
app.include_router(social_router)           # /auth/social/*
app.include_router(upload_router)  # File upload routes (Kong strips /api/upload)
app.include_router(admin_router)            # /admin/* (platform administration)
app.include_router(operator_router)         # /operator/* (Kubernetes operator integration)
app.include_router(ldap_router)             # /tenants/{id}/ldap/* (LDAP/AD sync)
app.include_router(darkhole_proxy_router)   # /tenants/{id}/orgs/{id}/apps/darkhole/*
app.include_router(org_access_router)       # /api/access/* (organization access control)
app.include_router(org_azure_ad_router)     # /api/platform/organizations/{id}/azure-ad/* (org Azure AD integration)
app.include_router(org_groups_router)       # /api/platform/organizations/{id}/groups/* (manual groups management)
app.include_router(directory_sync_router)   # /api/platform/organizations/{id}/sync-directory-to-platform (directory to platform sync)
app.include_router(token_enhancement_router) # /api/token-enhancement/* (JWT token enhancement for Keycloak)
app.include_router(audit_events_router)      # /api/audit/* (centralized audit ingestion)
app.include_router(org_resolver_router)       # /api/organizations/* (org resolution for DNS routing)

# Legacy auth endpoint support for backward compatibility
@app.post("/api/tenants/auth/login")
async def legacy_login_endpoint(request: dict):
    """Legacy login endpoint - redirects to main auth login"""
    from modules.authentication import login_user
    from schemas import LoginRequest

    # Convert dict to LoginRequest
    login_request = LoginRequest(**request)
    db = next(get_db())

    try:
        return await login_user(login_request, db)
    finally:
        db.close()

# API documentation and info endpoints
@app.get("/info")
async def service_info():
    """Service information and module status"""
    return {
        "service": "tenants",
        "version": "2.0.1",
        "modules": {
            "tenant_management": "✅ Active",
            "authentication": "✅ Active",
            "email_verification": "✅ Active",
            "user_management": "✅ Active",
            "social_auth": "✅ Active",
            "file_upload": "✅ Active",
            "admin_info": "✅ Active",
            "ldap_management": "✅ Active"
        },
        "features": {
            "multi_tenant": True,
            "keycloak_integration": True,
            "email_verification": True,
            "social_login": True,
            "file_storage": True,
            "audit_logging": True,
            "ldap_sync": True
        },
        "endpoints": {
            "tenant_creation": "/tenants",
            "user_login": "/auth/login",
            "user_registration": "/auth/register",
            "email_verification": "/auth/verify-email",
            "social_login": "/auth/social/providers",
            "file_upload": "/upload/users/{id}/avatar",
            "logo_upload": "/upload/tenants/{id}/logo",
            "storage_health": "/upload/storage/health",
            "ldap_config": "/tenants/{id}/ldap/config",
            "ldap_sync": "/tenants/{id}/ldap/sync"
        }
    }

# Application startup event
@app.on_event("startup")
async def startup_event():
    """Application startup tasks"""
    logger.info("🚀 Tenants Service v2.0.1 starting up...")
    logger.info("📦 Modules loaded: tenant_management, organization_management, authentication, email_verification, user_management, social_auth, file_upload, ldap_management")
    logger.info("🔗 Keycloak integration enabled")
    logger.info("📧 Email verification enabled")
    logger.info("🌐 Social authentication enabled")
    logger.info("📁 File storage with MinIO enabled")
    logger.info("🔐 LDAP/AD sync enabled")

    # Auto-setup organization-scoped protocol mappers on startup
    try:
        logger.info("🔧 Setting up organization-scoped protocol mappers...")
        from modules.keycloak_client import KeycloakClient

        keycloak_client = KeycloakClient()
        configured_clients = 0
        for client_id in KEYCLOAK_ORG_MAPPER_CLIENTS:
            mappers = await keycloak_client.ensure_client_org_mappers(client_id)
            if mappers:
                configured_clients += 1
                logger.info(
                    "✅ Organization-scoped mappers configured for %s: %s",
                    client_id,
                    list(mappers.keys()),
                )
            else:
                logger.warning("⚠️  No organization mappers configured for %s", client_id)

        if configured_clients == 0:
            logger.warning("⚠️  No organization mappers configured for any client")

    except Exception as e:
        logger.warning(f"⚠️  Failed to auto-setup org mappers: {e}")
        logger.info("💡 Run manually: python scripts/setup_unified_org_mappers.py")

    # Normalize any legacy local DNS records to the configured public data-plane zone.
    try:
        from modules.organization_management import repair_legacy_local_dns_records

        db = SessionLocal()
        try:
            repair_counts = repair_legacy_local_dns_records(db)
        finally:
            db.close()

        logger.info(
            "🛠️  DNS normalization complete: organizations=%s org_app_access=%s",
            repair_counts.get("organizations", 0),
            repair_counts.get("org_app_access", 0),
        )
    except Exception as e:
        logger.warning(f"⚠️  Failed DNS normalization step: {e}")

    logger.info("✅ Tenants Service ready!")

# Application shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Application shutdown tasks"""
    logger.info("🛑 Tenants Service shutting down...")
    logger.info("👋 Goodbye!")

# Main entry point
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
