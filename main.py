"""
Tenant Service Main Application
Clean, modular FastAPI application using organized modules
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging
from datetime import datetime
from prometheus_fastapi_instrumentator import Instrumentator

# Import all module routers
from services.tenants.modules.tenant_management import router as tenant_router
from services.tenants.modules.authentication import router as auth_router
from services.tenants.modules.email_verification import router as email_router
from services.tenants.modules.user_management import router as user_router
from services.tenants.modules.user_profile import router as profile_router
from services.tenants.modules.social_auth import router as social_router
from services.tenants.modules.file_upload import router as upload_router
from services.tenants.modules.admin_info import router as admin_router
from services.tenants.modules.operator_integration import router as operator_router
from services.tenants.modules.ldap_management import router as ldap_router

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI application
app = FastAPI(
    title="Tenants Service",
    description="Multi-tenant user and organization management service",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Prometheus metrics instrumentation
Instrumentator().instrument(app).expose(app)

# CORS middleware for frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:3002",
        "http://localhost:8000",  # Kong Gateway frontend access
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",
        "http://127.0.0.1:3002",
        "http://127.0.0.1:8000"  # Kong Gateway frontend access
    ],
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
        "version": "2.0.0",
        "timestamp": datetime.utcnow().isoformat()
    }

# Include all module routers
app.include_router(tenant_router)           # /tenants/*
app.include_router(auth_router)             # /auth/*
app.include_router(email_router)            # /auth/verify-email, etc.
app.include_router(user_router)             # /tenants/{id}/users, etc.
app.include_router(profile_router)          # /user/profile, /user/password
app.include_router(social_router)           # /auth/social/*
app.include_router(upload_router)  # File upload routes (Kong strips /api/upload)
app.include_router(admin_router)            # /admin/* (platform administration)
app.include_router(operator_router)         # /operator/* (Kubernetes operator integration)
app.include_router(ldap_router)             # /tenants/{id}/ldap/* (LDAP/AD sync)

# Legacy auth endpoint support for backward compatibility
@app.post("/api/tenants/auth/login")
async def legacy_login_endpoint(request: dict):
    """Legacy login endpoint - redirects to main auth login"""
    from services.tenants.modules.authentication import login_user
    from services.tenants.schemas import LoginRequest
    from services.shared.database import get_db

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
        "version": "2.0.0",
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
    logger.info("🚀 Tenants Service v2.0.0 starting up...")
    logger.info("📦 Modules loaded: tenant_management, authentication, email_verification, user_management, social_auth, file_upload, ldap_management")
    logger.info("🔗 Keycloak integration enabled")
    logger.info("📧 Email verification enabled")
    logger.info("🌐 Social authentication enabled")
    logger.info("📁 File storage with MinIO enabled")
    logger.info("🔐 LDAP/AD sync enabled")
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