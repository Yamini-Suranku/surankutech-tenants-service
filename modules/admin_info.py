"""
Admin Info routes for platform-wide administration
Provides authentication server information and platform statistics
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Dict, Any, List
import logging
import os
from datetime import datetime

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))

from services.shared.database import get_db
from services.shared.auth import get_current_token_data, TokenData, require_app_role
from services.shared.models import User, Tenant

router = APIRouter()
logger = logging.getLogger(__name__)

def require_platform_admin(token_data: TokenData) -> bool:
    """Check if user has platform admin access"""
    return require_app_role(token_data, "darkhole", "admin")

@router.get("/admin/auth-server-info")
async def get_auth_server_info(
    token_data: TokenData = Depends(get_current_token_data),
    db: Session = Depends(get_db)
):
    """Get authentication server configuration and statistics"""
    try:
        if not require_platform_admin(token_data):
            raise HTTPException(status_code=403, detail="Platform admin access required")

        # Get user statistics
        total_users = db.query(User).count()
        active_users = db.query(User).filter(User.is_active == True).count()
        total_tenants = db.query(Tenant).count()
        active_tenants = db.query(Tenant).filter(Tenant.is_active == True).count()

        # Detect authentication configuration
        keycloak_enabled = bool(os.getenv('KEYCLOAK_SERVER_URL'))
        ldap_enabled = bool(os.getenv('LDAP_SERVER_URL'))

        # Build auth methods array
        auth_methods = []
        primary_auth_method = "internal"

        if keycloak_enabled:
            auth_methods.append({
                "type": "keycloak",
                "config": {
                    "server": os.getenv('KEYCLOAK_SERVER_URL', 'http://localhost:8080'),
                    "realm": os.getenv('KEYCLOAK_REALM', 'suranku-platform'),
                    "client_id": os.getenv('KEYCLOAK_CLIENT_ID', 'suranku-api')
                },
                "status": "active",
                "user_sync": "enabled"
            })
            primary_auth_method = "keycloak"

        if ldap_enabled:
            auth_methods.append({
                "type": "ldap",
                "config": {
                    "server": os.getenv('LDAP_SERVER_URL'),
                    "base_dn": os.getenv('LDAP_BASE_DN'),
                    "bind_dn": os.getenv('LDAP_BIND_DN')
                },
                "status": "active",
                "user_sync": "enabled"
            })
            if primary_auth_method == "internal":
                primary_auth_method = "ldap"

        # Always include internal auth as fallback
        auth_methods.append({
            "type": "internal",
            "config": {
                "password_policy": "standard",
                "session_timeout": "24h"
            },
            "status": "active",
            "user_sync": "local"
        })

        # Build response
        response = {
            "auth_methods": auth_methods,
            "primary_auth_method": primary_auth_method,
            "user_statistics": {
                "total": total_users,
                "active": active_users,
                "keycloak": total_users if keycloak_enabled else 0,  # Simplified for now
                "local": total_users if not keycloak_enabled else 0,
                "tenants": {
                    "total": total_tenants,
                    "active": active_tenants
                }
            },
            "last_sync": datetime.utcnow().isoformat(),
            "server_status": "healthy"
        }

        logger.info(f"Retrieved auth server info for admin user {token_data.sub}")
        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving auth server info: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve authentication server information")