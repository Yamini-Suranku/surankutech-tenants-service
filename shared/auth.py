from jose import JWTError, jwt, jwk
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import requests
from typing import Optional, Dict, List
import logging
import re

logger = logging.getLogger(__name__)

KEYCLOAK_URL = "http://keycloak.shared-services.svc.cluster.local:8080"
REALM = "suranku-platform"

# Security scheme for JWT tokens
security = HTTPBearer()

class TokenData:
    def __init__(self, token_data: dict):
        self.sub = token_data.get("sub")  # User ID
        self.user_id = token_data.get("sub")  # Alias for user_id
        self.email = token_data.get("email")
        self.name = token_data.get("name")
        self.preferred_username = token_data.get("preferred_username")
        self.tenant_id = token_data.get("tenant_id")  # Current tenant from JWT
        self.active_tenant = token_data.get("active_tenant")
        self.all_tenants = token_data.get("all_tenants", [])
        self.resource_access = token_data.get("resource_access", {})
        self.app_roles = token_data.get("app_roles", {})  # New app_roles format
        self.plan = token_data.get("plan", "free")
        self.trial_expires = token_data.get("trial_expires")
        self.groups = token_data.get("groups", [])

        # Enhanced organization support for multi-tenant isolation
        self.current_org = token_data.get("current_org", {})
        self.org_memberships = token_data.get("org_memberships", [])

async def verify_token(token: str) -> Optional[TokenData]:
    """Verify JWT token with Keycloak and return user data"""
    try:
        # Debug: Basic token info
        token_parts = token.split('.')
        logger.info(f"🔍 JWT token segments: {len(token_parts)}")
        logger.info(f"📏 Token length: {len(token)} chars")
        logger.info(f"🎯 Token preview: {token[:50]}...{token[-20:] if len(token) > 70 else ''}")

        # Get Keycloak public key
        jwks_url = f"{KEYCLOAK_URL}/realms/{REALM}/.well-known/openid-configuration"
        logger.info(f"Fetching Keycloak config from: {jwks_url}")
        response = requests.get(jwks_url, timeout=10)
        response.raise_for_status()
        jwks_uri = response.json()["jwks_uri"]
        logger.info(f"JWKS URI: {jwks_uri}")

        jwks_response = requests.get(jwks_uri, timeout=10)
        jwks_response.raise_for_status()
        jwks = jwks_response.json()
        logger.info(f"Retrieved {len(jwks.get('keys', []))} keys from JWKS")

        # Decode token
        payload = jwt.decode(
            token,
            jwks,
            algorithms=["RS256"],
            options={"verify_signature": True, "verify_aud": False, "verify_exp": True}
        )

        # Add detailed debugging of the complete token payload
        logger.info(f"🎯 Complete JWT payload: {payload}")
        logger.info(f"🔍 Token claims - sub: {payload.get('sub')}, email: {payload.get('email')}")
        logger.info(f"🔍 Token claims - groups: {payload.get('groups', [])}")
        logger.info(f"🔍 Token claims - tenant_id: {payload.get('tenant_id')}")
        logger.info(f"🔍 Token claims - active_tenant: {payload.get('active_tenant')}")
        logger.info(f"🔍 Token claims - all_tenants: {payload.get('all_tenants', [])}")

        token_data = TokenData(payload)
        logger.info(f"Token verification successful. User: {token_data.email}")
        logger.info(f"📦 TokenData - active_tenant: {token_data.active_tenant}, tenant_id: {token_data.tenant_id}")
        logger.info(f"📦 TokenData - all_tenants: {token_data.all_tenants}, groups: {token_data.groups}")
        logger.info(f"📦 TokenData - app_roles: {token_data.app_roles}")
        logger.info(f"🔍 Raw token resource_access: {payload.get('resource_access', {})}")
        return token_data

    except JWTError as e:
        logger.error(f"JWT validation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except requests.RequestException as e:
        logger.error(f"Keycloak connection error: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service unavailable"
        )

# ========== HOSTNAME AND ORGANIZATION UTILITIES ==========

def extract_subdomain_from_hostname(hostname: str) -> Optional[str]:
    """
    Extract organization slug from hostname for DNS-based org resolution.

    Supported patterns:
    - acme.darkhole.suranku.net -> "acme"
    - dnstest.darkhole.suranku.net -> "dnstest"
    - acme.darkhole.local.suranku -> "acme" (development)
    - darkhole.suranku.net -> None (no org subdomain)

    Args:
        hostname: The hostname from request headers

    Returns:
        Organization slug if found, None otherwise
    """
    if not hostname:
        return None

    # Remove port if present
    hostname = hostname.split(':')[0].lower()

    # Patterns for org subdomain extraction
    patterns = [
        r"^([a-z0-9\-]+)\.darkhole\.suranku\.(net|com)$",          # Production
        r"^([a-z0-9\-]+)\.darkhole\.local\.suranku$",             # Development
        r"^([a-z0-9\-]+)\.darkfolio\.suranku\.(net|com)$",        # Darkfolio app
        r"^([a-z0-9\-]+)\.confiploy\.suranku\.(net|com)$",        # Confiploy app
    ]

    for pattern in patterns:
        match = re.match(pattern, hostname)
        if match:
            org_slug = match.group(1)
            # Skip shared/common subdomains
            if org_slug not in ['shared', 'api', 'www', 'admin', 'status']:
                logger.info(f"📍 Extracted org slug '{org_slug}' from hostname '{hostname}'")
                return org_slug

    logger.debug(f"🔍 No org slug found in hostname '{hostname}'")
    return None

def require_org_app_role(token_data: TokenData, hostname: str, app_client: str, required_role: str) -> bool:
    """
    Check if user has specific role in app for the organization determined by hostname.

    This is the enhanced version that provides proper organization-level isolation
    to prevent cross-org access vulnerabilities.

    Args:
        token_data: Validated JWT token data
        hostname: Request hostname (e.g., "acme.darkhole.suranku.net")
        app_client: App client name (e.g., "darkhole", "darkfolio")
        required_role: Required role (e.g., "admin", "consumer")

    Returns:
        True if user has the required role for this org's app, False otherwise

    Raises:
        HTTPException: If user has no access to the organization
    """
    logger.info(f"🔐 ORG ROLE CHECK: hostname={hostname}, app={app_client}, role={required_role}")
    logger.info(f"👤 User: {getattr(token_data, 'email', 'unknown')}")

    # Extract organization slug from hostname
    org_slug = extract_subdomain_from_hostname(hostname)
    if not org_slug:
        logger.warning(f"⚠️ No org slug in hostname '{hostname}', falling back to legacy validation")
        # Fallback to legacy role checking for domains without org subdomains
        return require_app_role(token_data, app_client, required_role)

    logger.info(f"🏢 Target organization: {org_slug}")

    # Check if token has org memberships (future enhancement)
    org_memberships = getattr(token_data, 'org_memberships', [])
    if org_memberships:
        logger.info(f"📋 User org memberships: {[m.get('org_slug') for m in org_memberships]}")

        # Find matching organization membership
        for org_membership in org_memberships:
            if org_membership.get('org_slug') == org_slug:
                org_app_roles = org_membership.get('app_roles', {}).get(app_client, [])
                logger.info(f"🎯 User roles in {org_slug}.{app_client}: {org_app_roles}")

                if required_role in org_app_roles:
                    logger.info(f"✅ Access granted: {required_role} found in org-specific roles")
                    return True
                else:
                    logger.warning(f"❌ Access denied: {required_role} not in org-specific roles {org_app_roles}")
                    return False

        logger.warning(f"❌ Access denied: User not member of organization '{org_slug}'")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: No membership in organization '{org_slug}'"
        )

    # Temporary fallback: Use legacy role checking with additional org validation
    # TODO: Remove this once org_memberships are properly populated in tokens
    logger.info("🔄 Using legacy role validation with org context (TEMPORARY)")

    # For now, we'll validate using groups or tenant context
    # This is a temporary security measure until full org tokens are implemented
    user_groups = getattr(token_data, 'groups', [])
    logger.info(f"👥 User groups: {user_groups}")

    # Check if user has any group that suggests org access
    org_related_groups = [g for g in user_groups if org_slug in g.lower()]
    if not org_related_groups:
        logger.warning(f"❌ Access denied: No org-related groups for '{org_slug}'")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: No access to organization '{org_slug}'"
        )

    # Use legacy role checking as fallback
    has_role = require_app_role(token_data, app_client, required_role)
    if has_role:
        logger.info(f"✅ Access granted via legacy validation for {org_slug}")
        return True

    logger.warning(f"❌ Access denied: Role '{required_role}' not found for {app_client}")
    return False

async def get_current_token_data(credentials: HTTPAuthorizationCredentials = Depends(security)) -> TokenData:
    """FastAPI dependency to extract and verify JWT token from Authorization header"""
    try:
        logger.info(f"📥 Received credentials object: {type(credentials)}")
        logger.info(f"📥 Credentials.credentials type: {type(credentials.credentials)}")
        logger.info(f"📥 Token preview: {credentials.credentials[:50] if credentials.credentials else 'NONE'}...")

        token_data = await verify_token(credentials.credentials)
        logger.info(f"🎉 Token verification successful for user: {token_data.email}")
        logger.info(f"🔑 User resource_access: {getattr(token_data, 'resource_access', {})}")
        logger.info(f"🎭 User app_roles: {getattr(token_data, 'app_roles', {})}")
        logger.info(f"👥 User groups: {getattr(token_data, 'groups', [])}")
        return token_data
    except Exception as e:
        logger.error(f"Token verification failed: {e}")
        raise

def require_tenant_access(token_data: TokenData, tenant_id: str) -> bool:
    """Check if user has access to specific tenant"""
    return tenant_id in token_data.all_tenants

def require_app_role(token_data: TokenData, app_client: str, required_role: str) -> bool:
    """
    Check if user has specific role in app (LEGACY - use require_org_app_role for org-scoped validation)

    ⚠️ SECURITY NOTICE: This function provides tenant-level role validation only.
    For organization-level isolation, use require_org_app_role() instead.
    """
    logger.warning(f"⚠️ LEGACY AUTH: Using tenant-level role validation (consider require_org_app_role)")
    logger.info(f"🔍 ROLE CHECK START: app_client={app_client}, required_role={required_role}")
    logger.info(f"👤 User: {getattr(token_data, 'email', 'unknown')}")
    logger.info(f"🔑 Token resource_access: {getattr(token_data, 'resource_access', {})}")
    logger.info(f"🎭 Token app_roles: {getattr(token_data, 'app_roles', {})}")

    # Check resource_access format - try both the exact app_client and with "-client" suffix
    resource_access = getattr(token_data, 'resource_access', {})

    # First try the exact app_client name
    app_access = resource_access.get(app_client, {})
    roles = app_access.get("roles", [])
    logger.info(f"📋 Resource access roles for {app_client}: {roles}")

    if required_role in roles:
        logger.info(f"✅ Found {required_role} in resource_access for {app_client}")
        return True

    # If not found and app_client doesn't end with "-client", try with "-client" suffix
    if not app_client.endswith("-client"):
        client_name = f"{app_client}-client"
        app_access = resource_access.get(client_name, {})
        roles = app_access.get("roles", [])
        logger.info(f"📋 Resource access roles for {client_name}: {roles}")

        if required_role in roles:
            logger.info(f"✅ Found {required_role} in resource_access for {client_name}")
            return True

    # If not found in resource_access, check the app_roles format
    # Map app_client names: "darkhole-client" -> "darkhole", "connectors-client" -> "connectors"
    app_name = app_client.replace("-client", "") if app_client.endswith("-client") else app_client
    app_roles = getattr(token_data, 'app_roles', {}).get(app_name, [])
    logger.info(f"🎯 App roles for {app_name}: {app_roles}")

    result = required_role in app_roles
    logger.info(f"🏁 ROLE CHECK RESULT: {result}")
    if not result:
        logger.warning(f"❌ User {getattr(token_data, 'email', 'unknown')} lacks {required_role} role for {app_client}")
    return result

def get_user_tenant_id(token_data: TokenData) -> str:
    """Extract tenant ID from token groups"""
    if not token_data.groups:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tenant access found"
        )

    # Groups format: ["tenant123"]
    tenant_group = token_data.groups[0]
    if not tenant_group.startswith("tenant"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid tenant group format"
        )

    return tenant_group.replace("tenant", "")

def get_user_tenant_id_from_db(token_data: TokenData, db) -> str:
    """Get tenant ID from database using user's ID - fallback when groups aren't available"""
    from shared.models import User, UserTenant

    # Get user from database
    user = db.query(User).filter(User.keycloak_id == token_data.sub).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Get user's tenant relationship
    user_tenant = db.query(UserTenant).filter(UserTenant.user_id == user.id).first()
    if not user_tenant:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tenant access found for user"
        )

    return user_tenant.tenant_id

def get_tenant_id_safe(token_data: TokenData, db=None) -> str:
    """Safely get tenant ID - try groups first, fallback to database if available"""
    try:
        # Try to get from groups first (preferred method)
        return get_user_tenant_id(token_data)
    except HTTPException:
        # If groups not available and database provided, try database lookup
        if db is not None:
            return get_user_tenant_id_from_db(token_data, db)
        # If no database available, re-raise the original exception
        raise

def check_feature_access(token_data: TokenData, app: str, feature: str) -> bool:
    """Check if user has access to specific feature based on plan"""
    # During trial, all features are available
    if token_data.trial_expires and token_data.plan == "trial":
        return True

    # Feature access based on plan
    feature_matrix = {
        "free": {
            "darkhole": ["admin", "administrator", "consumer"],
            "darkfolio": ["admin", "user"],
            "confiploy": ["admin", "user"]
        },
        "pro": {
            "darkhole": ["admin", "administrator", "model_engineer", "evaluator", "stuart", "consumer"],
            "darkfolio": ["admin", "user", "stuart", "analyst", "reports"],
            "confiploy": ["admin", "user", "devops-engineer", "release-manager", "pipelines"]
        },
        "enterprise": ["all"]  # All features
    }

    if token_data.plan == "enterprise":
        return True

    allowed_features = feature_matrix.get(token_data.plan, {}).get(app, [])
    return feature in allowed_features

def require_darkhole_admin_access(token_data: TokenData, app_client: str = "darkhole") -> bool:
    """Check if user has DarkHole admin access (legacy admin or new administrator roles)"""
    return (require_app_role(token_data, app_client, "admin") or
            require_app_role(token_data, app_client, "administrator"))

def require_model_approval_access(token_data: TokenData, app_client: str) -> bool:
    """Check if user has model approval access (admin, administrator, evaluator, or stuart roles)"""
    return (require_app_role(token_data, app_client, "admin") or
            require_app_role(token_data, app_client, "administrator") or
            require_app_role(token_data, app_client, "evaluator") or
            require_app_role(token_data, app_client, "stuart"))

def require_platform_admin_access(token_data: TokenData) -> bool:
    """Check if user has platform administrator access for cross-tenant operations"""
    logger.info(f"🔍 PLATFORM ADMIN CHECK START for user: {getattr(token_data, 'email', 'unknown')}")
    logger.info(f"👥 User groups: {getattr(token_data, 'groups', [])}")

    # Check if user belongs to platform administrators group
    platform_admin_groups = ["platform-admins", "platform-admin", "admin", "superadmin"]
    user_groups = getattr(token_data, 'groups', [])

    for group in user_groups:
        if group.lower() in platform_admin_groups:
            logger.info(f"✅ User has platform admin access via group: {group}")
            return True

    # Also check if user has admin roles across multiple tenants (indicates platform admin)
    app_roles = getattr(token_data, 'app_roles', {})
    all_tenants = getattr(token_data, 'all_tenants', [])

    if len(all_tenants) >= 2:  # If user has access to multiple tenants
        admin_tenant_count = 0
        for app_name in ["darkhole", "darkfolio", "confiploy"]:
            app_tenant_roles = app_roles.get(app_name, [])
            if any(role in ["admin", "administrator"] for role in app_tenant_roles):
                admin_tenant_count += 1

        if admin_tenant_count >= 1:  # Has admin role in at least one app
            logger.info(f"✅ User has platform admin access via multi-tenant admin roles")
            return True

    logger.warning(f"❌ User {getattr(token_data, 'email', 'unknown')} lacks platform admin access")
    return False

async def get_current_user(token_data: TokenData = Depends(get_current_token_data)):
    """Get current user information from token data"""
    return token_data