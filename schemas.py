from pydantic import BaseModel, Field, EmailStr, validator
from typing import Optional, List, Dict, Any
from datetime import datetime

# ===== TENANT SCHEMAS =====

class TenantCreateRequest(BaseModel):
    company_name: str = Field(..., min_length=2, max_length=100)
    admin_email: EmailStr
    admin_password: str = Field(..., min_length=8, max_length=128)
    admin_first_name: str = Field(..., min_length=1, max_length=50)
    admin_last_name: str = Field(..., min_length=1, max_length=50)
    company_size: Optional[str] = Field(None, max_length=50)
    industry: Optional[str] = Field(None, max_length=100)
    timezone: Optional[str] = Field("UTC", max_length=50)
    currency: Optional[str] = Field("USD", max_length=10)
    language: Optional[str] = Field("en", max_length=10)

class TenantResponse(BaseModel):
    id: str
    name: str
    subscription_status: str
    plan_id: str
    trial_expires_at: Optional[datetime] = None
    created_at: datetime
    admin_user: Optional["UserResponse"] = None
    # Organization/Company information
    logo_url: Optional[str] = None
    company_size: Optional[str] = None
    industry: Optional[str] = None
    company_website: Optional[str] = None
    company_description: Optional[str] = None

    class Config:
        from_attributes = True

class TenantUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    company_size: Optional[str] = Field(None, max_length=50)
    industry: Optional[str] = Field(None, max_length=100)
    company_website: Optional[str] = Field(None, max_length=255)
    company_description: Optional[str] = Field(None, max_length=1000)

class TenantSettingsResponse(BaseModel):
    timezone: str
    date_format: str
    time_format: str
    language: str
    currency: str
    company_size: Optional[str] = None
    industry: Optional[str] = None
    company_logo_url: Optional[str] = None
    company_website: Optional[str] = None
    company_description: Optional[str] = None
    session_timeout_minutes: int
    password_policy: Dict[str, Any]
    two_factor_required: bool
    allow_user_registration: bool
    require_email_verification: bool
    allow_social_login: bool
    allowed_social_providers: List[str]
    email_notifications: Dict[str, Any]
    api_rate_limits: Dict[str, Any]
    audit_log_retention_days: int

    class Config:
        from_attributes = True

class TenantSettingsUpdateRequest(BaseModel):
    timezone: Optional[str] = Field(None, max_length=50)
    date_format: Optional[str] = Field(None, max_length=20)
    time_format: Optional[str] = Field(None, max_length=20)
    language: Optional[str] = Field(None, max_length=10)
    currency: Optional[str] = Field(None, max_length=10)
    company_size: Optional[str] = Field(None, max_length=50)
    industry: Optional[str] = Field(None, max_length=100)
    company_logo_url: Optional[str] = Field(None, max_length=500)
    company_website: Optional[str] = Field(None, max_length=255)
    company_description: Optional[str] = Field(None, max_length=1000)
    session_timeout_minutes: Optional[int] = Field(None, ge=30, le=1440)
    password_policy: Optional[Dict[str, Any]] = None
    two_factor_required: Optional[bool] = None
    allow_user_registration: Optional[bool] = None
    require_email_verification: Optional[bool] = None
    allow_social_login: Optional[bool] = None
    allowed_social_providers: Optional[List[str]] = None
    email_notifications: Optional[Dict[str, Any]] = None
    api_rate_limits: Optional[Dict[str, Any]] = None
    audit_log_retention_days: Optional[int] = Field(None, ge=30, le=365)

# ===== USER SCHEMAS =====

class UserResponse(BaseModel):
    id: str
    email: str
    first_name: str
    last_name: str
    status: str
    avatar_url: Optional[str] = None
    app_roles: Optional[Dict[str, List[str]]] = None
    joined_at: Optional[datetime] = None
    last_login: Optional[datetime] = None
    social_accounts: Optional[List[Dict[str, Any]]] = []

    class Config:
        from_attributes = True

class UserInviteRequest(BaseModel):
    email: EmailStr
    app_roles: Dict[str, List[str]] = Field(..., description="App-specific roles")
    message: Optional[str] = Field(None, max_length=500)

    @validator('app_roles')
    def validate_app_roles(cls, v):
        valid_apps = ["darkhole", "darkfolio", "confiploy"]
        valid_roles = [
            # Legacy admin role (keep for backward compatibility)
            "admin",
            # DarkFolio roles
            "analyst",
            # ConfiPloy roles
            "devops-engineer", "release-manager",
            # New DarkHole roles
            "administrator", "model_engineer", "evaluator", "stuart", "consumer"
        ]

        for app_name, roles in v.items():
            if app_name not in valid_apps:
                raise ValueError(f"Invalid app name: {app_name}")
            for role in roles:
                if role not in valid_roles:
                    raise ValueError(f"Invalid role: {role}")
        return v

class UserUpdateRequest(BaseModel):
    first_name: Optional[str] = Field(None, min_length=1, max_length=50)
    last_name: Optional[str] = Field(None, min_length=1, max_length=50)
    app_roles: Optional[Dict[str, List[str]]] = None
    status: Optional[str] = Field(None, pattern="^(active|suspended|inactive)$")

class PaginationInfo(BaseModel):
    page: int
    size: int
    total: int
    pages: int

class UserListResponse(BaseModel):
    users: List[UserResponse]
    pagination: PaginationInfo

    class Config:
        from_attributes = True

# ===== INVITATION SCHEMAS =====

class InvitationResponse(BaseModel):
    id: str
    email: str
    app_roles: Dict[str, List[str]]
    status: str
    expires_at: datetime
    created_at: datetime
    invited_by: str
    resent_count: int
    last_sent_at: datetime

    class Config:
        from_attributes = True

class InvitationAcceptRequest(BaseModel):
    invitation_token: str = Field("", description="Legacy field, not required")
    password: str = Field(..., min_length=8, max_length=128)
    first_name: str = Field(..., min_length=1, max_length=50)
    last_name: str = Field(..., min_length=1, max_length=50)

class InvitationResendRequest(BaseModel):
    invitation_id: str
    message: Optional[str] = Field(None, max_length=500)

# ===== AUTH SCHEMAS =====

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1)

class TenantInfo(BaseModel):
    """Tenant information for user's tenant list"""
    id: str
    name: str
    domain: Optional[str] = None
    logo_url: Optional[str] = None
    roles: List[str] = []
    is_active: bool = True

    class Config:
        from_attributes = True

class UserMeResponse(BaseModel):
    """Response for /auth/me endpoint with full tenant information"""
    user: UserResponse
    tenants: List[TenantInfo] = []
    current_tenant: Optional[TenantInfo] = None

    class Config:
        from_attributes = True

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse
    tenants: List[TenantInfo] = []
    current_tenant: Optional[TenantInfo] = None

# ===== SOCIAL LOGIN SCHEMAS =====

class SocialLoginRequest(BaseModel):
    provider: str = Field(..., pattern="^(google|github|microsoft)$")
    redirect_uri: str = Field(..., max_length=500)

class SocialLoginResponse(BaseModel):
    provider: str
    auth_url: str
    state: str

class SocialAccountResponse(BaseModel):
    id: str
    provider: str
    email: str
    avatar_url: Optional[str] = None
    profile_url: Optional[str] = None
    is_active: bool
    last_login: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True

class SocialAccountLinkRequest(BaseModel):
    provider: str = Field(..., pattern="^(google|github|microsoft)$")
    auth_code: str
    redirect_uri: str

class SocialAccountUnlinkRequest(BaseModel):
    provider: str = Field(..., pattern="^(google|github|microsoft)$")

# ===== TENANT SWITCHING SCHEMAS =====

class TenantSwitchRequest(BaseModel):
    tenant_id: str

class TenantSwitchResponse(BaseModel):
    new_token: str
    active_tenant: str
    tenant_name: str
    app_access: List["AppAccessResponse"]

# ===== APP ACCESS SCHEMAS =====

class AppAccessResponse(BaseModel):
    app_name: str
    is_enabled: bool
    user_limit: int
    current_users: int
    enabled_features: List[str]

    class Config:
        from_attributes = True

# ===== API KEY SCHEMAS =====

class ApiKeyCreateRequest(BaseModel):
    name: str = Field(..., min_length=3, max_length=100)
    scopes: List[str] = Field(..., min_items=1)
    description: Optional[str] = Field(None, max_length=500)
    expires_in_days: Optional[int] = Field(None, ge=1, le=365)
    allowed_ips: Optional[List[str]] = None

class ApiKeyResponse(BaseModel):
    id: str
    name: str
    key_prefix: str
    scopes: List[str]
    is_active: bool
    last_used_at: Optional[datetime] = None
    usage_count: int
    expires_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True

class ApiKeyCreateResponse(BaseModel):
    api_key: str
    key_info: ApiKeyResponse

# ===== DOMAIN SCHEMAS =====

class DomainCreateRequest(BaseModel):
    domain: str = Field(..., max_length=255)
    subdomain: Optional[str] = Field(None, max_length=100)
    is_primary: Optional[bool] = False

class DomainResponse(BaseModel):
    id: str
    domain: str
    subdomain: Optional[str] = None
    is_primary: bool
    is_verified: bool
    ssl_enabled: bool
    dns_configured: bool
    created_at: datetime

    class Config:
        from_attributes = True

class DomainVerificationRequest(BaseModel):
    domain_id: str

class DomainVerificationResponse(BaseModel):
    domain: str
    verification_token: str
    dns_records: List[Dict[str, str]]
    instructions: str

# ===== AUDIT LOG SCHEMAS =====

class AuditLogResponse(BaseModel):
    id: str
    action: str
    resource_type: str
    resource_id: str
    user_id: str
    user_email: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    details: Dict[str, Any]
    created_at: datetime

    class Config:
        from_attributes = True

class AuditLogSearchRequest(BaseModel):
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    action: Optional[str] = None
    resource_type: Optional[str] = None
    user_id: Optional[str] = None
    limit: Optional[int] = Field(50, ge=1, le=100)
    offset: Optional[int] = Field(0, ge=0)

# ===== WEBHOOK SCHEMAS =====

class WebhookCreateRequest(BaseModel):
    url: str = Field(..., max_length=500)
    events: List[str] = Field(..., min_items=1)
    secret: Optional[str] = Field(None, max_length=255)
    is_active: Optional[bool] = True

class WebhookResponse(BaseModel):
    id: str
    url: str
    events: List[str]
    is_active: bool
    created_at: datetime
    last_triggered_at: Optional[datetime] = None

    class Config:
        from_attributes = True

# ===== ANALYTICS SCHEMAS =====

class TenantAnalyticsResponse(BaseModel):
    tenant_id: str
    active_users: int
    total_users: int
    apps_usage: Dict[str, Dict[str, Any]]
    subscription_info: Dict[str, Any]
    usage_trends: List[Dict[str, Any]]
    top_features: List[Dict[str, Any]]

# ===== LDAP CONFIGURATION SCHEMAS =====

class LDAPConfigCreateRequest(BaseModel):
    """Request schema for creating LDAP configuration"""
    # LDAP Server Configuration
    connection_url: str = Field(..., max_length=500, description="LDAP server URL (e.g., ldap://ad.company.com:389)")
    bind_dn: str = Field(..., max_length=500, description="Bind DN for LDAP authentication")
    bind_credential: str = Field(..., min_length=1, description="Bind password (will be encrypted)")
    connection_timeout: Optional[int] = Field(30, ge=5, le=300, description="Connection timeout in seconds")
    read_timeout: Optional[int] = Field(30, ge=5, le=300, description="Read timeout in seconds")
    use_truststore_spi: Optional[str] = Field("ldapsOnly", max_length=50)

    # User Search Configuration
    users_dn: str = Field(..., max_length=500, description="Base DN for user search (e.g., OU=Users,DC=company,DC=com)")
    user_object_class: Optional[str] = Field("person", max_length=100)
    username_ldap_attribute: Optional[str] = Field("sAMAccountName", max_length=100)
    rdn_ldap_attribute: Optional[str] = Field("cn", max_length=100)
    uuid_ldap_attribute: Optional[str] = Field("objectGUID", max_length=100)
    user_ldap_filter: Optional[str] = Field(None, description="Additional LDAP filter for users")
    search_scope: Optional[str] = Field("SUBTREE", pattern="^(ONE_LEVEL|SUBTREE)$")

    # User Attribute Mapping
    email_ldap_attribute: Optional[str] = Field("mail", max_length=100)
    first_name_ldap_attribute: Optional[str] = Field("givenName", max_length=100)
    last_name_ldap_attribute: Optional[str] = Field("sn", max_length=100)

    # Group Search Configuration
    groups_dn: Optional[str] = Field(None, max_length=500, description="Base DN for group search")
    group_object_class: Optional[str] = Field("group", max_length=100)
    group_name_ldap_attribute: Optional[str] = Field("cn", max_length=100)
    group_membership_attribute: Optional[str] = Field("member", max_length=100)
    group_membership_type: Optional[str] = Field("DN", pattern="^(DN|UID)$")

    # Sync Settings
    sync_registrations: Optional[bool] = Field(True, description="Allow new user registrations from LDAP")
    import_enabled: Optional[bool] = Field(True, description="Enable user import from LDAP")
    edit_mode: Optional[str] = Field("READ_ONLY", pattern="^(READ_ONLY|WRITABLE|UNSYNCED)$")
    vendor: Optional[str] = Field("ad", pattern="^(ad|rhds|tivoli|edirectory|other)$")

    # Sync Schedule
    full_sync_period: Optional[int] = Field(604800, ge=3600, description="Full sync period in seconds (default: 7 days)")
    changed_sync_period: Optional[int] = Field(86400, ge=1800, description="Incremental sync period in seconds (default: 1 day)")
    batch_size: Optional[int] = Field(1000, ge=100, le=10000, description="Batch size for sync operations")

    enabled: Optional[bool] = Field(False, description="Enable LDAP sync")

class LDAPConfigUpdateRequest(BaseModel):
    """Request schema for updating LDAP configuration"""
    connection_url: Optional[str] = Field(None, max_length=500)
    bind_dn: Optional[str] = Field(None, max_length=500)
    bind_credential: Optional[str] = Field(None, min_length=1)
    connection_timeout: Optional[int] = Field(None, ge=5, le=300)
    read_timeout: Optional[int] = Field(None, ge=5, le=300)
    use_truststore_spi: Optional[str] = Field(None, max_length=50)

    users_dn: Optional[str] = Field(None, max_length=500)
    user_object_class: Optional[str] = Field(None, max_length=100)
    username_ldap_attribute: Optional[str] = Field(None, max_length=100)
    rdn_ldap_attribute: Optional[str] = Field(None, max_length=100)
    uuid_ldap_attribute: Optional[str] = Field(None, max_length=100)
    user_ldap_filter: Optional[str] = None
    search_scope: Optional[str] = Field(None, pattern="^(ONE_LEVEL|SUBTREE)$")

    email_ldap_attribute: Optional[str] = Field(None, max_length=100)
    first_name_ldap_attribute: Optional[str] = Field(None, max_length=100)
    last_name_ldap_attribute: Optional[str] = Field(None, max_length=100)

    groups_dn: Optional[str] = Field(None, max_length=500)
    group_object_class: Optional[str] = Field(None, max_length=100)
    group_name_ldap_attribute: Optional[str] = Field(None, max_length=100)
    group_membership_attribute: Optional[str] = Field(None, max_length=100)
    group_membership_type: Optional[str] = Field(None, pattern="^(DN|UID)$")

    sync_registrations: Optional[bool] = None
    import_enabled: Optional[bool] = None
    edit_mode: Optional[str] = Field(None, pattern="^(READ_ONLY|WRITABLE|UNSYNCED)$")
    vendor: Optional[str] = Field(None, pattern="^(ad|rhds|tivoli|edirectory|other)$")

    full_sync_period: Optional[int] = Field(None, ge=3600)
    changed_sync_period: Optional[int] = Field(None, ge=1800)
    batch_size: Optional[int] = Field(None, ge=100, le=10000)

    enabled: Optional[bool] = None

class LDAPConfigResponse(BaseModel):
    """Response schema for LDAP configuration (credentials stored in Vault, not returned)"""
    id: str
    tenant_id: str
    enabled: bool

    # LDAP Server Configuration
    connection_url: str
    bind_dn: str
    # NOTE: bind_credential is stored in Vault and never returned in API responses
    connection_timeout: int
    read_timeout: int
    use_truststore_spi: str

    # User Search Configuration
    users_dn: str
    user_object_class: str
    username_ldap_attribute: str
    rdn_ldap_attribute: str
    uuid_ldap_attribute: str
    user_ldap_filter: Optional[str]
    search_scope: str

    # User Attribute Mapping
    email_ldap_attribute: str
    first_name_ldap_attribute: str
    last_name_ldap_attribute: str

    # Group Search Configuration
    groups_dn: Optional[str]
    group_object_class: str
    group_name_ldap_attribute: str
    group_membership_attribute: str
    group_membership_type: str

    # Sync Settings
    sync_registrations: bool
    import_enabled: bool
    edit_mode: str
    vendor: str

    # Sync Schedule
    full_sync_period: int
    changed_sync_period: int
    batch_size: int

    # Sync Status
    last_sync_at: Optional[datetime]
    last_sync_status: Optional[str]
    last_sync_users_count: int
    last_sync_groups_count: int
    last_sync_error: Optional[str]

    # Keycloak Integration
    keycloak_federation_id: Optional[str]
    keycloak_group_mapper_id: Optional[str]

    # Metadata
    created_at: datetime
    updated_at: datetime
    created_by: Optional[str]

    class Config:
        from_attributes = True

class LDAPTestConnectionRequest(BaseModel):
    """Request to test LDAP connection"""
    connection_url: str = Field(..., max_length=500)
    bind_dn: str = Field(..., max_length=500)
    bind_credential: str = Field(..., min_length=1)
    connection_timeout: Optional[int] = Field(30, ge=5, le=300)

class LDAPTestConnectionResponse(BaseModel):
    """Response from LDAP connection test"""
    success: bool
    message: str
    details: Optional[Dict[str, Any]] = None
    server_info: Optional[Dict[str, Any]] = None

class LDAPSyncTriggerRequest(BaseModel):
    """Request to trigger manual LDAP sync"""
    sync_type: str = Field("full", pattern="^(full|incremental)$")
    force: Optional[bool] = Field(False, description="Force sync even if recently synced")

class LDAPSyncStatusResponse(BaseModel):
    """Current sync status response"""
    is_syncing: bool
    last_sync_at: Optional[datetime]
    last_sync_status: Optional[str]
    last_sync_users_count: int
    last_sync_groups_count: int
    last_sync_error: Optional[str]
    next_full_sync_at: Optional[datetime]
    next_incremental_sync_at: Optional[datetime]

class LDAPSyncHistoryResponse(BaseModel):
    """LDAP sync history entry"""
    id: str
    tenant_id: str
    ldap_config_id: str
    sync_type: str
    sync_status: str
    users_added: int
    users_updated: int
    users_removed: int
    groups_added: int
    groups_updated: int
    groups_removed: int
    started_at: datetime
    completed_at: Optional[datetime]
    duration_seconds: Optional[int]
    error_message: Optional[str]
    details: Optional[Dict[str, Any]]
    triggered_by: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True

class LDAPSyncHistoryListResponse(BaseModel):
    """List of LDAP sync history entries"""
    history: List[LDAPSyncHistoryResponse]
    pagination: PaginationInfo

    class Config:
        from_attributes = True

class LDAPUserPreviewResponse(BaseModel):
    """Preview of users that will be synced from LDAP"""
    total_users: int
    sample_users: List[Dict[str, Any]]
    groups: List[str]
    warnings: List[str]

# Forward reference resolution
TenantResponse.model_rebuild()
TenantSwitchResponse.model_rebuild()