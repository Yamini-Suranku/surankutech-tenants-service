from sqlalchemy import Column, String, Text, Boolean, DateTime, Integer, JSON, ForeignKey, Index, UniqueConstraint
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
import sys
from pathlib import Path

# Add parent directory to path to import shared modules
sys.path.append(str(Path(__file__).parent.parent))
from services.shared.database import Base
# Import shared models to ensure they're registered with SqlAlchemy metadata
from services.shared.models import Tenant  # Ensure Tenant model is available for foreign keys

class Invitation(Base):
    __tablename__ = "invitations"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    email = Column(String(255), nullable=False, index=True)
    app_roles = Column(JSON, nullable=False)
    invited_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    status = Column(String(20), default="pending", index=True)
    expires_at = Column(DateTime, nullable=False, index=True)
    accepted_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Additional fields
    invitation_token = Column(String(255), nullable=True, unique=True, index=True)
    resent_count = Column(Integer, default=0)
    last_sent_at = Column(DateTime, default=datetime.utcnow)

    # Relationships - simplified to avoid circular import issues

    # Constraints and indexes
    __table_args__ = (
        UniqueConstraint('tenant_id', 'email', name='uix_tenant_email_invitation'),
        Index('idx_invitation_status_expires', 'status', 'expires_at'),
        Index('idx_invitation_tenant_status', 'tenant_id', 'status'),
    )

class TenantSettings(Base):
    __tablename__ = "tenant_settings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)

    # Localization
    timezone = Column(String(50), default="UTC")
    date_format = Column(String(20), default="YYYY-MM-DD")
    time_format = Column(String(20), default="HH:mm")
    language = Column(String(10), default="en")
    currency = Column(String(10), default="USD")

    # Company information
    company_size = Column(String(50), nullable=True)
    industry = Column(String(100), nullable=True)
    company_logo_url = Column(String(500), nullable=True)
    company_website = Column(String(255), nullable=True)
    company_description = Column(Text, nullable=True)

    # Security settings
    session_timeout_minutes = Column(Integer, default=480)
    password_policy = Column(JSON, default=lambda: {
        "min_length": 8,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_numbers": True,
        "require_special_chars": True
    })
    two_factor_required = Column(Boolean, default=False)
    allowed_ip_ranges = Column(JSON, nullable=True)

    # Feature settings
    allow_user_registration = Column(Boolean, default=False)
    require_email_verification = Column(Boolean, default=True)
    allow_social_login = Column(Boolean, default=True)
    allowed_social_providers = Column(JSON, default=lambda: ["google", "github", "microsoft"])

    # Notification preferences
    email_notifications = Column(JSON, default=lambda: {
        "user_invitations": True,
        "subscription_changes": True,
        "security_alerts": True,
        "usage_alerts": True
    })

    # Integration settings
    webhook_urls = Column(JSON, nullable=True)
    api_rate_limits = Column(JSON, default=lambda: {
        "requests_per_minute": 100,
        "requests_per_hour": 1000,
        "requests_per_day": 10000
    })

    # Audit settings
    audit_log_retention_days = Column(Integer, default=90)
    export_format_preference = Column(String(20), default="json")

    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships - simplified

    # Indexes
    __table_args__ = (
        Index('idx_tenant_settings_tenant_id', 'tenant_id'),
    )

class SocialAccount(Base):
    __tablename__ = "social_accounts"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    provider = Column(String(50), nullable=False, index=True)
    social_id = Column(String(255), nullable=False, index=True)
    email = Column(String(255), nullable=False, index=True)

    # Profile information from social provider
    profile_data = Column(JSON, nullable=True)
    avatar_url = Column(String(500), nullable=True)
    profile_url = Column(String(500), nullable=True)

    # Connection status
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False, index=True)  # Email ownership verification
    verification_token = Column(String(255), nullable=True)
    verification_sent_at = Column(DateTime, nullable=True)
    last_login = Column(DateTime, nullable=True)

    # Token information (encrypted)
    access_token_hash = Column(Text, nullable=True)
    refresh_token_hash = Column(Text, nullable=True)
    token_expires_at = Column(DateTime, nullable=True)

    # Metadata
    connection_metadata = Column(JSON, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships - simplified

    # Constraints and indexes
    __table_args__ = (
        UniqueConstraint('provider', 'social_id', name='uix_provider_social_id'),
        UniqueConstraint('user_id', 'provider', name='uix_user_provider'),
        Index('idx_social_provider_email', 'provider', 'email'),
        Index('idx_social_user_active', 'user_id', 'is_active'),
    )

class TenantApiKey(Base):
    __tablename__ = "tenant_api_keys"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    key_hash = Column(String(255), nullable=False, unique=True, index=True)
    key_prefix = Column(String(20), nullable=False, index=True)

    # Permissions
    scopes = Column(JSON, nullable=False)
    allowed_ips = Column(JSON, nullable=True)

    # Status
    is_active = Column(Boolean, default=True)
    last_used_at = Column(DateTime, nullable=True)
    usage_count = Column(Integer, default=0)

    # Expiration
    expires_at = Column(DateTime, nullable=True)

    # Metadata
    created_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    description = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships - simplified

    # Constraints and indexes
    __table_args__ = (
        UniqueConstraint('tenant_id', 'name', name='uix_tenant_api_key_name'),
        Index('idx_api_key_tenant_active', 'tenant_id', 'is_active'),
        Index('idx_api_key_prefix_active', 'key_prefix', 'is_active'),
        Index('idx_api_key_expires', 'expires_at'),
    )

class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token = Column(String(255), nullable=False, unique=True, index=True)
    email = Column(String(255), nullable=False, index=True)

    # Token status
    is_used = Column(Boolean, default=False, index=True)
    expires_at = Column(DateTime, nullable=False, index=True)
    used_at = Column(DateTime, nullable=True)

    # Request metadata
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    # Constraints and indexes
    __table_args__ = (
        Index('idx_password_reset_user_active', 'user_id', 'is_used'),
        Index('idx_password_reset_expires', 'expires_at'),
    )

class EmailLog(Base):
    __tablename__ = "email_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email_type = Column(String(50), nullable=False, index=True)  # "verification", "invitation", "password_reset"
    recipient_email = Column(String(255), nullable=False, index=True)
    subject = Column(String(500), nullable=False)
    status = Column(String(20), nullable=False, index=True)  # "sent", "failed", "development"
    error_message = Column(Text, nullable=True)
    sent_at = Column(DateTime, default=datetime.utcnow, index=True)

    # Context references
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="SET NULL"), nullable=True, index=True)
    invitation_id = Column(String(36), ForeignKey("invitations.id", ondelete="SET NULL"), nullable=True, index=True)

    # Email delivery metadata
    smtp_response = Column(Text, nullable=True)  # SMTP server response
    delivery_attempts = Column(Integer, default=1)
    last_attempt_at = Column(DateTime, default=datetime.utcnow)

    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    # Constraints and indexes
    __table_args__ = (
        Index('idx_email_log_type_status', 'email_type', 'status'),
        Index('idx_email_log_recipient_date', 'recipient_email', 'sent_at'),
        Index('idx_email_log_tenant_type', 'tenant_id', 'email_type'),
        Index('idx_email_log_sent_at', 'sent_at'),
    )

class TenantDomain(Base):
    __tablename__ = "tenant_domains"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    domain = Column(String(255), nullable=False, unique=True, index=True)
    subdomain = Column(String(100), nullable=True, index=True)

    # Domain status
    is_primary = Column(Boolean, default=False)
    is_verified = Column(Boolean, default=False)
    verification_token = Column(String(255), nullable=True)

    # SSL settings
    ssl_enabled = Column(Boolean, default=True)
    ssl_certificate_id = Column(String(255), nullable=True)

    # DNS settings
    dns_configured = Column(Boolean, default=False)
    dns_records = Column(JSON, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships - simplified

    # Constraints and indexes
    __table_args__ = (
        UniqueConstraint('tenant_id', 'subdomain', name='uix_tenant_subdomain'),
        Index('idx_domain_verified', 'is_verified'),
        Index('idx_domain_primary', 'is_primary'),
        Index('idx_domain_tenant_primary', 'tenant_id', 'is_primary'),
    )

class TenantLDAPConfig(Base):
    """
    Stores LDAP/Active Directory configuration for tenant user/group synchronization.
    Supports integration with Keycloak LDAP User Federation.
    """
    __tablename__ = "tenant_ldap_configs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    enabled = Column(Boolean, default=False, index=True)

    # LDAP Server Configuration
    connection_url = Column(String(500), nullable=False)  # ldap://ad.company.com:389
    bind_dn = Column(String(500), nullable=False)  # CN=admin,DC=company,DC=com
    # NOTE: bind_credential is stored in Vault (service="ldap", key_name="credentials"), NOT in database
    connection_timeout = Column(Integer, default=30)
    read_timeout = Column(Integer, default=30)
    use_truststore_spi = Column(String(50), default='ldapsOnly')

    # User Search Configuration
    users_dn = Column(String(500), nullable=False)  # OU=Users,DC=company,DC=com
    user_object_class = Column(String(100), default='person')
    username_ldap_attribute = Column(String(100), default='sAMAccountName')
    rdn_ldap_attribute = Column(String(100), default='cn')
    uuid_ldap_attribute = Column(String(100), default='objectGUID')
    user_ldap_filter = Column(Text, nullable=True)  # Custom LDAP filter
    search_scope = Column(String(20), default='SUBTREE')  # ONE_LEVEL, SUBTREE

    # User Attribute Mapping
    email_ldap_attribute = Column(String(100), default='mail')
    first_name_ldap_attribute = Column(String(100), default='givenName')
    last_name_ldap_attribute = Column(String(100), default='sn')

    # Group Search Configuration
    groups_dn = Column(String(500), nullable=True)  # OU=Groups,DC=company,DC=com
    group_object_class = Column(String(100), default='group')
    group_name_ldap_attribute = Column(String(100), default='cn')
    group_membership_attribute = Column(String(100), default='member')
    group_membership_type = Column(String(20), default='DN')  # DN or UID

    # Sync Settings
    sync_registrations = Column(Boolean, default=True)  # Allow new user registration from LDAP
    import_enabled = Column(Boolean, default=True)  # Import users from LDAP
    edit_mode = Column(String(20), default='READ_ONLY')  # READ_ONLY, WRITABLE, UNSYNCED
    vendor = Column(String(50), default='ad')  # ad, other, rhds, tivoli, edirectory

    # Sync Schedule (in seconds)
    full_sync_period = Column(Integer, default=604800)  # 7 days
    changed_sync_period = Column(Integer, default=86400)  # 1 day
    batch_size = Column(Integer, default=1000)

    # Sync Status
    last_sync_at = Column(DateTime, nullable=True, index=True)
    last_sync_status = Column(String(50), nullable=True)  # success, partial, failed
    last_sync_users_count = Column(Integer, default=0)
    last_sync_groups_count = Column(Integer, default=0)
    last_sync_error = Column(Text, nullable=True)

    # Keycloak Integration
    keycloak_federation_id = Column(String(255), unique=True, nullable=True, index=True)
    keycloak_group_mapper_id = Column(String(255), nullable=True)

    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)

    # Constraints and indexes
    __table_args__ = (
        Index('idx_ldap_config_tenant', 'tenant_id'),
        Index('idx_ldap_config_enabled', 'enabled'),
        Index('idx_ldap_config_keycloak', 'keycloak_federation_id'),
        Index('idx_ldap_config_last_sync', 'last_sync_at'),
    )

class TenantLDAPSyncHistory(Base):
    """
    Audit log of LDAP sync operations for tracking and debugging.
    """
    __tablename__ = "tenant_ldap_sync_history"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    ldap_config_id = Column(String(36), ForeignKey("tenant_ldap_configs.id", ondelete="CASCADE"), nullable=False, index=True)

    # Sync metadata
    sync_type = Column(String(50), nullable=False, index=True)  # full, incremental, manual
    sync_status = Column(String(50), nullable=False, index=True)  # success, partial, failed

    # Statistics
    users_added = Column(Integer, default=0)
    users_updated = Column(Integer, default=0)
    users_removed = Column(Integer, default=0)
    groups_added = Column(Integer, default=0)
    groups_updated = Column(Integer, default=0)
    groups_removed = Column(Integer, default=0)

    # Timing
    started_at = Column(DateTime, nullable=False, index=True)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Integer, nullable=True)

    # Error details
    error_message = Column(Text, nullable=True)
    details = Column(JSON, nullable=True)  # Additional sync details

    # Who triggered the sync
    triggered_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)

    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    # Constraints and indexes
    __table_args__ = (
        Index('idx_ldap_sync_tenant', 'tenant_id'),
        Index('idx_ldap_sync_config', 'ldap_config_id'),
        Index('idx_ldap_sync_started', 'started_at'),
        Index('idx_ldap_sync_status', 'sync_status'),
        Index('idx_ldap_sync_type', 'sync_type'),
    )