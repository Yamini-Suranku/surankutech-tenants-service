from sqlalchemy import Column, String, DateTime, Integer, Boolean, JSON, Text, ForeignKey, Index, UniqueConstraint
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
from enum import Enum

# Import Base from database module to ensure single Base class
from .database import Base

class SubscriptionStatus(str, Enum):
    TRIAL = "trial"
    ACTIVE = "active"
    PAST_DUE = "past_due"
    CANCELED = "canceled"
    SUSPENDED = "suspended"

class PlanType(str, Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"

class UserStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING = "pending"

class BaseTenantModel(Base):
    """Base model with tenant isolation"""
    __abstract__ = True

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Tenant(Base):
    """Multi-tenant organization model"""
    __tablename__ = "tenants"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False, index=True)
    domain = Column(String(255), unique=True, index=True)  # Optional custom domain
    logo_url = Column(String(500), nullable=True)  # Company logo URL

    # Stripe integration
    stripe_customer_id = Column(String(255), unique=True, index=True)
    subscription_status = Column(String(20), default=SubscriptionStatus.TRIAL, index=True)
    plan_id = Column(String(50), default=PlanType.FREE, index=True)

    # Trial management
    trial_started_at = Column(DateTime, default=datetime.utcnow)
    trial_expires_at = Column(DateTime, index=True)

    # Tenant settings
    settings = Column(JSON, default=dict)
    is_active = Column(Boolean, default=True, index=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships - simplified to avoid conflicts
    users = relationship("UserTenant", back_populates="tenant")

    # Indexes
    __table_args__ = (
        Index('idx_tenant_active_status', 'is_active', 'subscription_status'),
        Index('idx_tenant_trial_expires', 'trial_expires_at'),
    )

class User(Base):
    """Platform user model"""
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), nullable=False, unique=True, index=True)
    keycloak_id = Column(String(255), unique=True, index=True)

    # User profile
    first_name = Column(String(100))
    last_name = Column(String(100))
    avatar_url = Column(String(500))

    # Status
    status = Column(String(20), default=UserStatus.PENDING, index=True)  # Start as PENDING until email verified
    is_email_verified = Column(Boolean, default=False, index=True)

    # Email verification
    email_verification_token = Column(String(255), nullable=True, index=True)
    email_verification_sent_at = Column(DateTime, nullable=True)
    email_verification_expires_at = Column(DateTime, nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, index=True)

    # Relationships - removed to avoid FK conflicts during user creation

    # Indexes
    __table_args__ = (
        Index('idx_user_status_verified', 'status', 'is_email_verified'),
        Index('idx_user_last_login', 'last_login'),
        Index('idx_user_verification_token', 'email_verification_token'),
        Index('idx_user_verification_expires', 'email_verification_expires_at'),
    )

class UserTenant(Base):
    """User-Tenant relationship with app-specific roles"""
    __tablename__ = "user_tenants"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)

    # App-specific roles stored as JSON
    app_roles = Column(JSON, default=dict)  # {"darkhole": ["admin"], "darkfolio": ["user"]}

    # Status
    status = Column(String(20), default=UserStatus.ACTIVE, index=True)
    invited_by = Column(String(255), nullable=True)  # Email or ID of who invited (no FK constraint)
    joined_at = Column(DateTime, index=True)
    last_accessed_at = Column(DateTime, nullable=True, index=True)  # Track last tenant access for current tenant logic

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships - simplified, no back_populates to avoid FK ambiguity
    tenant = relationship("Tenant", back_populates="users")

    # Constraints and indexes
    __table_args__ = (
        UniqueConstraint('user_id', 'tenant_id', name='uix_user_tenant'),
        Index('idx_user_tenant_status', 'user_id', 'tenant_id', 'status'),
        Index('idx_tenant_users_active', 'tenant_id', 'status'),
    )

class TenantAppAccess(Base):
    """App access control per tenant based on subscription"""
    __tablename__ = "tenant_app_access"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    app_name = Column(String(50), nullable=False, index=True)  # darkhole, darkfolio, confiploy

    # Access control
    is_enabled = Column(Boolean, default=True, index=True)
    user_limit = Column(Integer, default=5)
    current_users = Column(Integer, default=0)

    # Feature flags (JSON array of enabled features)
    enabled_features = Column(JSON, default=list)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Constraints and indexes
    __table_args__ = (
        UniqueConstraint('tenant_id', 'app_name', name='uix_tenant_app'),
        Index('idx_app_access_enabled', 'tenant_id', 'is_enabled'),
    )

class FeatureFlag(Base):
    """Dynamic feature flags for real-time control"""
    __tablename__ = "feature_flags"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    app_name = Column(String(50), nullable=False, index=True)
    feature_name = Column(String(100), nullable=False, index=True)

    # Feature control
    is_enabled = Column(Boolean, default=True, index=True)
    expires_at = Column(DateTime, index=True)  # For time-limited features

    # Configuration
    config = Column(JSON, default=dict)  # Feature-specific config
    notes = Column(Text)  # Admin notes

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Constraints and indexes
    __table_args__ = (
        UniqueConstraint('tenant_id', 'app_name', 'feature_name', name='uix_tenant_app_feature'),
        Index('idx_feature_enabled_expires', 'is_enabled', 'expires_at'),
    )

class AuditLog(Base):
    """Audit trail for tenant activities"""
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)

    # Action details
    action = Column(String(100), nullable=False, index=True)  # login, feature_access, plan_change, etc.
    resource_type = Column(String(50), index=True)  # user, tenant, subscription, feature
    resource_id = Column(String(36), index=True)

    # Context
    app_name = Column(String(50), index=True)
    ip_address = Column(String(45))  # IPv6 compatible
    user_agent = Column(Text)

    # Data
    details = Column(JSON, default=dict)

    # Timestamp
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    # Indexes for performance
    __table_args__ = (
        Index('idx_audit_tenant_action_date', 'tenant_id', 'action', 'created_at'),
        Index('idx_audit_user_action_date', 'user_id', 'action', 'created_at'),
        Index('idx_audit_resource', 'resource_type', 'resource_id'),
    )

class MCPToolkit(BaseTenantModel):
    """MCP Toolkit - Group of related tools requiring specific credentials"""
    __tablename__ = "mcp_toolkits"

    # Toolkit identification
    toolkit_name = Column(String(255), nullable=False, index=True)  # e.g., "github", "filesystem", "brave_search"
    display_name = Column(String(255), nullable=False)  # e.g., "GitHub Integration", "File System"
    connector_id = Column(String(36), nullable=False, index=True)  # References connectors table

    # Toolkit metadata
    description = Column(Text, nullable=True)
    documentation_url = Column(String(500), nullable=True)
    icon = Column(String(100), nullable=True)  # Icon identifier or emoji

    # Credential requirements
    required_credentials = Column(JSON, nullable=True)  # List of required credential fields
    # Example: [{"name": "github_token", "label": "GitHub PAT", "type": "password", "required": true}]
    has_credentials = Column(Boolean, default=False, index=True)  # Whether credentials are configured

    # Approval status for the entire toolkit
    approval_status = Column(String(50), default='pending', nullable=False, index=True)
    # Values: pending, approved, rejected, deprecated
    approved_by = Column(String(36), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    rejection_reason = Column(Text, nullable=True)

    # State
    is_active = Column(Boolean, default=True, index=True)
    last_synced_at = Column(DateTime, default=datetime.utcnow)
    tool_count = Column(Integer, default=0)  # Number of tools in this toolkit

    # Indexes and constraints
    __table_args__ = (
        UniqueConstraint('tenant_id', 'connector_id', 'toolkit_name', name='uix_tenant_connector_toolkit'),
        Index('idx_toolkit_connector', 'connector_id', 'is_active'),
        Index('idx_toolkit_approval', 'tenant_id', 'approval_status'),
        Index('idx_toolkit_credentials', 'has_credentials', 'is_active'),
    )

class MCPTool(BaseTenantModel):
    """MCP Tool discovered from MCP servers"""
    __tablename__ = "mcp_tools"

    # Tool identification
    tool_name = Column(String(255), nullable=False, index=True)
    connector_id = Column(String(36), nullable=False, index=True)  # References connectors table
    toolkit_id = Column(String(36), nullable=True, index=True)  # References mcp_toolkits table (nullable for migration)

    # Tool metadata
    description = Column(Text, nullable=True)
    documentation = Column(Text, nullable=True)
    input_schema = Column(JSON, nullable=True)  # JSON schema for tool input
    category = Column(String(100), nullable=True, index=True)  # API, Database, File System, etc.

    # Provider information
    provider_name = Column(String(255), nullable=True)  # e.g., "Anthropic MCP Server"
    provider_url = Column(String(500), nullable=True)  # Server URL

    # Approval status
    approval_status = Column(String(50), default='not_reviewed', nullable=False, index=True)
    # Values: not_reviewed, approved, rejected, deprecated
    approved_by = Column(String(36), nullable=True)  # User ID who approved
    approved_at = Column(DateTime, nullable=True)
    rejection_reason = Column(Text, nullable=True)

    # Usage tracking
    last_used_at = Column(DateTime, nullable=True, index=True)
    usage_count = Column(Integer, default=0)

    # Sync information
    last_synced_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True, index=True)  # Tool still available from server

    # Indexes and constraints
    __table_args__ = (
        UniqueConstraint('tenant_id', 'connector_id', 'tool_name', name='uix_tenant_connector_tool'),
        Index('idx_mcp_tool_status', 'tenant_id', 'approval_status'),
        Index('idx_mcp_tool_connector', 'connector_id', 'is_active'),
        Index('idx_mcp_tool_toolkit', 'toolkit_id', 'is_active'),
        Index('idx_mcp_tool_category', 'category', 'approval_status'),
        Index('idx_mcp_tool_last_used', 'last_used_at'),
    )

class MCPToolGroupPermission(Base):
    """User group permissions for MCP tools"""
    __tablename__ = "mcp_tool_group_permissions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    tool_id = Column(String(36), ForeignKey("mcp_tools.id", ondelete="CASCADE"), nullable=False, index=True)

    # User group identification (from Keycloak groups)
    group_name = Column(String(255), nullable=False, index=True)  # e.g., "engineering", "data-science"

    # Permissions
    can_execute = Column(Boolean, default=True)
    can_configure = Column(Boolean, default=False)  # Can modify tool parameters

    # Rate limiting per group
    rate_limit_per_hour = Column(Integer, nullable=True)  # NULL = unlimited
    rate_limit_per_day = Column(Integer, nullable=True)

    # Time restrictions
    allowed_days = Column(JSON, nullable=True)  # ["monday", "tuesday", ...] NULL = all days
    allowed_hours_start = Column(Integer, nullable=True)  # 0-23, NULL = anytime
    allowed_hours_end = Column(Integer, nullable=True)  # 0-23

    # Metadata
    granted_by = Column(String(36), nullable=True)  # User ID who granted permission
    granted_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True, index=True)  # NULL = never expires
    notes = Column(Text, nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Indexes and constraints
    __table_args__ = (
        UniqueConstraint('tenant_id', 'tool_id', 'group_name', name='uix_tenant_tool_group'),
        Index('idx_tool_group_active', 'tenant_id', 'tool_id', 'expires_at'),
        Index('idx_group_permissions', 'tenant_id', 'group_name'),
    )