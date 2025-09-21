"""
Role-Based Access Control (RBAC) Models

Database models for comprehensive permission management across the SoftPOS platform.
Supports hierarchical roles, resource scoping, and fine-grained permissions.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Dict, Any
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Text, JSON,
    ForeignKey, Table, UniqueConstraint, Index
)
from sqlalchemy.orm import relationship, Mapped, mapped_column
from sqlalchemy.ext.declarative import declarative_base

try:
    from ..database import Base
except ImportError:
    # Fallback for testing
    from sqlalchemy.ext.declarative import declarative_base
    Base = declarative_base()


class UserType(Enum):
    """User type classification"""
    PLATFORM_ADMIN = "platform_admin"  # Internal platform staff
    MERCHANT_USER = "merchant_user"     # Merchant staff
    PARTNER_USER = "partner_user"       # Platform/marketplace partners
    EXTERNAL_AUDITOR = "external_auditor"  # External auditors


class AccessLevel(Enum):
    """Data access level classification"""
    NONE = "none"
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"


class ResourceType(Enum):
    """Resource types for permission scoping"""
    MERCHANT = "merchant"
    TRANSACTION = "transaction"
    PAYOUT = "payout"
    DISPUTE = "dispute"
    KYC_DOCUMENT = "kyc_document"
    API_KEY = "api_key"
    WEBHOOK = "webhook"
    DEVICE = "device"
    REPORT = "report"
    SYSTEM_CONFIG = "system_config"


# Association tables for many-to-many relationships
# Note: user_roles relationship is handled by UserRoleAssignment model

role_permissions = Table(
    'role_permissions',
    Base.metadata,
    Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True),
    Column('permission_id', Integer, ForeignKey('permissions.id'), primary_key=True),
    Column('access_level', String(20), default=AccessLevel.READ.value),
    Column('conditions', JSON, default=dict),  # Additional conditions
)


class Role(Base):
    """Role definition with hierarchical support"""
    __tablename__ = 'roles'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)

    # Role classification
    user_type: Mapped[str] = mapped_column(String(50), nullable=False)
    is_system_role: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    # Hierarchical roles
    parent_role_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey('roles.id'), nullable=True)
    level: Mapped[int] = mapped_column(Integer, default=0)  # Role hierarchy level

    # Security requirements
    requires_2fa: Mapped[bool] = mapped_column(Boolean, default=True)
    requires_hardware_key: Mapped[bool] = mapped_column(Boolean, default=False)
    requires_ip_allowlist: Mapped[bool] = mapped_column(Boolean, default=False)
    session_timeout_minutes: Mapped[int] = mapped_column(Integer, default=480)  # 8 hours

    # Approval requirements
    requires_dual_control: Mapped[bool] = mapped_column(Boolean, default=False)
    max_transaction_amount: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # In minor units

    # Metadata
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    created_by: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey('users.id'), nullable=True)

    # Configuration
    ui_config: Mapped[Dict] = mapped_column(JSON, default=dict)  # UI-specific config
    feature_flags: Mapped[Dict] = mapped_column(JSON, default=dict)  # Feature access

    # Relationships
    parent_role: Mapped[Optional["Role"]] = relationship("Role", remote_side=[id], back_populates="child_roles")
    child_roles: Mapped[List["Role"]] = relationship("Role", back_populates="parent_role")
    permissions: Mapped[List["Permission"]] = relationship("Permission", secondary=role_permissions, back_populates="roles")
    # Users relationship handled through UserRoleAssignment model
    user_assignments: Mapped[List["UserRoleAssignment"]] = relationship("UserRoleAssignment", back_populates="role")

    # Indexes
    __table_args__ = (
        Index('idx_role_user_type', 'user_type'),
        Index('idx_role_active', 'is_active'),
        Index('idx_role_parent', 'parent_role_id'),
    )


class Permission(Base):
    """Fine-grained permission definition"""
    __tablename__ = 'permissions'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)

    # Permission classification
    resource_type: Mapped[str] = mapped_column(String(50), nullable=False)
    action: Mapped[str] = mapped_column(String(50), nullable=False)  # create, read, update, delete, approve, etc.

    # Scope and constraints
    is_global: Mapped[bool] = mapped_column(Boolean, default=False)  # Global vs scoped permission
    requires_ownership: Mapped[bool] = mapped_column(Boolean, default=False)  # Must own resource
    max_amount: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # Amount limits

    # Approval workflow
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    approval_chain: Mapped[List] = mapped_column(JSON, default=list)  # Required approver roles

    # Rate limiting
    rate_limit_per_hour: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    rate_limit_per_day: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Metadata
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Configuration
    conditions: Mapped[Dict] = mapped_column(JSON, default=dict)  # Additional conditions
    ui_config: Mapped[Dict] = mapped_column(JSON, default=dict)  # UI display config

    # Relationships
    roles: Mapped[List["Role"]] = relationship("Role", secondary=role_permissions, back_populates="permissions")

    # Indexes
    __table_args__ = (
        Index('idx_permission_resource_action', 'resource_type', 'action'),
        Index('idx_permission_active', 'is_active'),
        UniqueConstraint('resource_type', 'action', 'name', name='uix_permission_unique'),
    )


class UserRoleAssignment(Base):
    """Track user role assignments with metadata"""
    __tablename__ = 'user_role_assignments'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id'), nullable=False)
    role_id: Mapped[int] = mapped_column(Integer, ForeignKey('roles.id'), nullable=False)

    # Assignment metadata
    assigned_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    assigned_by: Mapped[int] = mapped_column(Integer, ForeignKey('users.id'), nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    revoked_by: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey('users.id'), nullable=True)

    # Scoping
    scope_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # merchant, partner, global
    scope_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)  # Specific resource ID
    scope_data: Mapped[Dict] = mapped_column(JSON, default=dict)  # Additional scoping data

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Assignment/revocation reason

    # Relationships
    user: Mapped["User"] = relationship("User", foreign_keys=[user_id])
    role: Mapped["Role"] = relationship("Role", back_populates="user_assignments")
    assigned_by_user: Mapped["User"] = relationship("User", foreign_keys=[assigned_by])
    revoked_by_user: Mapped[Optional["User"]] = relationship("User", foreign_keys=[revoked_by])

    # Indexes
    __table_args__ = (
        Index('idx_user_role_active', 'user_id', 'is_active'),
        Index('idx_user_role_scope', 'scope_type', 'scope_id'),
        Index('idx_user_role_expires', 'expires_at'),
        UniqueConstraint('user_id', 'role_id', 'scope_type', 'scope_id', name='uix_user_role_scope'),
    )


class PermissionGrant(Base):
    """Direct permission grants to users (bypass roles)"""
    __tablename__ = 'permission_grants'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id'), nullable=False)
    permission_id: Mapped[int] = mapped_column(Integer, ForeignKey('permissions.id'), nullable=False)

    # Grant details
    access_level: Mapped[str] = mapped_column(String(20), default=AccessLevel.READ.value)
    granted_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    granted_by: Mapped[int] = mapped_column(Integer, ForeignKey('users.id'), nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Scoping
    scope_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    scope_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    scope_data: Mapped[Dict] = mapped_column(JSON, default=dict)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)  # Justification required

    # Conditions and limits
    conditions: Mapped[Dict] = mapped_column(JSON, default=dict)
    rate_limit_override: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    amount_limit_override: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Relationships
    user: Mapped["User"] = relationship("User", foreign_keys=[user_id])
    permission: Mapped["Permission"] = relationship("Permission")
    granted_by_user: Mapped["User"] = relationship("User", foreign_keys=[granted_by])

    # Indexes
    __table_args__ = (
        Index('idx_permission_grant_user', 'user_id', 'is_active'),
        Index('idx_permission_grant_expires', 'expires_at'),
        UniqueConstraint('user_id', 'permission_id', 'scope_type', 'scope_id', name='uix_user_permission_scope'),
    )


class AccessSession(Base):
    """Track user access sessions for security monitoring"""
    __tablename__ = 'access_sessions'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id'), nullable=False)
    session_token: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)

    # Session details
    started_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_activity: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    ended_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Security context
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)  # IPv6 compatible
    user_agent: Mapped[str] = mapped_column(Text, nullable=False)
    device_fingerprint: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Authentication details
    auth_method: Mapped[str] = mapped_column(String(50), nullable=False)  # sso, password, api_key
    mfa_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    hardware_key_used: Mapped[bool] = mapped_column(Boolean, default=False)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    termination_reason: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Risk assessment
    risk_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # 0-100
    anomaly_flags: Mapped[List] = mapped_column(JSON, default=list)

    # Relationships
    user: Mapped["User"] = relationship("User")

    # Indexes
    __table_args__ = (
        Index('idx_session_user_active', 'user_id', 'is_active'),
        Index('idx_session_token', 'session_token'),
        Index('idx_session_expires', 'expires_at'),
        Index('idx_session_ip', 'ip_address'),
    )


class AuditLog(Base):
    """Comprehensive audit logging for RBAC actions"""
    __tablename__ = 'audit_logs'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # Action details
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(50), nullable=False)
    resource_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Actor details
    user_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey('users.id'), nullable=True)
    session_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey('access_sessions.id'), nullable=True)
    api_key_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Context
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Change details
    old_values: Mapped[Dict] = mapped_column(JSON, default=dict)
    new_values: Mapped[Dict] = mapped_column(JSON, default=dict)
    affected_user_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey('users.id'), nullable=True)

    # Status and result
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Metadata
    correlation_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    additional_data: Mapped[Dict] = mapped_column(JSON, default=dict)

    # Risk and compliance
    risk_level: Mapped[str] = mapped_column(String(20), default="low")
    compliance_tags: Mapped[List] = mapped_column(JSON, default=list)

    # Relationships
    user: Mapped[Optional["User"]] = relationship("User", foreign_keys=[user_id])
    session: Mapped[Optional["AccessSession"]] = relationship("AccessSession")
    affected_user: Mapped[Optional["User"]] = relationship("User", foreign_keys=[affected_user_id])

    # Indexes
    __table_args__ = (
        Index('idx_audit_user_action', 'user_id', 'action'),
        Index('idx_audit_resource', 'resource_type', 'resource_id'),
        Index('idx_audit_timestamp', 'timestamp'),
        Index('idx_audit_correlation', 'correlation_id'),
        Index('idx_audit_risk', 'risk_level'),
    )


class ApprovalWorkflow(Base):
    """Approval workflows for sensitive actions"""
    __tablename__ = 'approval_workflows'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # Request details
    requester_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id'), nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(50), nullable=False)
    resource_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Workflow state
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending, approved, rejected, cancelled
    priority: Mapped[str] = mapped_column(String(20), default="normal")

    # Request data
    request_data: Mapped[Dict] = mapped_column(JSON, default=dict)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    amount: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Timing
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Approval chain
    required_approvers: Mapped[List] = mapped_column(JSON, default=list)  # Role IDs or user IDs
    approvals: Mapped[List] = mapped_column(JSON, default=list)  # Approval records

    # Final result
    approved_by: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey('users.id'), nullable=True)
    rejected_by: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey('users.id'), nullable=True)
    completion_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    requester: Mapped["User"] = relationship("User", foreign_keys=[requester_id])
    approved_by_user: Mapped[Optional["User"]] = relationship("User", foreign_keys=[approved_by])
    rejected_by_user: Mapped[Optional["User"]] = relationship("User", foreign_keys=[rejected_by])

    # Indexes
    __table_args__ = (
        Index('idx_workflow_requester', 'requester_id'),
        Index('idx_workflow_status', 'status'),
        Index('idx_workflow_expires', 'expires_at'),
        Index('idx_workflow_resource', 'resource_type', 'resource_id'),
    )