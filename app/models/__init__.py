"""
SoftPOS Data Models

Database models and Pydantic schemas for the SoftPOS platform.
"""

# Import API models (Pydantic schemas) - these are always needed
from .api import (
    APIError, HealthResponse, PaymentStatus, CaptureMode, Channel,
    PaymentIntentCreate, PaymentIntent, PaymentConfirm, Payment,
    MerchantStatus, Merchant, MerchantApplicationRequest,
    TransactionSummary, RefundRequest, RefundResponse,
    PaginationParams, PaginatedResponse
)

# Import database models with fallbacks
try:
    from .users import User
except ImportError:
    User = None

try:
    from .rbac import (
        Role, Permission, UserRoleAssignment, PermissionGrant,
        AccessSession, AuditLog, ApprovalWorkflow,
        UserType, AccessLevel, ResourceType
    )
except ImportError:
    Role = Permission = UserRoleAssignment = None
    PermissionGrant = AccessSession = AuditLog = None
    ApprovalWorkflow = UserType = AccessLevel = ResourceType = None

# Export all models
__all__ = [
    # Database models
    "User",
    "Role",
    "Permission",
    "UserRoleAssignment",
    "PermissionGrant",
    "AccessSession",
    "AuditLog",
    "ApprovalWorkflow",
    "UserType",
    "AccessLevel",
    "ResourceType",
    # API models
    "APIError",
    "HealthResponse",
    "PaymentStatus",
    "CaptureMode",
    "Channel",
    "PaymentIntentCreate",
    "PaymentIntent",
    "PaymentConfirm",
    "Payment",
    "MerchantStatus",
    "Merchant",
    "MerchantApplicationRequest",
    "TransactionSummary",
    "RefundRequest",
    "RefundResponse",
    "PaginationParams",
    "PaginatedResponse"
]