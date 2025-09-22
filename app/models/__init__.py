"""
SoftPOS Data Models

Database models and Pydantic schemas for the SoftPOS platform.
"""

# Import database models
try:
    from .users import User
except ImportError:
    pass

try:
    from .rbac import (
        Role, Permission, UserRoleAssignment, PermissionGrant,
        AccessSession, AuditLog, ApprovalWorkflow,
        UserType, AccessLevel, ResourceType
    )
except ImportError:
    pass

# Import API models (Pydantic schemas)
try:
    from .api import (
        APIError, HealthResponse, PaymentStatus, CaptureMode, Channel,
        PaymentIntentCreate, PaymentIntent, PaymentConfirm, Payment,
        MerchantStatus, Merchant, MerchantApplicationRequest,
        TransactionSummary, RefundRequest, RefundResponse,
        PaginationParams, PaginatedResponse
    )
except ImportError:
    pass

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