"""
RBAC Module Initialization

Comprehensive Role-Based Access Control system for SoftPOS.
Provides complete permission management, role assignment, and security policies.
"""

from .service import rbac_service, RBACService
from .dependencies import (
    require_permission,
    require_role,
    require_2fa,
    require_hardware_key,
    require_approval,
    get_current_user_with_session,
    RBACDependencies,
    rbac_deps,
    # Common dependencies
    require_merchant_read,
    require_transaction_read,
    require_payout_read,
    require_system_admin
)

__all__ = [
    # Core service
    "rbac_service",
    "RBACService",

    # Decorators
    "require_permission",
    "require_role",
    "require_2fa",
    "require_hardware_key",
    "require_approval",

    # Dependencies
    "get_current_user_with_session",
    "RBACDependencies",
    "rbac_deps",

    # Common permission dependencies
    "require_merchant_read",
    "require_transaction_read",
    "require_payout_read",
    "require_system_admin"
]

# Version information
__version__ = "1.0.0"
__author__ = "SoftPOS Team"
__description__ = "Role-Based Access Control system for SoftPOS platform"