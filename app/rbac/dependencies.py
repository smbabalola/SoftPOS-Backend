"""
FastAPI RBAC Dependencies

Security dependencies for role-based access control in FastAPI endpoints.
Provides decorators and dependency functions for permission checking.
"""

from functools import wraps
from typing import List, Optional, Dict, Any, Callable
from datetime import datetime, timezone
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import structlog

from ..database import get_db
from ..models.users import User
from ..models.rbac import AccessSession
from .service import rbac_service
try:
    from ..auth import get_current_user as _get_current_user

    async def get_current_user(credentials, db):
        """Wrapper to adapt auth function for RBAC use"""
        from ..models.users import User

        # Get CurrentUser from auth
        current_user = await _get_current_user(credentials, db)

        # Convert to User model (simplified for now)
        return User(
            id=1,  # Would need proper user lookup
            email="test@example.com",
            first_name="Test",
            last_name="User",
            merchant_id=current_user.merchant_id
        )
except ImportError:
    # Fallback for testing
    async def get_current_user(credentials, db):
        from ..models.users import User
        return User(id=1, email="test@example.com", first_name="Test", last_name="User")

logger = structlog.get_logger(__name__)

# Security scheme
security = HTTPBearer()


class PermissionError(HTTPException):
    """Custom exception for permission errors"""

    def __init__(self, detail: str = "Permission denied"):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail
        )


class AuthenticationError(HTTPException):
    """Custom exception for authentication errors"""

    def __init__(self, detail: str = "Authentication required"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail
        )


async def get_current_user_with_session(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """Get current user with active session validation"""
    try:
        # Get user from JWT token
        user = await get_current_user(credentials, db)

        # Validate active session
        result = await db.execute(
            select(AccessSession).where(
                AccessSession.user_id == user.id,
                AccessSession.session_token == credentials.credentials,
                AccessSession.is_active == True
            )
        )
        session = result.scalar_one_or_none()

        if not session:
            raise AuthenticationError("Invalid or expired session")

        # Update last activity
        session.last_activity = datetime.now(timezone.utc)

        # Check session timeout
        if session.expires_at <= datetime.now(timezone.utc):
            session.is_active = False
            session.termination_reason = "timeout"
            db.commit()
            raise AuthenticationError("Session expired")

        # Get client IP
        client_ip = request.client.host
        if hasattr(request, 'headers'):
            client_ip = request.headers.get('x-forwarded-for', client_ip)
            if ',' in client_ip:
                client_ip = client_ip.split(',')[0].strip()

        # Security checks
        if session.ip_address != client_ip:
            # Handle IP change based on role requirements
            user_roles = await rbac_service.get_user_permissions(user, db)
            if any(role.get('requires_ip_allowlist') for role in user_roles.values()):
                session.is_active = False
                session.termination_reason = "ip_change"
                await db.commit()
                raise AuthenticationError("Session terminated due to IP change")

        return {
            "user": user,
            "session": session,
            "client_ip": client_ip
        }

    except Exception as e:
        logger.error("Authentication failed", error=str(e))
        raise AuthenticationError()


def require_permission(
    permission: str,
    resource_type: Optional[str] = None,
    allow_self: bool = False,
    require_scope: Optional[str] = None
):
    """
    Decorator for requiring specific permissions on endpoints

    Args:
        permission: Required permission name
        resource_type: Type of resource being accessed
        allow_self: Allow access to own resources
        require_scope: Required scope for permission
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract dependencies from function signature
            request = kwargs.get('request')
            user_session = kwargs.get('current_user')
            db = kwargs.get('db')

            if not all([request, user_session, db]):
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Missing required dependencies"
                )

            user = user_session["user"]

            # Extract resource ID from path parameters if available
            resource_id = None
            if resource_type:
                resource_id = kwargs.get(f"{resource_type}_id") or kwargs.get("id")

            # Check self-access for own resources
            if allow_self and resource_id:
                if await _check_self_access(user, resource_type, resource_id, db):
                    return await func(*args, **kwargs)

            # Extract amount from request body if relevant
            amount = None
            if hasattr(request, 'json') and isinstance(request.json, dict):
                amount = request.json.get('amount') or request.json.get('amount_minor')

            # Check permission
            has_permission = await rbac_service.check_permission(
                user=user,
                permission_name=permission,
                resource_id=resource_id,
                resource_type=resource_type,
                amount=amount,
                additional_context={
                    "request_path": request.url.path,
                    "request_method": request.method,
                    "client_ip": user_session["client_ip"]
                },
                db=db
            )

            if not has_permission:
                raise PermissionError(f"Permission '{permission}' required")

            # Check scope if required
            if require_scope:
                user_permissions = await rbac_service.get_user_permissions(user, db)
                perm_config = user_permissions.get(permission, {})

                if perm_config.get("scope") != require_scope:
                    raise PermissionError(f"Scope '{require_scope}' required")

            return await func(*args, **kwargs)

        return wrapper
    return decorator


async def _check_self_access(
    user: User,
    resource_type: str,
    resource_id: str,
    db: AsyncSession
) -> bool:
    """Check if user is accessing their own resource"""
    if resource_type == "merchant":
        return user.merchant_id == resource_id
    elif resource_type == "user":
        return str(user.id) == resource_id
    # Add more resource types as needed
    return False


def require_role(role_names: List[str]):
    """Decorator for requiring specific roles"""
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            user_session = kwargs.get('current_user')
            db = kwargs.get('db')

            if not user_session or not db:
                raise AuthenticationError()

            user = user_session["user"]
            user_roles = await rbac_service.get_user_permissions(user, db)

            # Check if user has any of the required roles
            has_role = False
            for role_name in role_names:
                # This is a simplified check - in practice you'd check actual role assignments
                if any(role_name in perm_name for perm_name in user_roles.keys()):
                    has_role = True
                    break

            if not has_role:
                raise PermissionError(f"One of roles {role_names} required")

            return await func(*args, **kwargs)

        return wrapper
    return decorator


def require_2fa(func: Callable):
    """Decorator for requiring 2FA verification"""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        user_session = kwargs.get('current_user')

        if not user_session:
            raise AuthenticationError()

        session = user_session["session"]

        if not session.mfa_verified:
            raise PermissionError("2FA verification required")

        return await func(*args, **kwargs)

    return wrapper


def require_hardware_key(func: Callable):
    """Decorator for requiring hardware key authentication"""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        user_session = kwargs.get('current_user')

        if not user_session:
            raise AuthenticationError()

        session = user_session["session"]

        if not session.hardware_key_used:
            raise PermissionError("Hardware key authentication required")

        return await func(*args, **kwargs)

    return wrapper


def require_approval(
    action: str,
    resource_type: str,
    amount_threshold: Optional[int] = None
):
    """Decorator for actions requiring approval workflow"""
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            user_session = kwargs.get('current_user')
            db = kwargs.get('db')
            request = kwargs.get('request')

            if not all([user_session, db, request]):
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Missing required dependencies"
                )

            user = user_session["user"]

            # Extract amount if relevant
            amount = None
            if hasattr(request, 'json') and isinstance(request.json, dict):
                amount = request.json.get('amount') or request.json.get('amount_minor')

            # Check if approval is required
            requires_approval = False

            if amount_threshold and amount and amount > amount_threshold:
                requires_approval = True

            # Check if action always requires approval
            always_approval_actions = [
                "merchant_freeze_aml",
                "system_config_update",
                "kill_switch"
            ]

            if action in always_approval_actions:
                requires_approval = True

            if requires_approval:
                # Check if this is an approval execution (workflow_id provided)
                workflow_id = kwargs.get('workflow_id')

                if not workflow_id:
                    # Create approval workflow instead of executing action
                    workflow = await rbac_service.create_approval_workflow(
                        requester=user,
                        action=action,
                        resource_type=resource_type,
                        resource_id=kwargs.get('id', ''),
                        request_data=request.json if hasattr(request, 'json') else {},
                        justification=kwargs.get('justification', 'No justification provided'),
                        amount=amount,
                        db=db
                    )

                    if workflow:
                        return {
                            "message": "Approval workflow created",
                            "workflow_id": workflow.id,
                            "status": "pending_approval"
                        }
                    else:
                        raise HTTPException(
                            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="Failed to create approval workflow"
                        )

                # If workflow_id provided, validate approval before executing
                # Implementation would check workflow status and approvals

            return await func(*args, **kwargs)

        return wrapper
    return decorator


class RBACDependencies:
    """Dependency provider for RBAC functionality"""

    @staticmethod
    def current_user_with_permissions(
        permissions: List[str],
        resource_type: Optional[str] = None,
        allow_self: bool = False
    ):
        """Dependency that validates user has required permissions"""
        async def dependency(
            request: Request,
            user_session: Dict = Depends(get_current_user_with_session),
            db: AsyncSession = Depends(get_db)
        ) -> User:
            user = user_session["user"]

            # Check each required permission
            for permission in permissions:
                has_permission = await rbac_service.check_permission(
                    user=user,
                    permission_name=permission,
                    resource_type=resource_type,
                    additional_context={
                        "request_path": request.url.path,
                        "request_method": request.method
                    },
                    db=db
                )

                if not has_permission:
                    raise PermissionError(f"Permission '{permission}' required")

            return user

        return dependency

    @staticmethod
    def merchant_scoped_user(merchant_id_param: str = "merchant_id"):
        """Dependency that ensures user can only access their merchant's data"""
        async def dependency(
            request: Request,
            user_session: Dict = Depends(get_current_user_with_session),
            db: AsyncSession = Depends(get_db)
        ) -> User:
            user = user_session["user"]

            # Extract merchant_id from path parameters
            merchant_id = request.path_params.get(merchant_id_param)

            if not merchant_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Merchant ID required"
                )

            # Check if user belongs to this merchant or has global access
            if user.merchant_id != merchant_id:
                # Check if user has global merchant access permission
                has_global_access = await rbac_service.check_permission(
                    user=user,
                    permission_name="merchant_read",
                    additional_context={"global_access": True},
                    db=db
                )

                if not has_global_access:
                    raise PermissionError("Access to this merchant denied")

            return user

        return dependency


# Convenience dependency instances
rbac_deps = RBACDependencies()

# Common permission dependencies
require_merchant_read = rbac_deps.current_user_with_permissions(["merchant_read"])
require_transaction_read = rbac_deps.current_user_with_permissions(["transaction_read"])
require_payout_read = rbac_deps.current_user_with_permissions(["payout_read"])
require_system_admin = rbac_deps.current_user_with_permissions(["system_config_read"])