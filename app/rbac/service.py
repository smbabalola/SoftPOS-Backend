"""
RBAC Service for SoftPOS Platform

Provides role-based access control functionality including permission checking,
role management, and security policy enforcement.
"""

import yaml
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Set, Any, Union
from pathlib import Path
from functools import lru_cache
import structlog

from sqlalchemy.orm import Session
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import and_, or_, select

from ..models.rbac import (
    Role, Permission, UserRoleAssignment, PermissionGrant,
    AccessSession, AuditLog, ApprovalWorkflow,
    UserType, AccessLevel, ResourceType
)
from ..models.users import User
from ..database import get_db

logger = structlog.get_logger(__name__)


class RBACService:
    """Core RBAC service for permission management"""

    def __init__(self):
        self.config = self._load_config()
        self._permission_cache: Dict[str, Dict] = {}
        self._role_cache: Dict[str, Dict] = {}

    @lru_cache(maxsize=1)
    def _load_config(self) -> Dict:
        """Load RBAC configuration from YAML file"""
        config_path = Path(__file__).parent.parent.parent / "config" / "rbac_config.yaml"
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.error("RBAC config file not found", path=str(config_path))
            return {"roles": {}, "permissions": {}, "role_permissions": {}}

    async def initialize_system_roles(self, db: AsyncSession) -> bool:
        """Initialize system roles and permissions from config"""
        try:
            # Create permissions first
            await self._create_permissions_from_config(db)

            # Create roles
            await self._create_roles_from_config(db)

            # Assign permissions to roles
            await self._assign_role_permissions_from_config(db)

            await db.commit()
            logger.info("RBAC system initialized successfully")
            return True

        except Exception as e:
            logger.error("Failed to initialize RBAC system", error=str(e))
            await db.rollback()
            return False

    async def _create_permissions_from_config(self, db: AsyncSession):
        """Create permissions from configuration"""
        permissions_config = self.config.get("permissions", {})

        for perm_name, perm_data in permissions_config.items():
            result = await db.execute(select(Permission).where(Permission.name == perm_name))
            existing = result.scalar_one_or_none()
            if not existing:
                permission = Permission(
                    name=perm_name,
                    display_name=perm_data.get("display_name", perm_name),
                    description=perm_data.get("description", ""),
                    resource_type=perm_data.get("resource_type", "unknown"),
                    action=perm_data.get("action", "read"),
                    is_global=perm_data.get("is_global", False),
                    requires_ownership=perm_data.get("requires_ownership", False),
                    max_amount=perm_data.get("max_amount"),
                    requires_approval=perm_data.get("requires_approval", False),
                    approval_chain=perm_data.get("approval_chain", []),
                    rate_limit_per_hour=perm_data.get("rate_limit_per_hour"),
                    rate_limit_per_day=perm_data.get("rate_limit_per_day"),
                    conditions=perm_data.get("conditions", {}),
                    ui_config=perm_data.get("ui_config", {})
                )
                db.add(permission)

    async def _create_roles_from_config(self, db: AsyncSession):
        """Create roles from configuration"""
        roles_config = self.config.get("roles", {})

        for role_name, role_data in roles_config.items():
            result = await db.execute(select(Role).where(Role.name == role_name))
            existing = result.scalar_one_or_none()
            if not existing:
                # Find parent role if specified
                parent_role_id = None
                if "parent_role" in role_data:
                    result = await db.execute(select(Role).where(Role.name == role_data["parent_role"]))
                    parent_role = result.scalar_one_or_none()
                    if parent_role:
                        parent_role_id = parent_role.id

                role = Role(
                    name=role_name,
                    display_name=role_data.get("display_name", role_name),
                    description=role_data.get("description", ""),
                    user_type=role_data.get("user_type", UserType.PLATFORM_ADMIN.value),
                    is_system_role=role_data.get("is_system_role", False),
                    parent_role_id=parent_role_id,
                    level=role_data.get("level", 0),
                    requires_2fa=role_data.get("requires_2fa", True),
                    requires_hardware_key=role_data.get("requires_hardware_key", False),
                    requires_ip_allowlist=role_data.get("requires_ip_allowlist", False),
                    session_timeout_minutes=role_data.get("session_timeout_minutes", 480),
                    requires_dual_control=role_data.get("requires_dual_control", False),
                    max_transaction_amount=role_data.get("max_transaction_amount"),
                    ui_config=role_data.get("ui_config", {}),
                    feature_flags=role_data.get("feature_flags", {})
                )
                db.add(role)

    async def _assign_role_permissions_from_config(self, db: AsyncSession):
        """Assign permissions to roles based on configuration"""
        role_permissions_config = self.config.get("role_permissions", {})

        for role_name, permissions in role_permissions_config.items():
            result = await db.execute(select(Role).where(Role.name == role_name))
            role = result.scalar_one_or_none()
            if not role:
                continue

            for perm_config in permissions:
                perm_name = perm_config["permission"]

                # Handle wildcard permissions for super admin
                if perm_name == "*":
                    result = await db.execute(select(Permission))
                    all_permissions = result.scalars().all()
                    for permission in all_permissions:
                        # Check if association already exists
                        from app.models.rbac import role_permissions
                        existing_result = await db.execute(
                            select(role_permissions).where(
                                role_permissions.c.role_id == role.id,
                                role_permissions.c.permission_id == permission.id
                            )
                        )
                        if not existing_result.scalar_one_or_none():
                            await db.execute(
                                role_permissions.insert().values(
                                    role_id=role.id,
                                    permission_id=permission.id,
                                    access_level=perm_config.get("access_level", "read")
                                )
                            )
                else:
                    result = await db.execute(select(Permission).where(Permission.name == perm_name))
                    permission = result.scalar_one_or_none()
                    if permission:
                        # Check if association already exists
                        from app.models.rbac import role_permissions
                        existing_result = await db.execute(
                            select(role_permissions).where(
                                role_permissions.c.role_id == role.id,
                                role_permissions.c.permission_id == permission.id
                            )
                        )
                        if not existing_result.scalar_one_or_none():
                            await db.execute(
                                role_permissions.insert().values(
                                    role_id=role.id,
                                    permission_id=permission.id,
                                    access_level=perm_config.get("access_level", "read")
                                )
                            )

    async def check_permission(
        self,
        user: User,
        permission_name: str,
        resource_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        amount: Optional[int] = None,
        additional_context: Optional[Dict] = None,
        db: AsyncSession = None
    ) -> bool:
        """Check if user has specific permission"""
        try:
            # Get user's effective permissions
            user_permissions = await self.get_user_permissions(user, db)

            if permission_name not in user_permissions:
                await self._audit_permission_check(
                    user, permission_name, False, "permission_not_found", db
                )
                return False

            permission_config = user_permissions[permission_name]

            # Check amount limits
            if amount and permission_config.get("max_amount"):
                if amount > permission_config["max_amount"]:
                    await self._audit_permission_check(
                        user, permission_name, False, "amount_limit_exceeded", db
                    )
                    return False

            # Check resource ownership if required
            if permission_config.get("requires_ownership") and resource_id:
                if not await self._check_resource_ownership(user, resource_type, resource_id, db):
                    await self._audit_permission_check(
                        user, permission_name, False, "ownership_required", db
                    )
                    return False

            # Check rate limits
            if not await self._check_rate_limits(user, permission_name, db):
                await self._audit_permission_check(
                    user, permission_name, False, "rate_limit_exceeded", db
                )
                return False

            # Check conditions
            if not await self._check_permission_conditions(
                user, permission_config, additional_context, db
            ):
                await self._audit_permission_check(
                    user, permission_name, False, "conditions_not_met", db
                )
                return False

            await self._audit_permission_check(
                user, permission_name, True, "permission_granted", db
            )
            return True

        except Exception as e:
            logger.error("Permission check failed",
                        user_id=user.id, permission=permission_name, error=str(e))
            return False

    async def get_user_permissions(self, user: User, db: AsyncSession) -> Dict[str, Dict]:
        """Get all effective permissions for a user"""
        cache_key = f"user_permissions_{user.id}"

        # Check cache (in production, use Redis)
        if cache_key in self._permission_cache:
            cache_entry = self._permission_cache[cache_key]
            if cache_entry["expires"] > datetime.now():
                return cache_entry["permissions"]

        permissions = {}

        # Get permissions from roles
        result = await db.execute(
            select(UserRoleAssignment).where(
                and_(
                    UserRoleAssignment.user_id == user.id,
                    UserRoleAssignment.is_active == True,
                    or_(
                        UserRoleAssignment.expires_at.is_(None),
                        UserRoleAssignment.expires_at > datetime.now(timezone.utc)
                    )
                )
            )
        )
        user_roles = result.scalars().all()

        for assignment in user_roles:
            role_permissions = await self._get_role_permissions(assignment.role, db)
            for perm_name, perm_config in role_permissions.items():
                if perm_name not in permissions:
                    permissions[perm_name] = perm_config.copy()
                    permissions[perm_name]["scope"] = assignment.scope_type
                    permissions[perm_name]["scope_id"] = assignment.scope_id
                else:
                    # Merge permissions (take highest access level)
                    current_level = AccessLevel[permissions[perm_name].get("access_level", "READ")]
                    new_level = AccessLevel[perm_config.get("access_level", "READ")]
                    if new_level.value > current_level.value:
                        permissions[perm_name].update(perm_config)

        # Get direct permission grants
        result = await db.execute(
            select(PermissionGrant).where(
                and_(
                    PermissionGrant.user_id == user.id,
                    PermissionGrant.is_active == True,
                    or_(
                        PermissionGrant.expires_at.is_(None),
                        PermissionGrant.expires_at > datetime.now(timezone.utc)
                    )
                )
            )
        )
        direct_grants = result.scalars().all()

        for grant in direct_grants:
            perm_name = grant.permission.name
            permissions[perm_name] = {
                "access_level": grant.access_level,
                "scope": grant.scope_type,
                "scope_id": grant.scope_id,
                "conditions": grant.conditions,
                "max_amount": grant.amount_limit_override or grant.permission.max_amount,
                "rate_limit_override": grant.rate_limit_override
            }

        # Cache for 5 minutes
        self._permission_cache[cache_key] = {
            "permissions": permissions,
            "expires": datetime.now() + timedelta(minutes=5)
        }

        return permissions

    async def _get_role_permissions(self, role: Role, db: AsyncSession) -> Dict[str, Dict]:
        """Get permissions for a specific role"""
        permissions = {}

        # Query permissions for this role using the association table
        from app.models.rbac import role_permissions
        result = await db.execute(
            select(Permission, role_permissions.c.access_level)
            .select_from(Permission.__table__.join(role_permissions))
            .where(role_permissions.c.role_id == role.id)
        )

        for permission, access_level in result.all():
            permissions[permission.name] = {
                "access_level": access_level or AccessLevel.READ.value,
                "max_amount": permission.max_amount,
                "requires_approval": permission.requires_approval,
                "approval_chain": permission.approval_chain,
                "rate_limit_per_hour": permission.rate_limit_per_hour,
                "rate_limit_per_day": permission.rate_limit_per_day,
                "conditions": permission.conditions
            }

        # Include parent role permissions if hierarchical
        if role.parent_role_id:
            # Load parent role explicitly
            parent_result = await db.execute(select(Role).where(Role.id == role.parent_role_id))
            parent_role = parent_result.scalar_one_or_none()
            if parent_role:
                parent_permissions = await self._get_role_permissions(parent_role, db)
                for perm_name, perm_config in parent_permissions.items():
                    if perm_name not in permissions:
                        permissions[perm_name] = perm_config

        return permissions

    async def _check_resource_ownership(
        self,
        user: User,
        resource_type: str,
        resource_id: str,
        db: AsyncSession
    ) -> bool:
        """Check if user owns the specified resource"""
        # This would need to be implemented based on your specific resource models
        # For now, implement basic merchant ownership check

        if resource_type == "merchant":
            # Check if user belongs to this merchant
            return user.merchant_id == resource_id
        elif resource_type == "transaction":
            # Check if transaction belongs to user's merchant
            # Would need to query transaction table
            pass

        return True  # Default allow for now

    async def _check_rate_limits(self, user: User, permission_name: str, db: AsyncSession) -> bool:
        """Check if user has exceeded rate limits for permission"""
        # This would implement rate limiting logic
        # For now, return True (no limits)
        return True

    async def _check_permission_conditions(
        self,
        user: User,
        permission_config: Dict,
        context: Optional[Dict],
        db: AsyncSession
    ) -> bool:
        """Check additional permission conditions"""
        conditions = permission_config.get("conditions", {})

        if not conditions:
            return True

        # Implement specific condition checks
        if conditions.get("masked_data_only") and context:
            # Ensure only masked data is accessed
            pass

        if conditions.get("today_only"):
            # Ensure only today's data is accessed
            pass

        if conditions.get("same_day_only"):
            # For voids, ensure transaction is from same day
            pass

        return True

    async def _audit_permission_check(
        self,
        user: User,
        permission: str,
        success: bool,
        reason: str,
        db: AsyncSession
    ):
        """Audit permission check"""
        if db:
            audit_log = AuditLog(
                action="permission_check",
                resource_type="permission",
                resource_id=permission,
                user_id=user.id,
                timestamp=datetime.now(timezone.utc),
                ip_address="0.0.0.0",  # Should be passed from request context
                success=success,
                error_message=reason if not success else None,
                additional_data={
                    "permission": permission,
                    "user_id": user.id
                }
            )
            db.add(audit_log)

    async def assign_role_to_user(
        self,
        user: User,
        role_name: str,
        assigned_by: User,
        scope_type: Optional[str] = None,
        scope_id: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        reason: str = "",
        db: AsyncSession = None
    ) -> bool:
        """Assign role to user"""
        try:
            result = await db.execute(select(Role).where(Role.name == role_name))
            role = result.scalar_one_or_none()
            if not role:
                return False

            # Check if assignment already exists
            result = await db.execute(
                select(UserRoleAssignment).where(
                    and_(
                        UserRoleAssignment.user_id == user.id,
                        UserRoleAssignment.role_id == role.id,
                        UserRoleAssignment.scope_type == scope_type,
                        UserRoleAssignment.scope_id == scope_id,
                        UserRoleAssignment.is_active == True
                    )
                )
            )
            existing = result.scalar_one_or_none()

            if existing:
                return False  # Already assigned

            assignment = UserRoleAssignment(
                user_id=user.id,
                role_id=role.id,
                assigned_by=assigned_by.id,
                scope_type=scope_type,
                scope_id=scope_id,
                expires_at=expires_at,
                reason=reason
            )

            db.add(assignment)

            # Clear user permission cache
            cache_key = f"user_permissions_{user.id}"
            if cache_key in self._permission_cache:
                del self._permission_cache[cache_key]

            # Audit the assignment
            await self._audit_role_assignment(user, role, assigned_by, "assigned", db)

            # Commit the changes
            await db.commit()

            return True

        except Exception as e:
            logger.error("Role assignment failed",
                        user_id=user.id, role=role_name, error=str(e))
            return False

    async def revoke_role_from_user(
        self,
        user: User,
        role_name: str,
        revoked_by: User,
        reason: str = "",
        db: AsyncSession = None
    ) -> bool:
        """Revoke role from user"""
        try:
            result = await db.execute(select(Role).where(Role.name == role_name))
            role = result.scalar_one_or_none()
            if not role:
                return False

            result = await db.execute(
                select(UserRoleAssignment).where(
                    and_(
                        UserRoleAssignment.user_id == user.id,
                        UserRoleAssignment.role_id == role.id,
                        UserRoleAssignment.is_active == True
                    )
                )
            )
            assignment = result.scalar_one_or_none()

            if not assignment:
                return False

            assignment.is_active = False
            assignment.revoked_at = datetime.now(timezone.utc)
            assignment.revoked_by = revoked_by.id
            assignment.reason = reason

            # Clear user permission cache
            cache_key = f"user_permissions_{user.id}"
            if cache_key in self._permission_cache:
                del self._permission_cache[cache_key]

            # Audit the revocation
            await self._audit_role_assignment(user, role, revoked_by, "revoked", db)

            # Commit the changes
            await db.commit()

            return True

        except Exception as e:
            logger.error("Role revocation failed",
                        user_id=user.id, role=role_name, error=str(e))
            return False

    async def _audit_role_assignment(
        self,
        user: User,
        role: Role,
        actor: User,
        action: str,
        db: AsyncSession
    ):
        """Audit role assignment/revocation"""
        audit_log = AuditLog(
            action=f"role_{action}",
            resource_type="user_role",
            resource_id=f"{user.id}:{role.id}",
            user_id=actor.id,
            affected_user_id=user.id,
            timestamp=datetime.now(timezone.utc),
            ip_address="0.0.0.0",  # Should be from request context
            success=True,
            additional_data={
                "role_name": role.name,
                "target_user_id": user.id,
                "action": action
            }
        )
        db.add(audit_log)

    async def create_approval_workflow(
        self,
        requester: User,
        action: str,
        resource_type: str,
        resource_id: str,
        request_data: Dict,
        justification: str,
        amount: Optional[int] = None,
        db: AsyncSession = None
    ) -> Optional[ApprovalWorkflow]:
        """Create approval workflow for sensitive actions"""
        try:
            # Determine required approvers based on action
            required_approvers = await self._get_required_approvers(action, amount, db)

            workflow = ApprovalWorkflow(
                requester_id=requester.id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                request_data=request_data,
                justification=justification,
                amount=amount,
                required_approvers=required_approvers,
                status="pending",
                expires_at=datetime.now(timezone.utc) + timedelta(hours=24)  # 24 hour expiry
            )

            db.add(workflow)
            await db.flush()  # Get the ID

            # Audit workflow creation
            audit_log = AuditLog(
                action="approval_workflow_created",
                resource_type="approval_workflow",
                resource_id=str(workflow.id),
                user_id=requester.id,
                timestamp=datetime.now(timezone.utc),
                ip_address="0.0.0.0",
                success=True,
                additional_data={
                    "workflow_id": workflow.id,
                    "action": action,
                    "amount": amount
                }
            )
            db.add(audit_log)

            return workflow

        except Exception as e:
            logger.error("Approval workflow creation failed",
                        requester_id=requester.id, action=action, error=str(e))
            return None

    async def _get_required_approvers(self, action: str, amount: Optional[int], db: AsyncSession) -> List[str]:
        """Get required approvers for an action"""
        # This would be based on the approval chains defined in permissions
        approval_chains = {
            "transaction_refund_large": ["finance_lead", "risk_lead"],
            "payout_approve_large": ["finance_lead"],
            "merchant_freeze_aml": ["compliance_officer"],
            "system_config_update": ["super_admin"]
        }

        return approval_chains.get(action, [])


# Global RBAC service instance
rbac_service = RBACService()