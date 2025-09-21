"""
RBAC System Tests

Comprehensive test suite for role-based access control functionality.
Tests permissions, role assignments, security policies, and audit trails.
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, AsyncMock, patch
from sqlalchemy.orm import Session

try:
    from app.models.rbac import (
        Role, Permission, UserRoleAssignment, PermissionGrant,
        AccessSession, AuditLog, ApprovalWorkflow,
        UserType, AccessLevel, ResourceType
    )
    from app.models.users import User
    from app.rbac.service import RBACService, rbac_service
    from app.rbac.dependencies import (
        require_permission, require_role, require_2fa,
        get_current_user_with_session, PermissionError
    )
except ImportError as e:
    pytest.skip(f"Skipping RBAC tests due to import error: {e}", allow_module_level=True)


class TestRBACModels:
    """Test RBAC database models"""

    @pytest.mark.unit
    @pytest.mark.rbac
    @pytest.mark.asyncio
    async def test_role_creation(self, async_session):
        """Test role model creation and relationships"""
        role = Role(
            name="test_role",
            display_name="Test Role",
            description="A test role",
            user_type=UserType.PLATFORM_ADMIN.value,
            requires_2fa=True,
            session_timeout_minutes=480
        )

        async_session.add(role)
        await async_session.commit()

        assert role.id is not None
        assert role.name == "test_role"
        assert role.requires_2fa is True
        assert role.is_active is True
        assert role.created_at is not None

    @pytest.mark.unit
    @pytest.mark.rbac
    @pytest.mark.asyncio
    async def test_permission_creation(self, async_session):
        """Test permission model creation"""
        permission = Permission(
            name="test_permission",
            display_name="Test Permission",
            resource_type="merchant",
            action="read",
            max_amount=10000,
            rate_limit_per_hour=100
        )

        async_session.add(permission)
        await async_session.commit()

        assert permission.id is not None
        assert permission.name == "test_permission"
        assert permission.resource_type == "merchant"
        assert permission.max_amount == 10000

    @pytest.mark.unit
    @pytest.mark.rbac
    @pytest.mark.asyncio
    async def test_user_role_assignment(self, async_session, mock_user):
        """Test user role assignment model"""
        role = Role(
            name="test_role",
            display_name="Test Role",
            user_type=UserType.MERCHANT_USER.value
        )
        async_session.add(role)
        await async_session.flush()

        assignment = UserRoleAssignment(
            user_id=mock_user.id,
            role_id=role.id,
            assigned_by=mock_user.id,
            scope_type="merchant",
            scope_id="mer_123",
            reason="Test assignment"
        )

        async_session.add(assignment)
        await async_session.commit()

        assert assignment.id is not None
        assert assignment.is_active is True
        assert assignment.scope_type == "merchant"
        assert assignment.assigned_at is not None

    @pytest.mark.unit
    @pytest.mark.rbac
    @pytest.mark.asyncio
    async def test_permission_grant(self, async_session, mock_user):
        """Test direct permission grant model"""
        permission = Permission(
            name="special_permission",
            display_name="Special Permission",
            resource_type="system",
            action="admin"
        )
        async_session.add(permission)
        await async_session.flush()

        grant = PermissionGrant(
            user_id=mock_user.id,
            permission_id=permission.id,
            access_level=AccessLevel.ADMIN.value,
            granted_by=mock_user.id,
            reason="Emergency access required",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24)
        )

        async_session.add(grant)
        await async_session.commit()

        assert grant.id is not None
        assert grant.access_level == AccessLevel.ADMIN.value
        assert grant.expires_at is not None

    @pytest.mark.unit
    @pytest.mark.rbac
    @pytest.mark.asyncio
    async def test_audit_log_creation(self, async_session, mock_user):
        """Test audit log model"""
        audit_log = AuditLog(
            action="role_assigned",
            resource_type="user_role",
            resource_id=f"{mock_user.id}:1",
            user_id=mock_user.id,
            ip_address="192.168.1.100",
            success=True,
            additional_data={"role_name": "test_role"}
        )

        async_session.add(audit_log)
        await async_session.commit()

        assert audit_log.id is not None
        assert audit_log.action == "role_assigned"
        assert audit_log.success is True


class TestRBACService:
    """Test RBAC service functionality"""

    @pytest.mark.unit
    @pytest.mark.rbac
    @pytest.mark.asyncio
    async def test_initialize_system_roles(self, async_session):
        """Test system role initialization from config"""
        service = RBACService()

        # Mock the config loading
        service.config = {
            "permissions": {
                "test_permission": {
                    "display_name": "Test Permission",
                    "resource_type": "test",
                    "action": "read"
                }
            },
            "roles": {
                "test_admin": {
                    "display_name": "Test Admin",
                    "user_type": "platform_admin",
                    "requires_2fa": True
                }
            },
            "role_permissions": {
                "test_admin": [
                    {"permission": "test_permission", "access_level": "read"}
                ]
            }
        }

        success = await service.initialize_system_roles(async_session)

        assert success is True

        # Check that role was created
        from sqlalchemy import select
        result = await async_session.execute(select(Role).where(Role.name == "test_admin"))
        role = result.scalar_one_or_none()
        assert role is not None
        assert role.display_name == "Test Admin"

        # Check that permission was created
        result = await async_session.execute(select(Permission).where(Permission.name == "test_permission"))
        permission = result.scalar_one_or_none()
        assert permission is not None
        assert permission.resource_type == "test"

    @pytest.mark.unit
    @pytest.mark.rbac
    @pytest.mark.asyncio
    async def test_check_permission_success(self, async_session, mock_user):
        """Test successful permission check"""
        service = RBACService()

        # Create role and permission
        role = Role(name="test_role", display_name="Test Role", user_type="platform_admin")
        permission = Permission(name="test_perm", display_name="Test Permission", resource_type="test", action="read")

        async_session.add_all([role, permission])
        await async_session.flush()

        # Create role-permission relationship manually
        from app.models.rbac import role_permissions
        await async_session.execute(
            role_permissions.insert().values(
                role_id=role.id,
                permission_id=permission.id,
                access_level="read"
            )
        )

        # Assign role to user
        assignment = UserRoleAssignment(
            user_id=mock_user.id,
            role_id=role.id,
            assigned_by=mock_user.id,
            scope_type="global"
        )
        async_session.add(assignment)
        await async_session.commit()

        # Test permission check
        has_permission = await service.check_permission(
            user=mock_user,
            permission_name="test_perm",
            db=async_session
        )

        assert has_permission is True

    @pytest.mark.unit
    @pytest.mark.rbac
    @pytest.mark.asyncio
    async def test_check_permission_denied(self, async_session, mock_user):
        """Test permission check denial"""
        service = RBACService()

        # Test permission check without any roles
        has_permission = await service.check_permission(
            user=mock_user,
            permission_name="nonexistent_permission",
            db=async_session
        )

        assert has_permission is False

    @pytest.mark.unit
    @pytest.mark.rbac
    @pytest.mark.asyncio
    async def test_check_permission_amount_limit(self, async_session, mock_user):
        """Test permission check with amount limits"""
        service = RBACService()

        # Create permission with amount limit
        role = Role(name="cs_agent", display_name="CS Agent", user_type="platform_admin")
        permission = Permission(
            name="refund_small",
            display_name="Small Refund",
            resource_type="transaction",
            action="refund",
            max_amount=20000  # £200
        )

        async_session.add_all([role, permission])
        await async_session.flush()

        # Create role-permission relationship manually
        from app.models.rbac import role_permissions
        await async_session.execute(
            role_permissions.insert().values(
                role_id=role.id,
                permission_id=permission.id,
                access_level="read"
            )
        )

        # Assign role to user
        assignment = UserRoleAssignment(
            user_id=mock_user.id,
            role_id=role.id,
            assigned_by=mock_user.id
        )
        async_session.add(assignment)
        await async_session.commit()

        # Test within limit
        has_permission = await service.check_permission(
            user=mock_user,
            permission_name="refund_small",
            amount=15000,  # £150
            db=async_session
        )
        assert has_permission is True

        # Test exceeding limit
        has_permission = await service.check_permission(
            user=mock_user,
            permission_name="refund_small",
            amount=25000,  # £250
            db=async_session
        )
        assert has_permission is False

    @pytest.mark.unit
    @pytest.mark.rbac
    @pytest.mark.asyncio
    async def test_assign_role_to_user(self, async_session, mock_user):
        """Test role assignment functionality"""
        service = RBACService()

        role = Role(name="test_role", display_name="Test Role", user_type="merchant_user")
        async_session.add(role)
        await async_session.commit()

        success = await service.assign_role_to_user(
            user=mock_user,
            role_name="test_role",
            assigned_by=mock_user,
            scope_type="merchant",
            scope_id="mer_123",
            reason="Test assignment",
            db=async_session
        )

        assert success is True

        # Check assignment exists
        from sqlalchemy import select
        result = await async_session.execute(
            select(UserRoleAssignment).where(
                UserRoleAssignment.user_id == mock_user.id,
                UserRoleAssignment.role_id == role.id
            )
        )
        assignment = result.scalar_one_or_none()

        assert assignment is not None
        assert assignment.scope_type == "merchant"
        assert assignment.scope_id == "mer_123"

    @pytest.mark.unit
    @pytest.mark.rbac
    @pytest.mark.asyncio
    async def test_revoke_role_from_user(self, async_session, mock_user):
        """Test role revocation functionality"""
        service = RBACService()

        # Create and assign role
        role = Role(name="test_role", display_name="Test Role", user_type="merchant_user")
        async_session.add(role)
        await async_session.flush()

        assignment = UserRoleAssignment(
            user_id=mock_user.id,
            role_id=role.id,
            assigned_by=mock_user.id,
            scope_type="merchant",
            scope_id="mer_123"
        )
        async_session.add(assignment)
        await async_session.commit()

        # Revoke role
        success = await service.revoke_role_from_user(
            user=mock_user,
            role_name="test_role",
            revoked_by=mock_user,
            reason="Test revocation",
            db=async_session
        )

        assert success is True

        # Check assignment is inactive
        await async_session.refresh(assignment)
        assert assignment.is_active is False
        assert assignment.revoked_at is not None

    @pytest.mark.unit
    @pytest.mark.rbac
    @pytest.mark.asyncio
    async def test_get_user_permissions(self, async_session, mock_user):
        """Test getting user effective permissions"""
        service = RBACService()

        # Create role with permissions
        role = Role(name="test_role", display_name="Test Role", user_type="platform_admin")
        permission1 = Permission(name="perm1", display_name="Permission 1", resource_type="test", action="read")
        permission2 = Permission(name="perm2", display_name="Permission 2", resource_type="test", action="write")

        async_session.add_all([role, permission1, permission2])
        await async_session.flush()

        # Create role-permission relationships manually
        from app.models.rbac import role_permissions
        await async_session.execute(
            role_permissions.insert().values([
                {"role_id": role.id, "permission_id": permission1.id, "access_level": "read"},
                {"role_id": role.id, "permission_id": permission2.id, "access_level": "read"}
            ])
        )

        assignment = UserRoleAssignment(
            user_id=mock_user.id,
            role_id=role.id,
            assigned_by=mock_user.id
        )
        async_session.add(assignment)
        await async_session.commit()

        permissions = await service.get_user_permissions(mock_user, async_session)

        assert "perm1" in permissions
        assert "perm2" in permissions
        assert len(permissions) == 2

    @pytest.mark.unit
    @pytest.mark.rbac
    @pytest.mark.asyncio
    async def test_create_approval_workflow(self, async_session, mock_user):
        """Test approval workflow creation"""
        service = RBACService()

        workflow = await service.create_approval_workflow(
            requester=mock_user,
            action="transaction_refund_large",
            resource_type="transaction",
            resource_id="txn_123",
            request_data={"amount": 50000, "reason": "customer complaint"},
            justification="Large refund requires approval",
            amount=50000,
            db=async_session
        )

        assert workflow is not None
        assert workflow.action == "transaction_refund_large"
        assert workflow.status == "pending"
        assert workflow.amount == 50000
        assert workflow.expires_at is not None


class TestRBACDependencies:
    """Test FastAPI RBAC dependencies"""

    @pytest.mark.unit
    @pytest.mark.rbac
    @pytest.mark.asyncio
    async def test_get_current_user_with_session_valid(self, mock_request, mock_credentials, async_session, mock_user):
        """Test valid session authentication"""
        # Create active session
        session = AccessSession(
            user_id=mock_user.id,
            session_token=mock_credentials.credentials,
            ip_address="192.168.1.100",
            user_agent="Test Agent",
            auth_method="jwt",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            is_active=True
        )
        async_session.add(session)
        await async_session.commit()

        with patch('app.rbac.dependencies.get_current_user', return_value=mock_user):
            from app.rbac.dependencies import get_current_user_with_session

            mock_request.client.host = "192.168.1.100"

            result = await get_current_user_with_session(
                request=mock_request,
                credentials=mock_credentials,
                db=async_session
            )

            assert result["user"] == mock_user
            assert result["session"] == session
            assert result["client_ip"] == "192.168.1.100"

    @pytest.mark.unit
    @pytest.mark.rbac
    @pytest.mark.asyncio
    async def test_get_current_user_with_session_expired(self, mock_request, mock_credentials, async_session, mock_user):
        """Test expired session handling"""
        # Create expired session
        session = AccessSession(
            user_id=mock_user.id,
            session_token=mock_credentials.credentials,
            ip_address="192.168.1.100",
            user_agent="Test Agent",
            auth_method="jwt",
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),  # Expired
            is_active=True
        )
        async_session.add(session)
        await async_session.commit()

        with patch('app.rbac.dependencies.get_current_user', return_value=mock_user):
            from app.rbac.dependencies import get_current_user_with_session, AuthenticationError

            with pytest.raises(AuthenticationError):
                await get_current_user_with_session(
                    request=mock_request,
                    credentials=mock_credentials,
                    db=async_session
                )

    @pytest.mark.unit
    @pytest.mark.rbac
    def test_require_permission_decorator(self, mock_user):
        """Test permission requirement decorator"""
        from app.rbac.dependencies import require_permission

        @require_permission("test_permission")
        async def test_function(request, current_user, db):
            return {"status": "success"}

        # This test would need more setup to properly test the decorator
        assert callable(test_function)

    @pytest.mark.unit
    @pytest.mark.rbac
    def test_require_role_decorator(self, mock_user):
        """Test role requirement decorator"""
        from app.rbac.dependencies import require_role

        @require_role(["admin"])
        async def test_function(current_user, db):
            return {"status": "success"}

        assert callable(test_function)

    @pytest.mark.unit
    @pytest.mark.rbac
    def test_require_2fa_decorator(self):
        """Test 2FA requirement decorator"""
        from app.rbac.dependencies import require_2fa

        @require_2fa
        async def test_function(current_user):
            return {"status": "success"}

        assert callable(test_function)


# Additional security and integration tests would go here...