"""
RBAC Management API Endpoints

REST API endpoints for role-based access control management.
Provides role assignment, permission management, and audit trail functionality.
"""

from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Request, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import desc, and_, or_

from ..database import get_db
from ..models.rbac import (
    Role, Permission, UserRoleAssignment, PermissionGrant,
    AccessSession, AuditLog, ApprovalWorkflow
)
from ..models.users import User
from ..rbac.dependencies import (
    get_current_user_with_session, require_permission, require_role,
    require_2fa, require_hardware_key, PermissionError
)
from ..rbac.service import rbac_service

router = APIRouter(prefix="/rbac", tags=["RBAC Management"])


# ========== PYDANTIC MODELS ==========

class RoleResponse(BaseModel):
    """Role information response"""
    id: int
    name: str
    display_name: str
    description: Optional[str]
    user_type: str
    is_system_role: bool
    is_active: bool
    parent_role_id: Optional[int]
    level: int
    requires_2fa: bool
    requires_hardware_key: bool
    requires_ip_allowlist: bool
    session_timeout_minutes: int
    requires_dual_control: bool
    max_transaction_amount: Optional[int]
    ui_config: Dict[str, Any]
    feature_flags: Dict[str, Any]
    permission_count: int

    class Config:
        from_attributes = True


class PermissionResponse(BaseModel):
    """Permission information response"""
    id: int
    name: str
    display_name: str
    description: Optional[str]
    resource_type: str
    action: str
    is_global: bool
    requires_ownership: bool
    max_amount: Optional[int]
    requires_approval: bool
    approval_chain: List[str]
    rate_limit_per_hour: Optional[int]
    rate_limit_per_day: Optional[int]
    conditions: Dict[str, Any]

    class Config:
        from_attributes = True


class UserRoleAssignmentRequest(BaseModel):
    """Request to assign role to user"""
    user_id: int
    role_name: str
    scope_type: Optional[str] = None
    scope_id: Optional[str] = None
    expires_at: Optional[datetime] = None
    reason: str = Field(..., min_length=10, description="Justification for role assignment")


class UserRoleAssignmentResponse(BaseModel):
    """User role assignment response"""
    id: int
    user_id: int
    role_id: int
    role_name: str
    scope_type: Optional[str]
    scope_id: Optional[str]
    assigned_at: datetime
    assigned_by: int
    expires_at: Optional[datetime]
    is_active: bool
    reason: str

    class Config:
        from_attributes = True


class PermissionGrantRequest(BaseModel):
    """Request to grant permission directly to user"""
    user_id: int
    permission_name: str
    access_level: str = "read"
    scope_type: Optional[str] = None
    scope_id: Optional[str] = None
    expires_at: Optional[datetime] = None
    reason: str = Field(..., min_length=10, description="Justification for permission grant")
    conditions: Dict[str, Any] = {}
    rate_limit_override: Optional[int] = None
    amount_limit_override: Optional[int] = None


class ApprovalWorkflowResponse(BaseModel):
    """Approval workflow response"""
    id: int
    requester_id: int
    action: str
    resource_type: str
    resource_id: Optional[str]
    status: str
    priority: str
    request_data: Dict[str, Any]
    justification: str
    amount: Optional[int]
    created_at: datetime
    expires_at: Optional[datetime]
    required_approvers: List[str]
    approvals: List[Dict[str, Any]]

    class Config:
        from_attributes = True


class ApprovalActionRequest(BaseModel):
    """Request to approve or reject workflow"""
    action: str = Field(..., regex="^(approve|reject)$")
    comments: str = Field(..., min_length=5, description="Approval/rejection comments")


class AuditLogResponse(BaseModel):
    """Audit log entry response"""
    id: int
    action: str
    resource_type: str
    resource_id: Optional[str]
    user_id: Optional[int]
    timestamp: datetime
    ip_address: str
    success: bool
    error_message: Optional[str]
    additional_data: Dict[str, Any]
    risk_level: str

    class Config:
        from_attributes = True


class UserPermissionsResponse(BaseModel):
    """User effective permissions response"""
    user_id: int
    permissions: Dict[str, Dict[str, Any]]
    roles: List[str]
    last_updated: datetime


# ========== ROLE MANAGEMENT ENDPOINTS ==========

@router.get("/roles", response_model=List[RoleResponse])
@require_permission("system_config_read")
async def list_roles(
    user_type: Optional[str] = Query(None, description="Filter by user type"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    current_user: Dict = Depends(get_current_user_with_session),
    db: Session = Depends(get_db)
):
    """List all roles with optional filtering"""
    query = db.query(Role)

    if user_type:
        query = query.filter(Role.user_type == user_type)

    if is_active is not None:
        query = query.filter(Role.is_active == is_active)

    roles = query.order_by(Role.level, Role.name).all()

    role_responses = []
    for role in roles:
        role_dict = {
            "id": role.id,
            "name": role.name,
            "display_name": role.display_name,
            "description": role.description,
            "user_type": role.user_type,
            "is_system_role": role.is_system_role,
            "is_active": role.is_active,
            "parent_role_id": role.parent_role_id,
            "level": role.level,
            "requires_2fa": role.requires_2fa,
            "requires_hardware_key": role.requires_hardware_key,
            "requires_ip_allowlist": role.requires_ip_allowlist,
            "session_timeout_minutes": role.session_timeout_minutes,
            "requires_dual_control": role.requires_dual_control,
            "max_transaction_amount": role.max_transaction_amount,
            "ui_config": role.ui_config,
            "feature_flags": role.feature_flags,
            "permission_count": len(role.permissions)
        }
        role_responses.append(RoleResponse(**role_dict))

    return role_responses


@router.get("/roles/{role_id}", response_model=RoleResponse)
@require_permission("system_config_read")
async def get_role(
    role_id: int,
    current_user: Dict = Depends(get_current_user_with_session),
    db: Session = Depends(get_db)
):
    """Get specific role details"""
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    role_dict = {
        "id": role.id,
        "name": role.name,
        "display_name": role.display_name,
        "description": role.description,
        "user_type": role.user_type,
        "is_system_role": role.is_system_role,
        "is_active": role.is_active,
        "parent_role_id": role.parent_role_id,
        "level": role.level,
        "requires_2fa": role.requires_2fa,
        "requires_hardware_key": role.requires_hardware_key,
        "requires_ip_allowlist": role.requires_ip_allowlist,
        "session_timeout_minutes": role.session_timeout_minutes,
        "requires_dual_control": role.requires_dual_control,
        "max_transaction_amount": role.max_transaction_amount,
        "ui_config": role.ui_config,
        "feature_flags": role.feature_flags,
        "permission_count": len(role.permissions)
    }

    return RoleResponse(**role_dict)


@router.get("/permissions", response_model=List[PermissionResponse])
@require_permission("system_config_read")
async def list_permissions(
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    action: Optional[str] = Query(None, description="Filter by action"),
    current_user: Dict = Depends(get_current_user_with_session),
    db: Session = Depends(get_db)
):
    """List all permissions with optional filtering"""
    query = db.query(Permission).filter(Permission.is_active == True)

    if resource_type:
        query = query.filter(Permission.resource_type == resource_type)

    if action:
        query = query.filter(Permission.action == action)

    permissions = query.order_by(Permission.resource_type, Permission.action).all()

    return [PermissionResponse.from_orm(perm) for perm in permissions]


# ========== USER ROLE ASSIGNMENT ENDPOINTS ==========

@router.post("/users/roles/assign", response_model=UserRoleAssignmentResponse)
@require_permission("merchant_manage_staff")  # Or system role management permission
@require_2fa
async def assign_role_to_user(
    assignment_request: UserRoleAssignmentRequest,
    current_user: Dict = Depends(get_current_user_with_session),
    db: Session = Depends(get_db)
):
    """Assign role to user"""
    user = current_user["user"]

    # Get target user
    target_user = db.query(User).filter(User.id == assignment_request.user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Check if assigner has permission to assign this role
    # Implementation would check role hierarchy and scope

    # Assign role
    success = await rbac_service.assign_role_to_user(
        user=target_user,
        role_name=assignment_request.role_name,
        assigned_by=user,
        scope_type=assignment_request.scope_type,
        scope_id=assignment_request.scope_id,
        expires_at=assignment_request.expires_at,
        reason=assignment_request.reason,
        db=db
    )

    if not success:
        raise HTTPException(
            status_code=400,
            detail="Failed to assign role - role may not exist or already assigned"
        )

    db.commit()

    # Return the assignment
    assignment = db.query(UserRoleAssignment).filter(
        and_(
            UserRoleAssignment.user_id == assignment_request.user_id,
            UserRoleAssignment.role_id == db.query(Role).filter(
                Role.name == assignment_request.role_name
            ).first().id,
            UserRoleAssignment.is_active == True
        )
    ).first()

    return UserRoleAssignmentResponse(
        id=assignment.id,
        user_id=assignment.user_id,
        role_id=assignment.role_id,
        role_name=assignment_request.role_name,
        scope_type=assignment.scope_type,
        scope_id=assignment.scope_id,
        assigned_at=assignment.assigned_at,
        assigned_by=assignment.assigned_by,
        expires_at=assignment.expires_at,
        is_active=assignment.is_active,
        reason=assignment.reason
    )


@router.delete("/users/{user_id}/roles/{role_name}")
@require_permission("merchant_manage_staff")
@require_2fa
async def revoke_role_from_user(
    user_id: int,
    role_name: str,
    reason: str = Query(..., min_length=10, description="Reason for revocation"),
    current_user: Dict = Depends(get_current_user_with_session),
    db: Session = Depends(get_db)
):
    """Revoke role from user"""
    user = current_user["user"]

    # Get target user
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Revoke role
    success = await rbac_service.revoke_role_from_user(
        user=target_user,
        role_name=role_name,
        revoked_by=user,
        reason=reason,
        db=db
    )

    if not success:
        raise HTTPException(
            status_code=400,
            detail="Failed to revoke role - role may not exist or not assigned"
        )

    db.commit()

    return {"message": "Role revoked successfully"}


@router.get("/users/{user_id}/roles", response_model=List[UserRoleAssignmentResponse])
@require_permission("merchant_read")
async def get_user_roles(
    user_id: int,
    include_expired: bool = Query(False, description="Include expired assignments"),
    current_user: Dict = Depends(get_current_user_with_session),
    db: Session = Depends(get_db)
):
    """Get all role assignments for a user"""
    query = db.query(UserRoleAssignment).filter(UserRoleAssignment.user_id == user_id)

    if not include_expired:
        query = query.filter(
            and_(
                UserRoleAssignment.is_active == True,
                or_(
                    UserRoleAssignment.expires_at.is_(None),
                    UserRoleAssignment.expires_at > datetime.now(timezone.utc)
                )
            )
        )

    assignments = query.order_by(desc(UserRoleAssignment.assigned_at)).all()

    response_data = []
    for assignment in assignments:
        role = db.query(Role).filter(Role.id == assignment.role_id).first()
        response_data.append(UserRoleAssignmentResponse(
            id=assignment.id,
            user_id=assignment.user_id,
            role_id=assignment.role_id,
            role_name=role.name if role else "Unknown",
            scope_type=assignment.scope_type,
            scope_id=assignment.scope_id,
            assigned_at=assignment.assigned_at,
            assigned_by=assignment.assigned_by,
            expires_at=assignment.expires_at,
            is_active=assignment.is_active,
            reason=assignment.reason
        ))

    return response_data


@router.get("/users/{user_id}/permissions", response_model=UserPermissionsResponse)
@require_permission("merchant_read")
async def get_user_permissions(
    user_id: int,
    current_user: Dict = Depends(get_current_user_with_session),
    db: Session = Depends(get_db)
):
    """Get effective permissions for a user"""
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    permissions = await rbac_service.get_user_permissions(target_user, db)

    # Get user's roles
    role_assignments = db.query(UserRoleAssignment).filter(
        and_(
            UserRoleAssignment.user_id == user_id,
            UserRoleAssignment.is_active == True
        )
    ).all()

    roles = []
    for assignment in role_assignments:
        role = db.query(Role).filter(Role.id == assignment.role_id).first()
        if role:
            roles.append(role.name)

    return UserPermissionsResponse(
        user_id=user_id,
        permissions=permissions,
        roles=roles,
        last_updated=datetime.now(timezone.utc)
    )


# ========== PERMISSION GRANT ENDPOINTS ==========

@router.post("/users/permissions/grant")
@require_permission("system_config_update")
@require_hardware_key
async def grant_permission_to_user(
    grant_request: PermissionGrantRequest,
    current_user: Dict = Depends(get_current_user_with_session),
    db: Session = Depends(get_db)
):
    """Grant permission directly to user (bypass roles)"""
    user = current_user["user"]

    # Get target user and permission
    target_user = db.query(User).filter(User.id == grant_request.user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    permission = db.query(Permission).filter(Permission.name == grant_request.permission_name).first()
    if not permission:
        raise HTTPException(status_code=404, detail="Permission not found")

    # Check for existing grant
    existing = db.query(PermissionGrant).filter(
        and_(
            PermissionGrant.user_id == grant_request.user_id,
            PermissionGrant.permission_id == permission.id,
            PermissionGrant.scope_type == grant_request.scope_type,
            PermissionGrant.scope_id == grant_request.scope_id,
            PermissionGrant.is_active == True
        )
    ).first()

    if existing:
        raise HTTPException(status_code=400, detail="Permission already granted")

    # Create grant
    grant = PermissionGrant(
        user_id=grant_request.user_id,
        permission_id=permission.id,
        access_level=grant_request.access_level,
        granted_by=user.id,
        expires_at=grant_request.expires_at,
        scope_type=grant_request.scope_type,
        scope_id=grant_request.scope_id,
        scope_data={},
        reason=grant_request.reason,
        conditions=grant_request.conditions,
        rate_limit_override=grant_request.rate_limit_override,
        amount_limit_override=grant_request.amount_limit_override
    )

    db.add(grant)
    db.commit()

    return {"message": "Permission granted successfully", "grant_id": grant.id}


# ========== APPROVAL WORKFLOW ENDPOINTS ==========

@router.get("/approvals/pending", response_model=List[ApprovalWorkflowResponse])
@require_permission("system_config_read")
async def get_pending_approvals(
    current_user: Dict = Depends(get_current_user_with_session),
    db: Session = Depends(get_db)
):
    """Get pending approval workflows"""
    user = current_user["user"]

    # Get user's roles to determine which approvals they can handle
    user_permissions = await rbac_service.get_user_permissions(user, db)
    user_roles = []

    role_assignments = db.query(UserRoleAssignment).filter(
        and_(
            UserRoleAssignment.user_id == user.id,
            UserRoleAssignment.is_active == True
        )
    ).all()

    for assignment in role_assignments:
        role = db.query(Role).filter(Role.id == assignment.role_id).first()
        if role:
            user_roles.append(role.name)

    # Get workflows where user can approve
    workflows = db.query(ApprovalWorkflow).filter(
        and_(
            ApprovalWorkflow.status == "pending",
            ApprovalWorkflow.expires_at > datetime.now(timezone.utc)
        )
    ).all()

    # Filter workflows user can approve
    relevant_workflows = []
    for workflow in workflows:
        required_approvers = workflow.required_approvers
        if any(role in required_approvers for role in user_roles):
            relevant_workflows.append(workflow)

    return [ApprovalWorkflowResponse.from_orm(wf) for wf in relevant_workflows]


@router.post("/approvals/{workflow_id}/action")
@require_permission("system_config_update")
@require_2fa
async def handle_approval(
    workflow_id: int,
    action_request: ApprovalActionRequest,
    current_user: Dict = Depends(get_current_user_with_session),
    db: Session = Depends(get_db)
):
    """Approve or reject an approval workflow"""
    user = current_user["user"]

    workflow = db.query(ApprovalWorkflow).filter(ApprovalWorkflow.id == workflow_id).first()
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")

    if workflow.status != "pending":
        raise HTTPException(status_code=400, detail="Workflow is not pending")

    if workflow.expires_at <= datetime.now(timezone.utc):
        workflow.status = "expired"
        db.commit()
        raise HTTPException(status_code=400, detail="Workflow has expired")

    # Check if user can approve this workflow
    user_roles = []
    role_assignments = db.query(UserRoleAssignment).filter(
        and_(
            UserRoleAssignment.user_id == user.id,
            UserRoleAssignment.is_active == True
        )
    ).all()

    for assignment in role_assignments:
        role = db.query(Role).filter(Role.id == assignment.role_id).first()
        if role:
            user_roles.append(role.name)

    if not any(role in workflow.required_approvers for role in user_roles):
        raise PermissionError("You cannot approve this workflow")

    # Update workflow
    approval_record = {
        "user_id": user.id,
        "action": action_request.action,
        "comments": action_request.comments,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    approvals = workflow.approvals.copy()
    approvals.append(approval_record)
    workflow.approvals = approvals

    if action_request.action == "approve":
        workflow.status = "approved"
        workflow.approved_by = user.id
    else:
        workflow.status = "rejected"
        workflow.rejected_by = user.id

    workflow.completed_at = datetime.now(timezone.utc)
    workflow.completion_reason = action_request.comments

    db.commit()

    return {"message": f"Workflow {action_request.action}d successfully"}


# ========== AUDIT LOG ENDPOINTS ==========

@router.get("/audit-logs", response_model=List[AuditLogResponse])
@require_permission("system_config_read")
async def get_audit_logs(
    action: Optional[str] = Query(None, description="Filter by action"),
    user_id: Optional[int] = Query(None, description="Filter by user ID"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    start_date: Optional[datetime] = Query(None, description="Start date filter"),
    end_date: Optional[datetime] = Query(None, description="End date filter"),
    limit: int = Query(100, le=1000, description="Maximum number of results"),
    offset: int = Query(0, description="Offset for pagination"),
    current_user: Dict = Depends(get_current_user_with_session),
    db: Session = Depends(get_db)
):
    """Get audit logs with filtering and pagination"""
    query = db.query(AuditLog)

    if action:
        query = query.filter(AuditLog.action == action)

    if user_id:
        query = query.filter(AuditLog.user_id == user_id)

    if resource_type:
        query = query.filter(AuditLog.resource_type == resource_type)

    if start_date:
        query = query.filter(AuditLog.timestamp >= start_date)

    if end_date:
        query = query.filter(AuditLog.timestamp <= end_date)

    logs = query.order_by(desc(AuditLog.timestamp)).offset(offset).limit(limit).all()

    return [AuditLogResponse.from_orm(log) for log in logs]


# ========== SYSTEM MANAGEMENT ENDPOINTS ==========

@router.post("/initialize")
@require_role(["super_admin"])
@require_hardware_key
async def initialize_rbac_system(
    current_user: Dict = Depends(get_current_user_with_session),
    db: Session = Depends(get_db)
):
    """Initialize RBAC system with default roles and permissions"""
    success = await rbac_service.initialize_system_roles(db)

    if success:
        return {"message": "RBAC system initialized successfully"}
    else:
        raise HTTPException(
            status_code=500,
            detail="Failed to initialize RBAC system"
        )


@router.get("/system/status")
@require_permission("system_config_read")
async def get_rbac_system_status(
    current_user: Dict = Depends(get_current_user_with_session),
    db: Session = Depends(get_db)
):
    """Get RBAC system status and statistics"""
    total_users = db.query(User).count()
    total_roles = db.query(Role).count()
    total_permissions = db.query(Permission).count()
    active_sessions = db.query(AccessSession).filter(AccessSession.is_active == True).count()
    pending_approvals = db.query(ApprovalWorkflow).filter(ApprovalWorkflow.status == "pending").count()

    recent_audit_logs = db.query(AuditLog).filter(
        AuditLog.timestamp >= datetime.now(timezone.utc) - timedelta(hours=24)
    ).count()

    return {
        "system_status": "healthy",
        "statistics": {
            "total_users": total_users,
            "total_roles": total_roles,
            "total_permissions": total_permissions,
            "active_sessions": active_sessions,
            "pending_approvals": pending_approvals,
            "audit_logs_24h": recent_audit_logs
        },
        "timestamp": datetime.now(timezone.utc)
    }