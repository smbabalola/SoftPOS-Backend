"""
Terminal Management API Endpoints

RESTful API for managing SoftPOS terminals, groups, and fleet operations.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import CurrentUser, require_payments_create, require_payments_read
from ..terminal_management import (
    terminal_manager,
    TerminalCapability,
    TerminalStatus,
    TerminalType,
    ConfigurationType
)

router = APIRouter(prefix="/v1/terminals", tags=["Terminal Management"])


class TerminalRegistrationRequest(BaseModel):
    """Request model for terminal registration."""
    device_name: str = Field(..., description="Human-readable device name")
    device_model: str = Field(..., description="Device model/type")
    serial_number: str = Field(..., description="Device serial number")
    os_version: str = Field(..., description="Operating system version")
    app_version: str = Field(..., description="SoftPOS app version")
    hardware_id: Optional[str] = Field(None, description="Unique hardware identifier")
    device_type: Optional[str] = Field(None, description="Device type (phone, tablet, etc.)")
    form_factor: Optional[str] = Field(None, description="Device form factor")
    nfc_enabled: bool = Field(False, description="NFC capability")
    camera_available: bool = Field(False, description="Camera availability")
    biometric_available: bool = Field(False, description="Biometric authentication support")

    # Location information
    location_name: Optional[str] = Field(None, description="Location/store name")
    address: Optional[str] = Field(None, description="Physical address")
    timezone: str = Field("UTC", description="Timezone for the terminal")


class TerminalConfigurationRequest(BaseModel):
    """Request model for terminal configuration updates."""
    config_type: str = Field(..., description="Configuration type")
    configuration: Dict = Field(..., description="Configuration parameters")


class TerminalGroupRequest(BaseModel):
    """Request model for creating terminal groups."""
    group_name: str = Field(..., description="Group name")
    description: Optional[str] = Field(None, description="Group description")
    terminal_ids: Optional[Set[str]] = Field(default_factory=set, description="Initial terminal IDs")


class TerminalHeartbeatRequest(BaseModel):
    """Request model for terminal heartbeat."""
    status: str = Field(..., description="Terminal status")
    battery_level: Optional[int] = Field(None, ge=0, le=100, description="Battery percentage")
    network_strength: Optional[int] = Field(None, ge=0, le=100, description="Network signal strength")
    memory_usage: Optional[float] = Field(None, ge=0, le=1, description="Memory usage percentage")
    cpu_usage: Optional[float] = Field(None, ge=0, le=1, description="CPU usage percentage")
    disk_usage: Optional[float] = Field(None, ge=0, le=1, description="Disk usage percentage")
    last_error: Optional[str] = Field(None, description="Last error message")
    performance_metrics: Optional[Dict] = Field(default_factory=dict, description="Additional performance metrics")


class TerminalCommandRequest(BaseModel):
    """Request model for sending commands to terminals."""
    command_type: str = Field(..., description="Command type")
    payload: Dict = Field(..., description="Command payload")


class TerminalResponse(BaseModel):
    """Response model for terminal information."""
    terminal_id: str
    merchant_id: str
    device_name: str
    device_model: str
    terminal_type: str
    serial_number: str
    status: str
    location_name: Optional[str]
    address: Optional[str]
    last_heartbeat: Optional[str]
    last_transaction: Optional[str]
    transaction_count_today: int
    volume_today: str
    capabilities: List[str]
    created_at: str
    updated_at: str


@router.post("/register", response_model=TerminalResponse, status_code=201)
async def register_terminal(
    request: TerminalRegistrationRequest,
    current_user: CurrentUser = Depends(require_payments_create)
):
    """Register a new terminal device."""
    try:
        # Prepare device info
        device_info = {
            "device_name": request.device_name,
            "model": request.device_model,
            "serial_number": request.serial_number,
            "os_version": request.os_version,
            "app_version": request.app_version,
            "hardware_id": request.hardware_id,
            "device_type": request.device_type or "mobile",
            "form_factor": request.form_factor or "phone",
            "nfc_enabled": request.nfc_enabled,
            "camera_available": request.camera_available,
            "biometric_available": request.biometric_available
        }

        # Prepare location info
        location_info = None
        if request.location_name or request.address:
            location_info = {
                "name": request.location_name,
                "address": request.address,
                "timezone": request.timezone
            }

        # Register terminal
        terminal = await terminal_manager.register_terminal(
            merchant_id=current_user.merchant_id,
            device_info=device_info,
            location_info=location_info
        )

        return TerminalResponse(
            terminal_id=terminal.terminal_id,
            merchant_id=terminal.merchant_id,
            device_name=terminal.device_name,
            device_model=terminal.device_model,
            terminal_type=terminal.terminal_type.value,
            serial_number=terminal.serial_number,
            status=terminal.status.value,
            location_name=terminal.location_name,
            address=terminal.address,
            last_heartbeat=terminal.last_heartbeat.isoformat() if terminal.last_heartbeat else None,
            last_transaction=terminal.last_transaction.isoformat() if terminal.last_transaction else None,
            transaction_count_today=terminal.transaction_count_today,
            volume_today=str(terminal.volume_today),
            capabilities=[cap.value for cap in terminal.capabilities],
            created_at=terminal.created_at.isoformat(),
            updated_at=terminal.updated_at.isoformat()
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{terminal_id}/activate")
async def activate_terminal(
    terminal_id: str,
    current_user: CurrentUser = Depends(require_payments_create)
):
    """Activate a registered terminal."""
    # Verify terminal belongs to merchant
    if terminal_id not in terminal_manager.terminals:
        raise HTTPException(status_code=404, detail="Terminal not found")

    terminal = terminal_manager.terminals[terminal_id]
    if terminal.merchant_id != current_user.merchant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    success = await terminal_manager.activate_terminal(terminal_id)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to activate terminal")

    return {"message": "Terminal activated successfully", "terminal_id": terminal_id}


@router.post("/{terminal_id}/deactivate")
async def deactivate_terminal(
    terminal_id: str,
    reason: str = Query("", description="Deactivation reason"),
    current_user: CurrentUser = Depends(require_payments_create)
):
    """Deactivate a terminal."""
    # Verify terminal belongs to merchant
    if terminal_id not in terminal_manager.terminals:
        raise HTTPException(status_code=404, detail="Terminal not found")

    terminal = terminal_manager.terminals[terminal_id]
    if terminal.merchant_id != current_user.merchant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    success = await terminal_manager.deactivate_terminal(terminal_id, reason)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to deactivate terminal")

    return {"message": "Terminal deactivated successfully", "terminal_id": terminal_id}


@router.put("/{terminal_id}/configuration")
async def update_terminal_configuration(
    terminal_id: str,
    request: TerminalConfigurationRequest,
    current_user: CurrentUser = Depends(require_payments_create)
):
    """Update terminal configuration."""
    # Verify terminal belongs to merchant
    if terminal_id not in terminal_manager.terminals:
        raise HTTPException(status_code=404, detail="Terminal not found")

    terminal = terminal_manager.terminals[terminal_id]
    if terminal.merchant_id != current_user.merchant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    try:
        config_type = ConfigurationType(request.config_type)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid configuration type")

    success = await terminal_manager.update_terminal_configuration(
        terminal_id,
        config_type,
        request.configuration
    )

    if not success:
        raise HTTPException(status_code=400, detail="Failed to update configuration")

    return {"message": "Configuration updated successfully", "terminal_id": terminal_id}


@router.post("/{terminal_id}/heartbeat")
async def process_terminal_heartbeat(
    terminal_id: str,
    request: TerminalHeartbeatRequest,
    current_user: CurrentUser = Depends(require_payments_create)
):
    """Process terminal heartbeat."""
    # Verify terminal belongs to merchant
    if terminal_id not in terminal_manager.terminals:
        raise HTTPException(status_code=404, detail="Terminal not found")

    terminal = terminal_manager.terminals[terminal_id]
    if terminal.merchant_id != current_user.merchant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    heartbeat_data = {
        "status": request.status,
        "battery_level": request.battery_level,
        "network_strength": request.network_strength,
        "memory_usage": request.memory_usage,
        "cpu_usage": request.cpu_usage,
        "disk_usage": request.disk_usage,
        "last_error": request.last_error,
        "performance_metrics": request.performance_metrics
    }

    success = await terminal_manager.process_heartbeat(terminal_id, heartbeat_data)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to process heartbeat")

    return {"message": "Heartbeat processed successfully", "terminal_id": terminal_id}


@router.post("/{terminal_id}/commands")
async def send_terminal_command(
    terminal_id: str,
    request: TerminalCommandRequest,
    current_user: CurrentUser = Depends(require_payments_create)
):
    """Send command to terminal."""
    # Verify terminal belongs to merchant
    if terminal_id not in terminal_manager.terminals:
        raise HTTPException(status_code=404, detail="Terminal not found")

    terminal = terminal_manager.terminals[terminal_id]
    if terminal.merchant_id != current_user.merchant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    command = await terminal_manager.send_command_to_terminal(
        terminal_id,
        request.command_type,
        request.payload
    )

    if not command:
        raise HTTPException(status_code=400, detail="Failed to send command")

    return {
        "message": "Command sent successfully",
        "command_id": command.command_id,
        "terminal_id": terminal_id
    }


@router.get("/", response_model=List[TerminalResponse])
async def list_terminals(
    status: Optional[str] = Query(None, description="Filter by status"),
    current_user: CurrentUser = Depends(require_payments_read)
):
    """List all terminals for the merchant."""
    status_filter = None
    if status:
        try:
            status_filter = TerminalStatus(status)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid status filter")

    terminals = await terminal_manager.get_merchant_terminals(
        current_user.merchant_id,
        status_filter
    )

    return [
        TerminalResponse(
            terminal_id=terminal.terminal_id,
            merchant_id=terminal.merchant_id,
            device_name=terminal.device_name,
            device_model=terminal.device_model,
            terminal_type=terminal.terminal_type.value,
            serial_number=terminal.serial_number,
            status=terminal.status.value,
            location_name=terminal.location_name,
            address=terminal.address,
            last_heartbeat=terminal.last_heartbeat.isoformat() if terminal.last_heartbeat else None,
            last_transaction=terminal.last_transaction.isoformat() if terminal.last_transaction else None,
            transaction_count_today=terminal.transaction_count_today,
            volume_today=str(terminal.volume_today),
            capabilities=[cap.value for cap in terminal.capabilities],
            created_at=terminal.created_at.isoformat(),
            updated_at=terminal.updated_at.isoformat()
        )
        for terminal in terminals
    ]


@router.get("/{terminal_id}", response_model=TerminalResponse)
async def get_terminal(
    terminal_id: str,
    current_user: CurrentUser = Depends(require_payments_read)
):
    """Get terminal details."""
    if terminal_id not in terminal_manager.terminals:
        raise HTTPException(status_code=404, detail="Terminal not found")

    terminal = terminal_manager.terminals[terminal_id]
    if terminal.merchant_id != current_user.merchant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    return TerminalResponse(
        terminal_id=terminal.terminal_id,
        merchant_id=terminal.merchant_id,
        device_name=terminal.device_name,
        device_model=terminal.device_model,
        terminal_type=terminal.terminal_type.value,
        serial_number=terminal.serial_number,
        status=terminal.status.value,
        location_name=terminal.location_name,
        address=terminal.address,
        last_heartbeat=terminal.last_heartbeat.isoformat() if terminal.last_heartbeat else None,
        last_transaction=terminal.last_transaction.isoformat() if terminal.last_transaction else None,
        transaction_count_today=terminal.transaction_count_today,
        volume_today=str(terminal.volume_today),
        capabilities=[cap.value for cap in terminal.capabilities],
        created_at=terminal.created_at.isoformat(),
        updated_at=terminal.updated_at.isoformat()
    )


@router.get("/{terminal_id}/performance")
async def get_terminal_performance(
    terminal_id: str,
    start_date: Optional[datetime] = Query(None, description="Start date for metrics"),
    end_date: Optional[datetime] = Query(None, description="End date for metrics"),
    current_user: CurrentUser = Depends(require_payments_read)
):
    """Get terminal performance metrics."""
    if terminal_id not in terminal_manager.terminals:
        raise HTTPException(status_code=404, detail="Terminal not found")

    terminal = terminal_manager.terminals[terminal_id]
    if terminal.merchant_id != current_user.merchant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    metrics = await terminal_manager.get_terminal_performance(
        terminal_id,
        start_date,
        end_date
    )

    if metrics is None:
        raise HTTPException(status_code=404, detail="Performance data not found")

    return {
        "terminal_id": terminal_id,
        "metrics": [
            {
                "date": metric.date.isoformat(),
                "transaction_count": metric.transaction_count,
                "transaction_volume": str(metric.transaction_volume),
                "success_rate": f"{metric.success_rate:.2%}",
                "average_response_time": f"{metric.average_response_time:.1f}ms",
                "error_count": metric.error_count,
                "uptime_percentage": f"{metric.uptime_percentage:.1f}%",
                "peak_tps": metric.peak_tps,
                "revenue_generated": str(metric.revenue_generated)
            }
            for metric in metrics
        ]
    }


@router.get("/fleet/overview")
async def get_fleet_overview(
    current_user: CurrentUser = Depends(require_payments_read)
):
    """Get fleet overview for the merchant."""
    overview = await terminal_manager.get_fleet_overview(current_user.merchant_id)
    return overview


@router.post("/groups", status_code=201)
async def create_terminal_group(
    request: TerminalGroupRequest,
    current_user: CurrentUser = Depends(require_payments_create)
):
    """Create a terminal group."""
    try:
        group = await terminal_manager.create_terminal_group(
            merchant_id=current_user.merchant_id,
            group_name=request.group_name,
            description=request.description,
            terminal_ids=request.terminal_ids
        )

        return {
            "group_id": group.group_id,
            "group_name": group.group_name,
            "description": group.description,
            "terminal_count": len(group.terminal_ids),
            "created_at": group.created_at.isoformat()
        }

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/groups/{group_id}/terminals/{terminal_id}")
async def add_terminal_to_group(
    group_id: str,
    terminal_id: str,
    current_user: CurrentUser = Depends(require_payments_create)
):
    """Add terminal to a group."""
    # Verify group belongs to merchant
    if group_id not in terminal_manager.terminal_groups:
        raise HTTPException(status_code=404, detail="Group not found")

    group = terminal_manager.terminal_groups[group_id]
    if group.merchant_id != current_user.merchant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    success = await terminal_manager.add_terminal_to_group(group_id, terminal_id)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to add terminal to group")

    return {"message": "Terminal added to group successfully"}


@router.get("/groups")
async def list_terminal_groups(
    current_user: CurrentUser = Depends(require_payments_read)
):
    """List terminal groups for the merchant."""
    groups = [
        group for group in terminal_manager.terminal_groups.values()
        if group.merchant_id == current_user.merchant_id
    ]

    return [
        {
            "group_id": group.group_id,
            "group_name": group.group_name,
            "description": group.description,
            "terminal_count": len(group.terminal_ids),
            "created_at": group.created_at.isoformat()
        }
        for group in groups
    ]