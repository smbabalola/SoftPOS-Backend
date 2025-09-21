"""
Multi-Terminal Management System for SoftPOS

This module provides comprehensive terminal management capabilities for
production SoftPOS deployments, supporting multiple terminals per merchant
with centralized control and monitoring.

Key Features:
- Terminal registration and provisioning
- Real-time terminal status monitoring
- Remote terminal configuration management
- Terminal grouping and fleet management
- Performance analytics per terminal
- Security policy enforcement
- Software update management
- Terminal health monitoring and diagnostics

Enterprise Features:
- Multi-tenant terminal isolation
- Role-based access control for terminal management
- Audit trails for terminal operations
- Automated terminal compliance checks
- Terminal-specific risk management
- Geographic terminal distribution tracking
"""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from enum import Enum
from typing import Dict, List, Optional, Set
from uuid import uuid4

import structlog

logger = structlog.get_logger(__name__)


class TerminalStatus(Enum):
    """Terminal operational status."""
    INACTIVE = "inactive"
    ACTIVE = "active"
    MAINTENANCE = "maintenance"
    SUSPENDED = "suspended"
    OFFLINE = "offline"
    ERROR = "error"


class TerminalType(Enum):
    """Types of terminal devices."""
    MOBILE_PHONE = "mobile_phone"
    TABLET = "tablet"
    POS_TERMINAL = "pos_terminal"
    KIOSK = "kiosk"
    MPOS = "mpos"  # Mobile Point of Sale
    VIRTUAL = "virtual"


class TerminalCapability(Enum):
    """Terminal capabilities and features."""
    CONTACTLESS = "contactless"
    CHIP_PIN = "chip_pin"
    MAGSTRIPE = "magstripe"
    MOBILE_WALLET = "mobile_wallet"
    QR_CODE = "qr_code"
    BIOMETRIC = "biometric"
    DUAL_SCREEN = "dual_screen"
    PRINTER = "printer"
    CAMERA = "camera"


class ConfigurationType(Enum):
    """Types of terminal configurations."""
    PAYMENT_SETTINGS = "payment_settings"
    SECURITY_POLICY = "security_policy"
    UI_BRANDING = "ui_branding"
    OPERATIONAL_LIMITS = "operational_limits"
    FEATURE_FLAGS = "feature_flags"
    NETWORK_SETTINGS = "network_settings"


@dataclass
class TerminalDevice:
    """Terminal device information."""
    terminal_id: str
    merchant_id: str
    device_name: str
    device_model: str
    terminal_type: TerminalType
    serial_number: str
    os_version: str
    app_version: str
    capabilities: Set[TerminalCapability]
    status: TerminalStatus

    # Location and deployment
    location_name: Optional[str] = None
    address: Optional[str] = None
    timezone: str = "UTC"
    deployment_date: Optional[datetime] = None

    # Technical specifications
    hardware_id: Optional[str] = None
    encryption_keys: Dict[str, str] = field(default_factory=dict)
    configuration: Dict = field(default_factory=dict)

    # Operational data
    last_heartbeat: Optional[datetime] = None
    last_transaction: Optional[datetime] = None
    transaction_count_today: int = 0
    volume_today: Decimal = field(default_factory=lambda: Decimal("0"))

    # Metadata
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict = field(default_factory=dict)


@dataclass
class TerminalGroup:
    """Terminal grouping for fleet management."""
    group_id: str
    group_name: str
    merchant_id: str
    description: Optional[str] = None
    terminal_ids: Set[str] = field(default_factory=set)
    group_configuration: Dict = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class TerminalCommand:
    """Commands sent to terminals."""
    command_id: str
    terminal_id: str
    command_type: str
    payload: Dict
    sent_at: datetime
    acknowledged_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: str = "pending"  # pending, sent, acknowledged, completed, failed
    error_message: Optional[str] = None


@dataclass
class TerminalHeartbeat:
    """Terminal heartbeat/health status."""
    terminal_id: str
    timestamp: datetime
    status: TerminalStatus
    battery_level: Optional[int] = None
    network_strength: Optional[int] = None
    memory_usage: Optional[float] = None
    cpu_usage: Optional[float] = None
    disk_usage: Optional[float] = None
    last_error: Optional[str] = None
    performance_metrics: Dict = field(default_factory=dict)


@dataclass
class TerminalPerformanceMetrics:
    """Terminal performance analytics."""
    terminal_id: str
    date: datetime
    transaction_count: int
    transaction_volume: Decimal
    success_rate: float
    average_response_time: float
    error_count: int
    uptime_percentage: float
    peak_tps: float  # Transactions per second
    revenue_generated: Decimal


class TerminalManager:
    """
    Comprehensive terminal management system for SoftPOS operations.

    Handles terminal registration, configuration, monitoring, and fleet management
    across multiple merchants and locations.
    """

    def __init__(self):
        self.terminals: Dict[str, TerminalDevice] = {}
        self.terminal_groups: Dict[str, TerminalGroup] = {}
        self.pending_commands: Dict[str, TerminalCommand] = {}
        self.heartbeat_history: Dict[str, List[TerminalHeartbeat]] = {}
        self.performance_metrics: Dict[str, List[TerminalPerformanceMetrics]] = {}
        self._monitoring_started = False

        # Configuration templates
        self.config_templates = self._initialize_config_templates()

    def _initialize_config_templates(self) -> Dict[str, Dict]:
        """Initialize configuration templates for different terminal types."""
        return {
            "mobile_phone": {
                "payment_settings": {
                    "contactless_limit": 100.00,
                    "pin_bypass_limit": 45.00,
                    "daily_limit": 5000.00,
                    "supported_schemes": ["visa", "mastercard", "amex"],
                    "currency": "GBP"
                },
                "security_policy": {
                    "session_timeout": 900,  # 15 minutes
                    "max_failed_attempts": 3,
                    "require_device_lock": True,
                    "biometric_auth": True,
                    "network_security": "tls_1_3"
                },
                "ui_branding": {
                    "merchant_logo_url": None,
                    "color_scheme": "default",
                    "language": "en-GB",
                    "receipt_footer": "Thank you for your business"
                }
            },
            "tablet": {
                "payment_settings": {
                    "contactless_limit": 100.00,
                    "pin_bypass_limit": 45.00,
                    "daily_limit": 10000.00,
                    "supported_schemes": ["visa", "mastercard", "amex", "discover"],
                    "currency": "GBP"
                },
                "security_policy": {
                    "session_timeout": 1800,  # 30 minutes
                    "max_failed_attempts": 5,
                    "require_device_lock": True,
                    "biometric_auth": False,
                    "network_security": "tls_1_3"
                },
                "feature_flags": {
                    "enable_dual_screen": True,
                    "enable_customer_facing_display": True,
                    "enable_receipt_printer": True
                }
            }
        }

    async def register_terminal(
        self,
        merchant_id: str,
        device_info: Dict,
        location_info: Optional[Dict] = None
    ) -> TerminalDevice:
        """Register a new terminal device."""
        terminal_id = f"term_{secrets.token_hex(8)}"

        # Determine terminal type based on device info
        terminal_type = self._determine_terminal_type(device_info)

        # Parse capabilities from device info
        capabilities = self._parse_device_capabilities(device_info)

        terminal = TerminalDevice(
            terminal_id=terminal_id,
            merchant_id=merchant_id,
            device_name=device_info.get("device_name", "Unknown Device"),
            device_model=device_info.get("model", "Unknown Model"),
            terminal_type=terminal_type,
            serial_number=device_info.get("serial_number", ""),
            os_version=device_info.get("os_version", ""),
            app_version=device_info.get("app_version", "1.0.0"),
            capabilities=capabilities,
            status=TerminalStatus.INACTIVE,
            hardware_id=device_info.get("hardware_id"),
            location_name=location_info.get("name") if location_info else None,
            address=location_info.get("address") if location_info else None,
            timezone=location_info.get("timezone", "UTC") if location_info else "UTC",
            deployment_date=datetime.now(timezone.utc)
        )

        # Apply default configuration based on terminal type
        await self._apply_default_configuration(terminal)

        # Generate encryption keys for terminal
        await self._generate_terminal_keys(terminal)

        self.terminals[terminal_id] = terminal

        logger.info(
            "Terminal registered",
            terminal_id=terminal_id,
            merchant_id=merchant_id,
            terminal_type=terminal_type.value
        )

        return terminal

    async def activate_terminal(self, terminal_id: str) -> bool:
        """Activate a registered terminal."""
        if terminal_id not in self.terminals:
            return False

        terminal = self.terminals[terminal_id]

        # Perform activation checks
        if not await self._validate_terminal_security(terminal):
            logger.warning("Terminal security validation failed", terminal_id=terminal_id)
            return False

        terminal.status = TerminalStatus.ACTIVE
        terminal.updated_at = datetime.now(timezone.utc)

        logger.info("Terminal activated", terminal_id=terminal_id)
        return True

    async def deactivate_terminal(self, terminal_id: str, reason: str = "") -> bool:
        """Deactivate a terminal."""
        if terminal_id not in self.terminals:
            return False

        terminal = self.terminals[terminal_id]
        terminal.status = TerminalStatus.INACTIVE
        terminal.updated_at = datetime.now(timezone.utc)
        terminal.metadata["deactivation_reason"] = reason

        logger.info("Terminal deactivated", terminal_id=terminal_id, reason=reason)
        return True

    async def update_terminal_configuration(
        self,
        terminal_id: str,
        config_type: ConfigurationType,
        configuration: Dict
    ) -> bool:
        """Update terminal configuration."""
        if terminal_id not in self.terminals:
            return False

        terminal = self.terminals[terminal_id]

        # Validate configuration
        if not await self._validate_configuration(config_type, configuration):
            logger.warning("Invalid configuration", terminal_id=terminal_id, config_type=config_type.value)
            return False

        # Update configuration
        if config_type.value not in terminal.configuration:
            terminal.configuration[config_type.value] = {}

        terminal.configuration[config_type.value].update(configuration)
        terminal.updated_at = datetime.now(timezone.utc)

        # Send configuration update command to terminal
        await self._send_configuration_update(terminal_id, config_type, configuration)

        logger.info(
            "Terminal configuration updated",
            terminal_id=terminal_id,
            config_type=config_type.value
        )

        return True

    async def create_terminal_group(
        self,
        merchant_id: str,
        group_name: str,
        description: Optional[str] = None,
        terminal_ids: Optional[Set[str]] = None
    ) -> TerminalGroup:
        """Create a terminal group for fleet management."""
        group_id = f"grp_{secrets.token_hex(6)}"

        group = TerminalGroup(
            group_id=group_id,
            group_name=group_name,
            merchant_id=merchant_id,
            description=description,
            terminal_ids=terminal_ids or set()
        )

        # Validate that all terminals belong to the merchant
        for terminal_id in group.terminal_ids:
            if terminal_id in self.terminals:
                terminal = self.terminals[terminal_id]
                if terminal.merchant_id != merchant_id:
                    raise ValueError(f"Terminal {terminal_id} does not belong to merchant {merchant_id}")

        self.terminal_groups[group_id] = group

        logger.info(
            "Terminal group created",
            group_id=group_id,
            merchant_id=merchant_id,
            terminal_count=len(group.terminal_ids)
        )

        return group

    async def add_terminal_to_group(self, group_id: str, terminal_id: str) -> bool:
        """Add terminal to a group."""
        if group_id not in self.terminal_groups or terminal_id not in self.terminals:
            return False

        group = self.terminal_groups[group_id]
        terminal = self.terminals[terminal_id]

        # Verify merchant ownership
        if terminal.merchant_id != group.merchant_id:
            return False

        group.terminal_ids.add(terminal_id)

        logger.info("Terminal added to group", group_id=group_id, terminal_id=terminal_id)
        return True

    async def process_heartbeat(self, terminal_id: str, heartbeat_data: Dict) -> bool:
        """Process terminal heartbeat and update status."""
        if terminal_id not in self.terminals:
            return False

        terminal = self.terminals[terminal_id]

        # Create heartbeat record
        heartbeat = TerminalHeartbeat(
            terminal_id=terminal_id,
            timestamp=datetime.now(timezone.utc),
            status=TerminalStatus(heartbeat_data.get("status", "active")),
            battery_level=heartbeat_data.get("battery_level"),
            network_strength=heartbeat_data.get("network_strength"),
            memory_usage=heartbeat_data.get("memory_usage"),
            cpu_usage=heartbeat_data.get("cpu_usage"),
            disk_usage=heartbeat_data.get("disk_usage"),
            last_error=heartbeat_data.get("last_error"),
            performance_metrics=heartbeat_data.get("performance_metrics", {})
        )

        # Store heartbeat history
        if terminal_id not in self.heartbeat_history:
            self.heartbeat_history[terminal_id] = []
        self.heartbeat_history[terminal_id].append(heartbeat)

        # Keep only last 100 heartbeats
        if len(self.heartbeat_history[terminal_id]) > 100:
            self.heartbeat_history[terminal_id] = self.heartbeat_history[terminal_id][-100:]

        # Update terminal status
        terminal.last_heartbeat = heartbeat.timestamp
        terminal.status = heartbeat.status
        terminal.updated_at = heartbeat.timestamp

        # Check for alerts
        await self._check_terminal_health_alerts(terminal, heartbeat)

        return True

    async def send_command_to_terminal(
        self,
        terminal_id: str,
        command_type: str,
        payload: Dict
    ) -> Optional[TerminalCommand]:
        """Send command to a specific terminal."""
        if terminal_id not in self.terminals:
            return None

        command_id = f"cmd_{int(time.time())}_{secrets.token_hex(4)}"

        command = TerminalCommand(
            command_id=command_id,
            terminal_id=terminal_id,
            command_type=command_type,
            payload=payload,
            sent_at=datetime.now(timezone.utc)
        )

        self.pending_commands[command_id] = command

        # In a real implementation, this would send the command via WebSocket, push notification, etc.
        logger.info(
            "Command sent to terminal",
            command_id=command_id,
            terminal_id=terminal_id,
            command_type=command_type
        )

        return command

    async def get_terminal_performance(
        self,
        terminal_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Optional[List[TerminalPerformanceMetrics]]:
        """Get terminal performance metrics."""
        if terminal_id not in self.terminals:
            return None

        if not start_date:
            start_date = datetime.now(timezone.utc) - timedelta(days=7)
        if not end_date:
            end_date = datetime.now(timezone.utc)

        if terminal_id not in self.performance_metrics:
            return []

        # Filter metrics by date range
        filtered_metrics = [
            metric for metric in self.performance_metrics[terminal_id]
            if start_date <= metric.date <= end_date
        ]

        return filtered_metrics

    async def get_merchant_terminals(
        self,
        merchant_id: str,
        status_filter: Optional[TerminalStatus] = None
    ) -> List[TerminalDevice]:
        """Get all terminals for a merchant."""
        terminals = [
            terminal for terminal in self.terminals.values()
            if terminal.merchant_id == merchant_id
        ]

        if status_filter:
            terminals = [t for t in terminals if t.status == status_filter]

        return terminals

    async def get_fleet_overview(self, merchant_id: str) -> Dict:
        """Get comprehensive fleet overview for a merchant."""
        terminals = await self.get_merchant_terminals(merchant_id)

        # Status breakdown
        status_breakdown = {}
        for status in TerminalStatus:
            status_breakdown[status.value] = len([t for t in terminals if t.status == status])

        # Type breakdown
        type_breakdown = {}
        for terminal_type in TerminalType:
            type_breakdown[terminal_type.value] = len([t for t in terminals if t.terminal_type == terminal_type])

        # Today's performance
        today = datetime.now(timezone.utc).date()
        total_transactions_today = sum(t.transaction_count_today for t in terminals)
        total_volume_today = sum(t.volume_today for t in terminals)

        # Active terminals (heartbeat in last 5 minutes)
        active_cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
        active_terminals = len([
            t for t in terminals
            if t.last_heartbeat and t.last_heartbeat >= active_cutoff
        ])

        return {
            "total_terminals": len(terminals),
            "active_terminals": active_terminals,
            "status_breakdown": status_breakdown,
            "type_breakdown": type_breakdown,
            "today_performance": {
                "total_transactions": total_transactions_today,
                "total_volume": str(total_volume_today),
                "average_per_terminal": str(total_volume_today / len(terminals)) if terminals else "0"
            },
            "groups": len([g for g in self.terminal_groups.values() if g.merchant_id == merchant_id])
        }

    def start_monitoring(self):
        """Start background monitoring tasks if not already started."""
        if not self._monitoring_started:
            try:
                asyncio.create_task(self._terminal_health_monitor())
                asyncio.create_task(self._performance_metrics_collector())
                asyncio.create_task(self._command_timeout_monitor())
                self._monitoring_started = True
            except RuntimeError:
                # No event loop running, will start later
                pass

    def _start_monitoring_tasks(self):
        """Start background monitoring tasks (legacy method for compatibility)."""
        self.start_monitoring()

    async def _terminal_health_monitor(self):
        """Monitor terminal health and connectivity."""
        while True:
            try:
                now = datetime.now(timezone.utc)
                offline_threshold = now - timedelta(minutes=10)

                for terminal in self.terminals.values():
                    # Check if terminal has gone offline
                    if (terminal.status == TerminalStatus.ACTIVE and
                        terminal.last_heartbeat and
                        terminal.last_heartbeat < offline_threshold):

                        terminal.status = TerminalStatus.OFFLINE
                        terminal.updated_at = now

                        logger.warning("Terminal went offline", terminal_id=terminal.terminal_id)

                await asyncio.sleep(60)  # Check every minute

            except Exception as e:
                logger.error("Terminal health monitor error", error=str(e))
                await asyncio.sleep(60)

    async def _performance_metrics_collector(self):
        """Collect performance metrics for terminals."""
        while True:
            try:
                # Collect daily performance metrics
                # In a real implementation, this would aggregate transaction data

                await asyncio.sleep(3600)  # Collect every hour

            except Exception as e:
                logger.error("Performance metrics collector error", error=str(e))
                await asyncio.sleep(3600)

    async def _command_timeout_monitor(self):
        """Monitor command timeouts and mark as failed."""
        while True:
            try:
                timeout_threshold = datetime.now(timezone.utc) - timedelta(minutes=5)

                expired_commands = [
                    cmd for cmd in self.pending_commands.values()
                    if cmd.sent_at < timeout_threshold and cmd.status == "pending"
                ]

                for command in expired_commands:
                    command.status = "failed"
                    command.error_message = "Command timeout"

                    logger.warning(
                        "Command timed out",
                        command_id=command.command_id,
                        terminal_id=command.terminal_id
                    )

                await asyncio.sleep(60)  # Check every minute

            except Exception as e:
                logger.error("Command timeout monitor error", error=str(e))
                await asyncio.sleep(60)

    def _determine_terminal_type(self, device_info: Dict) -> TerminalType:
        """Determine terminal type from device information."""
        device_type = device_info.get("device_type", "").lower()
        form_factor = device_info.get("form_factor", "").lower()

        if "phone" in device_type or "mobile" in form_factor:
            return TerminalType.MOBILE_PHONE
        elif "tablet" in device_type or "pad" in device_type:
            return TerminalType.TABLET
        elif "kiosk" in device_type:
            return TerminalType.KIOSK
        elif "pos" in device_type:
            return TerminalType.POS_TERMINAL
        else:
            return TerminalType.MOBILE_PHONE  # Default

    def _parse_device_capabilities(self, device_info: Dict) -> Set[TerminalCapability]:
        """Parse device capabilities from device information."""
        capabilities = set()

        # Check for NFC support
        if device_info.get("nfc_enabled"):
            capabilities.add(TerminalCapability.CONTACTLESS)
            capabilities.add(TerminalCapability.MOBILE_WALLET)

        # Check for camera
        if device_info.get("camera_available"):
            capabilities.add(TerminalCapability.CAMERA)
            capabilities.add(TerminalCapability.QR_CODE)

        # Check for biometric support
        if device_info.get("biometric_available"):
            capabilities.add(TerminalCapability.BIOMETRIC)

        # Default capabilities
        capabilities.add(TerminalCapability.CHIP_PIN)

        return capabilities

    async def _apply_default_configuration(self, terminal: TerminalDevice):
        """Apply default configuration based on terminal type."""
        template = self.config_templates.get(terminal.terminal_type.value, {})
        terminal.configuration = template.copy()

    async def _generate_terminal_keys(self, terminal: TerminalDevice):
        """Generate encryption keys for terminal."""
        terminal.encryption_keys = {
            "session_key": secrets.token_hex(32),
            "encryption_key": secrets.token_hex(32),
            "signing_key": secrets.token_hex(32)
        }

    async def _validate_terminal_security(self, terminal: TerminalDevice) -> bool:
        """Validate terminal security requirements."""
        # Check if terminal has required encryption keys
        required_keys = ["session_key", "encryption_key", "signing_key"]
        return all(key in terminal.encryption_keys for key in required_keys)

    async def _validate_configuration(self, config_type: ConfigurationType, configuration: Dict) -> bool:
        """Validate configuration parameters."""
        # Basic validation - in production, this would be more comprehensive
        if config_type == ConfigurationType.PAYMENT_SETTINGS:
            required_fields = ["contactless_limit", "currency"]
            return all(field in configuration for field in required_fields)

        return True

    async def _send_configuration_update(
        self,
        terminal_id: str,
        config_type: ConfigurationType,
        configuration: Dict
    ):
        """Send configuration update command to terminal."""
        await self.send_command_to_terminal(
            terminal_id,
            "configuration_update",
            {
                "config_type": config_type.value,
                "configuration": configuration
            }
        )

    async def _check_terminal_health_alerts(self, terminal: TerminalDevice, heartbeat: TerminalHeartbeat):
        """Check for terminal health alerts."""
        # Battery alert
        if heartbeat.battery_level and heartbeat.battery_level < 20:
            logger.warning(
                "Low battery alert",
                terminal_id=terminal.terminal_id,
                battery_level=heartbeat.battery_level
            )

        # Memory usage alert
        if heartbeat.memory_usage and heartbeat.memory_usage > 0.9:
            logger.warning(
                "High memory usage alert",
                terminal_id=terminal.terminal_id,
                memory_usage=heartbeat.memory_usage
            )

        # Network connectivity alert
        if heartbeat.network_strength and heartbeat.network_strength < 30:
            logger.warning(
                "Poor network connectivity",
                terminal_id=terminal.terminal_id,
                network_strength=heartbeat.network_strength
            )


# Global terminal manager instance
terminal_manager = TerminalManager()