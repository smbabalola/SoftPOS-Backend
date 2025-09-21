"""
Terminal Management Tests

Test suite for terminal management functionality including:
- Terminal registration and activation
- Configuration management
- Health monitoring and heartbeats
- Fleet management and grouping
- Performance tracking
"""

import pytest
from decimal import Decimal
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch, MagicMock

from app.terminal_management import (
    terminal_manager,
    TerminalDevice,
    TerminalGroup,
    TerminalHeartbeat,
    TerminalStatus,
    TerminalType,
    TerminalCapability,
    ConfigurationType
)


class TestTerminalRegistration:
    """Test terminal registration and lifecycle management."""

    @pytest.mark.terminal
    @pytest.mark.unit
    async def test_register_mobile_terminal(self):
        """Test registering a mobile phone terminal."""
        device_info = {
            "device_name": "iPhone 13 Pro",
            "model": "iPhone14,2",
            "serial_number": "ABC123456789",
            "os_version": "iOS 16.1",
            "app_version": "1.2.3",
            "hardware_id": "hw_001",
            "device_type": "phone",
            "form_factor": "mobile",
            "nfc_enabled": True,
            "camera_available": True,
            "biometric_available": True
        }

        location_info = {
            "name": "Main Store",
            "address": "123 High Street, London",
            "timezone": "Europe/London"
        }

        terminal = await terminal_manager.register_terminal(
            merchant_id="mer_test_001",
            device_info=device_info,
            location_info=location_info
        )

        assert terminal.merchant_id == "mer_test_001"
        assert terminal.device_name == "iPhone 13 Pro"
        assert terminal.terminal_type == TerminalType.MOBILE_PHONE
        assert terminal.status == TerminalStatus.INACTIVE
        assert TerminalCapability.CONTACTLESS in terminal.capabilities
        assert TerminalCapability.MOBILE_WALLET in terminal.capabilities
        assert TerminalCapability.BIOMETRIC in terminal.capabilities
        assert terminal.location_name == "Main Store"
        assert terminal.timezone == "Europe/London"

    @pytest.mark.terminal
    @pytest.mark.unit
    async def test_register_tablet_terminal(self):
        """Test registering a tablet terminal."""
        device_info = {
            "device_name": "iPad Pro",
            "model": "iPad14,3",
            "serial_number": "TAB123456789",
            "os_version": "iPadOS 16.1",
            "app_version": "1.2.3",
            "device_type": "tablet",
            "nfc_enabled": True,
            "camera_available": True,
            "biometric_available": False
        }

        terminal = await terminal_manager.register_terminal(
            merchant_id="mer_test_001",
            device_info=device_info
        )

        assert terminal.terminal_type == TerminalType.TABLET
        assert TerminalCapability.CONTACTLESS in terminal.capabilities
        assert TerminalCapability.BIOMETRIC not in terminal.capabilities

    @pytest.mark.terminal
    @pytest.mark.unit
    async def test_terminal_activation(self):
        """Test terminal activation process."""
        # First register a terminal
        device_info = {
            "device_name": "Test Terminal",
            "model": "Test Model",
            "serial_number": "TEST123",
            "os_version": "Test OS",
            "app_version": "1.0.0",
            "device_type": "phone",
            "nfc_enabled": True
        }

        terminal = await terminal_manager.register_terminal(
            merchant_id="mer_test_001",
            device_info=device_info
        )

        assert terminal.status == TerminalStatus.INACTIVE

        # Activate the terminal
        success = await terminal_manager.activate_terminal(terminal.terminal_id)

        assert success is True
        assert terminal.status == TerminalStatus.ACTIVE

    @pytest.mark.terminal
    @pytest.mark.unit
    async def test_terminal_deactivation(self):
        """Test terminal deactivation."""
        # Register and activate terminal
        device_info = {
            "device_name": "Test Terminal",
            "model": "Test Model",
            "serial_number": "TEST123",
            "os_version": "Test OS",
            "app_version": "1.0.0",
            "device_type": "phone",
            "nfc_enabled": True
        }

        terminal = await terminal_manager.register_terminal(
            merchant_id="mer_test_001",
            device_info=device_info
        )

        await terminal_manager.activate_terminal(terminal.terminal_id)
        assert terminal.status == TerminalStatus.ACTIVE

        # Deactivate terminal
        reason = "Maintenance required"
        success = await terminal_manager.deactivate_terminal(terminal.terminal_id, reason)

        assert success is True
        assert terminal.status == TerminalStatus.INACTIVE
        assert terminal.metadata["deactivation_reason"] == reason


class TestTerminalConfiguration:
    """Test terminal configuration management."""

    @pytest.fixture
    async def test_terminal(self):
        """Create a test terminal."""
        device_info = {
            "device_name": "Config Test Terminal",
            "model": "Test Model",
            "serial_number": "CONFIG123",
            "os_version": "Test OS",
            "app_version": "1.0.0",
            "device_type": "phone",
            "nfc_enabled": True
        }

        terminal = await terminal_manager.register_terminal(
            merchant_id="mer_test_001",
            device_info=device_info
        )

        await terminal_manager.activate_terminal(terminal.terminal_id)
        return terminal

    @pytest.mark.terminal
    @pytest.mark.unit
    async def test_payment_settings_configuration(self, test_terminal):
        """Test updating payment settings configuration."""
        payment_config = {
            "contactless_limit": 150.00,
            "pin_bypass_limit": 50.00,
            "daily_limit": 7500.00,
            "supported_schemes": ["visa", "mastercard", "amex", "discover"],
            "currency": "GBP"
        }

        success = await terminal_manager.update_terminal_configuration(
            test_terminal.terminal_id,
            ConfigurationType.PAYMENT_SETTINGS,
            payment_config
        )

        assert success is True
        stored_config = test_terminal.configuration["payment_settings"]
        assert stored_config["contactless_limit"] == 150.00
        assert stored_config["currency"] == "GBP"
        assert "amex" in stored_config["supported_schemes"]

    @pytest.mark.terminal
    @pytest.mark.unit
    async def test_security_policy_configuration(self, test_terminal):
        """Test updating security policy configuration."""
        security_config = {
            "session_timeout": 1200,  # 20 minutes
            "max_failed_attempts": 5,
            "require_device_lock": True,
            "biometric_auth": True,
            "network_security": "tls_1_3"
        }

        success = await terminal_manager.update_terminal_configuration(
            test_terminal.terminal_id,
            ConfigurationType.SECURITY_POLICY,
            security_config
        )

        assert success is True
        stored_config = test_terminal.configuration["security_policy"]
        assert stored_config["session_timeout"] == 1200
        assert stored_config["biometric_auth"] is True

    @pytest.mark.terminal
    @pytest.mark.unit
    async def test_ui_branding_configuration(self, test_terminal):
        """Test updating UI branding configuration."""
        branding_config = {
            "merchant_logo_url": "https://example.com/logo.png",
            "color_scheme": "blue",
            "language": "en-GB",
            "receipt_footer": "Thank you for shopping with us!"
        }

        success = await terminal_manager.update_terminal_configuration(
            test_terminal.terminal_id,
            ConfigurationType.UI_BRANDING,
            branding_config
        )

        assert success is True
        stored_config = test_terminal.configuration["ui_branding"]
        assert stored_config["language"] == "en-GB"
        assert "Thank you" in stored_config["receipt_footer"]

    @pytest.mark.terminal
    @pytest.mark.unit
    async def test_invalid_configuration(self, test_terminal):
        """Test handling of invalid configuration."""
        invalid_config = {
            "invalid_field": "invalid_value"
            # Missing required fields for payment settings
        }

        success = await terminal_manager.update_terminal_configuration(
            test_terminal.terminal_id,
            ConfigurationType.PAYMENT_SETTINGS,
            invalid_config
        )

        assert success is False


class TestTerminalHeartbeat:
    """Test terminal heartbeat and health monitoring."""

    @pytest.fixture
    async def active_terminal(self):
        """Create an active test terminal."""
        device_info = {
            "device_name": "Heartbeat Test Terminal",
            "model": "Test Model",
            "serial_number": "HEARTBEAT123",
            "os_version": "Test OS",
            "app_version": "1.0.0",
            "device_type": "phone",
            "nfc_enabled": True
        }

        terminal = await terminal_manager.register_terminal(
            merchant_id="mer_test_001",
            device_info=device_info
        )

        await terminal_manager.activate_terminal(terminal.terminal_id)
        return terminal

    @pytest.mark.terminal
    @pytest.mark.unit
    async def test_normal_heartbeat(self, active_terminal):
        """Test processing normal heartbeat."""
        heartbeat_data = {
            "status": "active",
            "battery_level": 85,
            "network_strength": 75,
            "memory_usage": 0.6,
            "cpu_usage": 0.3,
            "disk_usage": 0.4,
            "performance_metrics": {
                "transactions_processed": 25,
                "average_response_time": 120
            }
        }

        success = await terminal_manager.process_heartbeat(
            active_terminal.terminal_id,
            heartbeat_data
        )

        assert success is True
        assert active_terminal.last_heartbeat is not None
        assert active_terminal.status == TerminalStatus.ACTIVE

        # Check heartbeat history
        heartbeat_history = terminal_manager.heartbeat_history.get(active_terminal.terminal_id)
        assert heartbeat_history is not None
        assert len(heartbeat_history) > 0

        latest_heartbeat = heartbeat_history[-1]
        assert latest_heartbeat.battery_level == 85
        assert latest_heartbeat.network_strength == 75

    @pytest.mark.terminal
    @pytest.mark.unit
    async def test_low_battery_heartbeat(self, active_terminal):
        """Test heartbeat with low battery level."""
        heartbeat_data = {
            "status": "active",
            "battery_level": 15,  # Low battery
            "network_strength": 75,
            "memory_usage": 0.6,
            "cpu_usage": 0.3
        }

        with patch('app.terminal_management.logger') as mock_logger:
            success = await terminal_manager.process_heartbeat(
                active_terminal.terminal_id,
                heartbeat_data
            )

            assert success is True
            # Should log low battery warning
            mock_logger.warning.assert_called()

    @pytest.mark.terminal
    @pytest.mark.unit
    async def test_high_memory_usage_heartbeat(self, active_terminal):
        """Test heartbeat with high memory usage."""
        heartbeat_data = {
            "status": "active",
            "battery_level": 85,
            "network_strength": 75,
            "memory_usage": 0.95,  # High memory usage
            "cpu_usage": 0.3
        }

        with patch('app.terminal_management.logger') as mock_logger:
            success = await terminal_manager.process_heartbeat(
                active_terminal.terminal_id,
                heartbeat_data
            )

            assert success is True
            # Should log high memory usage warning
            mock_logger.warning.assert_called()

    @pytest.mark.terminal
    @pytest.mark.unit
    async def test_poor_network_heartbeat(self, active_terminal):
        """Test heartbeat with poor network connectivity."""
        heartbeat_data = {
            "status": "active",
            "battery_level": 85,
            "network_strength": 20,  # Poor network
            "memory_usage": 0.6,
            "cpu_usage": 0.3
        }

        with patch('app.terminal_management.logger') as mock_logger:
            success = await terminal_manager.process_heartbeat(
                active_terminal.terminal_id,
                heartbeat_data
            )

            assert success is True
            # Should log poor network warning
            mock_logger.warning.assert_called()

    @pytest.mark.terminal
    @pytest.mark.unit
    async def test_error_status_heartbeat(self, active_terminal):
        """Test heartbeat with error status."""
        heartbeat_data = {
            "status": "error",
            "battery_level": 85,
            "network_strength": 75,
            "memory_usage": 0.6,
            "cpu_usage": 0.3,
            "last_error": "NFC module failure"
        }

        success = await terminal_manager.process_heartbeat(
            active_terminal.terminal_id,
            heartbeat_data
        )

        assert success is True
        assert active_terminal.status == TerminalStatus.ERROR

        # Check error details in heartbeat history
        heartbeat_history = terminal_manager.heartbeat_history[active_terminal.terminal_id]
        latest_heartbeat = heartbeat_history[-1]
        assert latest_heartbeat.last_error == "NFC module failure"


class TestTerminalCommands:
    """Test sending commands to terminals."""

    @pytest.fixture
    async def active_terminal(self):
        """Create an active test terminal."""
        device_info = {
            "device_name": "Command Test Terminal",
            "model": "Test Model",
            "serial_number": "COMMAND123",
            "os_version": "Test OS",
            "app_version": "1.0.0",
            "device_type": "phone",
            "nfc_enabled": True
        }

        terminal = await terminal_manager.register_terminal(
            merchant_id="mer_test_001",
            device_info=device_info
        )

        await terminal_manager.activate_terminal(terminal.terminal_id)
        return terminal

    @pytest.mark.terminal
    @pytest.mark.unit
    async def test_configuration_update_command(self, active_terminal):
        """Test sending configuration update command."""
        payload = {
            "config_type": "payment_settings",
            "configuration": {
                "contactless_limit": 100.00,
                "currency": "USD"
            }
        }

        command = await terminal_manager.send_command_to_terminal(
            active_terminal.terminal_id,
            "configuration_update",
            payload
        )

        assert command is not None
        assert command.terminal_id == active_terminal.terminal_id
        assert command.command_type == "configuration_update"
        assert command.payload == payload
        assert command.status == "pending"

    @pytest.mark.terminal
    @pytest.mark.unit
    async def test_restart_command(self, active_terminal):
        """Test sending restart command."""
        payload = {
            "restart_type": "soft",
            "reason": "Software update"
        }

        command = await terminal_manager.send_command_to_terminal(
            active_terminal.terminal_id,
            "restart",
            payload
        )

        assert command is not None
        assert command.command_type == "restart"
        assert command.payload["restart_type"] == "soft"

    @pytest.mark.terminal
    @pytest.mark.unit
    async def test_ping_command(self, active_terminal):
        """Test sending ping command."""
        payload = {"timestamp": datetime.now(timezone.utc).isoformat()}

        command = await terminal_manager.send_command_to_terminal(
            active_terminal.terminal_id,
            "ping",
            payload
        )

        assert command is not None
        assert command.command_type == "ping"

    @pytest.mark.terminal
    @pytest.mark.unit
    async def test_command_to_nonexistent_terminal(self):
        """Test sending command to non-existent terminal."""
        command = await terminal_manager.send_command_to_terminal(
            "nonexistent_terminal",
            "ping",
            {}
        )

        assert command is None


class TestTerminalGroups:
    """Test terminal grouping and fleet management."""

    @pytest.fixture
    async def test_terminals(self):
        """Create multiple test terminals."""
        terminals = []

        for i in range(3):
            device_info = {
                "device_name": f"Group Test Terminal {i+1}",
                "model": "Test Model",
                "serial_number": f"GROUP{i+1:03d}",
                "os_version": "Test OS",
                "app_version": "1.0.0",
                "device_type": "phone",
                "nfc_enabled": True
            }

            terminal = await terminal_manager.register_terminal(
                merchant_id="mer_test_001",
                device_info=device_info
            )

            terminals.append(terminal)

        return terminals

    @pytest.mark.terminal
    @pytest.mark.unit
    async def test_create_terminal_group(self, test_terminals):
        """Test creating a terminal group."""
        terminal_ids = {terminal.terminal_id for terminal in test_terminals}

        group = await terminal_manager.create_terminal_group(
            merchant_id="mer_test_001",
            group_name="Store Front Terminals",
            description="Terminals at the main store entrance",
            terminal_ids=terminal_ids
        )

        assert group.group_name == "Store Front Terminals"
        assert group.merchant_id == "mer_test_001"
        assert group.description == "Terminals at the main store entrance"
        assert len(group.terminal_ids) == 3
        assert all(tid in group.terminal_ids for tid in terminal_ids)

    @pytest.mark.terminal
    @pytest.mark.unit
    async def test_add_terminal_to_group(self, test_terminals):
        """Test adding terminal to existing group."""
        # Create group with first two terminals
        initial_terminal_ids = {terminal.terminal_id for terminal in test_terminals[:2]}

        group = await terminal_manager.create_terminal_group(
            merchant_id="mer_test_001",
            group_name="Initial Group",
            terminal_ids=initial_terminal_ids
        )

        assert len(group.terminal_ids) == 2

        # Add third terminal to group
        third_terminal_id = test_terminals[2].terminal_id
        success = await terminal_manager.add_terminal_to_group(
            group.group_id,
            third_terminal_id
        )

        assert success is True
        assert len(group.terminal_ids) == 3
        assert third_terminal_id in group.terminal_ids

    @pytest.mark.terminal
    @pytest.mark.unit
    async def test_group_cross_merchant_protection(self, test_terminals):
        """Test that terminals can't be added to groups from different merchants."""
        # Create terminal for different merchant
        device_info = {
            "device_name": "Other Merchant Terminal",
            "model": "Test Model",
            "serial_number": "OTHER123",
            "os_version": "Test OS",
            "app_version": "1.0.0",
            "device_type": "phone",
            "nfc_enabled": True
        }

        other_terminal = await terminal_manager.register_terminal(
            merchant_id="mer_test_002",  # Different merchant
            device_info=device_info
        )

        # Try to create group with terminal from different merchant
        with pytest.raises(ValueError):
            await terminal_manager.create_terminal_group(
                merchant_id="mer_test_001",
                group_name="Cross Merchant Group",
                terminal_ids={other_terminal.terminal_id}
            )


class TestTerminalPerformance:
    """Test terminal performance tracking."""

    @pytest.fixture
    async def performance_terminal(self):
        """Create terminal for performance testing."""
        device_info = {
            "device_name": "Performance Test Terminal",
            "model": "Test Model",
            "serial_number": "PERF123",
            "os_version": "Test OS",
            "app_version": "1.0.0",
            "device_type": "phone",
            "nfc_enabled": True
        }

        terminal = await terminal_manager.register_terminal(
            merchant_id="mer_test_001",
            device_info=device_info
        )

        await terminal_manager.activate_terminal(terminal.terminal_id)
        return terminal

    @pytest.mark.terminal
    @pytest.mark.unit
    async def test_get_terminal_performance_no_data(self, performance_terminal):
        """Test getting performance metrics when no data exists."""
        metrics = await terminal_manager.get_terminal_performance(
            performance_terminal.terminal_id
        )

        assert metrics == []

    @pytest.mark.terminal
    @pytest.mark.unit
    async def test_get_merchant_terminals(self, test_terminals):
        """Test getting all terminals for a merchant."""
        terminals = await terminal_manager.get_merchant_terminals("mer_test_001")

        # Should include at least the test terminals
        terminal_ids = {t.terminal_id for t in terminals}
        test_terminal_ids = {t.terminal_id for t in test_terminals}

        assert test_terminal_ids.issubset(terminal_ids)
        assert all(t.merchant_id == "mer_test_001" for t in terminals)

    @pytest.mark.terminal
    @pytest.mark.unit
    async def test_get_merchant_terminals_with_status_filter(self, test_terminals):
        """Test getting terminals with status filter."""
        # Activate some terminals
        for terminal in test_terminals[:2]:
            await terminal_manager.activate_terminal(terminal.terminal_id)

        # Get only active terminals
        active_terminals = await terminal_manager.get_merchant_terminals(
            "mer_test_001",
            TerminalStatus.ACTIVE
        )

        assert len(active_terminals) >= 2
        assert all(t.status == TerminalStatus.ACTIVE for t in active_terminals)

    @pytest.mark.terminal
    @pytest.mark.unit
    async def test_fleet_overview(self, test_terminals):
        """Test getting fleet overview."""
        # Activate some terminals
        for terminal in test_terminals[:2]:
            await terminal_manager.activate_terminal(terminal.terminal_id)

        overview = await terminal_manager.get_fleet_overview("mer_test_001")

        assert "total_terminals" in overview
        assert "active_terminals" in overview
        assert "status_breakdown" in overview
        assert "type_breakdown" in overview
        assert "today_performance" in overview

        assert overview["total_terminals"] >= 3
        assert overview["status_breakdown"]["active"] >= 2
        assert overview["status_breakdown"]["inactive"] >= 1


class TestTerminalMonitoring:
    """Test terminal monitoring and health checks."""

    @pytest.mark.terminal
    @pytest.mark.slow
    async def test_terminal_offline_detection(self):
        """Test automatic detection of offline terminals."""
        # Create terminal with old heartbeat
        device_info = {
            "device_name": "Offline Test Terminal",
            "model": "Test Model",
            "serial_number": "OFFLINE123",
            "os_version": "Test OS",
            "app_version": "1.0.0",
            "device_type": "phone",
            "nfc_enabled": True
        }

        terminal = await terminal_manager.register_terminal(
            merchant_id="mer_test_001",
            device_info=device_info
        )

        await terminal_manager.activate_terminal(terminal.terminal_id)

        # Set old heartbeat (simulate terminal going offline)
        old_time = datetime.now(timezone.utc) - timedelta(minutes=15)
        terminal.last_heartbeat = old_time

        # Run health monitor (normally runs in background)
        await terminal_manager._terminal_health_monitor()

        # Terminal should be marked as offline
        assert terminal.status == TerminalStatus.OFFLINE

    @pytest.mark.terminal
    @pytest.mark.unit
    async def test_heartbeat_history_limit(self, active_terminal):
        """Test that heartbeat history is limited to prevent memory issues."""
        # Send many heartbeats
        for i in range(150):  # More than the 100 limit
            heartbeat_data = {
                "status": "active",
                "battery_level": 85,
                "network_strength": 75,
                "memory_usage": 0.6,
                "cpu_usage": 0.3
            }

            await terminal_manager.process_heartbeat(
                active_terminal.terminal_id,
                heartbeat_data
            )

        # Should keep only last 100 heartbeats
        heartbeat_history = terminal_manager.heartbeat_history[active_terminal.terminal_id]
        assert len(heartbeat_history) == 100