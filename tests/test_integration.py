"""
Integration Tests

End-to-end integration tests for SoftPOS functionality including:
- Complete payment flows
- Terminal registration and management flows
- Webhook delivery flows
- Real-time monitoring integration
- Security and fraud detection integration
"""

import pytest
import asyncio
from decimal import Decimal
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch, MagicMock

from app.main import app
from app.terminal_management import terminal_manager
from app.webhooks import webhook_manager, WebhookEventType
from app.monitoring import monitoring_engine
from app.payment_processing import payment_engine


class TestPaymentFlows:
    """Test complete payment processing flows."""

    @pytest.mark.integration
    @pytest.mark.e2e
    async def test_complete_contactless_payment_flow(self, async_client, auth_headers):
        """Test complete contactless payment flow from intent to completion."""
        # Step 1: Create payment intent
        intent_data = {
            "merchant_id": "mer_test_001",
            "amount_minor": 2500,  # £25.00
            "currency": "GBP",
            "capture_mode": "auto",
            "metadata": {
                "order_id": "order_001",
                "customer_email": "customer@example.com"
            }
        }

        intent_response = await async_client.post(
            "/v1/payments/intent",
            json=intent_data,
            headers=auth_headers
        )

        assert intent_response.status_code == 201
        intent = intent_response.json()
        intent_id = intent["id"]

        # Step 2: Confirm payment with contactless data
        confirm_data = {
            "device_id": "term_contactless_001",
            "emv_payload": "4111111111111111|12|25|123",  # Mock EMV data
            "attestation": "mock_attestation_token_ios_device",
            "payment_method_details": {
                "type": "contactless",
                "entry_mode": "contactless_chip"
            }
        }

        # Mock successful payment processing
        with patch('app.main.payment_engine') as mock_engine:
            mock_response = AsyncMock()
            mock_response.approved = True
            mock_response.authorization_code = "AUTH123"
            mock_response.response_code.value = "00"
            mock_response.response_message = "Approved"
            mock_response.processor.value = "test_processor"
            mock_response.card_scheme.value = "visa"
            mock_response.amount = Decimal("25.00")
            mock_response.currency = "GBP"
            mock_response.processing_time_ms = 150
            mock_response.network_transaction_id = "net_txn_001"
            mock_response.avs_result = "Y"
            mock_response.cvv_result = "M"
            mock_response.risk_score = 0.1

            mock_engine.process_payment.return_value = mock_response

            confirm_response = await async_client.post(
                f"/v1/payments/intent/{intent_id}/confirm",
                json=confirm_data,
                headers=auth_headers
            )

        assert confirm_response.status_code == 200
        payment = confirm_response.json()

        # Verify payment success
        assert payment["status"] == "succeeded"
        assert payment["amount_minor"] == 2500
        assert payment["currency"] == "GBP"
        assert payment["auth_code"] == "AUTH123"
        assert payment["scheme"] == "VISA"

    @pytest.mark.integration
    @pytest.mark.e2e
    async def test_complete_chip_pin_payment_flow(self, async_client, auth_headers):
        """Test complete chip and PIN payment flow."""
        # Step 1: Create payment intent
        intent_data = {
            "merchant_id": "mer_test_001",
            "amount_minor": 5000,  # £50.00
            "currency": "GBP",
            "capture_mode": "auto"
        }

        intent_response = await async_client.post(
            "/v1/payments/intent",
            json=intent_data,
            headers=auth_headers
        )

        intent_id = intent_response.json()["id"]

        # Step 2: Confirm payment with chip and PIN
        confirm_data = {
            "device_id": "term_chip_pin_001",
            "emv_payload": "5555555555554444|12|25|456",  # Mastercard test data
            "attestation": "mock_attestation_token_android_device",
            "payment_method_details": {
                "type": "chip_pin",
                "entry_mode": "chip",
                "pin_verified": True
            }
        }

        # Mock successful payment processing
        with patch('app.main.payment_engine') as mock_engine:
            mock_response = AsyncMock()
            mock_response.approved = True
            mock_response.authorization_code = "AUTH456"
            mock_response.response_code.value = "00"
            mock_response.response_message = "Approved"
            mock_response.processor.value = "test_processor"
            mock_response.card_scheme.value = "mastercard"
            mock_response.amount = Decimal("50.00")
            mock_response.currency = "GBP"
            mock_response.processing_time_ms = 200
            mock_response.risk_score = 0.05

            mock_engine.process_payment.return_value = mock_response

            confirm_response = await async_client.post(
                f"/v1/payments/intent/{intent_id}/confirm",
                json=confirm_data,
                headers=auth_headers
            )

        assert confirm_response.status_code == 200
        payment = confirm_response.json()

        assert payment["status"] == "succeeded"
        assert payment["amount_minor"] == 5000
        assert payment["auth_code"] == "AUTH456"

    @pytest.mark.integration
    @pytest.mark.e2e
    async def test_declined_payment_flow(self, async_client, auth_headers):
        """Test payment flow with declined transaction."""
        # Create payment intent
        intent_data = {
            "merchant_id": "mer_test_001",
            "amount_minor": 1000,  # £10.00
            "currency": "GBP",
            "capture_mode": "auto"
        }

        intent_response = await async_client.post(
            "/v1/payments/intent",
            json=intent_data,
            headers=auth_headers
        )

        intent_id = intent_response.json()["id"]

        # Confirm payment with declined card
        confirm_data = {
            "device_id": "term_test_001",
            "emv_payload": "4000000000000002|12|25|123",  # Declined test card
            "attestation": "mock_attestation_token"
        }

        # Mock declined payment processing
        with patch('app.main.payment_engine') as mock_engine:
            mock_response = AsyncMock()
            mock_response.approved = False
            mock_response.authorization_code = None
            mock_response.response_code.value = "05"
            mock_response.response_message = "Do not honor"
            mock_response.processor.value = "test_processor"
            mock_response.card_scheme.value = "visa"
            mock_response.amount = Decimal("10.00")
            mock_response.currency = "GBP"

            mock_engine.process_payment.return_value = mock_response

            confirm_response = await async_client.post(
                f"/v1/payments/intent/{intent_id}/confirm",
                json=confirm_data,
                headers=auth_headers
            )

        # Should return 400 for declined payment
        assert confirm_response.status_code == 400
        error = confirm_response.json()
        assert "declined" in error["detail"].lower()

    @pytest.mark.integration
    @pytest.mark.e2e
    async def test_fraud_blocked_payment_flow(self, async_client, auth_headers):
        """Test payment flow blocked by fraud detection."""
        # Create payment intent for high amount
        intent_data = {
            "merchant_id": "mer_test_001",
            "amount_minor": 100000,  # £1,000.00 - high amount
            "currency": "GBP",
            "capture_mode": "auto"
        }

        intent_response = await async_client.post(
            "/v1/payments/intent",
            json=intent_data,
            headers=auth_headers
        )

        intent_id = intent_response.json()["id"]

        # Confirm payment from suspicious device
        confirm_data = {
            "device_id": "term_suspicious_001",
            "emv_payload": "4111111111111111|12|25|123",
            "attestation": "suspicious_attestation_token"
        }

        # Mock fraud detection blocking payment
        with patch('app.attestation.attestation_validator') as mock_validator:
            from app.attestation import AttestationResult, AttestationStatus, DevicePlatform

            mock_validator.validate_attestation.return_value = AttestationResult(
                status=AttestationStatus.INVALID,
                device_id="suspicious_device",
                platform=DevicePlatform.IOS,
                risk_score=0.95,  # Very high risk
                details={"jailbroken": True, "debugger": True}
            )

            confirm_response = await async_client.post(
                f"/v1/payments/intent/{intent_id}/confirm",
                json=confirm_data,
                headers=auth_headers
            )

        # Should be blocked due to device attestation failure
        assert confirm_response.status_code == 400
        error = confirm_response.json()
        assert "attestation failed" in error["detail"].lower()


class TestTerminalManagementFlows:
    """Test complete terminal management flows."""

    @pytest.mark.integration
    @pytest.mark.e2e
    async def test_terminal_lifecycle_flow(self, async_client, auth_headers):
        """Test complete terminal lifecycle from registration to deactivation."""
        # Step 1: Register terminal
        registration_data = {
            "device_name": "Integration Test Terminal",
            "device_model": "iPhone 14 Pro",
            "serial_number": "INT_TEST_001",
            "os_version": "iOS 16.1",
            "app_version": "1.2.3",
            "hardware_id": "hw_int_test_001",
            "device_type": "phone",
            "nfc_enabled": True,
            "camera_available": True,
            "biometric_available": True,
            "location_name": "Integration Test Store",
            "address": "123 Test Street, Test City",
            "timezone": "Europe/London"
        }

        register_response = await async_client.post(
            "/v1/terminals/register",
            json=registration_data,
            headers=auth_headers
        )

        assert register_response.status_code == 201
        terminal = register_response.json()
        terminal_id = terminal["terminal_id"]

        # Verify registration
        assert terminal["device_name"] == "Integration Test Terminal"
        assert terminal["status"] == "inactive"
        assert "contactless" in terminal["capabilities"]

        # Step 2: Activate terminal
        activate_response = await async_client.post(
            f"/v1/terminals/{terminal_id}/activate",
            headers=auth_headers
        )

        assert activate_response.status_code == 200

        # Step 3: Update terminal configuration
        config_data = {
            "config_type": "payment_settings",
            "configuration": {
                "contactless_limit": 100.00,
                "pin_bypass_limit": 45.00,
                "daily_limit": 5000.00,
                "currency": "GBP"
            }
        }

        config_response = await async_client.put(
            f"/v1/terminals/{terminal_id}/configuration",
            json=config_data,
            headers=auth_headers
        )

        assert config_response.status_code == 200

        # Step 4: Send heartbeat
        heartbeat_data = {
            "status": "active",
            "battery_level": 85,
            "network_strength": 75,
            "memory_usage": 0.6,
            "cpu_usage": 0.3,
            "performance_metrics": {
                "transactions_processed": 25,
                "average_response_time": 120
            }
        }

        heartbeat_response = await async_client.post(
            f"/v1/terminals/{terminal_id}/heartbeat",
            json=heartbeat_data,
            headers=auth_headers
        )

        assert heartbeat_response.status_code == 200

        # Step 5: Send command to terminal
        command_data = {
            "command_type": "configuration_update",
            "payload": {
                "config_type": "ui_branding",
                "configuration": {
                    "color_scheme": "blue"
                }
            }
        }

        command_response = await async_client.post(
            f"/v1/terminals/{terminal_id}/commands",
            json=command_data,
            headers=auth_headers
        )

        assert command_response.status_code == 200

        # Step 6: Get terminal details
        details_response = await async_client.get(
            f"/v1/terminals/{terminal_id}",
            headers=auth_headers
        )

        assert details_response.status_code == 200
        details = details_response.json()
        assert details["status"] == "active"

        # Step 7: Deactivate terminal
        deactivate_response = await async_client.post(
            f"/v1/terminals/{terminal_id}/deactivate?reason=End of integration test",
            headers=auth_headers
        )

        assert deactivate_response.status_code == 200


class TestWebhookFlows:
    """Test complete webhook flows."""

    @pytest.mark.integration
    @pytest.mark.e2e
    async def test_webhook_registration_and_delivery_flow(self, async_client, auth_headers, mock_http_client):
        """Test complete webhook registration and event delivery flow."""
        # Step 1: Register webhook endpoint
        webhook_data = {
            "url": "https://merchant.example.com/webhooks",
            "event_types": ["payment.successful", "payment.failed"],
            "max_retries": 3,
            "timeout_seconds": 30,
            "custom_headers": {
                "X-Merchant-ID": "mer_test_001"
            }
        }

        register_response = await async_client.post(
            "/v1/webhooks/endpoints",
            json=webhook_data,
            headers=auth_headers
        )

        assert register_response.status_code == 201
        endpoint = register_response.json()
        endpoint_id = endpoint["endpoint_id"]

        # Step 2: Emit test event
        event_data = {
            "event_type": "payment.successful",
            "data": {
                "transaction_id": "txn_webhook_test_001",
                "amount": "25.00",
                "currency": "GBP",
                "status": "succeeded"
            },
            "priority": "high",
            "terminal_id": "term_webhook_test"
        }

        # Mock successful webhook delivery
        with patch.object(webhook_manager.http_client, 'post') as mock_post:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.text = '{"status": "received"}'
            mock_response.headers = {"content-type": "application/json"}
            mock_post.return_value = mock_response

            emit_response = await async_client.post(
                "/v1/webhooks/events",
                json=event_data,
                headers=auth_headers
            )

            assert emit_response.status_code == 201

            # Wait for webhook processing
            await asyncio.sleep(0.1)

        # Step 3: Check webhook deliveries
        deliveries_response = await async_client.get(
            f"/v1/webhooks/deliveries?endpoint_id={endpoint_id}",
            headers=auth_headers
        )

        assert deliveries_response.status_code == 200
        deliveries = deliveries_response.json()
        assert len(deliveries) > 0

        # Verify delivery success
        delivery = deliveries[0]
        assert delivery["status"] == "delivered"
        assert delivery["response_status"] == 200

        # Step 4: Test webhook endpoint
        test_response = await async_client.post(
            f"/v1/webhooks/test?endpoint_id={endpoint_id}",
            headers=auth_headers
        )

        assert test_response.status_code == 200

        # Step 5: Get webhook analytics
        analytics_response = await async_client.get(
            "/v1/webhooks/analytics",
            headers=auth_headers
        )

        assert analytics_response.status_code == 200
        analytics = analytics_response.json()
        assert "overview" in analytics
        assert analytics["overview"]["total_deliveries"] > 0


class TestMonitoringFlows:
    """Test monitoring and alerting flows."""

    @pytest.mark.integration
    @pytest.mark.e2e
    async def test_monitoring_and_alerting_flow(self, async_client, auth_headers):
        """Test complete monitoring and alerting flow."""
        # Step 1: Get system overview
        overview_response = await async_client.get(
            "/v1/monitoring/overview",
            headers=auth_headers
        )

        assert overview_response.status_code == 200
        overview = overview_response.json()
        assert "overall_status" in overview
        assert "active_alerts" in overview

        # Step 2: Record custom metric
        metric_data = {
            "name": "integration_test_metric",
            "value": 75.5,
            "metric_type": "gauge",
            "tags": {
                "test_run": "integration",
                "component": "api"
            },
            "description": "Integration test metric"
        }

        metric_response = await async_client.post(
            "/v1/monitoring/metrics",
            json=metric_data,
            headers=auth_headers
        )

        assert metric_response.status_code == 200

        # Step 3: Get health checks
        health_response = await async_client.get(
            "/v1/monitoring/health",
            headers=auth_headers
        )

        assert health_response.status_code == 200
        health_checks = health_response.json()
        assert isinstance(health_checks, list)

        # Step 4: Generate report
        report_data = {
            "report_type": "transaction_summary",
            "start_date": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
            "end_date": datetime.now(timezone.utc).isoformat(),
            "format": "json"
        }

        report_response = await async_client.post(
            "/v1/monitoring/reports/generate",
            json=report_data,
            headers=auth_headers
        )

        assert report_response.status_code == 200
        report = report_response.json()
        assert "summary" in report
        assert "details" in report

        # Step 5: Get dashboard data
        dashboard_response = await async_client.get(
            "/v1/monitoring/dashboard",
            headers=auth_headers
        )

        assert dashboard_response.status_code == 200
        dashboard = dashboard_response.json()
        assert "system_status" in dashboard
        assert "business_metrics" in dashboard


class TestRealTimeFlows:
    """Test real-time communication flows."""

    @pytest.mark.integration
    @pytest.mark.e2e
    async def test_websocket_connection_flow(self, auth_headers):
        """Test WebSocket connection and messaging flow."""
        from fastapi.testclient import TestClient
        from app.main import app

        # Extract token from auth headers
        token = auth_headers["Authorization"].replace("Bearer ", "")

        with TestClient(app) as client:
            # Connect to WebSocket
            with client.websocket_connect(f"/v1/realtime/connect?token={token}") as websocket:
                # Should receive welcome message
                welcome_data = websocket.receive_json()
                assert welcome_data["type"] == "welcome"
                assert "features" in welcome_data

                # Send ping
                websocket.send_json({"type": "ping"})

                # Should receive pong
                pong_data = websocket.receive_json()
                assert pong_data["type"] == "pong"

                # Request status
                websocket.send_json({"type": "get_status"})

                # Should receive status response
                status_data = websocket.receive_json()
                assert status_data["type"] == "status_response"
                assert "data" in status_data

    @pytest.mark.integration
    @pytest.mark.e2e
    async def test_realtime_notification_flow(self, async_client, auth_headers):
        """Test real-time notification delivery flow."""
        # Test transaction notification
        notification_data = {
            "merchant_id": "mer_test_001",
            "transaction_data": {
                "transaction_id": "txn_realtime_001",
                "amount": "50.00",
                "status": "succeeded"
            }
        }

        response = await async_client.post(
            "/v1/realtime/notify/transaction",
            json=notification_data,
            headers=auth_headers
        )

        assert response.status_code == 200

        # Test terminal status notification
        terminal_notification = {
            "merchant_id": "mer_test_001",
            "terminal_id": "term_realtime_001",
            "status": "active",
            "details": {
                "battery_level": 85,
                "network_strength": 75
            }
        }

        response = await async_client.post(
            "/v1/realtime/notify/terminal",
            json=terminal_notification,
            headers=auth_headers
        )

        assert response.status_code == 200

        # Test system alert notification
        alert_notification = {
            "alert_data": {
                "alert_id": "alert_realtime_001",
                "title": "Integration Test Alert",
                "severity": "warning",
                "component": "test"
            }
        }

        response = await async_client.post(
            "/v1/realtime/notify/alert",
            json=alert_notification,
            headers=auth_headers
        )

        assert response.status_code == 200


class TestSecurityIntegration:
    """Test security integration across components."""

    @pytest.mark.integration
    @pytest.mark.security
    async def test_end_to_end_security_flow(self, async_client, auth_headers):
        """Test end-to-end security flow with encryption and fraud detection."""
        # This test would verify that:
        # 1. Payment data is properly encrypted
        # 2. Fraud detection is applied
        # 3. Device attestation is validated
        # 4. HSM signing works
        # 5. All security policies are enforced

        # Create high-value payment that triggers fraud checks
        intent_data = {
            "merchant_id": "mer_test_001",
            "amount_minor": 50000,  # £500.00
            "currency": "GBP",
            "capture_mode": "auto"
        }

        intent_response = await async_client.post(
            "/v1/payments/intent",
            json=intent_data,
            headers=auth_headers
        )

        intent_id = intent_response.json()["id"]

        # Confirm payment with device attestation
        confirm_data = {
            "device_id": "term_security_test_001",
            "emv_payload": "4111111111111111|12|25|123",
            "attestation": "valid_attestation_token"
        }

        # Mock all security components
        with patch('app.main.payment_engine') as mock_engine, \
             patch('app.attestation.attestation_validator') as mock_validator, \
             patch('app.hsm.hsm_manager') as mock_hsm, \
             patch('app.fraud_detection.fraud_engine') as mock_fraud:

            # Mock valid attestation
            from app.attestation import AttestationResult, AttestationStatus, DevicePlatform
            mock_validator.validate_attestation.return_value = AttestationResult(
                status=AttestationStatus.VALID,
                device_id="secure_device",
                platform=DevicePlatform.IOS,
                risk_score=0.1,
                details={"jailbroken": False, "debugger": False}
            )

            # Mock low fraud risk
            mock_fraud.assess_risk.return_value = {
                "risk_score": 0.2,
                "risk_level": "LOW",
                "rules_triggered": [],
                "recommendation": "APPROVE"
            }

            # Mock HSM operations
            mock_hsm.encrypt_payment_data.return_value = ("encrypted_data", "key_ref")
            mock_hsm.sign_transaction.return_value = "signature"

            # Mock successful payment
            mock_response = AsyncMock()
            mock_response.approved = True
            mock_response.authorization_code = "SEC_AUTH_001"
            mock_response.response_code.value = "00"
            mock_response.response_message = "Approved"
            mock_response.processor.value = "test_processor"
            mock_response.card_scheme.value = "visa"
            mock_response.amount = Decimal("500.00")
            mock_response.currency = "GBP"
            mock_response.risk_score = 0.2

            mock_engine.process_payment.return_value = mock_response

            confirm_response = await async_client.post(
                f"/v1/payments/intent/{intent_id}/confirm",
                json=confirm_data,
                headers=auth_headers
            )

        assert confirm_response.status_code == 200

        # Verify all security components were called
        mock_validator.validate_attestation.assert_called_once()
        mock_fraud.assess_risk.assert_called_once()
        mock_hsm.encrypt_payment_data.assert_called()
        mock_hsm.sign_transaction.assert_called()


class TestPerformanceAndLoad:
    """Test system performance under load."""

    @pytest.mark.integration
    @pytest.mark.slow
    async def test_concurrent_payment_processing(self, async_client, auth_headers):
        """Test concurrent payment processing performance."""
        # Create multiple payment intents concurrently
        tasks = []

        async def create_and_confirm_payment(payment_id):
            # Create intent
            intent_data = {
                "merchant_id": "mer_test_001",
                "amount_minor": 1000 + payment_id,
                "currency": "GBP",
                "capture_mode": "auto"
            }

            intent_response = await async_client.post(
                "/v1/payments/intent",
                json=intent_data,
                headers=auth_headers
            )

            if intent_response.status_code != 201:
                return False

            intent_id = intent_response.json()["id"]

            # Confirm payment
            confirm_data = {
                "device_id": f"term_load_test_{payment_id:03d}",
                "emv_payload": f"411111111111111{payment_id % 10}|12|25|123",
                "attestation": f"attestation_token_{payment_id}"
            }

            with patch('app.main.payment_engine') as mock_engine:
                mock_response = AsyncMock()
                mock_response.approved = True
                mock_response.authorization_code = f"AUTH{payment_id:03d}"
                mock_response.response_code.value = "00"
                mock_response.response_message = "Approved"
                mock_response.processor.value = "test_processor"
                mock_response.card_scheme.value = "visa"
                mock_response.amount = Decimal(str(10.00 + payment_id))
                mock_response.currency = "GBP"
                mock_response.processing_time_ms = 150

                mock_engine.process_payment.return_value = mock_response

                confirm_response = await async_client.post(
                    f"/v1/payments/intent/{intent_id}/confirm",
                    json=confirm_data,
                    headers=auth_headers
                )

            return confirm_response.status_code == 200

        # Create tasks for concurrent execution
        for i in range(10):  # 10 concurrent payments
            task = create_and_confirm_payment(i)
            tasks.append(task)

        # Execute all tasks concurrently
        start_time = datetime.now()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        end_time = datetime.now()

        # Verify results
        successful_payments = sum(1 for result in results if result is True)
        total_time = (end_time - start_time).total_seconds()

        assert successful_payments >= 8  # At least 80% success rate
        assert total_time < 10.0  # Should complete within 10 seconds

        print(f"Processed {successful_payments}/10 payments in {total_time:.2f} seconds")

    @pytest.mark.integration
    @pytest.mark.slow
    async def test_webhook_delivery_performance(self, async_client, auth_headers):
        """Test webhook delivery performance under load."""
        # Register webhook endpoint
        webhook_data = {
            "url": "https://merchant.example.com/webhooks",
            "event_types": ["payment.successful"],
            "max_retries": 1
        }

        register_response = await async_client.post(
            "/v1/webhooks/endpoints",
            json=webhook_data,
            headers=auth_headers
        )

        endpoint_id = register_response.json()["endpoint_id"]

        # Emit multiple events concurrently
        async def emit_event(event_id):
            event_data = {
                "event_type": "payment.successful",
                "data": {
                    "transaction_id": f"txn_perf_test_{event_id:03d}",
                    "amount": "25.00"
                }
            }

            with patch.object(webhook_manager.http_client, 'post') as mock_post:
                mock_response = AsyncMock()
                mock_response.status_code = 200
                mock_response.text = '{"status": "received"}'
                mock_response.headers = {}
                mock_post.return_value = mock_response

                response = await async_client.post(
                    "/v1/webhooks/events",
                    json=event_data,
                    headers=auth_headers
                )

            return response.status_code == 201

        # Emit events concurrently
        tasks = [emit_event(i) for i in range(20)]
        start_time = datetime.now()
        results = await asyncio.gather(*tasks)
        end_time = datetime.now()

        # Wait for webhook processing
        await asyncio.sleep(1.0)

        successful_emissions = sum(results)
        total_time = (end_time - start_time).total_seconds()

        assert successful_emissions >= 18  # At least 90% success rate
        assert total_time < 5.0  # Should complete within 5 seconds

        print(f"Emitted {successful_emissions}/20 webhook events in {total_time:.2f} seconds")