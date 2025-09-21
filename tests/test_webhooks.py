"""
Webhook System Tests

Test suite for webhook functionality including:
- Webhook endpoint registration and management
- Event emission and delivery
- Retry logic and error handling
- Circuit breaker functionality
- Rate limiting
- Security and authentication
"""

import pytest
import json
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch, MagicMock
from decimal import Decimal

from app.webhooks import (
    webhook_manager,
    WebhookEventType,
    WebhookPriority,
    WebhookStatus,
    WebhookEndpoint,
    WebhookEvent,
    WebhookDelivery
)


class TestWebhookEndpointManagement:
    """Test webhook endpoint registration and management."""

    @pytest.mark.webhook
    @pytest.mark.unit
    async def test_register_webhook_endpoint(self):
        """Test registering a new webhook endpoint."""
        event_types = {WebhookEventType.PAYMENT_SUCCESSFUL, WebhookEventType.PAYMENT_FAILED}

        endpoint = await webhook_manager.register_webhook_endpoint(
            merchant_id="mer_test_001",
            url="https://merchant.example.com/webhooks",
            event_types=event_types,
            secret_key="test_secret_key"
        )

        assert endpoint.merchant_id == "mer_test_001"
        assert endpoint.url == "https://merchant.example.com/webhooks"
        assert endpoint.secret_key == "test_secret_key"
        assert endpoint.event_types == event_types
        assert endpoint.active is True
        assert endpoint.max_retries == 3
        assert endpoint.timeout_seconds == 30

        # Verify endpoint is stored
        assert endpoint.endpoint_id in webhook_manager.endpoints
        assert webhook_manager.endpoints[endpoint.endpoint_id] == endpoint

    @pytest.mark.webhook
    @pytest.mark.unit
    async def test_register_webhook_endpoint_with_config(self):
        """Test registering webhook endpoint with custom configuration."""
        event_types = {WebhookEventType.PAYMENT_SUCCESSFUL}
        config = {
            "max_retries": 5,
            "timeout_seconds": 60,
            "verify_ssl": False,
            "custom_headers": {
                "X-Custom-Header": "custom-value",
                "Authorization": "Bearer custom-token"
            },
            "event_filters": {
                "amount_min": 100,
                "currency": "GBP"
            }
        }

        endpoint = await webhook_manager.register_webhook_endpoint(
            merchant_id="mer_test_001",
            url="https://merchant.example.com/webhooks",
            event_types=event_types,
            config=config
        )

        assert endpoint.max_retries == 5
        assert endpoint.timeout_seconds == 60
        assert endpoint.verify_ssl is False
        assert endpoint.custom_headers["X-Custom-Header"] == "custom-value"
        assert endpoint.event_filters["amount_min"] == 100

    @pytest.mark.webhook
    @pytest.mark.unit
    async def test_register_webhook_endpoint_auto_secret(self):
        """Test registering webhook endpoint with auto-generated secret."""
        event_types = {WebhookEventType.PAYMENT_SUCCESSFUL}

        endpoint = await webhook_manager.register_webhook_endpoint(
            merchant_id="mer_test_001",
            url="https://merchant.example.com/webhooks",
            event_types=event_types
            # No secret_key provided
        )

        assert endpoint.secret_key is not None
        assert len(endpoint.secret_key) == 64  # 32 bytes hex = 64 chars

    @pytest.mark.webhook
    @pytest.mark.unit
    async def test_circuit_breaker_initialization(self):
        """Test that circuit breaker is initialized for new endpoints."""
        event_types = {WebhookEventType.PAYMENT_SUCCESSFUL}

        endpoint = await webhook_manager.register_webhook_endpoint(
            merchant_id="mer_test_001",
            url="https://merchant.example.com/webhooks",
            event_types=event_types
        )

        # Circuit breaker should be initialized
        assert endpoint.endpoint_id in webhook_manager.circuit_breakers
        breaker = webhook_manager.circuit_breakers[endpoint.endpoint_id]
        assert breaker["state"] == "closed"
        assert breaker["failure_count"] == 0


class TestWebhookEventEmission:
    """Test webhook event emission and queuing."""

    @pytest.fixture
    async def test_endpoint(self):
        """Create a test webhook endpoint."""
        event_types = {
            WebhookEventType.PAYMENT_SUCCESSFUL,
            WebhookEventType.PAYMENT_FAILED,
            WebhookEventType.TERMINAL_CONNECTED
        }

        return await webhook_manager.register_webhook_endpoint(
            merchant_id="mer_test_001",
            url="https://merchant.example.com/webhooks",
            event_types=event_types
        )

    @pytest.mark.webhook
    @pytest.mark.unit
    async def test_emit_payment_event(self, test_endpoint):
        """Test emitting a payment event."""
        event_data = {
            "transaction_id": "txn_test_001",
            "amount": "25.00",
            "currency": "GBP",
            "status": "succeeded",
            "payment_method": "contactless"
        }

        event_id = await webhook_manager.emit_event(
            event_type=WebhookEventType.PAYMENT_SUCCESSFUL,
            merchant_id="mer_test_001",
            data=event_data,
            priority=WebhookPriority.HIGH,
            correlation_id="corr_001",
            terminal_id="term_001"
        )

        assert event_id is not None
        assert event_id.startswith("evt_")

        # Event should be in pending queue
        assert len(webhook_manager.pending_events) > 0

        # Find the emitted event
        emitted_event = None
        for event in webhook_manager.pending_events:
            if event.event_id == event_id:
                emitted_event = event
                break

        assert emitted_event is not None
        assert emitted_event.event_type == WebhookEventType.PAYMENT_SUCCESSFUL
        assert emitted_event.merchant_id == "mer_test_001"
        assert emitted_event.data == event_data
        assert emitted_event.priority == WebhookPriority.HIGH
        assert emitted_event.correlation_id == "corr_001"
        assert emitted_event.terminal_id == "term_001"

    @pytest.mark.webhook
    @pytest.mark.unit
    async def test_emit_terminal_event(self, test_endpoint):
        """Test emitting a terminal event."""
        event_data = {
            "terminal_id": "term_001",
            "previous_status": "inactive",
            "current_status": "active",
            "device_info": {
                "model": "iPhone 13",
                "os_version": "iOS 16.1"
            }
        }

        event_id = await webhook_manager.emit_event(
            event_type=WebhookEventType.TERMINAL_CONNECTED,
            merchant_id="mer_test_001",
            data=event_data,
            terminal_id="term_001"
        )

        assert event_id is not None

        # Find the emitted event
        emitted_event = None
        for event in webhook_manager.pending_events:
            if event.event_id == event_id:
                emitted_event = event
                break

        assert emitted_event is not None
        assert emitted_event.event_type == WebhookEventType.TERMINAL_CONNECTED
        assert emitted_event.data["terminal_id"] == "term_001"

    @pytest.mark.webhook
    @pytest.mark.unit
    async def test_event_priority_ordering(self, test_endpoint):
        """Test that events are ordered by priority."""
        # Emit events with different priorities
        await webhook_manager.emit_event(
            event_type=WebhookEventType.PAYMENT_SUCCESSFUL,
            merchant_id="mer_test_001",
            data={"order": 1},
            priority=WebhookPriority.LOW
        )

        await webhook_manager.emit_event(
            event_type=WebhookEventType.PAYMENT_SUCCESSFUL,
            merchant_id="mer_test_001",
            data={"order": 2},
            priority=WebhookPriority.CRITICAL
        )

        await webhook_manager.emit_event(
            event_type=WebhookEventType.PAYMENT_SUCCESSFUL,
            merchant_id="mer_test_001",
            data={"order": 3},
            priority=WebhookPriority.NORMAL
        )

        # Events should be sorted by priority (high to low)
        events = webhook_manager.pending_events
        assert len(events) >= 3

        # Critical priority should be first
        assert events[0].priority == WebhookPriority.CRITICAL
        assert events[0].data["order"] == 2


class TestWebhookDelivery:
    """Test webhook delivery logic."""

    @pytest.fixture
    async def test_endpoint(self):
        """Create a test webhook endpoint."""
        event_types = {WebhookEventType.PAYMENT_SUCCESSFUL}

        return await webhook_manager.register_webhook_endpoint(
            merchant_id="mer_test_001",
            url="https://merchant.example.com/webhooks",
            event_types=event_types
        )

    @pytest.fixture
    def mock_http_response(self):
        """Mock successful HTTP response."""
        response = AsyncMock()
        response.status_code = 200
        response.text = '{"status": "received"}'
        response.headers = {"content-type": "application/json"}
        return response

    @pytest.mark.webhook
    @pytest.mark.unit
    async def test_successful_webhook_delivery(self, test_endpoint, mock_http_response):
        """Test successful webhook delivery."""
        # Create test event
        event = WebhookEvent(
            event_id="evt_test_001",
            merchant_id="mer_test_001",
            event_type=WebhookEventType.PAYMENT_SUCCESSFUL,
            data={"transaction_id": "txn_001", "amount": "25.00"}
        )

        # Mock HTTP client
        with patch.object(webhook_manager.http_client, 'post', return_value=mock_http_response):
            deliveries = await webhook_manager.deliver_event(event)

        assert len(deliveries) == 1
        delivery = deliveries[0]

        assert delivery.status == WebhookStatus.DELIVERED
        assert delivery.response_status == 200
        assert delivery.error_message is None
        assert delivery.retry_count == 0
        assert delivery.duration_ms is not None

        # Endpoint stats should be updated
        assert test_endpoint.total_deliveries == 1
        assert test_endpoint.successful_deliveries == 1
        assert test_endpoint.failed_deliveries == 0

    @pytest.mark.webhook
    @pytest.mark.unit
    async def test_failed_webhook_delivery(self, test_endpoint):
        """Test failed webhook delivery with retry scheduling."""
        # Create test event
        event = WebhookEvent(
            event_id="evt_test_001",
            merchant_id="mer_test_001",
            event_type=WebhookEventType.PAYMENT_SUCCESSFUL,
            data={"transaction_id": "txn_001", "amount": "25.00"}
        )

        # Mock failed HTTP response
        failed_response = AsyncMock()
        failed_response.status_code = 500
        failed_response.text = "Internal Server Error"
        failed_response.headers = {}

        with patch.object(webhook_manager.http_client, 'post', return_value=failed_response):
            deliveries = await webhook_manager.deliver_event(event)

        assert len(deliveries) == 1
        delivery = deliveries[0]

        assert delivery.status == WebhookStatus.RETRYING
        assert delivery.response_status == 500
        assert delivery.error_message is not None
        assert delivery.retry_count == 0
        assert delivery.next_retry_at is not None

        # Endpoint stats should be updated
        assert test_endpoint.failed_deliveries == 1

    @pytest.mark.webhook
    @pytest.mark.unit
    async def test_webhook_delivery_timeout(self, test_endpoint):
        """Test webhook delivery timeout handling."""
        # Create test event
        event = WebhookEvent(
            event_id="evt_test_001",
            merchant_id="mer_test_001",
            event_type=WebhookEventType.PAYMENT_SUCCESSFUL,
            data={"transaction_id": "txn_001", "amount": "25.00"}
        )

        # Mock timeout exception
        import asyncio

        async def timeout_side_effect(*args, **kwargs):
            raise asyncio.TimeoutError("Request timeout")

        with patch.object(webhook_manager.http_client, 'post', side_effect=timeout_side_effect):
            deliveries = await webhook_manager.deliver_event(event)

        assert len(deliveries) == 1
        delivery = deliveries[0]

        assert delivery.status == WebhookStatus.RETRYING
        assert "timeout" in delivery.error_message.lower()

    @pytest.mark.webhook
    @pytest.mark.unit
    async def test_webhook_signature_generation(self, test_endpoint):
        """Test webhook signature generation."""
        # Create test event
        event = WebhookEvent(
            event_id="evt_test_001",
            merchant_id="mer_test_001",
            event_type=WebhookEventType.PAYMENT_SUCCESSFUL,
            data={"transaction_id": "txn_001"}
        )

        # Mock successful response
        response = AsyncMock()
        response.status_code = 200
        response.text = '{"status": "received"}'
        response.headers = {}

        with patch.object(webhook_manager.http_client, 'post', return_value=response) as mock_post:
            await webhook_manager.deliver_event(event)

            # Verify signature was included in headers
            call_args = mock_post.call_args
            headers = call_args.kwargs.get('headers', {})

            assert 'X-Webhook-Signature' in headers
            assert headers['X-Webhook-Signature'].startswith('sha256=')

    @pytest.mark.webhook
    @pytest.mark.unit
    async def test_webhook_payload_structure(self, test_endpoint):
        """Test webhook payload structure."""
        # Create test event
        event = WebhookEvent(
            event_id="evt_test_001",
            merchant_id="mer_test_001",
            event_type=WebhookEventType.PAYMENT_SUCCESSFUL,
            data={"transaction_id": "txn_001", "amount": "25.00"},
            correlation_id="corr_001",
            terminal_id="term_001"
        )

        # Mock successful response
        response = AsyncMock()
        response.status_code = 200
        response.text = '{"status": "received"}'
        response.headers = {}

        with patch.object(webhook_manager.http_client, 'post', return_value=response) as mock_post:
            await webhook_manager.deliver_event(event)

            # Verify payload structure
            call_args = mock_post.call_args
            payload = call_args.kwargs.get('json', {})

            assert payload['event_id'] == "evt_test_001"
            assert payload['event_type'] == WebhookEventType.PAYMENT_SUCCESSFUL.value
            assert payload['merchant_id'] == "mer_test_001"
            assert payload['data']['transaction_id'] == "txn_001"
            assert payload['correlation_id'] == "corr_001"
            assert payload['terminal_id'] == "term_001"
            assert payload['source'] == "softpos_api"
            assert payload['version'] == "1.0"


class TestWebhookRetryLogic:
    """Test webhook retry logic and error handling."""

    @pytest.fixture
    async def test_endpoint(self):
        """Create a test webhook endpoint."""
        event_types = {WebhookEventType.PAYMENT_SUCCESSFUL}

        return await webhook_manager.register_webhook_endpoint(
            merchant_id="mer_test_001",
            url="https://merchant.example.com/webhooks",
            event_types=event_types
        )

    @pytest.mark.webhook
    @pytest.mark.unit
    async def test_retry_exponential_backoff(self):
        """Test exponential backoff calculation for retries."""
        # Test retry delay calculation
        delay_0 = webhook_manager._calculate_next_retry(0)
        delay_1 = webhook_manager._calculate_next_retry(1)
        delay_2 = webhook_manager._calculate_next_retry(2)
        delay_3 = webhook_manager._calculate_next_retry(3)

        now = datetime.now(timezone.utc)

        # Each retry should have longer delay
        assert (delay_1 - now) > (delay_0 - now)
        assert (delay_2 - now) > (delay_1 - now)
        assert (delay_3 - now) > (delay_2 - now)

        # Should cap at maximum delay
        delay_10 = webhook_manager._calculate_next_retry(10)
        assert (delay_10 - now).total_seconds() <= 300  # Max 5 minutes

    @pytest.mark.webhook
    @pytest.mark.unit
    async def test_retry_processing(self, test_endpoint):
        """Test processing of failed deliveries for retry."""
        # Create a failed delivery ready for retry
        delivery = WebhookDelivery(
            delivery_id="del_test_001",
            event_id="evt_test_001",
            endpoint_id=test_endpoint.endpoint_id,
            status=WebhookStatus.RETRYING,
            url=test_endpoint.url,
            retry_count=1,
            next_retry_at=datetime.now(timezone.utc) - timedelta(seconds=1)  # Past due
        )

        webhook_manager.deliveries[delivery.delivery_id] = delivery

        # Create mock event
        event = WebhookEvent(
            event_id="evt_test_001",
            merchant_id="mer_test_001",
            event_type=WebhookEventType.PAYMENT_SUCCESSFUL,
            data={"test": True}
        )

        # Mock successful retry
        response = AsyncMock()
        response.status_code = 200
        response.text = '{"status": "received"}'
        response.headers = {}

        with patch.object(webhook_manager.http_client, 'post', return_value=response):
            with patch.object(webhook_manager, '_find_event_by_id', return_value=event):
                await webhook_manager.retry_failed_deliveries()

        # Delivery should now be successful
        assert delivery.status == WebhookStatus.DELIVERED

    @pytest.mark.webhook
    @pytest.mark.unit
    async def test_max_retries_exceeded(self, test_endpoint):
        """Test abandoning delivery after max retries."""
        # Create delivery that has exceeded max retries
        delivery = WebhookDelivery(
            delivery_id="del_test_001",
            event_id="evt_test_001",
            endpoint_id=test_endpoint.endpoint_id,
            status=WebhookStatus.RETRYING,
            url=test_endpoint.url,
            retry_count=3,  # At max retries
            next_retry_at=datetime.now(timezone.utc) - timedelta(seconds=1)
        )

        webhook_manager.deliveries[delivery.delivery_id] = delivery

        # Create mock event
        event = WebhookEvent(
            event_id="evt_test_001",
            merchant_id="mer_test_001",
            event_type=WebhookEventType.PAYMENT_SUCCESSFUL,
            data={"test": True}
        )

        # Mock continued failure
        response = AsyncMock()
        response.status_code = 500
        response.text = "Still failing"
        response.headers = {}

        with patch.object(webhook_manager.http_client, 'post', return_value=response):
            with patch.object(webhook_manager, '_find_event_by_id', return_value=event):
                await webhook_manager.retry_failed_deliveries()

        # Delivery should be abandoned
        assert delivery.status == WebhookStatus.ABANDONED


class TestWebhookCircuitBreaker:
    """Test webhook circuit breaker functionality."""

    @pytest.fixture
    async def test_endpoint(self):
        """Create a test webhook endpoint."""
        event_types = {WebhookEventType.PAYMENT_SUCCESSFUL}

        return await webhook_manager.register_webhook_endpoint(
            merchant_id="mer_test_001",
            url="https://merchant.example.com/webhooks",
            event_types=event_types
        )

    @pytest.mark.webhook
    @pytest.mark.unit
    async def test_circuit_breaker_opens_after_failures(self, test_endpoint):
        """Test that circuit breaker opens after consecutive failures."""
        # Record multiple failures
        for _ in range(5):
            webhook_manager._record_circuit_breaker_failure(test_endpoint.endpoint_id)

        # Circuit breaker should be open
        breaker = webhook_manager.circuit_breakers[test_endpoint.endpoint_id]
        assert breaker["state"] == "open"
        assert breaker["failure_count"] == 5

    @pytest.mark.webhook
    @pytest.mark.unit
    async def test_circuit_breaker_blocks_requests_when_open(self, test_endpoint):
        """Test that open circuit breaker blocks delivery attempts."""
        # Open the circuit breaker
        webhook_manager.circuit_breakers[test_endpoint.endpoint_id]["state"] = "open"

        # Create test event
        event = WebhookEvent(
            event_id="evt_test_001",
            merchant_id="mer_test_001",
            event_type=WebhookEventType.PAYMENT_SUCCESSFUL,
            data={"test": True}
        )

        # Attempt delivery
        deliveries = await webhook_manager.deliver_event(event)

        # Should not attempt delivery (empty list)
        assert len(deliveries) == 0

    @pytest.mark.webhook
    @pytest.mark.unit
    async def test_circuit_breaker_resets_on_success(self, test_endpoint):
        """Test that circuit breaker resets on successful delivery."""
        # Set some failures
        webhook_manager.circuit_breakers[test_endpoint.endpoint_id]["failure_count"] = 3

        # Record success
        webhook_manager._record_circuit_breaker_success(test_endpoint.endpoint_id)

        # Circuit breaker should be reset
        breaker = webhook_manager.circuit_breakers[test_endpoint.endpoint_id]
        assert breaker["state"] == "closed"
        assert breaker["failure_count"] == 0

    @pytest.mark.webhook
    @pytest.mark.unit
    async def test_circuit_breaker_half_open_recovery(self, test_endpoint):
        """Test circuit breaker half-open state and recovery."""
        # Set circuit breaker to open with recovery time in past
        breaker = webhook_manager.circuit_breakers[test_endpoint.endpoint_id]
        breaker["state"] = "open"
        breaker["next_attempt"] = datetime.now(timezone.utc) - timedelta(seconds=1)

        # Run recovery process
        await webhook_manager._circuit_breaker_recovery()

        # Should move to half-open state
        assert breaker["state"] == "half_open"


class TestWebhookRateLimiting:
    """Test webhook rate limiting functionality."""

    @pytest.fixture
    async def test_endpoint(self):
        """Create a test webhook endpoint."""
        event_types = {WebhookEventType.PAYMENT_SUCCESSFUL}

        return await webhook_manager.register_webhook_endpoint(
            merchant_id="mer_test_001",
            url="https://merchant.example.com/webhooks",
            event_types=event_types
        )

    @pytest.mark.webhook
    @pytest.mark.unit
    async def test_rate_limit_allows_normal_traffic(self, test_endpoint):
        """Test that rate limiting allows normal traffic levels."""
        # Should allow normal request rate
        for _ in range(10):
            allowed = webhook_manager._check_rate_limit(test_endpoint.endpoint_id)
            assert allowed is True

            # Update rate limit tracking
            webhook_manager._update_rate_limit(test_endpoint.endpoint_id)

    @pytest.mark.webhook
    @pytest.mark.unit
    async def test_rate_limit_blocks_excessive_traffic(self, test_endpoint):
        """Test that rate limiting blocks excessive traffic."""
        # Simulate excessive requests (more than 100 per minute)
        for _ in range(100):
            webhook_manager._update_rate_limit(test_endpoint.endpoint_id)

        # Next request should be blocked
        allowed = webhook_manager._check_rate_limit(test_endpoint.endpoint_id)
        assert allowed is False

    @pytest.mark.webhook
    @pytest.mark.unit
    async def test_rate_limit_window_reset(self, test_endpoint):
        """Test that rate limit window resets over time."""
        # Fill up rate limit
        for _ in range(100):
            webhook_manager._update_rate_limit(test_endpoint.endpoint_id)

        # Should be blocked
        assert webhook_manager._check_rate_limit(test_endpoint.endpoint_id) is False

        # Simulate time passing (in real implementation, old timestamps would be cleaned)
        webhook_manager.rate_limits[test_endpoint.endpoint_id] = []

        # Should be allowed again
        assert webhook_manager._check_rate_limit(test_endpoint.endpoint_id) is True


class TestWebhookAnalytics:
    """Test webhook analytics and monitoring."""

    @pytest.fixture
    async def test_endpoint_with_deliveries(self):
        """Create endpoint with some delivery history."""
        event_types = {WebhookEventType.PAYMENT_SUCCESSFUL}

        endpoint = await webhook_manager.register_webhook_endpoint(
            merchant_id="mer_test_001",
            url="https://merchant.example.com/webhooks",
            event_types=event_types
        )

        # Create some mock deliveries
        base_time = datetime.now(timezone.utc)

        for i in range(10):
            delivery = WebhookDelivery(
                delivery_id=f"del_test_{i:03d}",
                event_id=f"evt_test_{i:03d}",
                endpoint_id=endpoint.endpoint_id,
                status=WebhookStatus.DELIVERED if i < 8 else WebhookStatus.FAILED,
                url=endpoint.url,
                sent_at=base_time - timedelta(hours=i),
                completed_at=base_time - timedelta(hours=i) + timedelta(milliseconds=150),
                duration_ms=150,
                response_status=200 if i < 8 else 500
            )

            webhook_manager.deliveries[delivery.delivery_id] = delivery

        return endpoint

    @pytest.mark.webhook
    @pytest.mark.unit
    async def test_webhook_analytics_calculation(self, test_endpoint_with_deliveries):
        """Test webhook analytics calculation."""
        analytics = await webhook_manager.get_webhook_analytics(
            merchant_id="mer_test_001"
        )

        assert "overview" in analytics
        assert "endpoint_performance" in analytics

        overview = analytics["overview"]
        assert overview["total_deliveries"] == 10
        assert overview["successful_deliveries"] == 8
        assert overview["failed_deliveries"] == 2
        assert overview["success_rate"] == "80.00%"
        assert float(overview["average_delivery_time_ms"]) == 150.0

    @pytest.mark.webhook
    @pytest.mark.unit
    async def test_webhook_analytics_date_filtering(self, test_endpoint_with_deliveries):
        """Test webhook analytics with date filtering."""
        # Get analytics for last 5 hours only
        start_date = datetime.now(timezone.utc) - timedelta(hours=5)

        analytics = await webhook_manager.get_webhook_analytics(
            merchant_id="mer_test_001",
            start_date=start_date
        )

        # Should only include deliveries from last 5 hours
        overview = analytics["overview"]
        assert overview["total_deliveries"] <= 6  # 5 hours + current

    @pytest.mark.webhook
    @pytest.mark.unit
    async def test_webhook_analytics_endpoint_performance(self, test_endpoint_with_deliveries):
        """Test endpoint-specific performance analytics."""
        analytics = await webhook_manager.get_webhook_analytics(
            merchant_id="mer_test_001"
        )

        endpoint_performance = analytics["endpoint_performance"]
        assert test_endpoint_with_deliveries.endpoint_id in endpoint_performance

        endpoint_stats = endpoint_performance[test_endpoint_with_deliveries.endpoint_id]
        assert endpoint_stats["total"] == 10
        assert endpoint_stats["successful"] == 8
        assert endpoint_stats["failed"] == 2
        assert endpoint_stats["success_rate"] == 0.8


class TestWebhookSecurity:
    """Test webhook security features."""

    @pytest.mark.webhook
    @pytest.mark.security
    async def test_webhook_signature_validation(self):
        """Test webhook signature generation and validation."""
        payload = '{"event_id": "evt_001", "data": {"test": true}}'
        secret = "test_secret_key"

        signature = webhook_manager._generate_signature(payload, secret)

        assert signature.startswith("sha256=")
        assert len(signature) == 71  # "sha256=" (7) + 64 hex chars

        # Same payload and secret should generate same signature
        signature2 = webhook_manager._generate_signature(payload, secret)
        assert signature == signature2

        # Different payload should generate different signature
        different_payload = '{"event_id": "evt_002", "data": {"test": false}}'
        different_signature = webhook_manager._generate_signature(different_payload, secret)
        assert signature != different_signature

    @pytest.mark.webhook
    @pytest.mark.security
    async def test_secret_key_generation(self):
        """Test secure secret key generation."""
        secret1 = webhook_manager._generate_secret_key()
        secret2 = webhook_manager._generate_secret_key()

        # Should be different each time
        assert secret1 != secret2

        # Should be proper length (32 bytes = 64 hex chars)
        assert len(secret1) == 64
        assert len(secret2) == 64

        # Should be valid hex
        int(secret1, 16)  # Should not raise exception
        int(secret2, 16)  # Should not raise exception

    @pytest.mark.webhook
    @pytest.mark.security
    async def test_webhook_headers_security(self):
        """Test security-related headers in webhook requests."""
        event_types = {WebhookEventType.PAYMENT_SUCCESSFUL}

        endpoint = await webhook_manager.register_webhook_endpoint(
            merchant_id="mer_test_001",
            url="https://merchant.example.com/webhooks",
            event_types=event_types
        )

        event = WebhookEvent(
            event_id="evt_test_001",
            merchant_id="mer_test_001",
            event_type=WebhookEventType.PAYMENT_SUCCESSFUL,
            data={"test": True}
        )

        # Mock successful response
        response = AsyncMock()
        response.status_code = 200
        response.text = '{"status": "received"}'
        response.headers = {}

        with patch.object(webhook_manager.http_client, 'post', return_value=response) as mock_post:
            await webhook_manager.deliver_event(event)

            # Verify security headers
            call_args = mock_post.call_args
            headers = call_args.kwargs.get('headers', {})

            assert 'X-Webhook-Signature' in headers
            assert 'X-Webhook-Event-ID' in headers
            assert 'X-Webhook-Delivery-ID' in headers
            assert 'X-Webhook-Timestamp' in headers
            assert headers['User-Agent'] == "SoftPOS-Webhooks/1.0"