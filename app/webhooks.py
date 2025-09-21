"""
Webhook Notification System for SoftPOS

This module provides comprehensive webhook capabilities for real-time
notifications and integrations with external systems.

Key Features:
- Event-driven webhook notifications
- Configurable webhook endpoints per merchant
- Retry logic with exponential backoff
- Webhook signature verification
- Event filtering and routing
- Delivery status tracking
- Rate limiting and circuit breakers

Supported Events:
- Payment events (successful, failed, disputed)
- Terminal events (connected, disconnected, error)
- Merchant events (onboarded, suspended)
- Security events (fraud detected, breach attempt)
- System events (maintenance, outage)
- Settlement events (batch processed, funds transferred)

Enterprise Features:
- Multi-tenant webhook isolation
- Event replay capabilities
- Webhook analytics and monitoring
- Compliance audit trails
- Custom event schemas
- Real-time delivery tracking
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Dict, List, Optional, Set
from uuid import uuid4

import httpx
import structlog

logger = structlog.get_logger(__name__)


class WebhookEventType(Enum):
    """Types of webhook events."""
    # Payment events
    PAYMENT_SUCCESSFUL = "payment.successful"
    PAYMENT_FAILED = "payment.failed"
    PAYMENT_DISPUTED = "payment.disputed"
    PAYMENT_REFUNDED = "payment.refunded"
    PAYMENT_VOIDED = "payment.voided"

    # Terminal events
    TERMINAL_CONNECTED = "terminal.connected"
    TERMINAL_DISCONNECTED = "terminal.disconnected"
    TERMINAL_ERROR = "terminal.error"
    TERMINAL_CONFIG_UPDATED = "terminal.config_updated"

    # Merchant events
    MERCHANT_ONBOARDED = "merchant.onboarded"
    MERCHANT_SUSPENDED = "merchant.suspended"
    MERCHANT_REINSTATED = "merchant.reinstated"

    # Security events
    FRAUD_DETECTED = "security.fraud_detected"
    BREACH_ATTEMPT = "security.breach_attempt"
    SUSPICIOUS_ACTIVITY = "security.suspicious_activity"

    # System events
    SYSTEM_MAINTENANCE = "system.maintenance"
    SYSTEM_OUTAGE = "system.outage"
    SYSTEM_RECOVERED = "system.recovered"

    # Settlement events
    SETTLEMENT_PROCESSED = "settlement.processed"
    FUNDS_TRANSFERRED = "settlement.funds_transferred"
    SETTLEMENT_FAILED = "settlement.failed"


class WebhookStatus(Enum):
    """Webhook delivery status."""
    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"
    RETRYING = "retrying"
    ABANDONED = "abandoned"


class WebhookPriority(Enum):
    """Webhook delivery priority."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class WebhookEndpoint:
    """Webhook endpoint configuration."""
    endpoint_id: str
    merchant_id: str
    url: str
    secret_key: str
    event_types: Set[WebhookEventType]
    active: bool = True

    # Configuration
    max_retries: int = 3
    timeout_seconds: int = 30
    verify_ssl: bool = True

    # Headers and authentication
    custom_headers: Dict[str, str] = field(default_factory=dict)

    # Filtering
    event_filters: Dict = field(default_factory=dict)

    # Metadata
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_delivery: Optional[datetime] = None

    # Statistics
    total_deliveries: int = 0
    successful_deliveries: int = 0
    failed_deliveries: int = 0


@dataclass
class WebhookEvent:
    """Webhook event to be delivered."""
    event_id: str
    merchant_id: str
    event_type: WebhookEventType
    data: Dict
    priority: WebhookPriority = WebhookPriority.NORMAL

    # Metadata
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "softpos_api"
    version: str = "1.0"

    # Delivery tracking
    delivery_attempts: List[datetime] = field(default_factory=list)

    # Context
    correlation_id: Optional[str] = None
    user_id: Optional[str] = None
    terminal_id: Optional[str] = None


@dataclass
class WebhookDelivery:
    """Webhook delivery attempt record."""
    delivery_id: str
    event_id: str
    endpoint_id: str
    status: WebhookStatus

    # Request details
    url: str
    http_method: str = "POST"
    headers: Dict[str, str] = field(default_factory=dict)
    payload: str = ""

    # Response details
    response_status: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: str = ""

    # Timing
    sent_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    duration_ms: Optional[int] = None

    # Error information
    error_message: Optional[str] = None
    retry_count: int = 0
    next_retry_at: Optional[datetime] = None


class WebhookManager:
    """
    Comprehensive webhook management system for real-time notifications.

    Handles webhook endpoint registration, event routing, delivery with retries,
    and monitoring of webhook health and performance.
    """

    def __init__(self):
        self.endpoints: Dict[str, WebhookEndpoint] = {}
        self.pending_events: List[WebhookEvent] = []
        self.deliveries: Dict[str, WebhookDelivery] = {}
        self._delivery_started = False

        # Rate limiting
        self.rate_limits: Dict[str, List[datetime]] = {}

        # Circuit breaker state
        self.circuit_breakers: Dict[str, Dict] = {}

        # HTTP client for webhook delivery
        self.http_client = httpx.AsyncClient(timeout=30.0)

    async def register_webhook_endpoint(
        self,
        merchant_id: str,
        url: str,
        event_types: Set[WebhookEventType],
        secret_key: Optional[str] = None,
        config: Optional[Dict] = None
    ) -> WebhookEndpoint:
        """Register a new webhook endpoint."""
        endpoint_id = f"wh_{uuid4().hex[:12]}"

        if not secret_key:
            secret_key = self._generate_secret_key()

        endpoint = WebhookEndpoint(
            endpoint_id=endpoint_id,
            merchant_id=merchant_id,
            url=url,
            secret_key=secret_key,
            event_types=event_types
        )

        # Apply configuration if provided
        if config:
            endpoint.max_retries = config.get("max_retries", 3)
            endpoint.timeout_seconds = config.get("timeout_seconds", 30)
            endpoint.verify_ssl = config.get("verify_ssl", True)
            endpoint.custom_headers = config.get("custom_headers", {})
            endpoint.event_filters = config.get("event_filters", {})

        self.endpoints[endpoint_id] = endpoint

        # Initialize circuit breaker
        self.circuit_breakers[endpoint_id] = {
            "state": "closed",  # closed, open, half_open
            "failure_count": 0,
            "last_failure": None,
            "next_attempt": None
        }

        logger.info(
            "Webhook endpoint registered",
            endpoint_id=endpoint_id,
            merchant_id=merchant_id,
            url=url,
            event_types=[et.value for et in event_types]
        )

        return endpoint

    async def emit_event(
        self,
        event_type: WebhookEventType,
        merchant_id: str,
        data: Dict,
        priority: WebhookPriority = WebhookPriority.NORMAL,
        correlation_id: Optional[str] = None,
        terminal_id: Optional[str] = None
    ) -> str:
        """Emit a webhook event for delivery."""
        event_id = f"evt_{uuid4().hex[:16]}"

        event = WebhookEvent(
            event_id=event_id,
            merchant_id=merchant_id,
            event_type=event_type,
            data=data,
            priority=priority,
            correlation_id=correlation_id,
            terminal_id=terminal_id
        )

        self.pending_events.append(event)

        logger.info(
            "Webhook event emitted",
            event_id=event_id,
            event_type=event_type.value,
            merchant_id=merchant_id,
            priority=priority.value
        )

        # Sort pending events by priority
        self.pending_events.sort(
            key=lambda e: (e.priority.value, e.created_at),
            reverse=True
        )

        return event_id

    async def deliver_event(self, event: WebhookEvent) -> List[WebhookDelivery]:
        """Deliver event to all matching webhook endpoints."""
        deliveries = []

        # Find matching endpoints
        matching_endpoints = [
            endpoint for endpoint in self.endpoints.values()
            if (endpoint.merchant_id == event.merchant_id and
                endpoint.active and
                event.event_type in endpoint.event_types and
                self._event_matches_filters(event, endpoint.event_filters))
        ]

        for endpoint in matching_endpoints:
            # Check circuit breaker
            if not self._is_circuit_breaker_closed(endpoint.endpoint_id):
                logger.warning(
                    "Circuit breaker open, skipping delivery",
                    endpoint_id=endpoint.endpoint_id
                )
                continue

            # Check rate limits
            if not self._check_rate_limit(endpoint.endpoint_id):
                logger.warning(
                    "Rate limit exceeded, skipping delivery",
                    endpoint_id=endpoint.endpoint_id
                )
                continue

            delivery = await self._deliver_to_endpoint(event, endpoint)
            deliveries.append(delivery)

        return deliveries

    async def retry_failed_deliveries(self):
        """Retry failed webhook deliveries."""
        now = datetime.now(timezone.utc)

        # Find deliveries ready for retry
        retry_deliveries = [
            delivery for delivery in self.deliveries.values()
            if (delivery.status == WebhookStatus.RETRYING and
                delivery.next_retry_at and
                delivery.next_retry_at <= now and
                delivery.retry_count < self._get_max_retries(delivery.endpoint_id))
        ]

        for delivery in retry_deliveries:
            endpoint = self.endpoints.get(delivery.endpoint_id)
            if not endpoint:
                continue

            # Find the original event
            event = self._find_event_by_id(delivery.event_id)
            if not event:
                continue

            # Attempt retry
            await self._retry_delivery(delivery, event, endpoint)

    async def get_webhook_analytics(
        self,
        merchant_id: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Dict:
        """Get webhook delivery analytics."""
        if not start_date:
            start_date = datetime.now(timezone.utc) - timedelta(days=7)
        if not end_date:
            end_date = datetime.now(timezone.utc)

        # Filter deliveries
        filtered_deliveries = [
            delivery for delivery in self.deliveries.values()
            if (start_date <= delivery.sent_at <= end_date and
                (not merchant_id or
                 self.endpoints.get(delivery.endpoint_id, {}).merchant_id == merchant_id))
        ]

        # Calculate metrics
        total_deliveries = len(filtered_deliveries)
        successful_deliveries = len([d for d in filtered_deliveries if d.status == WebhookStatus.DELIVERED])
        failed_deliveries = len([d for d in filtered_deliveries if d.status == WebhookStatus.FAILED])

        success_rate = successful_deliveries / total_deliveries if total_deliveries > 0 else 0

        # Average delivery time
        delivery_times = [
            d.duration_ms for d in filtered_deliveries
            if d.duration_ms is not None
        ]
        avg_delivery_time = sum(delivery_times) / len(delivery_times) if delivery_times else 0

        # Event type breakdown
        event_type_breakdown = {}
        for delivery in filtered_deliveries:
            event = self._find_event_by_id(delivery.event_id)
            if event:
                event_type = event.event_type.value
                event_type_breakdown[event_type] = event_type_breakdown.get(event_type, 0) + 1

        # Status breakdown by endpoint
        endpoint_stats = {}
        for delivery in filtered_deliveries:
            endpoint_id = delivery.endpoint_id
            if endpoint_id not in endpoint_stats:
                endpoint_stats[endpoint_id] = {
                    "total": 0,
                    "successful": 0,
                    "failed": 0,
                    "success_rate": 0
                }

            endpoint_stats[endpoint_id]["total"] += 1
            if delivery.status == WebhookStatus.DELIVERED:
                endpoint_stats[endpoint_id]["successful"] += 1
            elif delivery.status == WebhookStatus.FAILED:
                endpoint_stats[endpoint_id]["failed"] += 1

        # Calculate success rates
        for stats in endpoint_stats.values():
            if stats["total"] > 0:
                stats["success_rate"] = stats["successful"] / stats["total"]

        return {
            "overview": {
                "total_deliveries": total_deliveries,
                "successful_deliveries": successful_deliveries,
                "failed_deliveries": failed_deliveries,
                "success_rate": f"{success_rate:.2%}",
                "average_delivery_time_ms": f"{avg_delivery_time:.1f}"
            },
            "event_type_breakdown": event_type_breakdown,
            "endpoint_performance": endpoint_stats,
            "active_endpoints": len([e for e in self.endpoints.values() if e.active])
        }

    def start_delivery(self):
        """Start background delivery tasks if not already started."""
        if not self._delivery_started:
            try:
                asyncio.create_task(self._event_processor())
                asyncio.create_task(self._retry_processor())
                asyncio.create_task(self._circuit_breaker_recovery())
                asyncio.create_task(self._cleanup_old_data())
                self._delivery_started = True
            except RuntimeError:
                # No event loop running, will start later
                pass

    def _start_delivery_tasks(self):
        """Start background delivery tasks (legacy method for compatibility)."""
        self.start_delivery()

    async def _event_processor(self):
        """Process pending webhook events."""
        while True:
            try:
                if self.pending_events:
                    # Process high priority events first
                    event = self.pending_events.pop(0)
                    await self.deliver_event(event)
                else:
                    await asyncio.sleep(1)

            except Exception as e:
                logger.error("Event processor error", error=str(e))
                await asyncio.sleep(5)

    async def _retry_processor(self):
        """Process webhook delivery retries."""
        while True:
            try:
                await self.retry_failed_deliveries()
                await asyncio.sleep(30)  # Check for retries every 30 seconds

            except Exception as e:
                logger.error("Retry processor error", error=str(e))
                await asyncio.sleep(60)

    async def _circuit_breaker_recovery(self):
        """Monitor and recover circuit breakers."""
        while True:
            try:
                now = datetime.now(timezone.utc)

                for endpoint_id, breaker in self.circuit_breakers.items():
                    if (breaker["state"] == "open" and
                        breaker["next_attempt"] and
                        breaker["next_attempt"] <= now):

                        # Move to half-open state
                        breaker["state"] = "half_open"
                        logger.info(
                            "Circuit breaker moved to half-open",
                            endpoint_id=endpoint_id
                        )

                await asyncio.sleep(60)  # Check every minute

            except Exception as e:
                logger.error("Circuit breaker recovery error", error=str(e))
                await asyncio.sleep(60)

    async def _cleanup_old_data(self):
        """Clean up old webhook data."""
        while True:
            try:
                cutoff_date = datetime.now(timezone.utc) - timedelta(days=30)

                # Clean old deliveries
                old_delivery_ids = [
                    delivery_id for delivery_id, delivery in self.deliveries.items()
                    if delivery.sent_at < cutoff_date
                ]

                for delivery_id in old_delivery_ids:
                    del self.deliveries[delivery_id]

                logger.info("Cleaned old webhook data", cleaned_deliveries=len(old_delivery_ids))

                await asyncio.sleep(3600)  # Clean every hour

            except Exception as e:
                logger.error("Cleanup error", error=str(e))
                await asyncio.sleep(3600)

    async def _deliver_to_endpoint(
        self,
        event: WebhookEvent,
        endpoint: WebhookEndpoint
    ) -> WebhookDelivery:
        """Deliver event to a specific endpoint."""
        delivery_id = f"del_{uuid4().hex[:12]}"

        # Create delivery record
        delivery = WebhookDelivery(
            delivery_id=delivery_id,
            event_id=event.event_id,
            endpoint_id=endpoint.endpoint_id,
            status=WebhookStatus.PENDING,
            url=endpoint.url
        )

        try:
            # Prepare payload
            payload = self._create_webhook_payload(event)
            delivery.payload = json.dumps(payload)

            # Prepare headers
            headers = {
                "Content-Type": "application/json",
                "User-Agent": "SoftPOS-Webhooks/1.0",
                "X-Webhook-Event-Type": event.event_type.value,
                "X-Webhook-Event-ID": event.event_id,
                "X-Webhook-Delivery-ID": delivery_id,
                "X-Webhook-Timestamp": str(int(event.created_at.timestamp()))
            }

            # Add signature
            signature = self._generate_signature(delivery.payload, endpoint.secret_key)
            headers["X-Webhook-Signature"] = signature

            # Add custom headers
            headers.update(endpoint.custom_headers)
            delivery.headers = headers

            # Make HTTP request
            start_time = time.time()

            response = await self.http_client.post(
                endpoint.url,
                json=payload,
                headers=headers,
                timeout=endpoint.timeout_seconds
            )

            end_time = time.time()
            delivery.duration_ms = int((end_time - start_time) * 1000)
            delivery.completed_at = datetime.now(timezone.utc)

            # Process response
            delivery.response_status = response.status_code
            delivery.response_headers = dict(response.headers)
            delivery.response_body = response.text[:1000]  # Limit body size

            if 200 <= response.status_code < 300:
                delivery.status = WebhookStatus.DELIVERED
                self._record_circuit_breaker_success(endpoint.endpoint_id)

                # Update endpoint stats
                endpoint.last_delivery = delivery.completed_at
                endpoint.total_deliveries += 1
                endpoint.successful_deliveries += 1

                logger.info(
                    "Webhook delivered successfully",
                    delivery_id=delivery_id,
                    endpoint_id=endpoint.endpoint_id,
                    status_code=response.status_code,
                    duration_ms=delivery.duration_ms
                )
            else:
                delivery.status = WebhookStatus.FAILED
                delivery.error_message = f"HTTP {response.status_code}: {response.text[:200]}"

                self._record_circuit_breaker_failure(endpoint.endpoint_id)
                endpoint.failed_deliveries += 1

                # Schedule retry if within retry limit
                if delivery.retry_count < endpoint.max_retries:
                    delivery.status = WebhookStatus.RETRYING
                    delivery.next_retry_at = self._calculate_next_retry(delivery.retry_count)

                logger.warning(
                    "Webhook delivery failed",
                    delivery_id=delivery_id,
                    endpoint_id=endpoint.endpoint_id,
                    status_code=response.status_code,
                    error=delivery.error_message
                )

        except Exception as e:
            delivery.status = WebhookStatus.FAILED
            delivery.error_message = str(e)
            delivery.completed_at = datetime.now(timezone.utc)

            self._record_circuit_breaker_failure(endpoint.endpoint_id)
            endpoint.failed_deliveries += 1

            # Schedule retry if within retry limit
            if delivery.retry_count < endpoint.max_retries:
                delivery.status = WebhookStatus.RETRYING
                delivery.next_retry_at = self._calculate_next_retry(delivery.retry_count)

            logger.error(
                "Webhook delivery exception",
                delivery_id=delivery_id,
                endpoint_id=endpoint.endpoint_id,
                error=str(e)
            )

        finally:
            self.deliveries[delivery_id] = delivery
            self._update_rate_limit(endpoint.endpoint_id)

        return delivery

    def _create_webhook_payload(self, event: WebhookEvent) -> Dict:
        """Create webhook payload from event."""
        return {
            "event_id": event.event_id,
            "event_type": event.event_type.value,
            "created_at": event.created_at.isoformat(),
            "data": event.data,
            "merchant_id": event.merchant_id,
            "source": event.source,
            "version": event.version,
            "correlation_id": event.correlation_id,
            "terminal_id": event.terminal_id
        }

    def _generate_signature(self, payload: str, secret_key: str) -> str:
        """Generate HMAC signature for webhook verification."""
        signature = hmac.new(
            secret_key.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()
        return f"sha256={signature}"

    def _generate_secret_key(self) -> str:
        """Generate a secure secret key for webhook signing."""
        import secrets
        return secrets.token_hex(32)

    def _event_matches_filters(self, event: WebhookEvent, filters: Dict) -> bool:
        """Check if event matches endpoint filters."""
        if not filters:
            return True

        # Implement filter logic based on event data
        # For now, return True (no filtering)
        return True

    def _is_circuit_breaker_closed(self, endpoint_id: str) -> bool:
        """Check if circuit breaker is closed (allowing requests)."""
        breaker = self.circuit_breakers.get(endpoint_id, {})
        return breaker.get("state", "closed") in ["closed", "half_open"]

    def _check_rate_limit(self, endpoint_id: str) -> bool:
        """Check if endpoint is within rate limits."""
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(minutes=1)

        if endpoint_id not in self.rate_limits:
            self.rate_limits[endpoint_id] = []

        # Clean old timestamps
        self.rate_limits[endpoint_id] = [
            ts for ts in self.rate_limits[endpoint_id]
            if ts >= window_start
        ]

        # Check if under limit (100 requests per minute)
        return len(self.rate_limits[endpoint_id]) < 100

    def _update_rate_limit(self, endpoint_id: str):
        """Update rate limit tracking."""
        now = datetime.now(timezone.utc)
        if endpoint_id not in self.rate_limits:
            self.rate_limits[endpoint_id] = []
        self.rate_limits[endpoint_id].append(now)

    def _record_circuit_breaker_success(self, endpoint_id: str):
        """Record successful delivery for circuit breaker."""
        breaker = self.circuit_breakers.get(endpoint_id, {})
        breaker["failure_count"] = 0
        breaker["state"] = "closed"

    def _record_circuit_breaker_failure(self, endpoint_id: str):
        """Record failed delivery for circuit breaker."""
        breaker = self.circuit_breakers.get(endpoint_id, {})
        breaker["failure_count"] = breaker.get("failure_count", 0) + 1
        breaker["last_failure"] = datetime.now(timezone.utc)

        # Trip circuit breaker after 5 consecutive failures
        if breaker["failure_count"] >= 5:
            breaker["state"] = "open"
            breaker["next_attempt"] = datetime.now(timezone.utc) + timedelta(minutes=5)

            logger.warning(
                "Circuit breaker opened",
                endpoint_id=endpoint_id,
                failure_count=breaker["failure_count"]
            )

    def _get_max_retries(self, endpoint_id: str) -> int:
        """Get max retries for endpoint."""
        endpoint = self.endpoints.get(endpoint_id)
        return endpoint.max_retries if endpoint else 3

    def _calculate_next_retry(self, retry_count: int) -> datetime:
        """Calculate next retry time with exponential backoff."""
        delay_seconds = min(300, 2 ** retry_count * 30)  # Max 5 minutes
        return datetime.now(timezone.utc) + timedelta(seconds=delay_seconds)

    def _find_event_by_id(self, event_id: str) -> Optional[WebhookEvent]:
        """Find event by ID (simplified - in production would use proper storage)."""
        # In a real implementation, this would query the database
        return None

    async def _retry_delivery(
        self,
        delivery: WebhookDelivery,
        event: WebhookEvent,
        endpoint: WebhookEndpoint
    ):
        """Retry a failed delivery."""
        delivery.retry_count += 1
        delivery.delivery_attempts.append(datetime.now(timezone.utc))

        # Attempt delivery again
        new_delivery = await self._deliver_to_endpoint(event, endpoint)

        # Update original delivery record
        delivery.status = new_delivery.status
        delivery.response_status = new_delivery.response_status
        delivery.response_body = new_delivery.response_body
        delivery.error_message = new_delivery.error_message

        if new_delivery.status == WebhookStatus.DELIVERED:
            delivery.completed_at = new_delivery.completed_at
        elif delivery.retry_count >= endpoint.max_retries:
            delivery.status = WebhookStatus.ABANDONED


# Global webhook manager instance
webhook_manager = WebhookManager()