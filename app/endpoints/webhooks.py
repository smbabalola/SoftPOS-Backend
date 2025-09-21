"""
Webhook Management API Endpoints

RESTful API for managing webhook endpoints, events, and delivery monitoring.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import CurrentUser, require_payments_create, require_payments_read
from ..webhooks import (
    webhook_manager,
    WebhookEventType,
    WebhookPriority,
    WebhookStatus
)

router = APIRouter(prefix="/v1/webhooks", tags=["Webhook Management"])


class WebhookEndpointRequest(BaseModel):
    """Request model for webhook endpoint registration."""
    url: HttpUrl = Field(..., description="Webhook endpoint URL")
    event_types: Set[str] = Field(..., description="Event types to subscribe to")
    secret_key: Optional[str] = Field(None, description="Webhook secret key (auto-generated if not provided)")
    max_retries: int = Field(3, ge=0, le=10, description="Maximum delivery retries")
    timeout_seconds: int = Field(30, ge=5, le=300, description="Request timeout in seconds")
    verify_ssl: bool = Field(True, description="Verify SSL certificates")
    custom_headers: Optional[Dict[str, str]] = Field(default_factory=dict, description="Custom HTTP headers")
    event_filters: Optional[Dict] = Field(default_factory=dict, description="Event filtering rules")


class WebhookEventRequest(BaseModel):
    """Request model for emitting webhook events."""
    event_type: str = Field(..., description="Event type")
    data: Dict = Field(..., description="Event data payload")
    priority: str = Field("normal", description="Event priority")
    correlation_id: Optional[str] = Field(None, description="Correlation ID for tracking")
    terminal_id: Optional[str] = Field(None, description="Associated terminal ID")


class WebhookEndpointResponse(BaseModel):
    """Response model for webhook endpoint information."""
    endpoint_id: str
    merchant_id: str
    url: str
    event_types: List[str]
    active: bool
    max_retries: int
    timeout_seconds: int
    verify_ssl: bool
    created_at: str
    updated_at: str
    last_delivery: Optional[str]
    total_deliveries: int
    successful_deliveries: int
    failed_deliveries: int
    success_rate: str


class WebhookDeliveryResponse(BaseModel):
    """Response model for webhook delivery information."""
    delivery_id: str
    event_id: str
    endpoint_id: str
    status: str
    url: str
    response_status: Optional[int]
    sent_at: str
    completed_at: Optional[str]
    duration_ms: Optional[int]
    error_message: Optional[str]
    retry_count: int


@router.post("/endpoints", response_model=WebhookEndpointResponse, status_code=201)
async def register_webhook_endpoint(
    request: WebhookEndpointRequest,
    current_user: CurrentUser = Depends(require_payments_create)
):
    """Register a new webhook endpoint."""
    try:
        # Validate event types
        event_types = set()
        for event_type_str in request.event_types:
            try:
                event_type = WebhookEventType(event_type_str)
                event_types.add(event_type)
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid event type: {event_type_str}"
                )

        # Prepare configuration
        config = {
            "max_retries": request.max_retries,
            "timeout_seconds": request.timeout_seconds,
            "verify_ssl": request.verify_ssl,
            "custom_headers": request.custom_headers,
            "event_filters": request.event_filters
        }

        # Register endpoint
        endpoint = await webhook_manager.register_webhook_endpoint(
            merchant_id=current_user.merchant_id,
            url=str(request.url),
            event_types=event_types,
            secret_key=request.secret_key,
            config=config
        )

        success_rate = 0.0
        if endpoint.total_deliveries > 0:
            success_rate = endpoint.successful_deliveries / endpoint.total_deliveries

        return WebhookEndpointResponse(
            endpoint_id=endpoint.endpoint_id,
            merchant_id=endpoint.merchant_id,
            url=endpoint.url,
            event_types=[et.value for et in endpoint.event_types],
            active=endpoint.active,
            max_retries=endpoint.max_retries,
            timeout_seconds=endpoint.timeout_seconds,
            verify_ssl=endpoint.verify_ssl,
            created_at=endpoint.created_at.isoformat(),
            updated_at=endpoint.updated_at.isoformat(),
            last_delivery=endpoint.last_delivery.isoformat() if endpoint.last_delivery else None,
            total_deliveries=endpoint.total_deliveries,
            successful_deliveries=endpoint.successful_deliveries,
            failed_deliveries=endpoint.failed_deliveries,
            success_rate=f"{success_rate:.2%}"
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/endpoints", response_model=List[WebhookEndpointResponse])
async def list_webhook_endpoints(
    current_user: CurrentUser = Depends(require_payments_read)
):
    """List all webhook endpoints for the merchant."""
    endpoints = [
        endpoint for endpoint in webhook_manager.endpoints.values()
        if endpoint.merchant_id == current_user.merchant_id
    ]

    return [
        WebhookEndpointResponse(
            endpoint_id=endpoint.endpoint_id,
            merchant_id=endpoint.merchant_id,
            url=endpoint.url,
            event_types=[et.value for et in endpoint.event_types],
            active=endpoint.active,
            max_retries=endpoint.max_retries,
            timeout_seconds=endpoint.timeout_seconds,
            verify_ssl=endpoint.verify_ssl,
            created_at=endpoint.created_at.isoformat(),
            updated_at=endpoint.updated_at.isoformat(),
            last_delivery=endpoint.last_delivery.isoformat() if endpoint.last_delivery else None,
            total_deliveries=endpoint.total_deliveries,
            successful_deliveries=endpoint.successful_deliveries,
            failed_deliveries=endpoint.failed_deliveries,
            success_rate=f"{endpoint.successful_deliveries / endpoint.total_deliveries:.2%}" if endpoint.total_deliveries > 0 else "0%"
        )
        for endpoint in endpoints
    ]


@router.get("/endpoints/{endpoint_id}", response_model=WebhookEndpointResponse)
async def get_webhook_endpoint(
    endpoint_id: str,
    current_user: CurrentUser = Depends(require_payments_read)
):
    """Get webhook endpoint details."""
    if endpoint_id not in webhook_manager.endpoints:
        raise HTTPException(status_code=404, detail="Webhook endpoint not found")

    endpoint = webhook_manager.endpoints[endpoint_id]
    if endpoint.merchant_id != current_user.merchant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    success_rate = 0.0
    if endpoint.total_deliveries > 0:
        success_rate = endpoint.successful_deliveries / endpoint.total_deliveries

    return WebhookEndpointResponse(
        endpoint_id=endpoint.endpoint_id,
        merchant_id=endpoint.merchant_id,
        url=endpoint.url,
        event_types=[et.value for et in endpoint.event_types],
        active=endpoint.active,
        max_retries=endpoint.max_retries,
        timeout_seconds=endpoint.timeout_seconds,
        verify_ssl=endpoint.verify_ssl,
        created_at=endpoint.created_at.isoformat(),
        updated_at=endpoint.updated_at.isoformat(),
        last_delivery=endpoint.last_delivery.isoformat() if endpoint.last_delivery else None,
        total_deliveries=endpoint.total_deliveries,
        successful_deliveries=endpoint.successful_deliveries,
        failed_deliveries=endpoint.failed_deliveries,
        success_rate=f"{success_rate:.2%}"
    )


@router.put("/endpoints/{endpoint_id}")
async def update_webhook_endpoint(
    endpoint_id: str,
    request: WebhookEndpointRequest,
    current_user: CurrentUser = Depends(require_payments_create)
):
    """Update webhook endpoint configuration."""
    if endpoint_id not in webhook_manager.endpoints:
        raise HTTPException(status_code=404, detail="Webhook endpoint not found")

    endpoint = webhook_manager.endpoints[endpoint_id]
    if endpoint.merchant_id != current_user.merchant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    try:
        # Validate and update event types
        event_types = set()
        for event_type_str in request.event_types:
            try:
                event_type = WebhookEventType(event_type_str)
                event_types.add(event_type)
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid event type: {event_type_str}"
                )

        # Update endpoint configuration
        endpoint.url = str(request.url)
        endpoint.event_types = event_types
        endpoint.max_retries = request.max_retries
        endpoint.timeout_seconds = request.timeout_seconds
        endpoint.verify_ssl = request.verify_ssl
        endpoint.custom_headers = request.custom_headers
        endpoint.event_filters = request.event_filters
        endpoint.updated_at = datetime.now(timezone.utc)

        if request.secret_key:
            endpoint.secret_key = request.secret_key

        return {"message": "Webhook endpoint updated successfully", "endpoint_id": endpoint_id}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/endpoints/{endpoint_id}")
async def delete_webhook_endpoint(
    endpoint_id: str,
    current_user: CurrentUser = Depends(require_payments_create)
):
    """Delete webhook endpoint."""
    if endpoint_id not in webhook_manager.endpoints:
        raise HTTPException(status_code=404, detail="Webhook endpoint not found")

    endpoint = webhook_manager.endpoints[endpoint_id]
    if endpoint.merchant_id != current_user.merchant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    del webhook_manager.endpoints[endpoint_id]

    # Clean up related data
    if endpoint_id in webhook_manager.circuit_breakers:
        del webhook_manager.circuit_breakers[endpoint_id]
    if endpoint_id in webhook_manager.rate_limits:
        del webhook_manager.rate_limits[endpoint_id]

    return {"message": "Webhook endpoint deleted successfully", "endpoint_id": endpoint_id}


@router.post("/endpoints/{endpoint_id}/activate")
async def activate_webhook_endpoint(
    endpoint_id: str,
    current_user: CurrentUser = Depends(require_payments_create)
):
    """Activate webhook endpoint."""
    if endpoint_id not in webhook_manager.endpoints:
        raise HTTPException(status_code=404, detail="Webhook endpoint not found")

    endpoint = webhook_manager.endpoints[endpoint_id]
    if endpoint.merchant_id != current_user.merchant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    endpoint.active = True
    endpoint.updated_at = datetime.now(timezone.utc)

    return {"message": "Webhook endpoint activated successfully", "endpoint_id": endpoint_id}


@router.post("/endpoints/{endpoint_id}/deactivate")
async def deactivate_webhook_endpoint(
    endpoint_id: str,
    current_user: CurrentUser = Depends(require_payments_create)
):
    """Deactivate webhook endpoint."""
    if endpoint_id not in webhook_manager.endpoints:
        raise HTTPException(status_code=404, detail="Webhook endpoint not found")

    endpoint = webhook_manager.endpoints[endpoint_id]
    if endpoint.merchant_id != current_user.merchant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    endpoint.active = False
    endpoint.updated_at = datetime.now(timezone.utc)

    return {"message": "Webhook endpoint deactivated successfully", "endpoint_id": endpoint_id}


@router.post("/events", status_code=201)
async def emit_webhook_event(
    request: WebhookEventRequest,
    current_user: CurrentUser = Depends(require_payments_create)
):
    """Emit a webhook event (for testing purposes)."""
    try:
        # Validate event type
        try:
            event_type = WebhookEventType(request.event_type)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid event type: {request.event_type}"
            )

        # Validate priority
        try:
            priority = WebhookPriority(request.priority)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid priority: {request.priority}"
            )

        # Emit event
        event_id = await webhook_manager.emit_event(
            event_type=event_type,
            merchant_id=current_user.merchant_id,
            data=request.data,
            priority=priority,
            correlation_id=request.correlation_id,
            terminal_id=request.terminal_id
        )

        return {
            "message": "Webhook event emitted successfully",
            "event_id": event_id,
            "event_type": event_type.value
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/deliveries", response_model=List[WebhookDeliveryResponse])
async def list_webhook_deliveries(
    endpoint_id: Optional[str] = Query(None, description="Filter by endpoint ID"),
    status: Optional[str] = Query(None, description="Filter by delivery status"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of results"),
    current_user: CurrentUser = Depends(require_payments_read)
):
    """List webhook deliveries for the merchant."""
    # Filter deliveries for merchant's endpoints
    merchant_endpoint_ids = {
        endpoint.endpoint_id for endpoint in webhook_manager.endpoints.values()
        if endpoint.merchant_id == current_user.merchant_id
    }

    deliveries = [
        delivery for delivery in webhook_manager.deliveries.values()
        if delivery.endpoint_id in merchant_endpoint_ids
    ]

    # Apply filters
    if endpoint_id:
        if endpoint_id not in merchant_endpoint_ids:
            raise HTTPException(status_code=403, detail="Access denied")
        deliveries = [d for d in deliveries if d.endpoint_id == endpoint_id]

    if status:
        try:
            status_filter = WebhookStatus(status)
            deliveries = [d for d in deliveries if d.status == status_filter]
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid status filter")

    # Sort by sent time (newest first) and limit
    deliveries.sort(key=lambda d: d.sent_at, reverse=True)
    deliveries = deliveries[:limit]

    return [
        WebhookDeliveryResponse(
            delivery_id=delivery.delivery_id,
            event_id=delivery.event_id,
            endpoint_id=delivery.endpoint_id,
            status=delivery.status.value,
            url=delivery.url,
            response_status=delivery.response_status,
            sent_at=delivery.sent_at.isoformat(),
            completed_at=delivery.completed_at.isoformat() if delivery.completed_at else None,
            duration_ms=delivery.duration_ms,
            error_message=delivery.error_message,
            retry_count=delivery.retry_count
        )
        for delivery in deliveries
    ]


@router.get("/deliveries/{delivery_id}", response_model=WebhookDeliveryResponse)
async def get_webhook_delivery(
    delivery_id: str,
    current_user: CurrentUser = Depends(require_payments_read)
):
    """Get webhook delivery details."""
    if delivery_id not in webhook_manager.deliveries:
        raise HTTPException(status_code=404, detail="Webhook delivery not found")

    delivery = webhook_manager.deliveries[delivery_id]

    # Verify access through endpoint ownership
    if delivery.endpoint_id not in webhook_manager.endpoints:
        raise HTTPException(status_code=404, detail="Associated endpoint not found")

    endpoint = webhook_manager.endpoints[delivery.endpoint_id]
    if endpoint.merchant_id != current_user.merchant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    return WebhookDeliveryResponse(
        delivery_id=delivery.delivery_id,
        event_id=delivery.event_id,
        endpoint_id=delivery.endpoint_id,
        status=delivery.status.value,
        url=delivery.url,
        response_status=delivery.response_status,
        sent_at=delivery.sent_at.isoformat(),
        completed_at=delivery.completed_at.isoformat() if delivery.completed_at else None,
        duration_ms=delivery.duration_ms,
        error_message=delivery.error_message,
        retry_count=delivery.retry_count
    )


@router.get("/analytics")
async def get_webhook_analytics(
    start_date: Optional[datetime] = Query(None, description="Start date for analytics"),
    end_date: Optional[datetime] = Query(None, description="End date for analytics"),
    current_user: CurrentUser = Depends(require_payments_read)
):
    """Get webhook delivery analytics for the merchant."""
    analytics = await webhook_manager.get_webhook_analytics(
        merchant_id=current_user.merchant_id,
        start_date=start_date,
        end_date=end_date
    )

    return analytics


@router.get("/event-types")
async def list_event_types():
    """List all available webhook event types."""
    return {
        "event_types": [
            {
                "value": event_type.value,
                "description": event_type.value.replace("_", " ").replace(".", " ").title(),
                "category": event_type.value.split(".")[0]
            }
            for event_type in WebhookEventType
        ],
        "categories": list(set(event_type.value.split(".")[0] for event_type in WebhookEventType))
    }


@router.post("/test")
async def test_webhook_endpoint(
    endpoint_id: str,
    current_user: CurrentUser = Depends(require_payments_create)
):
    """Send a test webhook to verify endpoint configuration."""
    if endpoint_id not in webhook_manager.endpoints:
        raise HTTPException(status_code=404, detail="Webhook endpoint not found")

    endpoint = webhook_manager.endpoints[endpoint_id]
    if endpoint.merchant_id != current_user.merchant_id:
        raise HTTPException(status_code=403, detail="Access denied")

    # Create test event
    test_data = {
        "test": True,
        "message": "This is a test webhook delivery",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    # Emit test event
    event_id = await webhook_manager.emit_event(
        event_type=WebhookEventType.PAYMENT_SUCCESSFUL,  # Use a common event type
        merchant_id=current_user.merchant_id,
        data=test_data,
        priority=WebhookPriority.HIGH,
        correlation_id=f"test_{endpoint_id}"
    )

    return {
        "message": "Test webhook sent successfully",
        "event_id": event_id,
        "endpoint_id": endpoint_id
    }