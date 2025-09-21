"""
Real-time WebSocket API Endpoints

WebSocket endpoints for real-time communication with SoftPOS clients.
"""

from __future__ import annotations

import json
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException, Query
from jose import JWTError, jwt

from ..realtime import connection_manager, realtime_notifier
from ..auth import SECRET_KEY, ALGORITHM

router = APIRouter(prefix="/v1/realtime", tags=["Real-time"])


async def get_current_user_websocket(
    websocket: WebSocket,
    token: Optional[str] = Query(None)
):
    """Get current user from WebSocket token."""
    if not token:
        await websocket.close(code=4001, reason="Missing authentication token")
        return None

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        merchant_id: str = payload.get("sub")
        scopes: list = payload.get("scopes", [])

        if merchant_id is None:
            await websocket.close(code=4001, reason="Invalid authentication token")
            return None

        return {
            "merchant_id": merchant_id,
            "scopes": scopes,
            "user_id": merchant_id  # Simplified - in production would be separate user ID
        }
    except JWTError:
        await websocket.close(code=4001, reason="Invalid authentication token")
        return None


@router.websocket("/connect")
async def websocket_endpoint(
    websocket: WebSocket,
    token: Optional[str] = Query(None)
):
    """WebSocket endpoint for real-time updates."""
    # Authenticate user
    user = await get_current_user_websocket(websocket, token)
    if not user:
        return

    merchant_id = user["merchant_id"]
    user_id = user["user_id"]

    # Establish connection
    connection_id = await connection_manager.connect(websocket, merchant_id, user_id)

    try:
        # Send welcome message
        welcome_message = {
            "type": "welcome",
            "connection_id": connection_id,
            "timestamp": "2024-01-01T00:00:00Z",
            "features": [
                "transaction_updates",
                "terminal_status",
                "system_alerts",
                "performance_metrics",
                "webhook_notifications"
            ]
        }
        await connection_manager.send_personal_message(welcome_message, connection_id)

        # Listen for messages
        while True:
            try:
                data = await websocket.receive_text()
                message = json.loads(data)

                # Check rate limit
                if not await connection_manager.check_rate_limit(connection_id):
                    await connection_manager.send_personal_message({
                        "type": "error",
                        "message": "Rate limit exceeded",
                        "code": "RATE_LIMIT_EXCEEDED"
                    }, connection_id)
                    continue

                # Handle different message types
                message_type = message.get("type")

                if message_type == "ping":
                    await connection_manager.handle_ping(connection_id)

                elif message_type == "subscribe":
                    # Handle subscription to specific event types
                    event_types = message.get("event_types", [])
                    await connection_manager.send_personal_message({
                        "type": "subscribed",
                        "event_types": event_types,
                        "message": f"Subscribed to {len(event_types)} event types"
                    }, connection_id)

                elif message_type == "unsubscribe":
                    # Handle unsubscription
                    event_types = message.get("event_types", [])
                    await connection_manager.send_personal_message({
                        "type": "unsubscribed",
                        "event_types": event_types,
                        "message": f"Unsubscribed from {len(event_types)} event types"
                    }, connection_id)

                elif message_type == "get_status":
                    # Send current system status
                    from ..monitoring import monitoring_engine

                    system_overview = await monitoring_engine.get_system_overview()
                    await connection_manager.send_personal_message({
                        "type": "status_response",
                        "data": {
                            "overall_status": system_overview["overall_status"].value,
                            "active_alerts": system_overview["active_alerts"],
                            "transaction_summary": system_overview["transaction_summary"]
                        }
                    }, connection_id)

                else:
                    await connection_manager.send_personal_message({
                        "type": "error",
                        "message": f"Unknown message type: {message_type}",
                        "code": "UNKNOWN_MESSAGE_TYPE"
                    }, connection_id)

            except json.JSONDecodeError:
                await connection_manager.send_personal_message({
                    "type": "error",
                    "message": "Invalid JSON format",
                    "code": "INVALID_JSON"
                }, connection_id)

            except Exception as e:
                await connection_manager.send_personal_message({
                    "type": "error",
                    "message": f"Message processing error: {str(e)}",
                    "code": "PROCESSING_ERROR"
                }, connection_id)

    except WebSocketDisconnect:
        await connection_manager.disconnect(connection_id)
    except Exception as e:
        await connection_manager.disconnect(connection_id)


@router.get("/stats")
async def get_realtime_stats():
    """Get real-time connection statistics."""
    return connection_manager.get_connection_stats()


@router.post("/broadcast/test")
async def broadcast_test_message(
    message: str,
    merchant_id: Optional[str] = None
):
    """Broadcast a test message (for development/testing)."""
    test_message = {
        "type": "test_broadcast",
        "message": message,
        "timestamp": "2024-01-01T00:00:00Z"
    }

    if merchant_id:
        await connection_manager.broadcast_to_merchant(test_message, merchant_id)
        return {"message": f"Test message sent to merchant {merchant_id}"}
    else:
        await connection_manager.broadcast_system_wide(test_message)
        return {"message": "Test message sent to all connections"}


@router.post("/notify/transaction")
async def notify_transaction_update(
    merchant_id: str,
    transaction_data: dict
):
    """Send transaction update notification (for integration testing)."""
    await realtime_notifier.notify_transaction_update(merchant_id, transaction_data)
    return {"message": "Transaction notification sent"}


@router.post("/notify/terminal")
async def notify_terminal_status(
    merchant_id: str,
    terminal_id: str,
    status: str,
    details: Optional[dict] = None
):
    """Send terminal status notification (for integration testing)."""
    await realtime_notifier.notify_terminal_status(merchant_id, terminal_id, status, details)
    return {"message": "Terminal status notification sent"}


@router.post("/notify/alert")
async def notify_system_alert(
    alert_data: dict,
    merchant_id: Optional[str] = None
):
    """Send system alert notification (for integration testing)."""
    await realtime_notifier.notify_system_alert(alert_data, merchant_id)
    return {"message": "Alert notification sent"}