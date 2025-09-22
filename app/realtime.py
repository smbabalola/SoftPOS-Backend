"""
Real-time WebSocket Support for SoftPOS

This module provides WebSocket connections for real-time updates including:
- Live transaction monitoring
- Terminal status updates
- System health notifications
- Alert broadcasts
- Performance metrics streaming

Features:
- Connection management with authentication
- Room-based message broadcasting
- Automatic reconnection handling
- Message queuing for offline clients
- Rate limiting and security
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set
from uuid import uuid4

from fastapi import WebSocket, WebSocketDisconnect, HTTPException
import structlog

logger = structlog.get_logger(__name__)


class ConnectionManager:
    """Manages WebSocket connections for real-time updates."""

    def __init__(self):
        # Active connections by connection ID
        self.active_connections: Dict[str, WebSocket] = {}

        # Connection metadata
        self.connection_metadata: Dict[str, Dict] = {}

        # Room subscriptions (merchant_id -> set of connection_ids)
        self.room_subscriptions: Dict[str, Set[str]] = {}

        # Message queue for offline clients
        self.message_queue: Dict[str, List[Dict]] = {}

        # Rate limiting
        self.rate_limits: Dict[str, List[float]] = {}

    async def connect(self, websocket: WebSocket, merchant_id: str, user_id: str) -> str:
        """Accept a new WebSocket connection."""
        await websocket.accept()

        connection_id = f"conn_{uuid4().hex[:12]}"

        self.active_connections[connection_id] = websocket
        self.connection_metadata[connection_id] = {
            "merchant_id": merchant_id,
            "user_id": user_id,
            "connected_at": datetime.now(timezone.utc),
            "last_ping": datetime.now(timezone.utc)
        }

        # Subscribe to merchant room
        if merchant_id not in self.room_subscriptions:
            self.room_subscriptions[merchant_id] = set()
        self.room_subscriptions[merchant_id].add(connection_id)

        # Send queued messages
        await self._send_queued_messages(connection_id, merchant_id)

        logger.info(
            "WebSocket connection established",
            connection_id=connection_id,
            merchant_id=merchant_id,
            user_id=user_id
        )

        return connection_id

    async def disconnect(self, connection_id: str):
        """Close a WebSocket connection."""
        if connection_id in self.active_connections:
            websocket = self.active_connections[connection_id]
            metadata = self.connection_metadata.get(connection_id, {})
            merchant_id = metadata.get("merchant_id")

            # Remove from active connections
            del self.active_connections[connection_id]
            del self.connection_metadata[connection_id]

            # Remove from room subscriptions
            if merchant_id and merchant_id in self.room_subscriptions:
                self.room_subscriptions[merchant_id].discard(connection_id)
                if not self.room_subscriptions[merchant_id]:
                    del self.room_subscriptions[merchant_id]

            # Clean up rate limiting
            if connection_id in self.rate_limits:
                del self.rate_limits[connection_id]

            logger.info(
                "WebSocket connection closed",
                connection_id=connection_id,
                merchant_id=merchant_id
            )

    async def send_personal_message(self, message: Dict, connection_id: str):
        """Send message to a specific connection."""
        if connection_id in self.active_connections:
            websocket = self.active_connections[connection_id]
            try:
                await websocket.send_text(json.dumps(message))
            except Exception as e:
                logger.warning(
                    "Failed to send personal message",
                    connection_id=connection_id,
                    error=str(e)
                )
                await self.disconnect(connection_id)

    async def broadcast_to_merchant(self, message: Dict, merchant_id: str):
        """Broadcast message to all connections in a merchant room."""
        if merchant_id not in self.room_subscriptions:
            # Queue message for when merchant connects
            if merchant_id not in self.message_queue:
                self.message_queue[merchant_id] = []
            self.message_queue[merchant_id].append({
                **message,
                "queued_at": datetime.now(timezone.utc).isoformat()
            })
            return

        connection_ids = list(self.room_subscriptions[merchant_id])

        for connection_id in connection_ids:
            await self.send_personal_message(message, connection_id)

    async def broadcast_system_wide(self, message: Dict):
        """Broadcast message to all active connections."""
        connection_ids = list(self.active_connections.keys())

        for connection_id in connection_ids:
            await self.send_personal_message(message, connection_id)

    async def handle_ping(self, connection_id: str):
        """Handle ping from client."""
        if connection_id in self.connection_metadata:
            self.connection_metadata[connection_id]["last_ping"] = datetime.now(timezone.utc)

            # Send pong response
            await self.send_personal_message({
                "type": "pong",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }, connection_id)

    async def check_rate_limit(self, connection_id: str) -> bool:
        """Check if connection is within rate limits."""
        now = time.time()
        window_start = now - 60  # 1 minute window

        if connection_id not in self.rate_limits:
            self.rate_limits[connection_id] = []

        # Clean old timestamps
        self.rate_limits[connection_id] = [
            ts for ts in self.rate_limits[connection_id]
            if ts >= window_start
        ]

        # Check limit (60 messages per minute)
        if len(self.rate_limits[connection_id]) >= 60:
            return False

        self.rate_limits[connection_id].append(now)
        return True

    async def _send_queued_messages(self, connection_id: str, merchant_id: str):
        """Send queued messages to newly connected client."""
        if merchant_id in self.message_queue:
            messages = self.message_queue[merchant_id]

            # Send last 10 messages
            for message in messages[-10:]:
                await self.send_personal_message(message, connection_id)

            # Clear old messages (keep last 50)
            self.message_queue[merchant_id] = messages[-50:]

    async def cleanup_stale_connections(self):
        """Clean up stale connections that haven't pinged recently."""
        stale_threshold = datetime.now(timezone.utc).timestamp() - 300  # 5 minutes

        stale_connections = [
            connection_id for connection_id, metadata in self.connection_metadata.items()
            if metadata["last_ping"].timestamp() < stale_threshold
        ]

        for connection_id in stale_connections:
            await self.disconnect(connection_id)
            logger.info("Cleaned up stale connection", connection_id=connection_id)

    def get_connection_stats(self) -> Dict:
        """Get connection statistics."""
        total_connections = len(self.active_connections)

        # Count by merchant
        merchant_counts = {}
        for metadata in self.connection_metadata.values():
            merchant_id = metadata["merchant_id"]
            merchant_counts[merchant_id] = merchant_counts.get(merchant_id, 0) + 1

        return {
            "total_connections": total_connections,
            "merchant_breakdown": merchant_counts,
            "active_rooms": len(self.room_subscriptions),
            "queued_messages": sum(len(queue) for queue in self.message_queue.values())
        }


class RealtimeNotifier:
    """Handles real-time notifications for various events."""

    def __init__(self, connection_manager: ConnectionManager):
        self.connection_manager = connection_manager

    async def notify_transaction_update(
        self,
        merchant_id: str,
        transaction_data: Dict
    ):
        """Notify about transaction updates."""
        message = {
            "type": "transaction_update",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": transaction_data
        }

        await self.connection_manager.broadcast_to_merchant(message, merchant_id)

    async def notify_terminal_status(
        self,
        merchant_id: str,
        terminal_id: str,
        status: str,
        details: Optional[Dict] = None
    ):
        """Notify about terminal status changes."""
        message = {
            "type": "terminal_status",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {
                "terminal_id": terminal_id,
                "status": status,
                "details": details or {}
            }
        }

        await self.connection_manager.broadcast_to_merchant(message, merchant_id)

    async def notify_system_alert(
        self,
        alert_data: Dict,
        merchant_id: Optional[str] = None
    ):
        """Notify about system alerts."""
        message = {
            "type": "system_alert",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": alert_data
        }

        if merchant_id:
            await self.connection_manager.broadcast_to_merchant(message, merchant_id)
        else:
            await self.connection_manager.broadcast_system_wide(message)

    async def notify_performance_metrics(
        self,
        merchant_id: str,
        metrics: Dict
    ):
        """Notify about performance metrics updates."""
        message = {
            "type": "performance_metrics",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": metrics
        }

        await self.connection_manager.broadcast_to_merchant(message, merchant_id)

    async def notify_webhook_delivery(
        self,
        merchant_id: str,
        delivery_data: Dict
    ):
        """Notify about webhook delivery status."""
        message = {
            "type": "webhook_delivery",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": delivery_data
        }

        await self.connection_manager.broadcast_to_merchant(message, merchant_id)

    async def notify_fraud_alert(
        self,
        merchant_id: str,
        fraud_data: Dict
    ):
        """Notify about fraud detection alerts."""
        message = {
            "type": "fraud_alert",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": fraud_data,
            "priority": "high"
        }

        await self.connection_manager.broadcast_to_merchant(message, merchant_id)

    async def notify_settlement_update(
        self,
        merchant_id: str,
        settlement_data: Dict
    ):
        """Notify about settlement updates."""
        message = {
            "type": "settlement_update",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": settlement_data
        }

        await self.connection_manager.broadcast_to_merchant(message, merchant_id)


# Global instances
connection_manager = ConnectionManager()
realtime_notifier = RealtimeNotifier(connection_manager)


async def start_realtime_tasks():
    """Start background tasks for real-time functionality."""
    # Connection cleanup task
    async def cleanup_task():
        while True:
            try:
                await connection_manager.cleanup_stale_connections()
                await asyncio.sleep(60)  # Run every minute
            except Exception as e:
                logger.error("Cleanup task error", error=str(e))
                await asyncio.sleep(60)

    # Heartbeat task
    async def heartbeat_task():
        while True:
            try:
                # Send heartbeat to all connections
                heartbeat_message = {
                    "type": "heartbeat",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "server_time": datetime.now(timezone.utc).isoformat()
                }

                await connection_manager.broadcast_system_wide(heartbeat_message)
                await asyncio.sleep(30)  # Send heartbeat every 30 seconds

            except Exception as e:
                logger.error("Heartbeat task error", error=str(e))
                await asyncio.sleep(30)

    # Start tasks
    asyncio.create_task(cleanup_task())
    asyncio.create_task(heartbeat_task())


# Integration with existing monitoring system
async def integrate_with_monitoring():
    """Integrate real-time notifications with monitoring system."""
    try:
        from .monitoring import monitoring_engine

        # Override monitoring engine's alert creation to send real-time notifications
        original_create_alert = monitoring_engine.create_alert

        async def create_alert_with_notification(*args, **kwargs):
            alert_id = await original_create_alert(*args, **kwargs)

            # Send real-time notification
            if alert_id in monitoring_engine.alerts:
                alert = monitoring_engine.alerts[alert_id]
                await realtime_notifier.notify_system_alert({
                    "alert_id": alert.alert_id,
                    "title": alert.title,
                    "description": alert.description,
                    "severity": alert.severity.value,
                    "component": alert.component
                })

            return alert_id

        monitoring_engine.create_alert = create_alert_with_notification

        logger.info("Real-time monitoring integration enabled")

    except ImportError as e:
        logger.info("Monitoring integration skipped", reason=str(e))