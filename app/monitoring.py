"""
Real-time Monitoring & Analytics System for SoftPOS

This module provides comprehensive monitoring, analytics, and alerting
capabilities for production SoftPOS operations.

Key Features:
- Real-time transaction monitoring
- Performance metrics collection
- System health monitoring
- Fraud detection alerts
- Business intelligence dashboards
- Automated alerting and notifications
- SLA monitoring and reporting

Monitoring Areas:
- Transaction volume and success rates
- Payment processor performance
- EMV kernel operations
- Security incidents
- System resource utilization
- Network connectivity
- Database performance
- API response times
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from enum import Enum
from typing import Dict, List, Optional, Tuple, Union

import asyncio
from collections import defaultdict, deque


class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class MetricType(Enum):
    """Types of metrics collected."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


class SystemStatus(Enum):
    """System health status."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    MAINTENANCE = "maintenance"


@dataclass
class Metric:
    """System metric data point."""
    name: str
    value: Union[int, float]
    metric_type: MetricType
    timestamp: datetime
    tags: Dict[str, str] = field(default_factory=dict)
    description: Optional[str] = None


@dataclass
class Alert:
    """System alert/notification."""
    alert_id: str
    title: str
    description: str
    severity: AlertSeverity
    component: str
    timestamp: datetime
    resolved: bool = False
    resolved_at: Optional[datetime] = None
    metadata: Dict = field(default_factory=dict)


@dataclass
class HealthCheck:
    """Component health check result."""
    component: str
    status: SystemStatus
    response_time_ms: float
    timestamp: datetime
    error_message: Optional[str] = None
    metadata: Dict = field(default_factory=dict)


@dataclass
class TransactionMetrics:
    """Transaction processing metrics."""
    total_transactions: int
    successful_transactions: int
    failed_transactions: int
    total_volume: Decimal
    average_amount: Decimal
    success_rate: float
    average_processing_time_ms: float
    peak_tps: float  # Transactions per second
    processor_breakdown: Dict[str, int]
    scheme_breakdown: Dict[str, int]
    error_breakdown: Dict[str, int]


class MonitoringEngine:
    """
    Core monitoring and analytics engine for SoftPOS operations.

    Collects, processes, and analyzes system metrics in real-time.
    Provides alerting, health checks, and business intelligence.
    """

    def __init__(self):
        self.metrics_store: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.alerts: Dict[str, Alert] = {}
        self.health_checks: Dict[str, HealthCheck] = {}
        self.transaction_buffer: deque = deque(maxlen=10000)
        self._monitoring_started = False

        # Thresholds for alerting
        self.alert_thresholds = {
            "transaction_failure_rate": 0.05,  # 5%
            "api_response_time": 2000,  # 2 seconds
            "database_response_time": 500,  # 500ms
            "memory_usage": 0.85,  # 85%
            "cpu_usage": 0.80,  # 80%
            "fraud_score": 0.8  # 80%
        }

    def start_monitoring(self):
        """Start background monitoring tasks if not already started."""
        if not self._monitoring_started:
            try:
                asyncio.create_task(self._health_check_loop())
                asyncio.create_task(self._metrics_analysis_loop())
                asyncio.create_task(self._cleanup_loop())
                self._monitoring_started = True
            except RuntimeError:
                # No event loop running, will start later
                pass

    def _start_monitoring_tasks(self):
        """Start background monitoring tasks (legacy method for compatibility)."""
        self.start_monitoring()

    async def record_metric(self, metric: Metric):
        """Record a system metric."""
        self.metrics_store[metric.name].append(metric)

        # Check for alert conditions
        await self._check_metric_alerts(metric)

    async def record_transaction(self, transaction_data: Dict):
        """Record transaction for analytics."""
        transaction_data["timestamp"] = datetime.now(timezone.utc)
        self.transaction_buffer.append(transaction_data)

    async def create_alert(
        self,
        title: str,
        description: str,
        severity: AlertSeverity,
        component: str,
        metadata: Optional[Dict] = None
    ) -> str:
        """Create and store system alert."""
        alert_id = f"alert_{int(time.time())}_{hash(title) % 10000}"

        alert = Alert(
            alert_id=alert_id,
            title=title,
            description=description,
            severity=severity,
            component=component,
            timestamp=datetime.now(timezone.utc),
            metadata=metadata or {}
        )

        self.alerts[alert_id] = alert

        # Send notification (would integrate with actual notification system)
        await self._send_alert_notification(alert)

        return alert_id

    async def resolve_alert(self, alert_id: str) -> bool:
        """Resolve an active alert."""
        if alert_id in self.alerts:
            alert = self.alerts[alert_id]
            alert.resolved = True
            alert.resolved_at = datetime.now(timezone.utc)
            return True
        return False

    async def perform_health_check(self, component: str) -> HealthCheck:
        """Perform health check for system component."""
        start_time = time.time()

        try:
            # Perform component-specific health check
            if component == "database":
                status = await self._check_database_health()
            elif component == "payment_processor":
                status = await self._check_processor_health()
            elif component == "hsm":
                status = await self._check_hsm_health()
            elif component == "emv_kernel":
                status = await self._check_emv_health()
            else:
                status = SystemStatus.HEALTHY

            response_time = (time.time() - start_time) * 1000

            health_check = HealthCheck(
                component=component,
                status=status,
                response_time_ms=response_time,
                timestamp=datetime.now(timezone.utc)
            )

            self.health_checks[component] = health_check

            # Alert on unhealthy components
            if status in [SystemStatus.UNHEALTHY, SystemStatus.DEGRADED]:
                await self.create_alert(
                    f"{component.title()} Health Check Failed",
                    f"Component {component} is {status.value}",
                    AlertSeverity.ERROR if status == SystemStatus.UNHEALTHY else AlertSeverity.WARNING,
                    component
                )

            return health_check

        except Exception as e:
            error_health = HealthCheck(
                component=component,
                status=SystemStatus.UNHEALTHY,
                response_time_ms=(time.time() - start_time) * 1000,
                timestamp=datetime.now(timezone.utc),
                error_message=str(e)
            )

            self.health_checks[component] = error_health

            await self.create_alert(
                f"{component.title()} Health Check Error",
                f"Health check failed: {str(e)}",
                AlertSeverity.CRITICAL,
                component
            )

            return error_health

    async def get_transaction_metrics(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> TransactionMetrics:
        """Get transaction processing metrics for specified time range."""
        if not start_time:
            start_time = datetime.now(timezone.utc) - timedelta(hours=1)
        if not end_time:
            end_time = datetime.now(timezone.utc)

        # Filter transactions by time range
        filtered_transactions = [
            tx for tx in self.transaction_buffer
            if start_time <= tx["timestamp"] <= end_time
        ]

        if not filtered_transactions:
            return TransactionMetrics(
                total_transactions=0,
                successful_transactions=0,
                failed_transactions=0,
                total_volume=Decimal("0"),
                average_amount=Decimal("0"),
                success_rate=0.0,
                average_processing_time_ms=0.0,
                peak_tps=0.0,
                processor_breakdown={},
                scheme_breakdown={},
                error_breakdown={}
            )

        # Calculate metrics
        total_transactions = len(filtered_transactions)
        successful_transactions = len([tx for tx in filtered_transactions if tx.get("approved", False)])
        failed_transactions = total_transactions - successful_transactions

        total_volume = sum(Decimal(str(tx.get("amount", 0))) for tx in filtered_transactions)
        average_amount = total_volume / total_transactions if total_transactions > 0 else Decimal("0")
        success_rate = successful_transactions / total_transactions if total_transactions > 0 else 0.0

        processing_times = [tx.get("processing_time_ms", 0) for tx in filtered_transactions]
        average_processing_time = sum(processing_times) / len(processing_times) if processing_times else 0.0

        # Calculate peak TPS (transactions per second)
        peak_tps = self._calculate_peak_tps(filtered_transactions)

        # Breakdown by processor
        processor_breakdown = defaultdict(int)
        for tx in filtered_transactions:
            processor = tx.get("processor", "unknown")
            processor_breakdown[processor] += 1

        # Breakdown by card scheme
        scheme_breakdown = defaultdict(int)
        for tx in filtered_transactions:
            scheme = tx.get("card_scheme", "unknown")
            scheme_breakdown[scheme] += 1

        # Error breakdown
        error_breakdown = defaultdict(int)
        for tx in filtered_transactions:
            if not tx.get("approved", False):
                error_code = tx.get("response_code", "unknown_error")
                error_breakdown[error_code] += 1

        return TransactionMetrics(
            total_transactions=total_transactions,
            successful_transactions=successful_transactions,
            failed_transactions=failed_transactions,
            total_volume=total_volume,
            average_amount=average_amount,
            success_rate=success_rate,
            average_processing_time_ms=average_processing_time,
            peak_tps=peak_tps,
            processor_breakdown=dict(processor_breakdown),
            scheme_breakdown=dict(scheme_breakdown),
            error_breakdown=dict(error_breakdown)
        )

    async def get_system_overview(self) -> Dict:
        """Get comprehensive system overview."""
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "overall_status": await self._get_overall_system_status(),
            "active_alerts": len([a for a in self.alerts.values() if not a.resolved]),
            "health_checks": {
                component: {
                    "status": check.status.value,
                    "response_time_ms": check.response_time_ms,
                    "last_check": check.timestamp.isoformat()
                }
                for component, check in self.health_checks.items()
            },
            "recent_metrics": await self._get_recent_metrics(),
            "transaction_summary": await self._get_transaction_summary()
        }

    async def _check_metric_alerts(self, metric: Metric):
        """Check if metric triggers any alerts."""
        metric_name = metric.name
        value = metric.value

        # Transaction failure rate alert
        if metric_name == "transaction_failure_rate" and value > self.alert_thresholds["transaction_failure_rate"]:
            await self.create_alert(
                "High Transaction Failure Rate",
                f"Transaction failure rate is {value:.2%}, above threshold {self.alert_thresholds['transaction_failure_rate']:.2%}",
                AlertSeverity.ERROR,
                "payment_processing"
            )

        # API response time alert
        elif metric_name == "api_response_time" and value > self.alert_thresholds["api_response_time"]:
            await self.create_alert(
                "High API Response Time",
                f"API response time is {value}ms, above threshold {self.alert_thresholds['api_response_time']}ms",
                AlertSeverity.WARNING,
                "api"
            )

        # Fraud score alert
        elif metric_name == "fraud_score" and value > self.alert_thresholds["fraud_score"]:
            await self.create_alert(
                "High Fraud Score Detected",
                f"Fraud score is {value:.2f}, above threshold {self.alert_thresholds['fraud_score']:.2f}",
                AlertSeverity.CRITICAL,
                "fraud_detection"
            )

    async def _health_check_loop(self):
        """Background health check loop."""
        components = ["database", "payment_processor", "hsm", "emv_kernel"]

        while True:
            try:
                for component in components:
                    await self.perform_health_check(component)

                await asyncio.sleep(30)  # Check every 30 seconds
            except Exception as e:
                print(f"Health check loop error: {e}")
                await asyncio.sleep(60)

    async def _metrics_analysis_loop(self):
        """Background metrics analysis loop."""
        while True:
            try:
                # Analyze transaction patterns
                await self._analyze_transaction_patterns()

                # Check system performance
                await self._analyze_system_performance()

                await asyncio.sleep(60)  # Analyze every minute
            except Exception as e:
                print(f"Metrics analysis loop error: {e}")
                await asyncio.sleep(120)

    async def _cleanup_loop(self):
        """Background cleanup loop for old data."""
        while True:
            try:
                cutoff_time = datetime.now(timezone.utc) - timedelta(hours=24)

                # Clean old alerts
                old_alerts = [
                    alert_id for alert_id, alert in self.alerts.items()
                    if alert.timestamp < cutoff_time and alert.resolved
                ]
                for alert_id in old_alerts:
                    del self.alerts[alert_id]

                await asyncio.sleep(3600)  # Cleanup every hour
            except Exception as e:
                print(f"Cleanup loop error: {e}")
                await asyncio.sleep(3600)

    async def _check_database_health(self) -> SystemStatus:
        """Check database health."""
        # Simulate database health check
        await asyncio.sleep(0.01)
        return SystemStatus.HEALTHY

    async def _check_processor_health(self) -> SystemStatus:
        """Check payment processor health."""
        # Simulate processor health check
        await asyncio.sleep(0.02)
        return SystemStatus.HEALTHY

    async def _check_hsm_health(self) -> SystemStatus:
        """Check HSM health."""
        # Simulate HSM health check
        await asyncio.sleep(0.01)
        return SystemStatus.HEALTHY

    async def _check_emv_health(self) -> SystemStatus:
        """Check EMV kernel health."""
        # Simulate EMV kernel health check
        await asyncio.sleep(0.01)
        return SystemStatus.HEALTHY

    async def _send_alert_notification(self, alert: Alert):
        """Send alert notification (would integrate with notification system)."""
        print(f"ALERT [{alert.severity.value.upper()}]: {alert.title} - {alert.description}")

    async def _get_overall_system_status(self) -> SystemStatus:
        """Determine overall system status."""
        if not self.health_checks:
            return SystemStatus.HEALTHY

        statuses = [check.status for check in self.health_checks.values()]

        if SystemStatus.UNHEALTHY in statuses:
            return SystemStatus.UNHEALTHY
        elif SystemStatus.DEGRADED in statuses:
            return SystemStatus.DEGRADED
        else:
            return SystemStatus.HEALTHY

    async def _get_recent_metrics(self) -> Dict:
        """Get recent metric values."""
        recent_metrics = {}
        cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=5)

        for metric_name, metric_deque in self.metrics_store.items():
            recent_values = [
                m.value for m in metric_deque
                if m.timestamp >= cutoff_time
            ]
            if recent_values:
                recent_metrics[metric_name] = {
                    "current": recent_values[-1],
                    "average": sum(recent_values) / len(recent_values),
                    "count": len(recent_values)
                }

        return recent_metrics

    async def _get_transaction_summary(self) -> Dict:
        """Get transaction summary for last hour."""
        metrics = await self.get_transaction_metrics()
        return {
            "total_transactions": metrics.total_transactions,
            "success_rate": f"{metrics.success_rate:.2%}",
            "total_volume": str(metrics.total_volume),
            "average_processing_time_ms": f"{metrics.average_processing_time_ms:.1f}"
        }

    def _calculate_peak_tps(self, transactions: List[Dict]) -> float:
        """Calculate peak transactions per second."""
        if not transactions:
            return 0.0

        # Group transactions by second
        tps_by_second = defaultdict(int)
        for tx in transactions:
            second = tx["timestamp"].replace(microsecond=0)
            tps_by_second[second] += 1

        return max(tps_by_second.values()) if tps_by_second else 0.0

    async def _analyze_transaction_patterns(self):
        """Analyze transaction patterns for anomalies."""
        recent_transactions = list(self.transaction_buffer)[-100:]  # Last 100 transactions

        if len(recent_transactions) < 10:
            return

        # Calculate failure rate
        failures = len([tx for tx in recent_transactions if not tx.get("approved", False)])
        failure_rate = failures / len(recent_transactions)

        await self.record_metric(Metric(
            name="transaction_failure_rate",
            value=failure_rate,
            metric_type=MetricType.GAUGE,
            timestamp=datetime.now(timezone.utc),
            tags={"component": "payment_processing"}
        ))

    async def _analyze_system_performance(self):
        """Analyze system performance metrics."""
        # Simulate system performance metrics
        import random

        await self.record_metric(Metric(
            name="api_response_time",
            value=random.uniform(100, 300),  # 100-300ms
            metric_type=MetricType.GAUGE,
            timestamp=datetime.now(timezone.utc),
            tags={"component": "api"}
        ))

        await self.record_metric(Metric(
            name="memory_usage",
            value=random.uniform(0.3, 0.7),  # 30-70%
            metric_type=MetricType.GAUGE,
            timestamp=datetime.now(timezone.utc),
            tags={"component": "system"}
        ))


# Global monitoring engine instance
monitoring_engine = MonitoringEngine()