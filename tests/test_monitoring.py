"""
Monitoring & Analytics Tests

Test suite for monitoring and analytics functionality including:
- Real-time monitoring and alerting
- Performance metrics collection
- System health monitoring
- Business intelligence reporting
- Alert management
"""

import pytest
from decimal import Decimal
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch, MagicMock

from app.monitoring import (
    monitoring_engine,
    AlertSeverity,
    MetricType,
    SystemStatus,
    Metric,
    Alert,
    HealthCheck,
    TransactionMetrics
)
from app.reporting import (
    reporting_engine,
    ReportType,
    ReportFormat,
    ReportRequest,
    ReportData
)


class TestMetricsCollection:
    """Test metrics collection and storage."""

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_record_counter_metric(self):
        """Test recording counter metrics."""
        metric = Metric(
            name="payment_transactions_total",
            value=1,
            metric_type=MetricType.COUNTER,
            timestamp=datetime.now(timezone.utc),
            tags={"processor": "stripe", "status": "success"}
        )

        await monitoring_engine.record_metric(metric)

        # Verify metric is stored
        assert "payment_transactions_total" in monitoring_engine.metrics_store
        stored_metrics = monitoring_engine.metrics_store["payment_transactions_total"]
        assert len(stored_metrics) == 1
        assert stored_metrics[0].value == 1
        assert stored_metrics[0].tags["processor"] == "stripe"

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_record_gauge_metric(self):
        """Test recording gauge metrics."""
        metric = Metric(
            name="active_terminals",
            value=15,
            metric_type=MetricType.GAUGE,
            timestamp=datetime.now(timezone.utc),
            tags={"merchant": "mer_001"}
        )

        await monitoring_engine.record_metric(metric)

        # Verify metric is stored
        stored_metrics = monitoring_engine.metrics_store["active_terminals"]
        assert len(stored_metrics) == 1
        assert stored_metrics[0].value == 15

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_record_histogram_metric(self):
        """Test recording histogram metrics."""
        # Record multiple response time measurements
        response_times = [120, 150, 95, 200, 180]

        for rt in response_times:
            metric = Metric(
                name="api_response_time",
                value=rt,
                metric_type=MetricType.HISTOGRAM,
                timestamp=datetime.now(timezone.utc),
                tags={"endpoint": "/v1/payments"}
            )
            await monitoring_engine.record_metric(metric)

        # Verify all measurements are stored
        stored_metrics = monitoring_engine.metrics_store["api_response_time"]
        assert len(stored_metrics) == 5

        # Calculate average
        values = [m.value for m in stored_metrics]
        average = sum(values) / len(values)
        assert average == 149.0  # (120+150+95+200+180)/5

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_metric_tags_filtering(self):
        """Test filtering metrics by tags."""
        # Record metrics with different tags
        metric1 = Metric(
            name="payment_volume",
            value=100.0,
            metric_type=MetricType.GAUGE,
            timestamp=datetime.now(timezone.utc),
            tags={"currency": "GBP", "processor": "stripe"}
        )

        metric2 = Metric(
            name="payment_volume",
            value=75.0,
            metric_type=MetricType.GAUGE,
            timestamp=datetime.now(timezone.utc),
            tags={"currency": "USD", "processor": "stripe"}
        )

        await monitoring_engine.record_metric(metric1)
        await monitoring_engine.record_metric(metric2)

        # Verify both metrics are stored
        stored_metrics = monitoring_engine.metrics_store["payment_volume"]
        assert len(stored_metrics) == 2

        # Filter by currency
        gbp_metrics = [m for m in stored_metrics if m.tags.get("currency") == "GBP"]
        usd_metrics = [m for m in stored_metrics if m.tags.get("currency") == "USD"]

        assert len(gbp_metrics) == 1
        assert len(usd_metrics) == 1
        assert gbp_metrics[0].value == 100.0
        assert usd_metrics[0].value == 75.0


class TestAlertManagement:
    """Test alert creation and management."""

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_create_alert(self):
        """Test creating system alerts."""
        alert_id = await monitoring_engine.create_alert(
            title="High Transaction Failure Rate",
            description="Transaction failure rate exceeded 5% threshold",
            severity=AlertSeverity.ERROR,
            component="payment_processing",
            metadata={"threshold": 0.05, "current_rate": 0.08}
        )

        assert alert_id is not None
        assert alert_id in monitoring_engine.alerts

        alert = monitoring_engine.alerts[alert_id]
        assert alert.title == "High Transaction Failure Rate"
        assert alert.severity == AlertSeverity.ERROR
        assert alert.component == "payment_processing"
        assert alert.resolved is False
        assert alert.metadata["current_rate"] == 0.08

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_resolve_alert(self):
        """Test resolving alerts."""
        # Create alert
        alert_id = await monitoring_engine.create_alert(
            title="Test Alert",
            description="Test alert description",
            severity=AlertSeverity.WARNING,
            component="test"
        )

        # Resolve alert
        success = await monitoring_engine.resolve_alert(alert_id)

        assert success is True

        alert = monitoring_engine.alerts[alert_id]
        assert alert.resolved is True
        assert alert.resolved_at is not None

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_resolve_nonexistent_alert(self):
        """Test resolving non-existent alert."""
        success = await monitoring_engine.resolve_alert("nonexistent_alert")
        assert success is False

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_alert_severity_levels(self):
        """Test different alert severity levels."""
        severities = [
            AlertSeverity.INFO,
            AlertSeverity.WARNING,
            AlertSeverity.ERROR,
            AlertSeverity.CRITICAL
        ]

        alert_ids = []
        for severity in severities:
            alert_id = await monitoring_engine.create_alert(
                title=f"{severity.value.title()} Alert",
                description=f"Test {severity.value} alert",
                severity=severity,
                component="test"
            )
            alert_ids.append(alert_id)

        # Verify all alerts created with correct severities
        for i, alert_id in enumerate(alert_ids):
            alert = monitoring_engine.alerts[alert_id]
            assert alert.severity == severities[i]


class TestHealthChecks:
    """Test system health monitoring."""

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_database_health_check(self):
        """Test database health check."""
        health_check = await monitoring_engine.perform_health_check("database")

        assert health_check.component == "database"
        assert health_check.status in [SystemStatus.HEALTHY, SystemStatus.UNHEALTHY]
        assert health_check.response_time_ms > 0
        assert health_check.timestamp is not None

        # Verify health check is stored
        assert "database" in monitoring_engine.health_checks
        assert monitoring_engine.health_checks["database"] == health_check

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_payment_processor_health_check(self):
        """Test payment processor health check."""
        health_check = await monitoring_engine.perform_health_check("payment_processor")

        assert health_check.component == "payment_processor"
        assert health_check.status in [SystemStatus.HEALTHY, SystemStatus.UNHEALTHY]

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_hsm_health_check(self):
        """Test HSM health check."""
        health_check = await monitoring_engine.perform_health_check("hsm")

        assert health_check.component == "hsm"
        assert health_check.status in [SystemStatus.HEALTHY, SystemStatus.UNHEALTHY]

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_emv_kernel_health_check(self):
        """Test EMV kernel health check."""
        health_check = await monitoring_engine.perform_health_check("emv_kernel")

        assert health_check.component == "emv_kernel"
        assert health_check.status in [SystemStatus.HEALTHY, SystemStatus.UNHEALTHY]

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_health_check_failure_creates_alert(self):
        """Test that failed health checks create alerts."""
        # Mock health check to fail
        with patch.object(monitoring_engine, '_check_database_health',
                         return_value=SystemStatus.UNHEALTHY):
            health_check = await monitoring_engine.perform_health_check("database")

            assert health_check.status == SystemStatus.UNHEALTHY

            # Should have created an alert
            database_alerts = [
                alert for alert in monitoring_engine.alerts.values()
                if alert.component == "database" and not alert.resolved
            ]
            assert len(database_alerts) > 0

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_unknown_component_health_check(self):
        """Test health check for unknown component."""
        health_check = await monitoring_engine.perform_health_check("unknown_component")

        assert health_check.component == "unknown_component"
        assert health_check.status == SystemStatus.HEALTHY  # Default for unknown


class TestTransactionMetrics:
    """Test transaction processing metrics."""

    @pytest.fixture
    def sample_transactions(self):
        """Create sample transaction data."""
        base_time = datetime.now(timezone.utc)
        transactions = []

        for i in range(100):
            transaction = {
                "transaction_id": f"txn_{i:03d}",
                "merchant_id": "mer_test_001",
                "amount": Decimal(str(25.00 + (i % 50))),
                "currency": "GBP",
                "processor": ["stripe", "adyen", "worldpay"][i % 3],
                "card_scheme": ["visa", "mastercard", "amex"][i % 3],
                "approved": i % 10 != 0,  # 90% success rate
                "processing_time_ms": 100 + (i % 100),
                "timestamp": base_time - timedelta(minutes=i),
                "fraud_score": (i % 100) / 100.0
            }
            transactions.append(transaction)

        return transactions

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_transaction_metrics_calculation(self, sample_transactions):
        """Test calculation of transaction metrics."""
        # Add sample transactions to buffer
        monitoring_engine.transaction_buffer.extend(sample_transactions)

        # Calculate metrics for last hour
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=1)

        metrics = await monitoring_engine.get_transaction_metrics(start_time, end_time)

        assert metrics.total_transactions == 60  # Last 60 transactions (1 per minute)
        assert metrics.successful_transactions == 54  # 90% success rate
        assert metrics.failed_transactions == 6
        assert abs(metrics.success_rate - 0.9) < 0.01  # ~90%

        # Verify volume calculation
        expected_volume = sum(tx["amount"] for tx in sample_transactions[:60])
        assert metrics.total_volume == expected_volume

        # Verify processor breakdown
        assert "stripe" in metrics.processor_breakdown
        assert "adyen" in metrics.processor_breakdown
        assert "worldpay" in metrics.processor_breakdown

        # Verify scheme breakdown
        assert "visa" in metrics.scheme_breakdown
        assert "mastercard" in metrics.scheme_breakdown
        assert "amex" in metrics.scheme_breakdown

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_transaction_metrics_empty_data(self):
        """Test transaction metrics with no data."""
        # Clear transaction buffer
        monitoring_engine.transaction_buffer.clear()

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=1)

        metrics = await monitoring_engine.get_transaction_metrics(start_time, end_time)

        assert metrics.total_transactions == 0
        assert metrics.successful_transactions == 0
        assert metrics.failed_transactions == 0
        assert metrics.total_volume == Decimal("0")
        assert metrics.success_rate == 0.0
        assert metrics.processor_breakdown == {}
        assert metrics.scheme_breakdown == {}

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_peak_tps_calculation(self, sample_transactions):
        """Test peak transactions per second calculation."""
        # Create transactions clustered in same second
        base_time = datetime.now(timezone.utc)
        clustered_transactions = []

        for i in range(10):
            transaction = {
                "transaction_id": f"txn_cluster_{i:03d}",
                "timestamp": base_time,  # All in same second
                "approved": True,
                "amount": Decimal("25.00")
            }
            clustered_transactions.append(transaction)

        peak_tps = monitoring_engine._calculate_peak_tps(clustered_transactions)
        assert peak_tps == 10.0  # 10 transactions in one second


class TestSystemOverview:
    """Test system overview functionality."""

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_system_overview_structure(self):
        """Test system overview response structure."""
        overview = await monitoring_engine.get_system_overview()

        assert "timestamp" in overview
        assert "overall_status" in overview
        assert "active_alerts" in overview
        assert "health_checks" in overview
        assert "recent_metrics" in overview
        assert "transaction_summary" in overview

        # Verify timestamp format
        timestamp = datetime.fromisoformat(overview["timestamp"].replace('Z', '+00:00'))
        assert isinstance(timestamp, datetime)

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_overall_system_status_healthy(self):
        """Test overall system status when all components healthy."""
        # Set all health checks to healthy
        monitoring_engine.health_checks = {
            "database": HealthCheck(
                component="database",
                status=SystemStatus.HEALTHY,
                response_time_ms=50.0,
                timestamp=datetime.now(timezone.utc)
            ),
            "payment_processor": HealthCheck(
                component="payment_processor",
                status=SystemStatus.HEALTHY,
                response_time_ms=100.0,
                timestamp=datetime.now(timezone.utc)
            )
        }

        overall_status = await monitoring_engine._get_overall_system_status()
        assert overall_status == SystemStatus.HEALTHY

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_overall_system_status_degraded(self):
        """Test overall system status when some components degraded."""
        monitoring_engine.health_checks = {
            "database": HealthCheck(
                component="database",
                status=SystemStatus.HEALTHY,
                response_time_ms=50.0,
                timestamp=datetime.now(timezone.utc)
            ),
            "payment_processor": HealthCheck(
                component="payment_processor",
                status=SystemStatus.DEGRADED,
                response_time_ms=500.0,
                timestamp=datetime.now(timezone.utc)
            )
        }

        overall_status = await monitoring_engine._get_overall_system_status()
        assert overall_status == SystemStatus.DEGRADED

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_overall_system_status_unhealthy(self):
        """Test overall system status when components unhealthy."""
        monitoring_engine.health_checks = {
            "database": HealthCheck(
                component="database",
                status=SystemStatus.UNHEALTHY,
                response_time_ms=5000.0,
                timestamp=datetime.now(timezone.utc),
                error_message="Connection timeout"
            )
        }

        overall_status = await monitoring_engine._get_overall_system_status()
        assert overall_status == SystemStatus.UNHEALTHY


class TestMetricAlerts:
    """Test metric-based alerting."""

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_transaction_failure_rate_alert(self):
        """Test alert creation for high transaction failure rate."""
        # Create metric that exceeds threshold
        metric = Metric(
            name="transaction_failure_rate",
            value=0.08,  # 8% (above 5% threshold)
            metric_type=MetricType.GAUGE,
            timestamp=datetime.now(timezone.utc)
        )

        await monitoring_engine.record_metric(metric)

        # Should have created an alert
        failure_alerts = [
            alert for alert in monitoring_engine.alerts.values()
            if "failure rate" in alert.title.lower() and not alert.resolved
        ]
        assert len(failure_alerts) > 0

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_api_response_time_alert(self):
        """Test alert creation for high API response time."""
        # Create metric that exceeds threshold
        metric = Metric(
            name="api_response_time",
            value=3000,  # 3 seconds (above 2 second threshold)
            metric_type=MetricType.GAUGE,
            timestamp=datetime.now(timezone.utc)
        )

        await monitoring_engine.record_metric(metric)

        # Should have created an alert
        response_time_alerts = [
            alert for alert in monitoring_engine.alerts.values()
            if "response time" in alert.title.lower() and not alert.resolved
        ]
        assert len(response_time_alerts) > 0

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_fraud_score_alert(self):
        """Test alert creation for high fraud score."""
        # Create metric that exceeds threshold
        metric = Metric(
            name="fraud_score",
            value=0.95,  # 95% (above 80% threshold)
            metric_type=MetricType.GAUGE,
            timestamp=datetime.now(timezone.utc)
        )

        await monitoring_engine.record_metric(metric)

        # Should have created a critical alert
        fraud_alerts = [
            alert for alert in monitoring_engine.alerts.values()
            if "fraud" in alert.title.lower() and not alert.resolved
        ]
        assert len(fraud_alerts) > 0

        # Should be critical severity
        fraud_alert = fraud_alerts[0]
        assert fraud_alert.severity == AlertSeverity.CRITICAL


class TestReportingEngine:
    """Test reporting functionality."""

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_transaction_summary_report(self):
        """Test generating transaction summary report."""
        start_date = datetime.now(timezone.utc) - timedelta(days=1)
        end_date = datetime.now(timezone.utc)

        request = ReportRequest(
            report_type=ReportType.TRANSACTION_SUMMARY,
            start_date=start_date,
            end_date=end_date,
            merchant_id="mer_test_001"
        )

        report = await reporting_engine.generate_report(request)

        assert report.report_type == ReportType.TRANSACTION_SUMMARY
        assert report.data_period == (start_date, end_date)
        assert "total_transactions" in report.summary
        assert "success_rate" in report.summary
        assert "total_volume" in report.summary

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_merchant_performance_report(self):
        """Test generating merchant performance report."""
        start_date = datetime.now(timezone.utc) - timedelta(days=7)
        end_date = datetime.now(timezone.utc)

        request = ReportRequest(
            report_type=ReportType.MERCHANT_PERFORMANCE,
            start_date=start_date,
            end_date=end_date
        )

        report = await reporting_engine.generate_report(request)

        assert report.report_type == ReportType.MERCHANT_PERFORMANCE
        assert "total_merchants" in report.summary
        assert isinstance(report.details, list)

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_fraud_analysis_report(self):
        """Test generating fraud analysis report."""
        start_date = datetime.now(timezone.utc) - timedelta(days=1)
        end_date = datetime.now(timezone.utc)

        request = ReportRequest(
            report_type=ReportType.FRAUD_ANALYSIS,
            start_date=start_date,
            end_date=end_date,
            merchant_id="mer_test_001"
        )

        report = await reporting_engine.generate_report(request)

        assert report.report_type == ReportType.FRAUD_ANALYSIS
        assert "total_transactions_analyzed" in report.summary
        assert "high_risk_transactions" in report.summary
        assert "overall_fraud_rate" in report.summary

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_report_export_json(self):
        """Test exporting report as JSON."""
        start_date = datetime.now(timezone.utc) - timedelta(days=1)
        end_date = datetime.now(timezone.utc)

        request = ReportRequest(
            report_type=ReportType.TRANSACTION_SUMMARY,
            start_date=start_date,
            end_date=end_date,
            format=ReportFormat.JSON
        )

        report = await reporting_engine.generate_report(request)
        exported_data = await reporting_engine.export_report(report, ReportFormat.JSON)

        # Should be valid JSON
        import json
        report_json = json.loads(exported_data.decode('utf-8'))

        assert report_json["report_id"] == report.report_id
        assert report_json["report_type"] == ReportType.TRANSACTION_SUMMARY.value
        assert "summary" in report_json
        assert "details" in report_json

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_report_export_csv(self):
        """Test exporting report as CSV."""
        start_date = datetime.now(timezone.utc) - timedelta(days=1)
        end_date = datetime.now(timezone.utc)

        request = ReportRequest(
            report_type=ReportType.TRANSACTION_SUMMARY,
            start_date=start_date,
            end_date=end_date,
            format=ReportFormat.CSV,
            include_raw_data=True
        )

        report = await reporting_engine.generate_report(request)
        exported_data = await reporting_engine.export_report(report, ReportFormat.CSV)

        # Should be valid CSV
        csv_content = exported_data.decode('utf-8')
        assert len(csv_content) > 0

        # Should have headers if details exist
        if report.details:
            lines = csv_content.strip().split('\n')
            assert len(lines) >= 1  # At least header row


class TestDashboardData:
    """Test dashboard data aggregation."""

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_dashboard_data_structure(self):
        """Test dashboard data structure."""
        dashboard_data = await reporting_engine.get_dashboard_data("mer_test_001")

        assert "overview" in dashboard_data
        assert "recent_activity" in dashboard_data
        assert "processor_performance" in dashboard_data
        assert "scheme_distribution" in dashboard_data
        assert "fraud_summary" in dashboard_data

        # Verify overview structure
        overview = dashboard_data["overview"]
        assert "total_transactions" in overview
        assert "successful_transactions" in overview
        assert "total_volume" in overview
        assert "success_rate" in overview

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_dashboard_recent_activity(self):
        """Test dashboard recent activity calculation."""
        dashboard_data = await reporting_engine.get_dashboard_data("mer_test_001")
        recent_activity = dashboard_data["recent_activity"]

        assert "transactions_24h" in recent_activity
        assert "volume_24h" in recent_activity
        assert "hourly_breakdown" in recent_activity

        # Hourly breakdown should be a dict with hour keys
        hourly_breakdown = recent_activity["hourly_breakdown"]
        assert isinstance(hourly_breakdown, dict)

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_dashboard_processor_performance(self):
        """Test dashboard processor performance metrics."""
        dashboard_data = await reporting_engine.get_dashboard_data("mer_test_001")
        processor_performance = dashboard_data["processor_performance"]

        assert isinstance(processor_performance, dict)

        # Each processor should have performance stats
        for processor, stats in processor_performance.items():
            assert "total" in stats
            assert "successful" in stats
            assert "success_rate" in stats

    @pytest.mark.monitoring
    @pytest.mark.unit
    async def test_dashboard_fraud_summary(self):
        """Test dashboard fraud summary."""
        dashboard_data = await reporting_engine.get_dashboard_data("mer_test_001")
        fraud_summary = dashboard_data["fraud_summary"]

        assert "high_risk_transactions" in fraud_summary
        assert "average_fraud_score" in fraud_summary
        assert isinstance(fraud_summary["high_risk_transactions"], int)
        assert isinstance(fraud_summary["average_fraud_score"], float)