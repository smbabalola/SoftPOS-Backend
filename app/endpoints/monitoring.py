"""
Monitoring & Analytics API Endpoints

RESTful API for accessing real-time monitoring data, analytics, and system health.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import CurrentUser, require_payments_read
from ..monitoring import monitoring_engine, AlertSeverity, MetricType, SystemStatus
from ..reporting import reporting_engine, ReportType, ReportFormat, ReportFrequency

router = APIRouter(prefix="/v1/monitoring", tags=["Monitoring & Analytics"])


class MetricRequest(BaseModel):
    """Request model for recording custom metrics."""
    name: str = Field(..., description="Metric name")
    value: float = Field(..., description="Metric value")
    metric_type: str = Field(..., description="Metric type (counter, gauge, histogram, timer)")
    tags: Optional[Dict[str, str]] = Field(default_factory=dict, description="Metric tags")
    description: Optional[str] = Field(None, description="Metric description")


class AlertResponse(BaseModel):
    """Response model for alert information."""
    alert_id: str
    title: str
    description: str
    severity: str
    component: str
    timestamp: str
    resolved: bool
    resolved_at: Optional[str]
    metadata: Dict


class HealthCheckResponse(BaseModel):
    """Response model for health check information."""
    component: str
    status: str
    response_time_ms: float
    timestamp: str
    error_message: Optional[str]
    metadata: Dict


class SystemOverviewResponse(BaseModel):
    """Response model for system overview."""
    timestamp: str
    overall_status: str
    active_alerts: int
    health_checks: Dict
    recent_metrics: Dict
    transaction_summary: Dict


@router.get("/overview", response_model=SystemOverviewResponse)
async def get_system_overview(
    current_user: CurrentUser = Depends(require_payments_read)
):
    """Get comprehensive system overview."""
    overview = await monitoring_engine.get_system_overview()

    return SystemOverviewResponse(
        timestamp=overview["timestamp"],
        overall_status=overview["overall_status"].value,
        active_alerts=overview["active_alerts"],
        health_checks=overview["health_checks"],
        recent_metrics=overview["recent_metrics"],
        transaction_summary=overview["transaction_summary"]
    )


@router.get("/health", response_model=List[HealthCheckResponse])
async def get_health_checks(
    component: Optional[str] = Query(None, description="Filter by component"),
    current_user: CurrentUser = Depends(require_payments_read)
):
    """Get system health checks."""
    health_checks = monitoring_engine.health_checks

    if component and component in health_checks:
        health_checks = {component: health_checks[component]}

    return [
        HealthCheckResponse(
            component=check.component,
            status=check.status.value,
            response_time_ms=check.response_time_ms,
            timestamp=check.timestamp.isoformat(),
            error_message=check.error_message,
            metadata=check.metadata
        )
        for check in health_checks.values()
    ]


@router.get("/alerts", response_model=List[AlertResponse])
async def get_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    component: Optional[str] = Query(None, description="Filter by component"),
    resolved: Optional[bool] = Query(None, description="Filter by resolution status"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of results"),
    current_user: CurrentUser = Depends(require_payments_read)
):
    """Get system alerts."""
    alerts = list(monitoring_engine.alerts.values())

    # Apply filters
    if severity:
        try:
            severity_filter = AlertSeverity(severity)
            alerts = [a for a in alerts if a.severity == severity_filter]
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid severity filter")

    if component:
        alerts = [a for a in alerts if a.component == component]

    if resolved is not None:
        alerts = [a for a in alerts if a.resolved == resolved]

    # Sort by timestamp (newest first) and limit
    alerts.sort(key=lambda a: a.timestamp, reverse=True)
    alerts = alerts[:limit]

    return [
        AlertResponse(
            alert_id=alert.alert_id,
            title=alert.title,
            description=alert.description,
            severity=alert.severity.value,
            component=alert.component,
            timestamp=alert.timestamp.isoformat(),
            resolved=alert.resolved,
            resolved_at=alert.resolved_at.isoformat() if alert.resolved_at else None,
            metadata=alert.metadata
        )
        for alert in alerts
    ]


@router.post("/alerts/{alert_id}/resolve")
async def resolve_alert(
    alert_id: str,
    current_user: CurrentUser = Depends(require_payments_read)
):
    """Resolve an active alert."""
    success = await monitoring_engine.resolve_alert(alert_id)
    if not success:
        raise HTTPException(status_code=404, detail="Alert not found")

    return {"message": "Alert resolved successfully", "alert_id": alert_id}


@router.post("/metrics")
async def record_metric(
    request: MetricRequest,
    current_user: CurrentUser = Depends(require_payments_read)
):
    """Record a custom metric."""
    try:
        metric_type = MetricType(request.metric_type)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid metric type")

    from ..monitoring import Metric

    metric = Metric(
        name=request.name,
        value=request.value,
        metric_type=metric_type,
        timestamp=datetime.now(timezone.utc),
        tags=request.tags,
        description=request.description
    )

    await monitoring_engine.record_metric(metric)

    return {"message": "Metric recorded successfully", "metric_name": request.name}


@router.get("/metrics/{metric_name}")
async def get_metric_history(
    metric_name: str,
    start_time: Optional[datetime] = Query(None, description="Start time for metric data"),
    end_time: Optional[datetime] = Query(None, description="End time for metric data"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of data points"),
    current_user: CurrentUser = Depends(require_payments_read)
):
    """Get metric history."""
    if metric_name not in monitoring_engine.metrics_store:
        raise HTTPException(status_code=404, detail="Metric not found")

    metrics = list(monitoring_engine.metrics_store[metric_name])

    # Apply time filters
    if start_time:
        metrics = [m for m in metrics if m.timestamp >= start_time]
    if end_time:
        metrics = [m for m in metrics if m.timestamp <= end_time]

    # Sort by timestamp and limit
    metrics.sort(key=lambda m: m.timestamp)
    if len(metrics) > limit:
        # Sample evenly if too many points
        step = len(metrics) // limit
        metrics = metrics[::step][:limit]

    return {
        "metric_name": metric_name,
        "data_points": [
            {
                "timestamp": metric.timestamp.isoformat(),
                "value": metric.value,
                "tags": metric.tags
            }
            for metric in metrics
        ],
        "total_points": len(metrics)
    }


@router.get("/transactions/metrics")
async def get_transaction_metrics(
    start_time: Optional[datetime] = Query(None, description="Start time for metrics"),
    end_time: Optional[datetime] = Query(None, description="End time for metrics"),
    current_user: CurrentUser = Depends(require_payments_read)
):
    """Get transaction processing metrics."""
    metrics = await monitoring_engine.get_transaction_metrics(start_time, end_time)

    return {
        "total_transactions": metrics.total_transactions,
        "successful_transactions": metrics.successful_transactions,
        "failed_transactions": metrics.failed_transactions,
        "total_volume": str(metrics.total_volume),
        "average_amount": str(metrics.average_amount),
        "success_rate": f"{metrics.success_rate:.2%}",
        "average_processing_time_ms": f"{metrics.average_processing_time_ms:.1f}",
        "peak_tps": metrics.peak_tps,
        "processor_breakdown": metrics.processor_breakdown,
        "scheme_breakdown": metrics.scheme_breakdown,
        "error_breakdown": metrics.error_breakdown
    }


@router.get("/dashboard")
async def get_dashboard_data(
    current_user: CurrentUser = Depends(require_payments_read)
):
    """Get real-time dashboard data."""
    # Get data from both monitoring and reporting engines
    system_overview = await monitoring_engine.get_system_overview()
    dashboard_data = await reporting_engine.get_dashboard_data(current_user.merchant_id)

    # Combine the data
    return {
        "system_status": {
            "overall_status": system_overview["overall_status"].value,
            "active_alerts": system_overview["active_alerts"],
            "health_checks": system_overview["health_checks"]
        },
        "business_metrics": dashboard_data["overview"],
        "recent_activity": dashboard_data["recent_activity"],
        "processor_performance": dashboard_data["processor_performance"],
        "scheme_distribution": dashboard_data["scheme_distribution"],
        "fraud_summary": dashboard_data["fraud_summary"],
        "top_merchants": dashboard_data["top_merchants"] if current_user.merchant_id is None else {}
    }


@router.get("/reports/types")
async def list_report_types():
    """List available report types."""
    return {
        "report_types": [
            {
                "value": report_type.value,
                "description": report_type.value.replace("_", " ").title()
            }
            for report_type in ReportType
        ]
    }


@router.post("/reports/generate")
async def generate_report(
    report_type: str,
    start_date: datetime,
    end_date: datetime,
    format: str = "json",
    include_raw_data: bool = False,
    current_user: CurrentUser = Depends(require_payments_read)
):
    """Generate a custom report."""
    try:
        report_type_enum = ReportType(report_type)
        format_enum = ReportFormat(format)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    from ..reporting import ReportRequest

    # Create report request
    request = ReportRequest(
        report_type=report_type_enum,
        start_date=start_date,
        end_date=end_date,
        merchant_id=current_user.merchant_id,
        format=format_enum,
        include_raw_data=include_raw_data
    )

    # Generate report
    report = await reporting_engine.generate_report(request)

    if format_enum == ReportFormat.JSON:
        return {
            "report_id": report.report_id,
            "report_type": report.report_type.value,
            "generated_at": report.generated_at.isoformat(),
            "data_period": {
                "start": report.data_period[0].isoformat(),
                "end": report.data_period[1].isoformat()
            },
            "summary": report.summary,
            "details": report.details,
            "metadata": report.metadata
        }
    else:
        # Export in requested format
        export_data = await reporting_engine.export_report(report, format_enum)

        # Return file info for download
        return {
            "report_id": report.report_id,
            "format": format_enum.value,
            "size_bytes": len(export_data),
            "download_url": f"/v1/reports/{report.report_id}/download"
        }


@router.get("/reports/{report_id}")
async def get_report(
    report_id: str,
    current_user: CurrentUser = Depends(require_payments_read)
):
    """Get generated report."""
    if report_id not in reporting_engine.report_cache:
        raise HTTPException(status_code=404, detail="Report not found")

    report = reporting_engine.report_cache[report_id]

    # Verify merchant access (simplified - in production would check proper ownership)
    # For now, assume all users can access cached reports

    return {
        "report_id": report.report_id,
        "report_type": report.report_type.value,
        "generated_at": report.generated_at.isoformat(),
        "data_period": {
            "start": report.data_period[0].isoformat(),
            "end": report.data_period[1].isoformat()
        },
        "summary": report.summary,
        "details": report.details[:100],  # Limit details for API response
        "metadata": report.metadata
    }


@router.get("/performance/terminals")
async def get_terminal_performance_overview(
    current_user: CurrentUser = Depends(require_payments_read)
):
    """Get performance overview for all merchant terminals."""
    # This would integrate with terminal manager
    # For now, return mock data
    return {
        "total_terminals": 5,
        "active_terminals": 4,
        "performance_summary": {
            "average_uptime": "99.2%",
            "average_success_rate": "97.8%",
            "total_transactions_today": 1250,
            "total_volume_today": "£45,678.90"
        },
        "top_performing_terminals": [
            {
                "terminal_id": "term_001",
                "name": "Store Front Register",
                "success_rate": "99.1%",
                "uptime": "99.8%",
                "transactions_today": 345
            },
            {
                "terminal_id": "term_002",
                "name": "Mobile Terminal 1",
                "success_rate": "98.7%",
                "uptime": "98.9%",
                "transactions_today": 278
            }
        ]
    }


@router.get("/analytics/trends")
async def get_analytics_trends(
    metric: str = Query(..., description="Metric to analyze (volume, transactions, success_rate)"),
    period: str = Query("24h", description="Time period (1h, 24h, 7d, 30d)"),
    current_user: CurrentUser = Depends(require_payments_read)
):
    """Get analytics trends for specified metrics."""
    # Parse period
    period_mapping = {
        "1h": timedelta(hours=1),
        "24h": timedelta(days=1),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30)
    }

    if period not in period_mapping:
        raise HTTPException(status_code=400, detail="Invalid period")

    end_time = datetime.now(timezone.utc)
    start_time = end_time - period_mapping[period]

    # Get transaction metrics for the period
    metrics = await monitoring_engine.get_transaction_metrics(start_time, end_time)

    # Generate trend data (simplified)
    if metric == "volume":
        trend_data = {
            "current_value": str(metrics.total_volume),
            "trend": "up",
            "percentage_change": "+12.5%",
            "comparison_period": f"vs previous {period}"
        }
    elif metric == "transactions":
        trend_data = {
            "current_value": metrics.total_transactions,
            "trend": "up",
            "percentage_change": "+8.3%",
            "comparison_period": f"vs previous {period}"
        }
    elif metric == "success_rate":
        trend_data = {
            "current_value": f"{metrics.success_rate:.2%}",
            "trend": "stable",
            "percentage_change": "-0.1%",
            "comparison_period": f"vs previous {period}"
        }
    else:
        raise HTTPException(status_code=400, detail="Invalid metric")

    return {
        "metric": metric,
        "period": period,
        "data": trend_data,
        "last_updated": end_time.isoformat()
    }