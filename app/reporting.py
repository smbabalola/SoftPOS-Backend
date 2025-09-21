"""
Advanced Reporting System for SoftPOS

This module provides comprehensive reporting capabilities including:
- Financial reports and reconciliation
- Transaction analytics and trends
- Merchant performance dashboards
- Compliance and audit reports
- Real-time business intelligence
- Automated report generation
- Data export in multiple formats

Report Types:
- Daily/Weekly/Monthly transaction summaries
- Settlement reports
- Chargeback and dispute reports
- Fraud analysis reports
- Performance and SLA reports
- Compliance audit reports
- Custom business intelligence reports
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from enum import Enum
from typing import Dict, List, Optional, Tuple, Union

import xlsxwriter


class ReportType(Enum):
    """Types of reports available."""
    TRANSACTION_SUMMARY = "transaction_summary"
    SETTLEMENT_REPORT = "settlement_report"
    MERCHANT_PERFORMANCE = "merchant_performance"
    FRAUD_ANALYSIS = "fraud_analysis"
    COMPLIANCE_AUDIT = "compliance_audit"
    CHARGEBACK_REPORT = "chargeback_report"
    PROCESSOR_PERFORMANCE = "processor_performance"
    SCHEME_ANALYSIS = "scheme_analysis"


class ReportFormat(Enum):
    """Report output formats."""
    PDF = "pdf"
    CSV = "csv"
    XLSX = "xlsx"
    JSON = "json"
    HTML = "html"


class ReportFrequency(Enum):
    """Report generation frequency."""
    REALTIME = "realtime"
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    ANNUAL = "annual"


@dataclass
class ReportRequest:
    """Report generation request."""
    report_type: ReportType
    start_date: datetime
    end_date: datetime
    merchant_id: Optional[str] = None
    terminal_id: Optional[str] = None
    format: ReportFormat = ReportFormat.JSON
    filters: Dict = field(default_factory=dict)
    group_by: Optional[List[str]] = None
    include_raw_data: bool = False


@dataclass
class ReportData:
    """Generated report data."""
    report_id: str
    report_type: ReportType
    generated_at: datetime
    data_period: Tuple[datetime, datetime]
    summary: Dict
    details: List[Dict]
    metadata: Dict = field(default_factory=dict)


@dataclass
class TransactionSummary:
    """Transaction summary data."""
    period: str
    transaction_count: int
    successful_count: int
    failed_count: int
    total_volume: Decimal
    average_transaction_value: Decimal
    success_rate: float
    processor_breakdown: Dict[str, int]
    scheme_breakdown: Dict[str, int]
    payment_method_breakdown: Dict[str, int]


@dataclass
class MerchantPerformance:
    """Merchant performance metrics."""
    merchant_id: str
    merchant_name: str
    transaction_volume: Decimal
    transaction_count: int
    success_rate: float
    average_processing_time: float
    fraud_rate: float
    chargeback_rate: float
    top_performing_terminals: List[str]
    performance_trend: str  # "improving", "stable", "declining"


class ReportingEngine:
    """
    Advanced reporting engine for SoftPOS analytics and business intelligence.

    Generates comprehensive reports for merchants, processors, and compliance.
    """

    def __init__(self):
        self.report_cache: Dict[str, ReportData] = {}
        self.scheduled_reports: Dict[str, Dict] = {}

        # Sample data for demo reports
        self._initialize_sample_data()

    def _initialize_sample_data(self):
        """Initialize sample data for demo reports."""
        self.sample_transactions = [
            {
                "transaction_id": f"tx_{i:06d}",
                "merchant_id": "mer_demo_001",
                "terminal_id": f"term_{(i % 5) + 1:03d}",
                "amount": Decimal(str(25.00 + (i % 100))),
                "currency": "GBP",
                "processor": ["chase_paymentech", "first_data", "worldpay"][i % 3],
                "scheme": ["visa", "mastercard", "amex"][i % 3],
                "approved": i % 10 != 0,  # 90% success rate
                "processing_time_ms": 150 + (i % 100),
                "timestamp": datetime.now(timezone.utc) - timedelta(minutes=i),
                "fraud_score": (i % 100) / 100.0,
                "payment_method": "contactless" if i % 2 == 0 else "chip_pin"
            }
            for i in range(1000)
        ]

    async def generate_report(self, request: ReportRequest) -> ReportData:
        """Generate report based on request parameters."""
        report_id = f"rpt_{int(datetime.now().timestamp())}_{hash(str(request)) % 10000}"

        if request.report_type == ReportType.TRANSACTION_SUMMARY:
            data = await self._generate_transaction_summary_report(request)
        elif request.report_type == ReportType.MERCHANT_PERFORMANCE:
            data = await self._generate_merchant_performance_report(request)
        elif request.report_type == ReportType.FRAUD_ANALYSIS:
            data = await self._generate_fraud_analysis_report(request)
        elif request.report_type == ReportType.SETTLEMENT_REPORT:
            data = await self._generate_settlement_report(request)
        elif request.report_type == ReportType.PROCESSOR_PERFORMANCE:
            data = await self._generate_processor_performance_report(request)
        else:
            data = await self._generate_default_report(request)

        report = ReportData(
            report_id=report_id,
            report_type=request.report_type,
            generated_at=datetime.now(timezone.utc),
            data_period=(request.start_date, request.end_date),
            summary=data["summary"],
            details=data["details"],
            metadata={
                "filters_applied": request.filters,
                "group_by": request.group_by,
                "total_records": len(data["details"])
            }
        )

        # Cache report
        self.report_cache[report_id] = report

        return report

    async def export_report(self, report: ReportData, format: ReportFormat) -> bytes:
        """Export report in specified format."""
        if format == ReportFormat.CSV:
            return await self._export_csv(report)
        elif format == ReportFormat.XLSX:
            return await self._export_xlsx(report)
        elif format == ReportFormat.JSON:
            return await self._export_json(report)
        elif format == ReportFormat.HTML:
            return await self._export_html(report)
        else:
            return await self._export_json(report)

    async def schedule_report(
        self,
        request: ReportRequest,
        frequency: ReportFrequency,
        recipients: List[str],
        schedule_name: str
    ) -> str:
        """Schedule automatic report generation."""
        schedule_id = f"sched_{int(datetime.now().timestamp())}"

        schedule_config = {
            "schedule_id": schedule_id,
            "schedule_name": schedule_name,
            "request": request,
            "frequency": frequency,
            "recipients": recipients,
            "created_at": datetime.now(timezone.utc),
            "last_run": None,
            "next_run": self._calculate_next_run(frequency),
            "active": True
        }

        self.scheduled_reports[schedule_id] = schedule_config
        return schedule_id

    async def get_dashboard_data(self, merchant_id: Optional[str] = None) -> Dict:
        """Get real-time dashboard data."""
        # Filter transactions for dashboard
        filtered_transactions = self.sample_transactions[:100]  # Last 100 transactions

        if merchant_id:
            filtered_transactions = [
                tx for tx in filtered_transactions
                if tx["merchant_id"] == merchant_id
            ]

        # Calculate dashboard metrics
        total_transactions = len(filtered_transactions)
        successful_transactions = len([tx for tx in filtered_transactions if tx["approved"]])
        total_volume = sum(tx["amount"] for tx in filtered_transactions)
        success_rate = successful_transactions / total_transactions if total_transactions > 0 else 0

        # Recent activity (last 24 hours)
        recent_cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        recent_transactions = [
            tx for tx in filtered_transactions
            if tx["timestamp"] >= recent_cutoff
        ]

        # Top merchants (if not filtered by merchant)
        top_merchants = {}
        if not merchant_id:
            merchant_volumes = {}
            for tx in filtered_transactions:
                mid = tx["merchant_id"]
                merchant_volumes[mid] = merchant_volumes.get(mid, Decimal("0")) + tx["amount"]

            top_merchants = dict(sorted(merchant_volumes.items(), key=lambda x: x[1], reverse=True)[:5])

        return {
            "overview": {
                "total_transactions": total_transactions,
                "successful_transactions": successful_transactions,
                "total_volume": str(total_volume),
                "success_rate": f"{success_rate:.2%}",
                "average_transaction_value": str(total_volume / total_transactions) if total_transactions > 0 else "0"
            },
            "recent_activity": {
                "transactions_24h": len(recent_transactions),
                "volume_24h": str(sum(tx["amount"] for tx in recent_transactions)),
                "hourly_breakdown": self._calculate_hourly_breakdown(recent_transactions)
            },
            "processor_performance": self._calculate_processor_breakdown(filtered_transactions),
            "scheme_distribution": self._calculate_scheme_breakdown(filtered_transactions),
            "top_merchants": top_merchants,
            "fraud_summary": {
                "high_risk_transactions": len([tx for tx in filtered_transactions if tx["fraud_score"] > 0.7]),
                "average_fraud_score": sum(tx["fraud_score"] for tx in filtered_transactions) / len(filtered_transactions) if filtered_transactions else 0
            }
        }

    async def _generate_transaction_summary_report(self, request: ReportRequest) -> Dict:
        """Generate transaction summary report."""
        # Filter transactions by date range
        filtered_transactions = [
            tx for tx in self.sample_transactions
            if request.start_date <= tx["timestamp"] <= request.end_date
        ]

        # Apply additional filters
        if request.merchant_id:
            filtered_transactions = [
                tx for tx in filtered_transactions
                if tx["merchant_id"] == request.merchant_id
            ]

        if request.terminal_id:
            filtered_transactions = [
                tx for tx in filtered_transactions
                if tx["terminal_id"] == request.terminal_id
            ]

        # Calculate summary metrics
        total_count = len(filtered_transactions)
        successful_count = len([tx for tx in filtered_transactions if tx["approved"]])
        failed_count = total_count - successful_count
        total_volume = sum(tx["amount"] for tx in filtered_transactions)
        success_rate = successful_count / total_count if total_count > 0 else 0

        # Group by processor
        processor_breakdown = {}
        for tx in filtered_transactions:
            processor = tx["processor"]
            processor_breakdown[processor] = processor_breakdown.get(processor, 0) + 1

        # Group by scheme
        scheme_breakdown = {}
        for tx in filtered_transactions:
            scheme = tx["scheme"]
            scheme_breakdown[scheme] = scheme_breakdown.get(scheme, 0) + 1

        summary = {
            "total_transactions": total_count,
            "successful_transactions": successful_count,
            "failed_transactions": failed_count,
            "total_volume": str(total_volume),
            "average_transaction_value": str(total_volume / total_count) if total_count > 0 else "0",
            "success_rate": f"{success_rate:.2%}",
            "processor_breakdown": processor_breakdown,
            "scheme_breakdown": scheme_breakdown
        }

        # Prepare detailed data
        details = []
        if request.include_raw_data:
            details = [
                {
                    "transaction_id": tx["transaction_id"],
                    "timestamp": tx["timestamp"].isoformat(),
                    "merchant_id": tx["merchant_id"],
                    "amount": str(tx["amount"]),
                    "currency": tx["currency"],
                    "processor": tx["processor"],
                    "scheme": tx["scheme"],
                    "approved": tx["approved"],
                    "processing_time_ms": tx["processing_time_ms"]
                }
                for tx in filtered_transactions[-100:]  # Last 100 for details
            ]

        return {"summary": summary, "details": details}

    async def _generate_merchant_performance_report(self, request: ReportRequest) -> Dict:
        """Generate merchant performance report."""
        # Group transactions by merchant
        merchant_data = {}
        for tx in self.sample_transactions:
            if request.start_date <= tx["timestamp"] <= request.end_date:
                merchant_id = tx["merchant_id"]
                if merchant_id not in merchant_data:
                    merchant_data[merchant_id] = []
                merchant_data[merchant_id].append(tx)

        merchant_performances = []
        for merchant_id, transactions in merchant_data.items():
            total_volume = sum(tx["amount"] for tx in transactions)
            total_count = len(transactions)
            successful_count = len([tx for tx in transactions if tx["approved"]])
            success_rate = successful_count / total_count if total_count > 0 else 0
            avg_processing_time = sum(tx["processing_time_ms"] for tx in transactions) / total_count
            fraud_count = len([tx for tx in transactions if tx["fraud_score"] > 0.7])
            fraud_rate = fraud_count / total_count if total_count > 0 else 0

            merchant_performances.append({
                "merchant_id": merchant_id,
                "merchant_name": f"Merchant {merchant_id.split('_')[-1]}",
                "transaction_volume": str(total_volume),
                "transaction_count": total_count,
                "success_rate": f"{success_rate:.2%}",
                "average_processing_time": f"{avg_processing_time:.1f}ms",
                "fraud_rate": f"{fraud_rate:.2%}",
                "chargeback_rate": "0.1%"  # Demo value
            })

        # Sort by volume
        merchant_performances.sort(key=lambda x: float(x["transaction_volume"]), reverse=True)

        summary = {
            "total_merchants": len(merchant_performances),
            "top_merchant_by_volume": merchant_performances[0]["merchant_id"] if merchant_performances else None,
            "average_success_rate": f"{sum(float(m['success_rate'].rstrip('%')) for m in merchant_performances) / len(merchant_performances):.2f}%" if merchant_performances else "0%"
        }

        return {"summary": summary, "details": merchant_performances}

    async def _generate_fraud_analysis_report(self, request: ReportRequest) -> Dict:
        """Generate fraud analysis report."""
        filtered_transactions = [
            tx for tx in self.sample_transactions
            if request.start_date <= tx["timestamp"] <= request.end_date
        ]

        # Fraud analysis
        high_risk_transactions = [tx for tx in filtered_transactions if tx["fraud_score"] > 0.7]
        medium_risk_transactions = [tx for tx in filtered_transactions if 0.4 <= tx["fraud_score"] <= 0.7]
        low_risk_transactions = [tx for tx in filtered_transactions if tx["fraud_score"] < 0.4]

        fraud_by_processor = {}
        for tx in high_risk_transactions:
            processor = tx["processor"]
            fraud_by_processor[processor] = fraud_by_processor.get(processor, 0) + 1

        summary = {
            "total_transactions_analyzed": len(filtered_transactions),
            "high_risk_transactions": len(high_risk_transactions),
            "medium_risk_transactions": len(medium_risk_transactions),
            "low_risk_transactions": len(low_risk_transactions),
            "overall_fraud_rate": f"{len(high_risk_transactions) / len(filtered_transactions):.2%}" if filtered_transactions else "0%",
            "fraud_by_processor": fraud_by_processor
        }

        details = [
            {
                "transaction_id": tx["transaction_id"],
                "fraud_score": tx["fraud_score"],
                "risk_level": "HIGH" if tx["fraud_score"] > 0.7 else "MEDIUM" if tx["fraud_score"] > 0.4 else "LOW",
                "processor": tx["processor"],
                "amount": str(tx["amount"]),
                "timestamp": tx["timestamp"].isoformat()
            }
            for tx in high_risk_transactions[:50]  # Top 50 high-risk transactions
        ]

        return {"summary": summary, "details": details}

    async def _generate_settlement_report(self, request: ReportRequest) -> Dict:
        """Generate settlement report."""
        # Mock settlement data
        summary = {
            "settlement_period": f"{request.start_date.date()} to {request.end_date.date()}",
            "total_batches": 15,
            "total_settled_amount": "£125,450.00",
            "total_fees": "£1,881.75",
            "net_settlement": "£123,568.25",
            "settlement_status": "Completed"
        }

        # Mock settlement details
        details = [
            {
                "batch_id": f"batch_{i:06d}",
                "processor": ["chase_paymentech", "first_data"][i % 2],
                "transaction_count": 50 + (i * 5),
                "gross_amount": f"£{8000 + (i * 100):.2f}",
                "fees": f"£{120 + (i * 1.5):.2f}",
                "net_amount": f"£{7880 + (i * 98.5):.2f}",
                "settled_date": (request.start_date + timedelta(days=i)).date().isoformat()
            }
            for i in range(15)
        ]

        return {"summary": summary, "details": details}

    async def _generate_processor_performance_report(self, request: ReportRequest) -> Dict:
        """Generate processor performance report."""
        # Group by processor
        processor_data = {}
        for tx in self.sample_transactions:
            if request.start_date <= tx["timestamp"] <= request.end_date:
                processor = tx["processor"]
                if processor not in processor_data:
                    processor_data[processor] = []
                processor_data[processor].append(tx)

        processor_performances = []
        for processor, transactions in processor_data.items():
            total_count = len(transactions)
            successful_count = len([tx for tx in transactions if tx["approved"]])
            success_rate = successful_count / total_count if total_count > 0 else 0
            avg_processing_time = sum(tx["processing_time_ms"] for tx in transactions) / total_count
            total_volume = sum(tx["amount"] for tx in transactions)

            processor_performances.append({
                "processor": processor,
                "transaction_count": total_count,
                "success_rate": f"{success_rate:.2%}",
                "average_processing_time": f"{avg_processing_time:.1f}ms",
                "total_volume": str(total_volume),
                "uptime": "99.9%",  # Demo value
                "availability": "Available"
            })

        summary = {
            "processors_analyzed": len(processor_performances),
            "best_performing_processor": max(processor_performances, key=lambda x: float(x["success_rate"].rstrip('%')))["processor"] if processor_performances else None,
            "average_processing_time": f"{sum(float(p['average_processing_time'].rstrip('ms')) for p in processor_performances) / len(processor_performances):.1f}ms" if processor_performances else "0ms"
        }

        return {"summary": summary, "details": processor_performances}

    async def _generate_default_report(self, request: ReportRequest) -> Dict:
        """Generate default report structure."""
        return {
            "summary": {"message": f"Report type {request.report_type.value} not implemented"},
            "details": []
        }

    async def _export_csv(self, report: ReportData) -> bytes:
        """Export report as CSV."""
        output = io.StringIO()
        if report.details:
            writer = csv.DictWriter(output, fieldnames=report.details[0].keys())
            writer.writeheader()
            writer.writerows(report.details)

        return output.getvalue().encode('utf-8')

    async def _export_xlsx(self, report: ReportData) -> bytes:
        """Export report as Excel file."""
        output = io.BytesIO()
        workbook = xlsxwriter.Workbook(output, {'in_memory': True})
        worksheet = workbook.add_worksheet('Report')

        # Write headers
        if report.details:
            headers = list(report.details[0].keys())
            for col, header in enumerate(headers):
                worksheet.write(0, col, header)

            # Write data
            for row, record in enumerate(report.details, 1):
                for col, header in enumerate(headers):
                    worksheet.write(row, col, record.get(header, ''))

        workbook.close()
        output.seek(0)
        return output.read()

    async def _export_json(self, report: ReportData) -> bytes:
        """Export report as JSON."""
        report_dict = {
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

        return json.dumps(report_dict, indent=2).encode('utf-8')

    async def _export_html(self, report: ReportData) -> bytes:
        """Export report as HTML."""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SoftPOS Report - {report.report_type.value}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f4f4f4; padding: 10px; border-radius: 5px; }}
                .summary {{ margin: 20px 0; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>SoftPOS Report: {report.report_type.value.replace('_', ' ').title()}</h1>
                <p>Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                <p>Period: {report.data_period[0].strftime('%Y-%m-%d')} to {report.data_period[1].strftime('%Y-%m-%d')}</p>
            </div>

            <div class="summary">
                <h2>Summary</h2>
                <ul>
        """

        for key, value in report.summary.items():
            html += f"<li><strong>{key.replace('_', ' ').title()}:</strong> {value}</li>"

        html += """
                </ul>
            </div>

            <div class="details">
                <h2>Details</h2>
        """

        if report.details:
            html += "<table><thead><tr>"
            headers = list(report.details[0].keys())
            for header in headers:
                html += f"<th>{header.replace('_', ' ').title()}</th>"
            html += "</tr></thead><tbody>"

            for record in report.details:
                html += "<tr>"
                for header in headers:
                    html += f"<td>{record.get(header, '')}</td>"
                html += "</tr>"

            html += "</tbody></table>"

        html += """
            </div>
        </body>
        </html>
        """

        return html.encode('utf-8')

    def _calculate_next_run(self, frequency: ReportFrequency) -> datetime:
        """Calculate next run time for scheduled report."""
        now = datetime.now(timezone.utc)

        if frequency == ReportFrequency.HOURLY:
            return now + timedelta(hours=1)
        elif frequency == ReportFrequency.DAILY:
            return now + timedelta(days=1)
        elif frequency == ReportFrequency.WEEKLY:
            return now + timedelta(weeks=1)
        elif frequency == ReportFrequency.MONTHLY:
            return now + timedelta(days=30)
        else:
            return now + timedelta(days=1)

    def _calculate_hourly_breakdown(self, transactions: List[Dict]) -> Dict[str, int]:
        """Calculate hourly transaction breakdown."""
        hourly_counts = {}
        for tx in transactions:
            hour = tx["timestamp"].strftime("%H:00")
            hourly_counts[hour] = hourly_counts.get(hour, 0) + 1
        return hourly_counts

    def _calculate_processor_breakdown(self, transactions: List[Dict]) -> Dict[str, Dict]:
        """Calculate processor performance breakdown."""
        processor_stats = {}
        for tx in transactions:
            processor = tx["processor"]
            if processor not in processor_stats:
                processor_stats[processor] = {"total": 0, "successful": 0}

            processor_stats[processor]["total"] += 1
            if tx["approved"]:
                processor_stats[processor]["successful"] += 1

        # Calculate success rates
        for processor, stats in processor_stats.items():
            stats["success_rate"] = f"{stats['successful'] / stats['total']:.2%}" if stats['total'] > 0 else "0%"

        return processor_stats

    def _calculate_scheme_breakdown(self, transactions: List[Dict]) -> Dict[str, int]:
        """Calculate card scheme distribution."""
        scheme_counts = {}
        for tx in transactions:
            scheme = tx["scheme"]
            scheme_counts[scheme] = scheme_counts.get(scheme, 0) + 1
        return scheme_counts


# Global reporting engine instance
reporting_engine = ReportingEngine()