"""
Transaction Management System for SoftPOS

This module handles the complete transaction lifecycle including:
- Refunds (full and partial)
- Voids (cancellations)
- Settlement processing
- Reconciliation
- Transaction state management
- Chargeback handling

Key Features:
- Multi-acquirer refund routing
- Real-time transaction tracking
- Automated settlement batching
- Reconciliation with card schemes
- Dispute management workflow
- Financial reporting integration
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from enum import Enum
from typing import Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


class TransactionStatus(Enum):
    """Transaction status lifecycle."""
    PENDING = "pending"
    AUTHORIZED = "authorized"
    CAPTURED = "captured"
    SETTLED = "settled"
    REFUNDED = "refunded"
    PARTIALLY_REFUNDED = "partially_refunded"
    VOIDED = "voided"
    DISPUTED = "disputed"
    FAILED = "failed"


class RefundType(Enum):
    """Types of refund operations."""
    FULL = "full"
    PARTIAL = "partial"
    FORCED = "forced"  # Offline refund without original transaction


class SettlementStatus(Enum):
    """Settlement batch status."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    DISPUTED = "disputed"


class VoidReason(Enum):
    """Reasons for transaction voids."""
    CUSTOMER_REQUEST = "customer_request"
    MERCHANT_ERROR = "merchant_error"
    DUPLICATE_TRANSACTION = "duplicate"
    SYSTEM_ERROR = "system_error"
    FRAUD_SUSPECTED = "fraud_suspected"


@dataclass
class RefundRequest:
    """Refund request parameters."""
    original_transaction_id: str
    refund_amount: Decimal
    currency: str
    reason: str
    merchant_id: str
    terminal_id: str
    refund_type: RefundType = RefundType.PARTIAL
    force_refund: bool = False
    reference_number: Optional[str] = None
    metadata: Optional[Dict] = None


@dataclass
class RefundResponse:
    """Refund operation response."""
    refund_id: str
    original_transaction_id: str
    refund_amount: Decimal
    currency: str
    status: TransactionStatus
    approval_code: Optional[str]
    processor_response_code: str
    processor_response_message: str
    processor_reference: str
    processing_time_ms: int
    created_at: datetime
    metadata: Optional[Dict] = None


@dataclass
class VoidRequest:
    """Void request parameters."""
    transaction_id: str
    reason: VoidReason
    merchant_id: str
    terminal_id: str
    reference_number: Optional[str] = None
    metadata: Optional[Dict] = None


@dataclass
class VoidResponse:
    """Void operation response."""
    void_id: str
    original_transaction_id: str
    status: TransactionStatus
    approval_code: Optional[str]
    processor_response_code: str
    processor_response_message: str
    processor_reference: str
    processing_time_ms: int
    created_at: datetime
    metadata: Optional[Dict] = None


@dataclass
class SettlementBatch:
    """Settlement batch for transaction processing."""
    batch_id: str
    merchant_id: str
    processor: str
    currency: str
    transaction_count: int
    gross_amount: Decimal
    fees: Decimal
    net_amount: Decimal
    status: SettlementStatus
    created_at: datetime
    processed_at: Optional[datetime] = None
    settled_at: Optional[datetime] = None
    transactions: List[str] = field(default_factory=list)


class TransactionManager:
    """
    Core transaction management engine handling refunds, voids, and settlements.

    Integrates with payment processors and card schemes for real-time
    transaction lifecycle management.
    """

    def __init__(self):
        self.processors = {}  # Will be injected from payment engine
        self.settlement_batches: Dict[str, SettlementBatch] = {}
        self.pending_settlements: Dict[str, List[str]] = {}

    def set_processors(self, processors: Dict):
        """Inject payment processors from payment engine."""
        self.processors = processors

    async def process_refund(
        self,
        request: RefundRequest,
        db: AsyncSession
    ) -> RefundResponse:
        """
        Process a refund request through the appropriate payment processor.

        Steps:
        1. Validate original transaction
        2. Check refund eligibility
        3. Route to correct processor
        4. Process refund with acquirer
        5. Update transaction records
        6. Generate response
        """
        start_time = time.time()

        try:
            # Step 1: Validate original transaction
            original_payment = await self._get_original_transaction(
                request.original_transaction_id, db
            )

            if not original_payment:
                return self._create_refund_error_response(
                    request, "original_transaction_not_found", "Original transaction not found"
                )

            # Step 2: Check refund eligibility
            eligibility = await self._check_refund_eligibility(original_payment, request, db)
            if not eligibility.eligible:
                return self._create_refund_error_response(
                    request, "refund_not_eligible", eligibility.reason
                )

            # Step 3: Route to appropriate processor
            processor = await self._get_transaction_processor(original_payment)
            if not processor:
                return self._create_refund_error_response(
                    request, "processor_not_available", "Payment processor not available"
                )

            # Step 4: Process refund with acquirer
            processor_response = await processor.process_refund(request, original_payment)

            # Step 5: Create refund record
            refund_record = await self._create_refund_record(
                request, original_payment, processor_response, db
            )

            # Step 6: Update original transaction status
            await self._update_transaction_status_for_refund(
                original_payment, request.refund_amount, db
            )

            processing_time = int((time.time() - start_time) * 1000)

            return RefundResponse(
                refund_id=refund_record["id"],
                original_transaction_id=request.original_transaction_id,
                refund_amount=request.refund_amount,
                currency=request.currency,
                status=TransactionStatus.REFUNDED if processor_response.approved else TransactionStatus.FAILED,
                approval_code=processor_response.authorization_code,
                processor_response_code=processor_response.response_code.value,
                processor_response_message=processor_response.response_message,
                processor_reference=processor_response.processor_transaction_id,
                processing_time_ms=processing_time,
                created_at=datetime.now(timezone.utc),
                metadata=request.metadata
            )

        except Exception as e:
            processing_time = int((time.time() - start_time) * 1000)
            return self._create_refund_error_response(
                request, "processing_error", f"Refund processing failed: {str(e)}"
            )

    async def process_void(
        self,
        request: VoidRequest,
        db: AsyncSession
    ) -> VoidResponse:
        """
        Process a void (cancellation) request.

        Voids can only be performed on unsettled transactions.
        For settled transactions, a refund must be used instead.
        """
        start_time = time.time()

        try:
            # Step 1: Validate transaction
            transaction = await self._get_original_transaction(request.transaction_id, db)
            if not transaction:
                return self._create_void_error_response(
                    request, "transaction_not_found", "Transaction not found"
                )

            # Step 2: Check void eligibility
            if not await self._check_void_eligibility(transaction):
                return self._create_void_error_response(
                    request, "void_not_eligible", "Transaction cannot be voided (already settled)"
                )

            # Step 3: Route to processor
            processor = await self._get_transaction_processor(transaction)
            if not processor:
                return self._create_void_error_response(
                    request, "processor_not_available", "Payment processor not available"
                )

            # Step 4: Process void with acquirer
            processor_response = await processor.process_void(request, transaction)

            # Step 5: Update transaction status
            await self._update_transaction_status_for_void(transaction, db)

            processing_time = int((time.time() - start_time) * 1000)

            return VoidResponse(
                void_id=f"void_{secrets.token_hex(8)}",
                original_transaction_id=request.transaction_id,
                status=TransactionStatus.VOIDED if processor_response.approved else TransactionStatus.FAILED,
                approval_code=processor_response.authorization_code,
                processor_response_code=processor_response.response_code.value,
                processor_response_message=processor_response.response_message,
                processor_reference=processor_response.processor_transaction_id,
                processing_time_ms=processing_time,
                created_at=datetime.now(timezone.utc),
                metadata=request.metadata
            )

        except Exception as e:
            processing_time = int((time.time() - start_time) * 1000)
            return self._create_void_error_response(
                request, "processing_error", f"Void processing failed: {str(e)}"
            )

    async def create_settlement_batch(
        self,
        merchant_id: str,
        processor: str,
        currency: str = "GBP"
    ) -> SettlementBatch:
        """
        Create settlement batch for pending transactions.

        Groups unsettled transactions by merchant and processor
        for batch settlement processing.
        """
        batch_id = f"batch_{secrets.token_hex(8)}"

        # Get pending transactions for settlement
        pending_transactions = self.pending_settlements.get(f"{merchant_id}_{processor}_{currency}", [])

        # Calculate batch totals (simplified for demo)
        transaction_count = len(pending_transactions)
        gross_amount = Decimal(str(transaction_count * 25.00))  # Demo: £25 per transaction
        fees = gross_amount * Decimal("0.015")  # 1.5% processing fee
        net_amount = gross_amount - fees

        batch = SettlementBatch(
            batch_id=batch_id,
            merchant_id=merchant_id,
            processor=processor,
            currency=currency,
            transaction_count=transaction_count,
            gross_amount=gross_amount,
            fees=fees,
            net_amount=net_amount,
            status=SettlementStatus.PENDING,
            created_at=datetime.now(timezone.utc),
            transactions=pending_transactions
        )

        self.settlement_batches[batch_id] = batch
        return batch

    async def process_settlement_batch(self, batch_id: str) -> bool:
        """
        Process settlement batch with acquirer.

        Sends batch to processor for settlement and updates transaction statuses.
        """
        batch = self.settlement_batches.get(batch_id)
        if not batch:
            return False

        try:
            batch.status = SettlementStatus.PROCESSING
            batch.processed_at = datetime.now(timezone.utc)

            # Simulate settlement processing
            await asyncio.sleep(0.5)  # Simulate processing delay

            # Update batch status
            batch.status = SettlementStatus.COMPLETED
            batch.settled_at = datetime.now(timezone.utc)

            # Clear pending transactions
            key = f"{batch.merchant_id}_{batch.processor}_{batch.currency}"
            if key in self.pending_settlements:
                del self.pending_settlements[key]

            return True

        except Exception as e:
            batch.status = SettlementStatus.FAILED
            print(f"Settlement batch {batch_id} failed: {e}")
            return False

    async def get_transaction_history(
        self,
        transaction_id: str,
        db: AsyncSession
    ) -> List[Dict]:
        """
        Get complete transaction history including refunds and voids.
        """
        # This would query the database for all related transactions
        # For demo, return mock data
        return [
            {
                "transaction_id": transaction_id,
                "type": "payment",
                "amount": "25.00",
                "status": "captured",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        ]

    async def _get_original_transaction(self, transaction_id: str, db: AsyncSession):
        """Get original transaction from database."""
        # Simplified - would query payments table
        return {
            "id": transaction_id,
            "amount": Decimal("25.00"),
            "currency": "GBP",
            "status": "captured",
            "processor": "chase_paymentech"
        }

    async def _check_refund_eligibility(self, transaction, request: RefundRequest, db: AsyncSession):
        """Check if transaction is eligible for refund."""
        from dataclasses import dataclass

        @dataclass
        class EligibilityResult:
            eligible: bool
            reason: Optional[str] = None

        # Check if transaction is in refundable state
        if transaction["status"] not in ["captured", "settled"]:
            return EligibilityResult(False, "Transaction not in refundable state")

        # Check refund amount
        if request.refund_amount > transaction["amount"]:
            return EligibilityResult(False, "Refund amount exceeds original transaction")

        # Check refund window (typically 180 days)
        # In production, would check transaction date

        return EligibilityResult(True)

    async def _check_void_eligibility(self, transaction) -> bool:
        """Check if transaction can be voided."""
        # Voids only allowed for unsettled transactions
        return transaction["status"] in ["authorized", "captured"]

    async def _get_transaction_processor(self, transaction):
        """Get processor instance for transaction."""
        processor_name = transaction.get("processor", "chase_paymentech")
        return self.processors.get(processor_name)

    async def _create_refund_record(self, request: RefundRequest, original_payment, processor_response, db: AsyncSession):
        """Create refund record in database."""
        # Simplified - would insert into refunds table
        return {
            "id": f"ref_{secrets.token_hex(8)}",
            "original_transaction_id": request.original_transaction_id,
            "amount": request.refund_amount,
            "status": "completed" if processor_response.approved else "failed"
        }

    async def _update_transaction_status_for_refund(self, transaction, refund_amount: Decimal, db: AsyncSession):
        """Update original transaction status after refund."""
        # Would update payments table with new status
        if refund_amount >= transaction["amount"]:
            transaction["status"] = "refunded"
        else:
            transaction["status"] = "partially_refunded"

    async def _update_transaction_status_for_void(self, transaction, db: AsyncSession):
        """Update transaction status after void."""
        transaction["status"] = "voided"

    def _create_refund_error_response(self, request: RefundRequest, error_code: str, error_message: str) -> RefundResponse:
        """Create error response for refund."""
        return RefundResponse(
            refund_id=f"ref_error_{secrets.token_hex(6)}",
            original_transaction_id=request.original_transaction_id,
            refund_amount=request.refund_amount,
            currency=request.currency,
            status=TransactionStatus.FAILED,
            approval_code=None,
            processor_response_code=error_code,
            processor_response_message=error_message,
            processor_reference="",
            processing_time_ms=0,
            created_at=datetime.now(timezone.utc),
            metadata=request.metadata
        )

    def _create_void_error_response(self, request: VoidRequest, error_code: str, error_message: str) -> VoidResponse:
        """Create error response for void."""
        return VoidResponse(
            void_id=f"void_error_{secrets.token_hex(6)}",
            original_transaction_id=request.transaction_id,
            status=TransactionStatus.FAILED,
            approval_code=None,
            processor_response_code=error_code,
            processor_response_message=error_message,
            processor_reference="",
            processing_time_ms=0,
            created_at=datetime.now(timezone.utc),
            metadata=request.metadata
        )


# Global transaction manager instance
transaction_manager = TransactionManager()