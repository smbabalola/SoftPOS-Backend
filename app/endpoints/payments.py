"""
Custom Payment Processing Endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from typing import Optional
import structlog

from ..simple_auth import CurrentUser, require_payments_create
from ..payment_processor.core import payment_processor, CardData, TransactionStatus

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/payments", tags=["payments"])


class PaymentRequest(BaseModel):
    """Payment processing request"""
    amount: int = Field(..., gt=0, description="Amount in pence")
    currency: str = Field(default="GBP", description="Currency code")
    description: str = Field(..., min_length=1, max_length=255)

    # Card data
    card_number: str = Field(..., min_length=13, max_length=19)
    expiry_month: int = Field(..., ge=1, le=12)
    expiry_year: int = Field(..., ge=24, le=99)
    cvv: str = Field(..., min_length=3, max_length=4)

    # Optional fields
    terminal_id: Optional[str] = Field(default="SOFTPOS_001")
    reference: Optional[str] = Field(None, max_length=100)


class PaymentResponse(BaseModel):
    """Payment processing response"""
    transaction_id: str
    status: str
    amount: Optional[int] = None
    currency: Optional[str] = None
    authorization_code: Optional[str] = None
    card_last_four: Optional[str] = None
    card_type: Optional[str] = None
    processing_fee: Optional[int] = None
    decline_reason: Optional[str] = None
    risk_score: Optional[float] = None
    created_at: Optional[str] = None


@router.post("/process", response_model=PaymentResponse)
async def process_payment(
    payment_request: PaymentRequest,
    current_user: CurrentUser = Depends(require_payments_create)
):
    """Process a real payment transaction"""

    try:
        # Create card data object
        card_data = CardData(
            pan=payment_request.card_number.replace(" ", ""),
            expiry_month=payment_request.expiry_month,
            expiry_year=payment_request.expiry_year,
            cvv=payment_request.cvv
        )

        # Process payment through custom processor
        result = await payment_processor.process_payment(
            amount=payment_request.amount,
            card_data=card_data,
            merchant_id=current_user.merchant_id,
            terminal_id=payment_request.terminal_id,
            currency=payment_request.currency
        )

        # Return response
        return PaymentResponse(**result)

    except ValueError as e:
        logger.warning(
            "Payment validation failed",
            error=str(e),
            merchant_id=current_user.merchant_id
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(
            "Payment processing error",
            error=str(e),
            merchant_id=current_user.merchant_id
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Payment processing failed"
        )


@router.get("/test-cards")
async def get_test_cards():
    """Get test card numbers for development"""
    return {
        "test_cards": {
            "success": {
                "visa": "4242424242424242",
                "mastercard": "5555555555554444",
                "description": "These cards will be approved"
            },
            "decline_insufficient_funds": {
                "visa": "4000000000000002",
                "description": "Will be declined with 'Insufficient funds'"
            },
            "decline_blocked": {
                "visa": "4000000000000069",
                "description": "Will be declined with 'Card blocked'"
            }
        },
        "test_data": {
            "expiry_month": 12,
            "expiry_year": 25,
            "cvv": "123"
        }
    }


class RefundRequest(BaseModel):
    """Refund request"""
    transaction_id: str = Field(..., description="Original transaction ID")
    amount: Optional[int] = Field(None, description="Refund amount (full refund if not specified)")
    reason: str = Field(..., min_length=1, max_length=255)


@router.post("/refund")
async def process_refund(
    refund_request: RefundRequest,
    current_user: CurrentUser = Depends(require_payments_create)
):
    """Process a refund"""

    # TODO: Implement refund processing
    # This would involve:
    # 1. Find original transaction
    # 2. Validate refund amount
    # 3. Process refund through payment processor
    # 4. Update transaction status

    return {
        "message": "Refund processing not yet implemented",
        "transaction_id": refund_request.transaction_id,
        "status": "pending"
    }