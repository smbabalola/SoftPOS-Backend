"""
SoftPOS API Models

Pydantic models for API requests/responses.
"""

from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field
from enum import Enum


class APIError(BaseModel):
    """Standard API error response"""
    error: str = Field(..., description="Error code")
    message: str = Field(..., description="Human readable error message")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional error details")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class HealthResponse(BaseModel):
    """Health check response"""
    status: str = "healthy"
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    version: str = "1.0.0"
    database: str = "connected"
    rbac: str = "active"


class PaymentStatus(str, Enum):
    """Payment status enum"""
    PENDING = "pending"
    PROCESSING = "processing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    REFUNDED = "refunded"


class CaptureMode(str, Enum):
    """Payment capture mode"""
    AUTO = "auto"
    MANUAL = "manual"


class Channel(str, Enum):
    """Payment channel"""
    CARD_PRESENT = "card_present"
    CARD_NOT_PRESENT = "card_not_present"
    ONLINE = "online"
    MOBILE = "mobile"


class PaymentIntentCreate(BaseModel):
    """Create payment intent request"""
    merchant_id: str = Field(..., description="Merchant identifier")
    amount_minor: int = Field(..., gt=0, description="Amount in minor currency units (pence)")
    currency: str = Field(default="GBP", description="Currency code")
    capture_mode: CaptureMode = Field(default=CaptureMode.AUTO, description="Payment capture mode")
    channel: Channel = Field(..., description="Payment channel")
    tip_minor: Optional[int] = Field(None, ge=0, description="Tip amount in minor units")
    reference: Optional[str] = Field(None, description="Merchant reference")
    description: Optional[str] = Field(None, description="Payment description")
    metadata: Optional[Dict[str, str]] = Field(None, description="Additional metadata")


class PaymentIntent(BaseModel):
    """Payment intent response"""
    payment_intent_id: str = Field(..., description="Payment intent identifier")
    merchant_id: str = Field(..., description="Merchant identifier")
    amount_minor: int = Field(..., description="Amount in minor currency units")
    currency: str = Field(..., description="Currency code")
    status: PaymentStatus = Field(..., description="Payment status")
    capture_mode: CaptureMode = Field(..., description="Payment capture mode")
    channel: Channel = Field(..., description="Payment channel")
    tip_minor: Optional[int] = Field(None, description="Tip amount")
    reference: Optional[str] = Field(None, description="Merchant reference")
    description: Optional[str] = Field(None, description="Payment description")
    metadata: Optional[Dict[str, str]] = Field(None, description="Additional metadata")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: Optional[datetime] = Field(None, description="Last update timestamp")


class PaymentConfirm(BaseModel):
    """Payment confirmation request"""
    device_id: str = Field(..., description="Device identifier")
    emv_payload: str = Field(..., description="EMV transaction data")
    attestation: str = Field(..., description="Device attestation")
    pin_verified: Optional[bool] = Field(None, description="PIN verification status")
    cardholder_verification: Optional[str] = Field(None, description="Cardholder verification method")


class Payment(BaseModel):
    """Payment response"""
    payment_id: str = Field(..., description="Payment identifier")
    payment_intent_id: str = Field(..., description="Associated payment intent")
    merchant_id: str = Field(..., description="Merchant identifier")
    amount_minor: int = Field(..., description="Amount in minor currency units")
    currency: str = Field(..., description="Currency code")
    status: PaymentStatus = Field(..., description="Payment status")
    channel: Channel = Field(..., description="Payment channel")
    payment_method: Optional[str] = Field(None, description="Payment method used")
    card_last_four: Optional[str] = Field(None, description="Last four digits of card")
    authorization_code: Optional[str] = Field(None, description="Authorization code")
    transaction_id: Optional[str] = Field(None, description="Transaction identifier")
    tip_minor: Optional[int] = Field(None, description="Tip amount")
    reference: Optional[str] = Field(None, description="Merchant reference")
    description: Optional[str] = Field(None, description="Payment description")
    metadata: Optional[Dict[str, str]] = Field(None, description="Additional metadata")
    processed_at: Optional[datetime] = Field(None, description="Processing timestamp")
    created_at: datetime = Field(..., description="Creation timestamp")


class MerchantStatus(str, Enum):
    """Merchant status enum"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING = "pending"


class Merchant(BaseModel):
    """Merchant information"""
    merchant_id: str = Field(..., description="Merchant identifier")
    business_name: str = Field(..., description="Business name")
    email: EmailStr = Field(..., description="Contact email")
    phone: Optional[str] = Field(None, description="Contact phone")
    address: Optional[str] = Field(None, description="Business address")
    status: MerchantStatus = Field(..., description="Merchant status")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: Optional[datetime] = Field(None, description="Last update timestamp")


class MerchantApplicationRequest(BaseModel):
    """Merchant application request"""
    business_name: str = Field(..., description="Business name")
    email: EmailStr = Field(..., description="Contact email")
    phone: Optional[str] = Field(None, description="Contact phone")
    address: Optional[str] = Field(None, description="Business address")
    business_type: Optional[str] = Field(None, description="Type of business")
    description: Optional[str] = Field(None, description="Business description")


class TransactionSummary(BaseModel):
    """Transaction summary for reporting"""
    total_amount: int = Field(..., description="Total amount in minor units")
    transaction_count: int = Field(..., description="Number of transactions")
    success_rate: float = Field(..., description="Success rate percentage")
    period_start: datetime = Field(..., description="Period start")
    period_end: datetime = Field(..., description="Period end")


class RefundRequest(BaseModel):
    """Refund request"""
    amount_minor: Optional[int] = Field(None, description="Refund amount (full if not specified)")
    reason: str = Field(..., description="Refund reason")
    reference: Optional[str] = Field(None, description="Refund reference")


class RefundResponse(BaseModel):
    """Refund response"""
    refund_id: str = Field(..., description="Refund identifier")
    payment_id: str = Field(..., description="Original payment identifier")
    amount_minor: int = Field(..., description="Refunded amount")
    status: str = Field(..., description="Refund status")
    reason: str = Field(..., description="Refund reason")
    processed_at: datetime = Field(..., description="Processing timestamp")


class PaginationParams(BaseModel):
    """Pagination parameters"""
    page: int = Field(default=1, ge=1, description="Page number")
    limit: int = Field(default=20, ge=1, le=100, description="Items per page")


class PaginatedResponse(BaseModel):
    """Paginated response wrapper"""
    items: List[Any] = Field(..., description="Response items")
    total: int = Field(..., description="Total item count")
    page: int = Field(..., description="Current page")
    limit: int = Field(..., description="Items per page")
    pages: int = Field(..., description="Total pages")


# Export all models
__all__ = [
    "APIError",
    "HealthResponse",
    "PaymentStatus",
    "CaptureMode",
    "Channel",
    "PaymentIntentCreate",
    "PaymentIntent",
    "PaymentConfirm",
    "Payment",
    "MerchantStatus",
    "Merchant",
    "MerchantApplicationRequest",
    "TransactionSummary",
    "RefundRequest",
    "RefundResponse",
    "PaginationParams",
    "PaginatedResponse"
]