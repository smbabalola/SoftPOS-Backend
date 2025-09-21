from __future__ import annotations

from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class CaptureMode(str, Enum):
    auto = "auto"
    manual = "manual"


class Channel(str, Enum):
    card_present = "card_present"
    card_not_present = "card_not_present"


class MerchantApplicationRequest(BaseModel):
    legal_name: str
    trading_name: Optional[str] = None
    country: str
    mcc: str
    tier: Optional[str] = Field(default="tier1")


class MerchantLimits(BaseModel):
    per_transaction_minor: int = 50000
    daily_volume_minor: int = 200000


class Merchant(BaseModel):
    id: str
    legal_name: str
    trading_name: Optional[str] = None
    mcc: Optional[str] = None
    tier: Optional[str] = None
    country: Optional[str] = None
    kyc_status: str = "pending"
    settlement_schedule: str = "T+1"
    default_fee_plan_id: Optional[str] = None
    limits: MerchantLimits = Field(default_factory=MerchantLimits)


class PaymentIntentCreate(BaseModel):
    merchant_id: str
    amount_minor: int = Field(gt=0)
    currency: str
    capture_mode: CaptureMode = CaptureMode.auto
    channel: Channel
    tip_minor: Optional[int] = Field(default=0, ge=0)
    metadata: Dict[str, Any] | None = None


class PaymentIntent(BaseModel):
    id: str
    status: str = "requires_presentment"
    ephemeral_key: str
    amount_minor: int = 0
    currency: str = "GBP"
    capture_mode: CaptureMode | None = None
    tip_minor: int | None = 0
    metadata: Dict[str, Any] | None = None
    expires_at: Optional[str] = None


class PaymentConfirm(BaseModel):
    device_id: str
    emv_payload: Optional[str] = None
    attestation: Optional[str] = None


class Payment(BaseModel):
    id: str
    payment_intent_id: str
    status: str
    scheme: Optional[str] = "VISA"
    brand: Optional[str] = "Debit"
    last4: Optional[str] = "1234"
    auth_code: Optional[str] = None
    approved_at: Optional[str] = None
    amount_minor: int
    currency: str
    tip_minor: Optional[int] = 0
    metadata: Dict[str, Any] | None = None


class RefundCreate(BaseModel):
    payment_id: str
    amount_minor: int
    reason: Optional[str] = None


class Refund(BaseModel):
    id: str
    payment_id: str
    amount_minor: int
    status: str


class APIError(BaseModel):
    code: str
    message: str
    details: Optional[Dict[str, Any]] = None
    request_id: Optional[str] = None
