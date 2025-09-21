from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


class PaymentIntentTable(Base):
    __tablename__ = "payment_intents"

    id: Mapped[str] = mapped_column(String(50), primary_key=True)
    status: Mapped[str] = mapped_column(String(50), default="requires_presentment")
    ephemeral_key: Mapped[str] = mapped_column(String(100))
    merchant_id: Mapped[str] = mapped_column(String(50))
    amount_minor: Mapped[int]
    currency: Mapped[str] = mapped_column(String(3))
    capture_mode: Mapped[str | None] = mapped_column(String(20), nullable=True)
    tip_minor: Mapped[int] = mapped_column(default=0)
    extra_data: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=func.now())
    updated_at: Mapped[datetime] = mapped_column(default=func.now(), onupdate=func.now())

    @classmethod
    def create_new(
        cls,
        *,
        merchant_id: str,
        amount_minor: int,
        currency: str,
        capture_mode: str | None = None,
        tip_minor: int = 0,
        extra_data: dict[str, Any] | None = None,
    ) -> PaymentIntentTable:
        intent_id = f"pi_{secrets.token_hex(6)}"
        ephemeral_key = f"ek_{secrets.token_urlsafe(16)}"

        return cls(
            id=intent_id,
            ephemeral_key=ephemeral_key,
            merchant_id=merchant_id,
            amount_minor=amount_minor,
            currency=currency,
            capture_mode=capture_mode,
            tip_minor=tip_minor,
            extra_data=extra_data,
        )


class PaymentTable(Base):
    __tablename__ = "payments"

    id: Mapped[str] = mapped_column(String(50), primary_key=True)
    payment_intent_id: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(50))
    scheme: Mapped[str | None] = mapped_column(String(20), nullable=True)
    brand: Mapped[str | None] = mapped_column(String(20), nullable=True)
    last4: Mapped[str | None] = mapped_column(String(4), nullable=True)
    auth_code: Mapped[str | None] = mapped_column(String(20), nullable=True)
    amount_minor: Mapped[int]
    currency: Mapped[str] = mapped_column(String(3))
    tip_minor: Mapped[int] = mapped_column(default=0)
    extra_data: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    device_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    emv_payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    attestation: Mapped[str | None] = mapped_column(Text, nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=func.now())
    updated_at: Mapped[datetime] = mapped_column(default=func.now(), onupdate=func.now())

    @classmethod
    def create_from_intent(
        cls,
        *,
        intent: PaymentIntentTable,
        device_id: str,
        emv_payload: str | None = None,
        attestation: str | None = None,
    ) -> PaymentTable:
        payment_id = f"pay_{secrets.token_hex(6)}"
        auth_code = secrets.token_hex(3)

        return cls(
            id=payment_id,
            payment_intent_id=intent.id,
            status="succeeded",
            scheme="VISA",
            brand="Debit",
            last4="1234",
            auth_code=auth_code,
            amount_minor=intent.amount_minor,
            currency=intent.currency,
            tip_minor=intent.tip_minor,
            extra_data=intent.extra_data,
            device_id=device_id,
            emv_payload=emv_payload,
            attestation=attestation,
            approved_at=datetime.now(timezone.utc),
        )


class MerchantTable(Base):
    __tablename__ = "merchants"

    id: Mapped[str] = mapped_column(String(50), primary_key=True)
    legal_name: Mapped[str] = mapped_column(String(200))
    trading_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    country: Mapped[str] = mapped_column(String(2))
    mcc: Mapped[str] = mapped_column(String(4))
    tier: Mapped[str] = mapped_column(String(20), default="tier1")
    kyc_status: Mapped[str] = mapped_column(String(20), default="pending")
    settlement_schedule: Mapped[str] = mapped_column(String(20), default="T+1")
    default_fee_plan_id: Mapped[str | None] = mapped_column(String(50), nullable=True)
    per_transaction_limit_minor: Mapped[int] = mapped_column(default=50000)
    daily_volume_limit_minor: Mapped[int] = mapped_column(default=200000)
    created_at: Mapped[datetime] = mapped_column(default=func.now())
    updated_at: Mapped[datetime] = mapped_column(default=func.now(), onupdate=func.now())