from __future__ import annotations

from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .attestation import attestation_validator, AttestationStatus, DevicePlatform
from .auth import CurrentUser, create_access_token, require_payments_create, require_payments_read
from .database import get_db
from .db_models import MerchantTable, PaymentIntentTable, PaymentTable
from .fraud_detection import fraud_engine
from .hsm import hsm_manager
from .idempotency import store as idem_store
from .payment_processing import (
    payment_engine, PaymentRequest, CardData, TransactionType, BillingAddress
)
from .models import (
    APIError,
    Merchant,
    MerchantApplicationRequest,
    Payment,
    PaymentConfirm,
    PaymentIntent,
    PaymentIntentCreate,
)
from .startup import startup
from .endpoints.card_schemes import router as card_schemes_router
from .endpoints.emv import router as emv_router
from .endpoints.terminal_management import router as terminal_management_router
from .endpoints.webhooks import router as webhooks_router
from .endpoints.monitoring import router as monitoring_router
from .endpoints.realtime import router as realtime_router

app = FastAPI(title="Surepay API", version="0.1.0")

# Add CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for debugging
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# Include routers
app.include_router(card_schemes_router)
app.include_router(emv_router)
app.include_router(terminal_management_router)
app.include_router(webhooks_router)
app.include_router(monitoring_router)
app.include_router(realtime_router)


@app.on_event("startup")
async def startup_event():
    await startup()

    # Initialize payment engine with security components
    payment_engine.set_fraud_engine(fraud_engine)
    payment_engine.set_hsm_manager(hsm_manager)

    # Start real-time services
    from .realtime import start_realtime_tasks, integrate_with_monitoring
    await start_realtime_tasks()
    await integrate_with_monitoring()


@app.options("/v1/auth/token")
async def options_auth_token():
    """Handle CORS preflight for auth token endpoint."""
    return PlainTextResponse("", status_code=200, headers={
        "Access-Control-Allow-Origin": "http://localhost:5173",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Allow-Credentials": "true",
    })




@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.post("/v1/merchants/apply", response_model=Merchant, status_code=201)
async def apply_merchant(
    application: MerchantApplicationRequest,
    db: AsyncSession = Depends(get_db),
):
    """Apply for merchant account."""
    import secrets

    merchant_id = f"mer_{secrets.token_hex(6)}"

    merchant_db = MerchantTable(
        id=merchant_id,
        legal_name=application.legal_name,
        trading_name=application.trading_name,
        country=application.country,
        mcc=application.mcc,
        tier=application.tier or "tier1",
    )

    db.add(merchant_db)
    await db.commit()
    await db.refresh(merchant_db)

    return Merchant(
        id=merchant_db.id,
        legal_name=merchant_db.legal_name,
        trading_name=merchant_db.trading_name,
        mcc=merchant_db.mcc,
        tier=merchant_db.tier,
        country=merchant_db.country,
        kyc_status=merchant_db.kyc_status,
        settlement_schedule=merchant_db.settlement_schedule,
        default_fee_plan_id=merchant_db.default_fee_plan_id,
        limits={
            "per_transaction_minor": merchant_db.per_transaction_limit_minor,
            "daily_volume_minor": merchant_db.daily_volume_limit_minor,
        },
    )


@app.post("/v1/auth/token")
async def create_token(
    merchant_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Create access token for merchant (simplified for demo)."""
    result = await db.execute(select(MerchantTable).where(MerchantTable.id == merchant_id))
    merchant = result.scalar_one_or_none()

    if not merchant:
        raise HTTPException(status_code=404, detail="merchant_not_found")

    access_token = create_access_token(
        data={"sub": merchant_id, "scopes": ["payments:create", "payments:read"]}
    )

    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/v1/attestation/validate")
async def validate_attestation_endpoint(
    device_id: str,
    platform: str,
    attestation_token: str,
    nonce: str
):
    """Test endpoint for device attestation validation."""
    try:
        platform_enum = DevicePlatform.IOS if platform.lower() == "ios" else DevicePlatform.ANDROID
        result = await attestation_validator.validate_attestation(
            attestation_token, nonce, platform_enum
        )
        return {
            "status": result.status.value,
            "device_id": result.device_id,
            "platform": result.platform.value,
            "risk_score": result.risk_score,
            "details": result.details
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/v1/hsm/keys/generate")
async def generate_hsm_keys(
    merchant_id: str,
    current_user: CurrentUser = Depends(require_payments_create)
):
    """Generate HSM keys for a merchant."""
    try:
        keys = await hsm_manager.generate_merchant_keys(merchant_id)
        return {"merchant_id": merchant_id, "keys": keys}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/v1/hsm/encrypt")
async def test_hsm_encryption(
    data: str,
    merchant_id: str,
    current_user: CurrentUser = Depends(require_payments_create)
):
    """Test HSM encryption functionality."""
    try:
        encrypted_data, key_ref = await hsm_manager.encrypt_payment_data(data, merchant_id)
        return {
            "encrypted_data": encrypted_data[:50] + "...",  # Truncate for display
            "key_reference": key_ref,
            "original_length": len(data),
            "encrypted_length": len(encrypted_data)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/v1/hsm/sign")
async def test_hsm_signing(
    transaction_data: dict,
    merchant_id: str,
    current_user: CurrentUser = Depends(require_payments_create)
):
    """Test HSM transaction signing."""
    try:
        signature = await hsm_manager.sign_transaction(transaction_data, merchant_id)
        is_valid = await hsm_manager.verify_transaction(transaction_data, signature, merchant_id)
        return {
            "signature": signature[:50] + "...",  # Truncate for display
            "verification": "valid" if is_valid else "invalid",
            "canonical_data": hsm_manager._canonicalize_transaction(transaction_data)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/v1/payments/process-card")
async def process_card_payment(
    card_number: str,
    expiry_month: str,
    expiry_year: str,
    cvv: str,
    amount: float,
    currency: str = "USD",
    current_user: CurrentUser = Depends(require_payments_create)
):
    """Direct card payment processing endpoint for testing."""
    try:
        from decimal import Decimal
        import uuid

        # Create payment request
        payment_request = PaymentRequest(
            transaction_id=f"test_{uuid.uuid4().hex[:8]}",
            merchant_id=current_user.merchant_id,
            amount=Decimal(str(amount)),
            currency=currency,
            transaction_type=TransactionType.SALE,
            card_data=CardData(
                pan=card_number,
                expiry_month=expiry_month,
                expiry_year=expiry_year,
                cvv=cvv
            ),
            description="Test card payment",
            terminal_id="test_terminal"
        )

        # Process payment
        payment_response = await payment_engine.process_payment(payment_request)

        return {
            "transaction_id": payment_response.transaction_id,
            "processor_transaction_id": payment_response.processor_transaction_id,
            "approved": payment_response.approved,
            "authorization_code": payment_response.authorization_code,
            "response_code": payment_response.response_code.value,
            "response_message": payment_response.response_message,
            "processor": payment_response.processor.value,
            "card_scheme": payment_response.card_scheme.value,
            "amount": str(payment_response.amount),
            "currency": payment_response.currency,
            "avs_result": payment_response.avs_result,
            "cvv_result": payment_response.cvv_result,
            "processing_time_ms": payment_response.processing_time_ms,
            "network_transaction_id": payment_response.network_transaction_id
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post(
    "/v1/payments/intent",
    response_model=PaymentIntent,
    responses={400: {"model": APIError}},
    status_code=201,
)
async def create_payment_intent(
    body: PaymentIntentCreate,
    response: Response,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_payments_create),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    # Ensure merchant can only create intents for themselves (unless admin)
    if body.merchant_id != current_user.merchant_id and "admin" not in current_user.scopes:
        raise HTTPException(status_code=403, detail="Cannot create payment intent for another merchant")

    fp = f"{request.url.path}:{body.merchant_id}:{body.amount_minor}:{body.currency}:{body.capture_mode}:{body.channel}:{body.tip_minor}"
    if idempotency_key:
        key = idem_store.make_key(idempotency_key, fp)
        cached = await idem_store.get(key)
        if cached:
            status_code, payload = cached
            return JSONResponse(payload, status_code=status_code)

    intent_db = PaymentIntentTable.create_new(
        merchant_id=body.merchant_id,
        amount_minor=body.amount_minor,
        currency=body.currency,
        capture_mode=body.capture_mode.value if body.capture_mode else None,
        tip_minor=body.tip_minor,
        extra_data=body.metadata,
    )

    db.add(intent_db)
    await db.commit()
    await db.refresh(intent_db)

    intent = PaymentIntent(
        id=intent_db.id,
        status=intent_db.status,
        ephemeral_key=intent_db.ephemeral_key,
        amount_minor=intent_db.amount_minor,
        currency=intent_db.currency,
        capture_mode=intent_db.capture_mode,
        tip_minor=intent_db.tip_minor,
        metadata=intent_db.extra_data,
    )

    payload = intent.model_dump()
    if idempotency_key:
        await idem_store.set(idem_store.make_key(idempotency_key, fp), 201, payload)
    return payload


@app.post(
    "/v1/payments/intent/{intent_id}/confirm",
    response_model=Payment,
    responses={400: {"model": APIError}},
)
async def confirm_payment_intent(
    intent_id: str,
    body: PaymentConfirm,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(require_payments_create),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    # Fetch intent from database
    result = await db.execute(select(PaymentIntentTable).where(PaymentIntentTable.id == intent_id))
    intent_db = result.scalar_one_or_none()
    if not intent_db:
        raise HTTPException(status_code=404, detail="intent_not_found")

    # Validate device attestation for security
    if body.attestation:
        # Extract platform from device_id (in production, this would be more sophisticated)
        platform = DevicePlatform.IOS if "ios" in body.device_id.lower() else DevicePlatform.ANDROID

        # Generate nonce based on intent (in production, store nonces in secure storage)
        expected_nonce = f"nonce_{intent_id}_{intent_db.created_at.timestamp()}"

        attestation_result = await attestation_validator.validate_attestation(
            body.attestation, expected_nonce, platform
        )

        # Reject payments from compromised or untrusted devices
        if attestation_result.status != AttestationStatus.VALID:
            raise HTTPException(
                status_code=400,
                detail=f"Device attestation failed: {attestation_result.status.value}"
            )

        # Apply additional risk checks for high-risk devices
        if attestation_result.risk_score > 0.7:
            raise HTTPException(
                status_code=400,
                detail="Payment rejected due to high device risk score"
            )

    # Minimal fingerprint for idempotency on confirm
    fp = f"{request.url.path}:{body.device_id}:{intent_id}:{body.attestation}:{body.emv_payload}"
    if idempotency_key:
        key = idem_store.make_key(idempotency_key, fp)
        cached = await idem_store.get(key)
        if cached:
            status_code, payload = cached
            return JSONResponse(payload, status_code=status_code)

    # Extract card data from EMV payload (in production, this would be properly parsed EMV data)
    # For demo, we'll simulate card data extraction
    if body.emv_payload:
        # Parse mock EMV data
        emv_parts = body.emv_payload.split("|") if "|" in body.emv_payload else ["4111111111111111", "12", "25", "123"]
        card_data = CardData(
            pan=emv_parts[0] if len(emv_parts) > 0 else "4111111111111111",
            expiry_month=emv_parts[1] if len(emv_parts) > 1 else "12",
            expiry_year=emv_parts[2] if len(emv_parts) > 2 else "25",
            cvv=emv_parts[3] if len(emv_parts) > 3 else "123"
        )
    else:
        # Fallback test card data
        card_data = CardData(
            pan="4111111111111111",
            expiry_month="12",
            expiry_year="25",
            cvv="123"
        )

    # Create payment request for real processing
    from decimal import Decimal
    payment_request = PaymentRequest(
        transaction_id=intent_id,
        merchant_id=current_user.merchant_id,
        amount=Decimal(str(intent_db.amount_minor / 100)),  # Convert to major units
        currency=intent_db.currency,
        transaction_type=TransactionType.SALE,
        card_data=card_data,
        order_id=intent_id,
        description=f"SoftPOS payment for {intent_db.amount_minor/100} {intent_db.currency}",
        terminal_id=body.device_id,
        capture_mode=intent_db.capture_mode or "auto"
    )

    # Process payment through real payment engine
    try:
        payment_response = await payment_engine.process_payment(payment_request)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Payment processing failed: {str(e)}")

    # Check if payment was approved
    if not payment_response.approved:
        raise HTTPException(
            status_code=400,
            detail=f"Payment declined: {payment_response.response_message}"
        )

    # Create payment record with real processor response
    payment_db = PaymentTable.create_from_intent(
        intent=intent_db,
        device_id=body.device_id,
        emv_payload=body.emv_payload,
        attestation=body.attestation,
    )

    # Update with real payment processor data
    payment_db.auth_code = payment_response.authorization_code
    payment_db.scheme = payment_response.card_scheme.value.upper()
    payment_db.extra_data = payment_db.extra_data or {}
    payment_db.extra_data.update({
        "processor": payment_response.processor.value,
        "processor_transaction_id": payment_response.processor_transaction_id,
        "response_code": payment_response.response_code.value,
        "avs_result": payment_response.avs_result,
        "cvv_result": payment_response.cvv_result,
        "network_transaction_id": payment_response.network_transaction_id,
        "processing_time_ms": payment_response.processing_time_ms,
        "risk_score": payment_response.risk_score
    })

    db.add(payment_db)
    intent_db.status = "succeeded"
    await db.commit()
    await db.refresh(payment_db)

    payment = Payment(
        id=payment_db.id,
        payment_intent_id=payment_db.payment_intent_id,
        status=payment_db.status,
        scheme=payment_db.scheme,
        brand=payment_db.brand,
        last4=payment_db.last4,
        auth_code=payment_db.auth_code,
        approved_at=payment_db.approved_at.isoformat() if payment_db.approved_at else None,
        amount_minor=payment_db.amount_minor,
        currency=payment_db.currency,
        tip_minor=payment_db.tip_minor,
        metadata=payment_db.extra_data,
    )

    payload = payment.model_dump()
    if idempotency_key:
        await idem_store.set(idem_store.make_key(idempotency_key, fp), 200, payload)
    return payload
