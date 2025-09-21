"""
EMV Contactless API Endpoints for SoftPOS

This module provides API endpoints for EMV contactless payment processing,
including card detection, transaction processing, and mobile payment simulation.
"""

from __future__ import annotations

from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..auth import CurrentUser, require_payments_create, require_payments_read
from ..emv_kernel import (
    create_emv_kernel, EMVKernelConfig, TransactionType, EMVResult, CVMMethod
)

router = APIRouter(prefix="/v1/emv", tags=["EMV Contactless"])


class ContactlessTransactionRequest(BaseModel):
    amount: int  # Amount in minor units (pence)
    currency: str = "GBP"
    transaction_type: str = "purchase"
    terminal_id: str = "TERMINAL01"


class MobilePaymentRequest(BaseModel):
    device_id: str
    amount: int
    currency: str = "GBP"
    device_type: str = "ios"  # ios, android


class EMVConfigRequest(BaseModel):
    contactless_floor_limit: Optional[int] = None
    contactless_cvm_limit: Optional[int] = None
    contactless_transaction_limit: Optional[int] = None


class ContactlessTransactionResponse(BaseModel):
    transaction_id: str
    result: str
    amount: int
    currency: str
    pan_masked: str
    application_label: str
    cvm_method: str
    cryptogram: Optional[str] = None
    online_required: bool
    emv_data: Dict[str, str]


@router.get("/kernel/status")
async def get_emv_kernel_status(
    current_user: CurrentUser = Depends(require_payments_read)
):
    """Get EMV kernel status and configuration."""
    kernel = create_emv_kernel()

    return {
        "status": "active",
        "supported_applications": list(kernel.supported_applications.keys()),
        "configuration": {
            "terminal_type": kernel.config.terminal_type,
            "contactless_floor_limit": kernel.config.contactless_floor_limit,
            "contactless_cvm_limit": kernel.config.contactless_cvm_limit,
            "contactless_transaction_limit": kernel.config.contactless_transaction_limit,
            "offline_authentication": kernel.config.offline_authentication,
            "cdcvm_supported": kernel.config.cdcvm_supported
        }
    }


@router.post("/kernel/configure")
async def configure_emv_kernel(
    config: EMVConfigRequest,
    current_user: CurrentUser = Depends(require_payments_create)
):
    """Configure EMV kernel parameters."""
    kernel_config = EMVKernelConfig()

    if config.contactless_floor_limit is not None:
        kernel_config.contactless_floor_limit = config.contactless_floor_limit
    if config.contactless_cvm_limit is not None:
        kernel_config.contactless_cvm_limit = config.contactless_cvm_limit
    if config.contactless_transaction_limit is not None:
        kernel_config.contactless_transaction_limit = config.contactless_transaction_limit

    return {
        "status": "configured",
        "configuration": {
            "contactless_floor_limit": kernel_config.contactless_floor_limit,
            "contactless_cvm_limit": kernel_config.contactless_cvm_limit,
            "contactless_transaction_limit": kernel_config.contactless_transaction_limit
        }
    }


@router.get("/detect-cards")
async def detect_contactless_cards(
    timeout_ms: int = 5000,
    current_user: CurrentUser = Depends(require_payments_create)
):
    """Detect contactless cards in the NFC field."""
    kernel = create_emv_kernel()

    try:
        cards = await kernel.detect_cards(timeout_ms)

        detected_cards = []
        for card in cards:
            detected_cards.append({
                "uid": card.uid,
                "aid": card.aid,
                "application_label": card.application_label,
                "interface": card.interface.value,
                "pan_masked": f"****-****-****-{card.pan[-4:]}",
                "expiry_date": card.expiry_date
            })

        return {
            "cards_detected": len(detected_cards),
            "cards": detected_cards
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Card detection failed: {str(e)}")


@router.post("/process-contactless", response_model=ContactlessTransactionResponse)
async def process_contactless_transaction(
    request: ContactlessTransactionRequest,
    current_user: CurrentUser = Depends(require_payments_create)
):
    """Process a contactless EMV transaction."""
    kernel = create_emv_kernel()

    try:
        # Map string transaction type to enum
        transaction_type_map = {
            "purchase": TransactionType.PURCHASE,
            "refund": TransactionType.REFUND,
            "cash_advance": TransactionType.CASH_ADVANCE,
            "cashback": TransactionType.CASHBACK
        }

        tx_type = transaction_type_map.get(request.transaction_type.lower(), TransactionType.PURCHASE)

        # Process the contactless transaction
        result, transaction = await kernel.process_contactless_transaction(
            amount=request.amount,
            currency_code=request.currency,
            transaction_type=tx_type,
            merchant_id=current_user.merchant_id,
            terminal_id=request.terminal_id
        )

        if not transaction.card_data:
            raise HTTPException(status_code=400, detail="No card data available")

        # Get EMV transaction data
        emv_data = kernel.get_transaction_data(transaction)

        return ContactlessTransactionResponse(
            transaction_id=transaction.transaction_id,
            result=result.value,
            amount=transaction.amount,
            currency=transaction.currency_code,
            pan_masked=f"****-****-****-{transaction.card_data.pan[-4:]}",
            application_label=transaction.card_data.application_label,
            cvm_method=transaction.cvm_performed.value,
            cryptogram=transaction.card_data.application_cryptogram,
            online_required=transaction.online_required,
            emv_data=emv_data
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Transaction processing failed: {str(e)}")


@router.post("/mobile-payment")
async def process_mobile_payment(
    request: MobilePaymentRequest,
    current_user: CurrentUser = Depends(require_payments_create)
):
    """Process a mobile payment (Apple Pay, Google Pay, Samsung Pay)."""
    kernel = create_emv_kernel()

    try:
        # Simulate mobile payment card
        mobile_card = kernel.simulate_mobile_payment(request.device_id, request.amount)

        # Add the mobile card to detected cards for processing
        kernel.detected_cards = [mobile_card]

        # Process as contactless transaction with CDCVM
        result, transaction = await kernel.process_contactless_transaction(
            amount=request.amount,
            currency_code=request.currency,
            transaction_type=TransactionType.PURCHASE,
            merchant_id=current_user.merchant_id,
            terminal_id=f"mobile_{request.device_type}"
        )

        if not transaction.card_data:
            raise HTTPException(status_code=400, detail="Mobile payment processing failed")

        # Mobile payments typically use CDCVM
        transaction.cvm_performed = CVMMethod.CDCVM

        emv_data = kernel.get_transaction_data(transaction)
        emv_data["mobile_payment"] = "true"
        emv_data["device_type"] = request.device_type
        emv_data["device_id"] = request.device_id

        return {
            "transaction_id": transaction.transaction_id,
            "result": result.value,
            "amount": transaction.amount,
            "currency": transaction.currency_code,
            "token_masked": f"****-****-****-{transaction.card_data.pan[-4:]}",
            "application_label": transaction.card_data.application_label,
            "cvm_method": "cdcvm",
            "device_type": request.device_type,
            "cryptogram": transaction.card_data.application_cryptogram,
            "online_required": transaction.online_required,
            "emv_data": emv_data
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Mobile payment failed: {str(e)}")


@router.post("/authorize-online")
async def authorize_online_transaction(
    transaction_id: str,
    authorization_response: str,
    current_user: CurrentUser = Depends(require_payments_create)
):
    """Process online authorization response for EMV transaction."""
    kernel = create_emv_kernel()

    try:
        # In a real implementation, we would retrieve the transaction from storage
        # For demo, we'll create a mock transaction
        if not kernel.current_transaction:
            raise HTTPException(status_code=404, detail="Transaction not found")

        transaction = kernel.current_transaction

        # Process online authorization
        result = await kernel.process_online_authorization(transaction, authorization_response)

        return {
            "transaction_id": transaction_id,
            "authorization_result": result.value,
            "cryptogram_type": transaction.cryptogram_type,
            "final_cryptogram": transaction.card_data.application_cryptogram if transaction.card_data else None
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Online authorization failed: {str(e)}")


@router.get("/transaction/{transaction_id}")
async def get_emv_transaction(
    transaction_id: str,
    current_user: CurrentUser = Depends(require_payments_read)
):
    """Get EMV transaction details."""
    kernel = create_emv_kernel()

    # In a real implementation, retrieve from database
    if kernel.current_transaction and kernel.current_transaction.transaction_id == transaction_id:
        transaction = kernel.current_transaction
        emv_data = kernel.get_transaction_data(transaction)

        return {
            "transaction_id": transaction.transaction_id,
            "amount": transaction.amount,
            "currency": transaction.currency_code,
            "transaction_type": transaction.transaction_type.value,
            "timestamp": transaction.timestamp.isoformat(),
            "selected_application": transaction.selected_application,
            "cvm_performed": transaction.cvm_performed.value,
            "online_required": transaction.online_required,
            "offline_approved": transaction.offline_approved,
            "cryptogram_type": transaction.cryptogram_type,
            "risk_score": transaction.risk_score,
            "emv_data": emv_data
        }
    else:
        raise HTTPException(status_code=404, detail="Transaction not found")


@router.get("/applications/supported")
async def get_supported_applications(
    current_user: CurrentUser = Depends(require_payments_read)
):
    """Get list of supported EMV applications."""
    kernel = create_emv_kernel()

    applications = []
    for aid, label in kernel.supported_applications.items():
        applications.append({
            "aid": aid,
            "label": label,
            "scheme": label.split()[0].lower()
        })

    return {
        "supported_applications": applications,
        "total_count": len(applications)
    }


@router.get("/test/simulate-tap")
async def simulate_contactless_tap(
    card_type: str = "visa",
    current_user: CurrentUser = Depends(require_payments_create)
):
    """Simulate a contactless card tap for testing."""
    kernel = create_emv_kernel()

    # Simulate different card types
    card_simulations = {
        "visa": {
            "aid": "A0000000031010",
            "pan": "4111111111111111",
            "label": "VISA CREDIT"
        },
        "mastercard": {
            "aid": "A0000000041010",
            "pan": "5555555555554444",
            "label": "MASTERCARD"
        },
        "amex": {
            "aid": "A00000002501",
            "pan": "378282246310005",
            "label": "AMERICAN EXPRESS"
        }
    }

    if card_type.lower() not in card_simulations:
        raise HTTPException(status_code=400, detail="Unsupported card type")

    sim_data = card_simulations[card_type.lower()]

    return {
        "simulation": "contactless_tap",
        "card_type": card_type.lower(),
        "aid": sim_data["aid"],
        "pan_masked": f"****-****-****-{sim_data['pan'][-4:]}",
        "application_label": sim_data["label"],
        "status": "ready_for_transaction"
    }