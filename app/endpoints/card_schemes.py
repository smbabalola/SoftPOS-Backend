"""
Card Scheme API Endpoints for SoftPOS

This module provides API endpoints for testing and managing card scheme integrations.
Includes endpoints for:
- Testing scheme connectivity
- Token provisioning
- Scheme capabilities
- Direct scheme transactions
"""

from __future__ import annotations

from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..auth import CurrentUser, require_payments_create, require_payments_read
from ..card_schemes import CardSchemeManager, SchemeRequest, CardScheme

router = APIRouter(prefix="/v1/card-schemes", tags=["Card Schemes"])


class TokenProvisionRequest(BaseModel):
    pan: str
    merchant_id: str


class SchemeTestRequest(BaseModel):
    scheme: str
    pan: str
    amount: float
    currency: str = "USD"


class SchemeCapabilitiesResponse(BaseModel):
    scheme: str
    capabilities: Dict


@router.get("/capabilities/{scheme}")
async def get_scheme_capabilities(
    scheme: str,
    current_user: CurrentUser = Depends(require_payments_read)
):
    """Get capabilities and features supported by a card scheme."""
    try:
        scheme_enum = CardScheme(scheme.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unknown card scheme: {scheme}")

    # Initialize card scheme manager
    scheme_config = {
        "visa": {"demo_mode": True},
        "mastercard": {"demo_mode": True},
        "amex": {"demo_mode": True}
    }

    manager = CardSchemeManager(scheme_config)
    capabilities = manager.get_scheme_capabilities(scheme_enum)

    return SchemeCapabilitiesResponse(
        scheme=scheme_enum.value,
        capabilities=capabilities
    )


@router.post("/test-transaction")
async def test_scheme_transaction(
    request: SchemeTestRequest,
    current_user: CurrentUser = Depends(require_payments_create)
):
    """Test a transaction through a specific card scheme."""
    try:
        scheme_enum = CardScheme(request.scheme.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unknown card scheme: {request.scheme}")

    # Initialize card scheme manager
    scheme_config = {
        "visa": {"demo_mode": True},
        "mastercard": {"demo_mode": True},
        "amex": {"demo_mode": True}
    }

    manager = CardSchemeManager(scheme_config)

    # Create scheme request
    scheme_request = SchemeRequest(
        scheme=scheme_enum,
        transaction_id=f"test_{current_user.merchant_id}_{request.pan[-4:]}",
        merchant_id=current_user.merchant_id,
        amount=request.amount,
        currency=request.currency,
        pan=request.pan,
        expiry_month="12",
        expiry_year="25",
        cvv="123"
    )

    # Process transaction
    response = await manager.process_transaction(scheme_request)

    return {
        "scheme": response.scheme.value,
        "success": response.success,
        "transaction_id": response.transaction_id,
        "scheme_transaction_id": response.scheme_transaction_id,
        "authorization_code": response.authorization_code,
        "response_code": response.response_code,
        "response_message": response.response_message,
        "risk_score": response.risk_score,
        "fees": response.fees,
        "interchange_data": response.interchange_data
    }


@router.post("/provision-token")
async def provision_token(
    request: TokenProvisionRequest,
    current_user: CurrentUser = Depends(require_payments_create)
):
    """Provision a payment token through the appropriate card scheme."""
    # Initialize card scheme manager
    scheme_config = {
        "visa": {"demo_mode": True},
        "mastercard": {"demo_mode": True},
        "amex": {"demo_mode": True}
    }

    manager = CardSchemeManager(scheme_config)

    try:
        # Provision token
        token = await manager.provision_token(request.pan, request.merchant_id)

        return {
            "token_value": token.token_value,
            "scheme": token.scheme.value,
            "token_type": token.token_type.value,
            "last4": token.last4,
            "expiry_month": token.expiry_month,
            "expiry_year": token.expiry_year,
            "created_at": token.created_at,
            "expires_at": token.expires_at
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Token provisioning failed: {str(e)}")


@router.get("/detect-scheme/{pan}")
async def detect_card_scheme(
    pan: str,
    current_user: CurrentUser = Depends(require_payments_read)
):
    """Detect card scheme from PAN (Bank Identification Number)."""
    # Initialize card scheme manager
    scheme_config = {
        "visa": {"demo_mode": True},
        "mastercard": {"demo_mode": True},
        "amex": {"demo_mode": True}
    }

    manager = CardSchemeManager(scheme_config)

    try:
        scheme = manager.detect_card_scheme(pan)
        capabilities = manager.get_scheme_capabilities(scheme)

        return {
            "scheme": scheme.value,
            "bin_range": pan[:6],
            "capabilities": capabilities
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Scheme detection failed: {str(e)}")


@router.post("/detokenize")
async def detokenize_token(
    token_value: str,
    current_user: CurrentUser = Depends(require_payments_create)
):
    """Detokenize a payment token (for authorized operations only)."""
    # Initialize card scheme manager
    scheme_config = {
        "visa": {"demo_mode": True},
        "mastercard": {"demo_mode": True},
        "amex": {"demo_mode": True}
    }

    manager = CardSchemeManager(scheme_config)

    try:
        pan = await manager.detokenize(token_value)

        if not pan:
            raise HTTPException(status_code=404, detail="Token not found or expired")

        return {
            "masked_pan": pan,
            "status": "success"
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Detokenization failed: {str(e)}")


@router.get("/schemes/supported")
async def get_supported_schemes(
    current_user: CurrentUser = Depends(require_payments_read)
):
    """Get list of supported card schemes and their status."""
    schemes = []

    for scheme in CardScheme:
        try:
            # Initialize manager to check if scheme is available
            scheme_config = {scheme.value: {"demo_mode": True}}
            manager = CardSchemeManager(scheme_config)
            capabilities = manager.get_scheme_capabilities(scheme)

            schemes.append({
                "scheme": scheme.value,
                "status": "available",
                "capabilities": capabilities
            })
        except Exception as e:
            schemes.append({
                "scheme": scheme.value,
                "status": "unavailable",
                "error": str(e)
            })

    return {"supported_schemes": schemes}