"""
Card Scheme Integrations for SoftPOS

This module implements direct integrations with major card schemes:
- Visa: Direct Connect, Visa Token Service (VTS), Visa Risk Manager
- Mastercard: Mastercard Connect, MDES (Mastercard Digital Enablement Service)
- American Express: Direct integration, SafeKey authentication

Each scheme has specific requirements for:
1. Message formats and protocols
2. Cryptographic standards
3. Certification requirements
4. Network-specific features
5. Token provisioning and lifecycle management
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from decimal import Decimal
from enum import Enum
from typing import Dict, List, Optional, Union

import httpx


class CardScheme(Enum):
    VISA = "visa"
    MASTERCARD = "mastercard"
    AMEX = "amex"
    DISCOVER = "discover"
    JCB = "jcb"
    UNIONPAY = "unionpay"


class TokenType(Enum):
    PAYMENT = "payment_token"
    PROVISIONING = "provisioning_token"
    AUTHENTICATION = "auth_token"


class TransactionCategory(Enum):
    PURCHASE = "purchase"
    REFUND = "refund"
    AUTHORIZATION = "authorization"
    CAPTURE = "capture"
    VOID = "void"


@dataclass
class CardToken:
    token_value: str
    scheme: CardScheme
    token_type: TokenType
    last4: str
    expiry_month: str
    expiry_year: str
    token_requestor_id: str
    created_at: int
    expires_at: int
    domain_restriction: Optional[str] = None
    usage_limit: Optional[int] = None
    usage_count: int = 0


@dataclass
class SchemeRequest:
    scheme: CardScheme
    transaction_id: str
    merchant_id: str
    amount: Decimal
    currency: str
    pan: Optional[str] = None
    token: Optional[str] = None
    cvv: Optional[str] = None
    expiry_month: Optional[str] = None
    expiry_year: Optional[str] = None
    cardholder_name: Optional[str] = None
    billing_address: Optional[Dict] = None
    three_ds_data: Optional[Dict] = None
    merchant_category: Optional[str] = None
    terminal_id: Optional[str] = None


@dataclass
class SchemeResponse:
    scheme: CardScheme
    success: bool
    transaction_id: str
    scheme_transaction_id: Optional[str] = None
    authorization_code: Optional[str] = None
    response_code: Optional[str] = None
    response_message: Optional[str] = None
    risk_score: Optional[float] = None
    token: Optional[CardToken] = None
    three_ds_required: bool = False
    three_ds_url: Optional[str] = None
    fees: Optional[Dict] = None
    interchange_data: Optional[Dict] = None
    error_details: Optional[Dict] = None


class VisaConnector:
    """
    Visa Direct Connect integration with support for:
    - Visa Token Service (VTS)
    - Visa Risk Manager
    - Visa Checkout
    - Visa Direct (push payments)
    """

    def __init__(self, config: Dict):
        self.config = config
        self.base_url = config.get("base_url", "https://sandbox.api.visa.com")
        self.user_id = config.get("user_id")
        self.password = config.get("password")
        self.cert_path = config.get("cert_path")
        self.key_path = config.get("key_path")
        self.demo_mode = config.get("demo_mode", True)

    async def process_transaction(self, request: SchemeRequest) -> SchemeResponse:
        """Process transaction through Visa network."""
        if self.demo_mode:
            return await self._demo_visa_response(request)

        # Real Visa integration would go here
        visa_request = self._build_visa_request(request)

        async with httpx.AsyncClient(
            cert=(self.cert_path, self.key_path),
            timeout=30.0
        ) as client:
            try:
                response = await client.post(
                    f"{self.base_url}/visadirect/fundstransfer/v1/pullfundstransactions",
                    json=visa_request,
                    auth=(self.user_id, self.password)
                )

                if response.status_code == 200:
                    return self._parse_visa_response(response.json(), request)
                else:
                    return SchemeResponse(
                        scheme=CardScheme.VISA,
                        success=False,
                        transaction_id=request.transaction_id,
                        response_code="visa_error",
                        response_message=f"Visa API error: {response.status_code}"
                    )

            except Exception as e:
                return SchemeResponse(
                    scheme=CardScheme.VISA,
                    success=False,
                    transaction_id=request.transaction_id,
                    response_code="network_error",
                    response_message=f"Network error: {str(e)}"
                )

    async def provision_token(self, pan: str, merchant_id: str) -> CardToken:
        """Provision token through Visa Token Service (VTS)."""
        if self.demo_mode:
            return self._create_demo_token(pan, CardScheme.VISA)

        # Real VTS integration
        vts_request = {
            "clientRequestId": f"req_{secrets.token_hex(8)}",
            "paymentInstrument": {
                "accountNumber": pan,
                "expirationDate": {
                    "month": "12",
                    "year": "2025"
                }
            },
            "tokenRequestorId": self.config.get("token_requestor_id", "40010030273"),
            "tokenType": "PAYMENT_TOKEN"
        }

        # Implementation would make actual VTS API call
        return self._create_demo_token(pan, CardScheme.VISA)

    def _build_visa_request(self, request: SchemeRequest) -> Dict:
        """Build Visa-specific request format."""
        return {
            "clientReferenceNumber": request.transaction_id,
            "amount": str(request.amount),
            "currency": request.currency,
            "merchantCategoryCode": request.merchant_category or "5999",
            "cardAcceptor": {
                "idCode": request.merchant_id,
                "name": "SoftPOS Merchant",
                "terminalId": request.terminal_id or "SOFTPOS01"
            },
            "originalDataElements": {
                "acquiringInstitutionIdentificationCode": "408999",
                "systemTraceAuditNumber": str(int(time.time()) % 999999),
                "timeLocalTransaction": time.strftime("%H%M%S"),
                "dateLocalTransaction": time.strftime("%m%d")
            }
        }

    def _parse_visa_response(self, response_data: Dict, request: SchemeRequest) -> SchemeResponse:
        """Parse Visa response into standard format."""
        return SchemeResponse(
            scheme=CardScheme.VISA,
            success=response_data.get("responseCode") == "00",
            transaction_id=request.transaction_id,
            scheme_transaction_id=response_data.get("transactionIdentifier"),
            authorization_code=response_data.get("approvalCode"),
            response_code=response_data.get("responseCode"),
            response_message=response_data.get("responseCodeDescription"),
            fees=response_data.get("fees"),
            interchange_data=response_data.get("networkInformation")
        )

    async def _demo_visa_response(self, request: SchemeRequest) -> SchemeResponse:
        """Generate demo Visa response."""
        # Simulate Visa processing delay
        await asyncio.sleep(0.2)

        success = not (request.pan and request.pan.startswith("4000"))  # Decline 4000 cards

        return SchemeResponse(
            scheme=CardScheme.VISA,
            success=success,
            transaction_id=request.transaction_id,
            scheme_transaction_id=f"visa_{secrets.token_hex(8)}",
            authorization_code=f"VI{secrets.randbelow(999999):06d}" if success else None,
            response_code="00" if success else "05",
            response_message="Approved" if success else "Do not honor",
            risk_score=0.1 if success else 0.9,
            fees={"interchange": "0.15", "assessment": "0.05"} if success else None
        )

    def _create_demo_token(self, pan: str, scheme: CardScheme) -> CardToken:
        """Create demo token for development."""
        return CardToken(
            token_value=f"visa_{hashlib.sha256(pan.encode()).hexdigest()[:16]}",
            scheme=scheme,
            token_type=TokenType.PAYMENT,
            last4=pan[-4:] if pan else "1111",
            expiry_month="12",
            expiry_year="25",
            token_requestor_id="40010030273",
            created_at=int(time.time()),
            expires_at=int(time.time()) + (365 * 24 * 60 * 60)  # 1 year
        )


class MastercardConnector:
    """
    Mastercard Connect integration with support for:
    - MDES (Mastercard Digital Enablement Service)
    - Mastercard Gateway
    - In Control for Merchants
    - Transaction Risk Score
    """

    def __init__(self, config: Dict):
        self.config = config
        self.base_url = config.get("base_url", "https://sandbox.api.mastercard.com")
        self.consumer_key = config.get("consumer_key")
        self.signing_key_path = config.get("signing_key_path")
        self.demo_mode = config.get("demo_mode", True)

    async def process_transaction(self, request: SchemeRequest) -> SchemeResponse:
        """Process transaction through Mastercard network."""
        if self.demo_mode:
            return await self._demo_mastercard_response(request)

        # Real Mastercard integration
        mc_request = self._build_mastercard_request(request)

        # Mastercard uses OAuth 1.0a with RSA signing
        headers = self._generate_oauth_headers(mc_request)

        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.post(
                    f"{self.base_url}/mdes/digitization/1/0/tokenize",
                    json=mc_request,
                    headers=headers
                )

                if response.status_code == 200:
                    return self._parse_mastercard_response(response.json(), request)
                else:
                    return SchemeResponse(
                        scheme=CardScheme.MASTERCARD,
                        success=False,
                        transaction_id=request.transaction_id,
                        response_code="mc_error",
                        response_message=f"Mastercard API error: {response.status_code}"
                    )

            except Exception as e:
                return SchemeResponse(
                    scheme=CardScheme.MASTERCARD,
                    success=False,
                    transaction_id=request.transaction_id,
                    response_code="network_error",
                    response_message=f"Network error: {str(e)}"
                )

    async def provision_token(self, pan: str, merchant_id: str) -> CardToken:
        """Provision token through MDES."""
        if self.demo_mode:
            return self._create_demo_token(pan, CardScheme.MASTERCARD)

        # Real MDES integration
        mdes_request = {
            "requestId": f"req_{secrets.token_hex(8)}",
            "tokenType": "CLOUD",
            "tokenRequestorId": self.config.get("token_requestor_id", "98765432101"),
            "taskId": f"task_{secrets.token_hex(8)}",
            "fundingAccountInfo": {
                "encryptedPayload": {
                    "encryptedData": self._encrypt_pan(pan),
                    "encryptionCertificateFingerprint": self.config.get("cert_fingerprint"),
                    "encryptionKeyFingerprint": self.config.get("key_fingerprint"),
                    "oaepHashingAlgorithm": "SHA256"
                }
            }
        }

        return self._create_demo_token(pan, CardScheme.MASTERCARD)

    def _build_mastercard_request(self, request: SchemeRequest) -> Dict:
        """Build Mastercard-specific request format."""
        return {
            "partnerBankId": "99999",
            "partnerMerchantId": request.merchant_id,
            "amount": {
                "value": int(request.amount * 100),  # Convert to minor units
                "currency": request.currency
            },
            "transactionInfo": {
                "transactionType": "PURCHASE",
                "transactionId": request.transaction_id,
                "merchantCategoryCode": request.merchant_category or "5999"
            },
            "paymentAccountReference": request.pan or request.token,
            "consumerLanguage": "en"
        }

    def _generate_oauth_headers(self, request_body: Dict) -> Dict:
        """Generate OAuth 1.0a headers for Mastercard API."""
        # Simplified for demo - real implementation would use proper OAuth signing
        return {
            "Authorization": f"OAuth oauth_consumer_key=\"{self.consumer_key}\"",
            "Content-Type": "application/json"
        }

    def _parse_mastercard_response(self, response_data: Dict, request: SchemeRequest) -> SchemeResponse:
        """Parse Mastercard response into standard format."""
        return SchemeResponse(
            scheme=CardScheme.MASTERCARD,
            success=response_data.get("decision") == "APPROVED",
            transaction_id=request.transaction_id,
            scheme_transaction_id=response_data.get("transactionId"),
            authorization_code=response_data.get("authorizationCode"),
            response_code=response_data.get("responseCode"),
            response_message=response_data.get("responseDescription"),
            risk_score=response_data.get("riskScore", {}).get("score"),
            interchange_data=response_data.get("interchangeData")
        )

    async def _demo_mastercard_response(self, request: SchemeRequest) -> SchemeResponse:
        """Generate demo Mastercard response."""
        import asyncio
        await asyncio.sleep(0.15)

        success = not (request.pan and request.pan.startswith("5555"))  # Decline 5555 cards

        return SchemeResponse(
            scheme=CardScheme.MASTERCARD,
            success=success,
            transaction_id=request.transaction_id,
            scheme_transaction_id=f"mc_{secrets.token_hex(8)}",
            authorization_code=f"MC{secrets.randbelow(999999):06d}" if success else None,
            response_code="00" if success else "51",
            response_message="Approved" if success else "Insufficient funds",
            risk_score=0.2 if success else 0.8,
            fees={"interchange": "0.18", "assessment": "0.06"} if success else None
        )

    def _create_demo_token(self, pan: str, scheme: CardScheme) -> CardToken:
        """Create demo token for development."""
        return CardToken(
            token_value=f"mc_{hashlib.sha256(pan.encode()).hexdigest()[:16]}",
            scheme=scheme,
            token_type=TokenType.PAYMENT,
            last4=pan[-4:] if pan else "4444",
            expiry_month="12",
            expiry_year="25",
            token_requestor_id="98765432101",
            created_at=int(time.time()),
            expires_at=int(time.time()) + (365 * 24 * 60 * 60)
        )

    def _encrypt_pan(self, pan: str) -> str:
        """Encrypt PAN for MDES (simplified for demo)."""
        return hashlib.sha256(pan.encode()).hexdigest()


class AmexConnector:
    """
    American Express direct integration with support for:
    - Amex Direct
    - SafeKey authentication (3DS)
    - Amex Express Checkout
    - Merchant-specific features
    """

    def __init__(self, config: Dict):
        self.config = config
        self.base_url = config.get("base_url", "https://apiuat.americanexpress.com")
        self.client_id = config.get("client_id")
        self.client_secret = config.get("client_secret")
        self.merchant_id = config.get("merchant_id")
        self.demo_mode = config.get("demo_mode", True)

    async def process_transaction(self, request: SchemeRequest) -> SchemeResponse:
        """Process transaction through Amex network."""
        if self.demo_mode:
            return await self._demo_amex_response(request)

        # Real Amex integration
        amex_request = self._build_amex_request(request)
        access_token = await self._get_access_token()

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.post(
                    f"{self.base_url}/payments/digital/v2/payments",
                    json=amex_request,
                    headers=headers
                )

                if response.status_code == 201:
                    return self._parse_amex_response(response.json(), request)
                else:
                    return SchemeResponse(
                        scheme=CardScheme.AMEX,
                        success=False,
                        transaction_id=request.transaction_id,
                        response_code="amex_error",
                        response_message=f"Amex API error: {response.status_code}"
                    )

            except Exception as e:
                return SchemeResponse(
                    scheme=CardScheme.AMEX,
                    success=False,
                    transaction_id=request.transaction_id,
                    response_code="network_error",
                    response_message=f"Network error: {str(e)}"
                )

    async def _get_access_token(self) -> str:
        """Get OAuth access token for Amex API."""
        # Simplified for demo
        return f"demo_token_{secrets.token_hex(16)}"

    def _build_amex_request(self, request: SchemeRequest) -> Dict:
        """Build Amex-specific request format."""
        return {
            "merchant_identifier": self.merchant_id,
            "request_id": request.transaction_id,
            "payment_method": {
                "type": "credit_card",
                "credit_card": {
                    "number": request.pan,
                    "security_code": request.cvv,
                    "expiry_month": request.expiry_month,
                    "expiry_year": request.expiry_year
                }
            },
            "order": {
                "order_id": request.transaction_id,
                "amount": {
                    "value": str(request.amount),
                    "currency_code": request.currency
                }
            },
            "capture": True
        }

    def _parse_amex_response(self, response_data: Dict, request: SchemeRequest) -> SchemeResponse:
        """Parse Amex response into standard format."""
        payment = response_data.get("payments", [{}])[0]

        return SchemeResponse(
            scheme=CardScheme.AMEX,
            success=payment.get("status") == "captured",
            transaction_id=request.transaction_id,
            scheme_transaction_id=payment.get("id"),
            authorization_code=payment.get("authorization_code"),
            response_code=payment.get("response_code"),
            response_message=payment.get("response_summary"),
            fees=payment.get("fees")
        )

    async def _demo_amex_response(self, request: SchemeRequest) -> SchemeResponse:
        """Generate demo Amex response."""
        import asyncio
        await asyncio.sleep(0.25)

        success = not (request.pan and request.pan.startswith("3700"))  # Decline 3700 cards

        return SchemeResponse(
            scheme=CardScheme.AMEX,
            success=success,
            transaction_id=request.transaction_id,
            scheme_transaction_id=f"amex_{secrets.token_hex(8)}",
            authorization_code=f"AX{secrets.randbelow(999999):06d}" if success else None,
            response_code="00" if success else "05",
            response_message="Approved" if success else "Do not honor",
            risk_score=0.15 if success else 0.85,
            fees={"assessment": "0.08", "processing": "0.12"} if success else None
        )


class CardSchemeManager:
    """
    Main manager for all card scheme integrations.

    Handles:
    - Routing transactions to appropriate schemes
    - Token provisioning and management
    - Scheme-specific features and compliance
    - Fallback and retry logic
    """

    def __init__(self, config: Dict):
        self.config = config
        self.connectors = {
            CardScheme.VISA: VisaConnector(config.get("visa", {})),
            CardScheme.MASTERCARD: MastercardConnector(config.get("mastercard", {})),
            CardScheme.AMEX: AmexConnector(config.get("amex", {}))
        }
        self.token_store: Dict[str, CardToken] = {}

    def detect_card_scheme(self, pan: str) -> CardScheme:
        """Detect card scheme from PAN (Bank Identification Number)."""
        if not pan or len(pan) < 6:
            raise ValueError("Invalid PAN")

        bin_range = pan[:6]

        # Visa: 4xxxxx
        if bin_range.startswith("4"):
            return CardScheme.VISA

        # Mastercard: 51-55xxxx, 2221-2720xx
        if bin_range.startswith(("51", "52", "53", "54", "55")):
            return CardScheme.MASTERCARD
        if "2221" <= bin_range <= "2720":
            return CardScheme.MASTERCARD

        # Amex: 34xxxx, 37xxxx
        if bin_range.startswith(("34", "37")):
            return CardScheme.AMEX

        # Discover: 6011xx, 622xxx, 64xxxx, 65xxxx
        if bin_range.startswith("6011") or bin_range.startswith("622") or \
           bin_range.startswith(("64", "65")):
            return CardScheme.DISCOVER

        # JCB: 35xxxx
        if bin_range.startswith("35"):
            return CardScheme.JCB

        # UnionPay: 62xxxx
        if bin_range.startswith("62"):
            return CardScheme.UNIONPAY

        raise ValueError(f"Unknown card scheme for BIN: {bin_range}")

    async def process_transaction(self, request: SchemeRequest) -> SchemeResponse:
        """Process transaction through appropriate card scheme."""
        if not request.scheme:
            if request.pan:
                request.scheme = self.detect_card_scheme(request.pan)
            elif request.token:
                token = self.token_store.get(request.token)
                if token:
                    request.scheme = token.scheme
                else:
                    raise ValueError("Token not found")
            else:
                raise ValueError("Cannot determine card scheme")

        connector = self.connectors.get(request.scheme)
        if not connector:
            return SchemeResponse(
                scheme=request.scheme,
                success=False,
                transaction_id=request.transaction_id,
                response_code="scheme_not_supported",
                response_message=f"Card scheme {request.scheme.value} not supported"
            )

        try:
            response = await connector.process_transaction(request)

            # Store scheme-specific data for reporting
            await self._log_scheme_transaction(request, response)

            return response

        except Exception as e:
            return SchemeResponse(
                scheme=request.scheme,
                success=False,
                transaction_id=request.transaction_id,
                response_code="processing_error",
                response_message=f"Processing error: {str(e)}"
            )

    async def provision_token(self, pan: str, merchant_id: str) -> CardToken:
        """Provision token for card through appropriate scheme."""
        scheme = self.detect_card_scheme(pan)
        connector = self.connectors.get(scheme)

        if not connector:
            raise ValueError(f"Card scheme {scheme.value} not supported for tokenization")

        token = await connector.provision_token(pan, merchant_id)
        self.token_store[token.token_value] = token

        return token

    async def detokenize(self, token_value: str) -> Optional[str]:
        """Detokenize card token to retrieve PAN (for authorized operations only)."""
        token = self.token_store.get(token_value)
        if not token:
            return None

        # Check token validity
        if int(time.time()) > token.expires_at:
            del self.token_store[token_value]
            return None

        # In production, this would call the appropriate scheme's detokenization API
        # For demo, we'll return a masked PAN
        return f"****-****-****-{token.last4}"

    async def _log_scheme_transaction(self, request: SchemeRequest, response: SchemeResponse):
        """Log transaction for scheme reporting and reconciliation."""
        log_data = {
            "timestamp": int(time.time()),
            "scheme": response.scheme.value,
            "transaction_id": request.transaction_id,
            "scheme_transaction_id": response.scheme_transaction_id,
            "merchant_id": request.merchant_id,
            "amount": str(request.amount),
            "currency": request.currency,
            "success": response.success,
            "response_code": response.response_code,
            "fees": response.fees
        }

        # In production, this would be stored in a dedicated reporting database
        print(f"Scheme transaction log: {json.dumps(log_data)}")

    def get_scheme_capabilities(self, scheme: CardScheme) -> Dict:
        """Get capabilities and features supported by each scheme."""
        capabilities = {
            CardScheme.VISA: {
                "tokenization": True,
                "3ds": True,
                "installments": True,
                "recurring": True,
                "push_payments": True,
                "risk_scoring": True,
                "real_time_decisions": True
            },
            CardScheme.MASTERCARD: {
                "tokenization": True,
                "3ds": True,
                "installments": True,
                "recurring": True,
                "push_payments": True,
                "risk_scoring": True,
                "biometric_auth": True
            },
            CardScheme.AMEX: {
                "tokenization": False,  # Amex has different tokenization
                "3ds": True,
                "installments": True,
                "recurring": True,
                "push_payments": False,
                "risk_scoring": True,
                "express_checkout": True
            }
        }

        return capabilities.get(scheme, {})


# Factory function
def create_card_scheme_manager(config: Dict) -> CardSchemeManager:
    """Create card scheme manager with configuration."""
    return CardSchemeManager(config)