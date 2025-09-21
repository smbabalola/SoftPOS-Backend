"""
3D Secure (3DS) Authentication Implementation for SoftPOS

This module implements 3D Secure 2.x authentication for Card-Not-Present (CNP) transactions
to comply with Strong Customer Authentication (SCA) requirements under PSD2.

Features:
- 3DS 2.x protocol implementation
- Risk-based authentication
- Frictionless authentication for low-risk transactions
- Challenge flow for high-risk transactions
- Exemption handling (TRA, Low Value, etc.)
- Directory Server integration
- Access Control Server (ACS) communication

Production integrations would include:
- Visa: Cardinal Centinel
- Mastercard: NuData/SecureCode
- American Express: SafeKey
- EMVCo 3DS specification compliance
"""

from __future__ import annotations

import base64
import json
import secrets
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple

import jwt


class ThreeDSVersion(Enum):
    V2_1 = "2.1.0"
    V2_2 = "2.2.0"


class TransactionStatus(Enum):
    SUCCESS = "Y"  # Authentication successful
    NOT_ENROLLED = "N"  # Card not enrolled in 3DS
    UNAVAILABLE = "U"  # Authentication unavailable
    CHALLENGE = "C"  # Challenge required
    REJECTED = "R"  # Authentication rejected
    ATTEMPT = "A"  # Authentication attempted
    INFORMATIONAL = "I"  # Informational only


class ChallengeIndicator(Enum):
    NO_PREFERENCE = "01"
    NO_CHALLENGE = "02"
    CHALLENGE_REQUESTED = "03"
    CHALLENGE_MANDATE = "04"


class ExemptionType(Enum):
    LOW_VALUE = "01"  # Low value payment
    TRA = "02"  # Transaction Risk Analysis
    TRUSTED_MERCHANT = "03"  # Trusted beneficiary
    CORPORATE_PAYMENT = "04"  # Corporate payment
    DELEGATED_AUTHENTICATION = "05"  # Delegated authentication
    SCA_DELEGATION = "06"  # SCA delegation


@dataclass
class DeviceInfo:
    accept_header: str
    user_agent: str
    screen_width: int
    screen_height: int
    screen_color_depth: int
    timezone: str
    language: str
    java_enabled: bool
    javascript_enabled: bool


@dataclass
class CardholderInfo:
    email: Optional[str] = None
    mobile_phone: Optional[str] = None
    home_phone: Optional[str] = None
    work_phone: Optional[str] = None
    cardholder_name: Optional[str] = None
    billing_address: Optional[Dict] = None
    shipping_address: Optional[Dict] = None


@dataclass
class MerchantInfo:
    merchant_id: str
    merchant_name: str
    merchant_category_code: str
    merchant_country: str
    merchant_url: str
    acquirer_bin: str
    acquirer_merchant_id: str


@dataclass
class TransactionInfo:
    amount: int  # Minor units
    currency: str
    transaction_type: str  # "01" = Goods/Services, "03" = Check Acceptance, etc.
    purchase_date: str
    purchase_instal: Optional[str] = None
    recurring_expiry: Optional[str] = None
    recurring_frequency: Optional[str] = None


@dataclass
class ThreeDSRequest:
    card_number: str
    expiry_month: str
    expiry_year: str
    cardholder_name: str
    transaction_info: TransactionInfo
    merchant_info: MerchantInfo
    device_info: DeviceInfo
    cardholder_info: Optional[CardholderInfo] = None
    challenge_indicator: ChallengeIndicator = ChallengeIndicator.NO_PREFERENCE
    exemption_type: Optional[ExemptionType] = None
    three_ri_ind: Optional[str] = None  # 3RI indicator for merchant initiated transactions


@dataclass
class ThreeDSResponse:
    status: TransactionStatus
    version: ThreeDSVersion
    transaction_id: str
    ds_transaction_id: str
    acs_transaction_id: Optional[str] = None
    authentication_value: Optional[str] = None  # CAVV/AAV
    eci: Optional[str] = None  # Electronic Commerce Indicator
    challenge_url: Optional[str] = None
    challenge_required: bool = False
    liability_shift: bool = False
    risk_score: Optional[float] = None
    exemption_applied: Optional[ExemptionType] = None
    processing_time_ms: int = 0
    error_code: Optional[str] = None
    error_description: Optional[str] = None


class ThreeDSAuthenticator:
    """
    3D Secure 2.x Authentication Service

    Handles the complete 3DS authentication flow including:
    - Initial authentication request
    - Risk assessment
    - Challenge handling
    - Result processing
    """

    def __init__(self):
        self.version = ThreeDSVersion.V2_2

        # Mock configuration - production would use real Directory Server
        self.directory_server_url = "https://ds.3dsecure.net"
        self.acs_url = "https://acs.3dsecure.net"

        # Merchant configuration
        self.merchant_id = "SUREPOS_MERCHANT_001"
        self.acquirer_bin = "123456"

        # Risk thresholds for frictionless authentication
        self.frictionless_threshold = 0.30  # Below this, try frictionless
        self.challenge_threshold = 0.70   # Above this, require challenge

        # Mock enrolled cards (production would query Directory Server)
        self.enrolled_cards = {
            "4111111111111111": {"enrolled": True, "acs_url": self.acs_url},
            "5555555555554444": {"enrolled": True, "acs_url": self.acs_url},
            "4000000000000002": {"enrolled": False, "acs_url": None},
        }

    async def authenticate(self, request: ThreeDSRequest) -> ThreeDSResponse:
        """
        Perform 3DS authentication.

        Args:
            request: 3DS authentication request

        Returns:
            ThreeDSResponse with authentication result
        """
        start_time = time.time()

        try:
            # Step 1: Check card enrollment
            enrollment_result = await self._check_enrollment(request.card_number)

            if not enrollment_result["enrolled"]:
                return ThreeDSResponse(
                    status=TransactionStatus.NOT_ENROLLED,
                    version=self.version,
                    transaction_id=self._generate_transaction_id(),
                    ds_transaction_id=self._generate_ds_transaction_id(),
                    liability_shift=False,
                    processing_time_ms=int((time.time() - start_time) * 1000)
                )

            # Step 2: Generate transaction IDs
            transaction_id = self._generate_transaction_id()
            ds_transaction_id = self._generate_ds_transaction_id()

            # Step 3: Perform risk assessment
            risk_score = await self._assess_risk(request)

            # Step 4: Check for exemptions
            exemption_applied = await self._check_exemptions(request, risk_score)

            # Step 5: Determine authentication flow
            if exemption_applied:
                # Exemption applied - skip authentication
                return await self._handle_exemption(
                    transaction_id, ds_transaction_id, exemption_applied, start_time
                )
            elif risk_score < self.frictionless_threshold or request.challenge_indicator == ChallengeIndicator.NO_CHALLENGE:
                # Try frictionless authentication
                return await self._frictionless_authentication(
                    request, transaction_id, ds_transaction_id, risk_score, start_time
                )
            else:
                # Require challenge
                return await self._challenge_authentication(
                    request, transaction_id, ds_transaction_id, risk_score, start_time
                )

        except Exception as e:
            return ThreeDSResponse(
                status=TransactionStatus.UNAVAILABLE,
                version=self.version,
                transaction_id=self._generate_transaction_id(),
                ds_transaction_id=self._generate_ds_transaction_id(),
                error_code="AUTH_ERROR",
                error_description=str(e),
                processing_time_ms=int((time.time() - start_time) * 1000)
            )

    async def _check_enrollment(self, card_number: str) -> Dict:
        """Check if card is enrolled in 3DS."""
        # Mask PAN for lookup
        masked_pan = card_number[:6] + "*" * (len(card_number) - 10) + card_number[-4:]

        # In production, this would query the Directory Server
        enrollment_info = self.enrolled_cards.get(card_number, {"enrolled": False})

        return enrollment_info

    async def _assess_risk(self, request: ThreeDSRequest) -> float:
        """Assess transaction risk for 3DS decision."""
        risk_score = 0.0

        # Transaction amount risk
        if request.transaction_info.amount > 100000:  # > $1000
            risk_score += 0.2
        elif request.transaction_info.amount > 50000:  # > $500
            risk_score += 0.1

        # First-time transaction with merchant
        risk_score += 0.1

        # Device risk assessment
        if not request.device_info.javascript_enabled:
            risk_score += 0.15

        # Check if mobile device (simplified)
        if "mobile" in request.device_info.user_agent.lower():
            risk_score += 0.05  # Mobile slightly riskier

        # Cardholder authentication history (mock)
        # In production, this would check previous authentication success rate
        risk_score += 0.1

        # Geographic risk
        if request.merchant_info.merchant_country in ["CN", "RU", "NG"]:
            risk_score += 0.2

        # Time-based risk (off-hours transactions)
        current_hour = time.gmtime().tm_hour
        if current_hour < 6 or current_hour > 22:  # Night hours
            risk_score += 0.05

        return min(risk_score, 1.0)

    async def _check_exemptions(self, request: ThreeDSRequest, risk_score: float) -> Optional[ExemptionType]:
        """Check if transaction qualifies for SCA exemptions."""

        # Low Value Payment exemption (under €30)
        if request.transaction_info.amount < 3000 and request.transaction_info.currency == "EUR":
            return ExemptionType.LOW_VALUE

        # Transaction Risk Analysis exemption
        if request.exemption_type == ExemptionType.TRA and risk_score < 0.13:
            # TRA exemption thresholds:
            # - €100: fraud rate < 0.13%
            # - €250: fraud rate < 0.06%
            # - €500: fraud rate < 0.01%
            if request.transaction_info.amount < 10000:  # €100
                return ExemptionType.TRA

        # Corporate payment exemption
        if request.exemption_type == ExemptionType.CORPORATE_PAYMENT:
            return ExemptionType.CORPORATE_PAYMENT

        # Trusted merchant exemption
        if request.exemption_type == ExemptionType.TRUSTED_MERCHANT:
            return ExemptionType.TRUSTED_MERCHANT

        return None

    async def _frictionless_authentication(
        self,
        request: ThreeDSRequest,
        transaction_id: str,
        ds_transaction_id: str,
        risk_score: float,
        start_time: float
    ) -> ThreeDSResponse:
        """Attempt frictionless authentication."""

        # Simulate ACS risk assessment
        # In production, this would send AReq to ACS and receive ARes

        if risk_score < 0.15:
            # Low risk - authentication successful
            authentication_value = self._generate_cavv()
            eci = "05" if request.card_number.startswith("4") else "02"  # Visa vs. Mastercard

            return ThreeDSResponse(
                status=TransactionStatus.SUCCESS,
                version=self.version,
                transaction_id=transaction_id,
                ds_transaction_id=ds_transaction_id,
                acs_transaction_id=self._generate_acs_transaction_id(),
                authentication_value=authentication_value,
                eci=eci,
                challenge_required=False,
                liability_shift=True,
                risk_score=risk_score,
                processing_time_ms=int((time.time() - start_time) * 1000)
            )
        else:
            # Risk too high for frictionless - step up to challenge
            return await self._challenge_authentication(
                request, transaction_id, ds_transaction_id, risk_score, start_time
            )

    async def _challenge_authentication(
        self,
        request: ThreeDSRequest,
        transaction_id: str,
        ds_transaction_id: str,
        risk_score: float,
        start_time: float
    ) -> ThreeDSResponse:
        """Initiate challenge authentication."""

        acs_transaction_id = self._generate_acs_transaction_id()

        # Generate challenge URL
        challenge_url = f"{self.acs_url}/challenge"
        challenge_params = {
            "threeDSServerTransID": transaction_id,
            "acsTransID": acs_transaction_id,
            "messageVersion": self.version.value,
            "challengeWindowSize": "02",  # 390x400px
        }

        # In production, this would be a proper 3DS challenge URL with JWT
        challenge_url += "?" + "&".join([f"{k}={v}" for k, v in challenge_params.items()])

        return ThreeDSResponse(
            status=TransactionStatus.CHALLENGE,
            version=self.version,
            transaction_id=transaction_id,
            ds_transaction_id=ds_transaction_id,
            acs_transaction_id=acs_transaction_id,
            challenge_url=challenge_url,
            challenge_required=True,
            liability_shift=False,  # Will be determined after challenge completion
            risk_score=risk_score,
            processing_time_ms=int((time.time() - start_time) * 1000)
        )

    async def _handle_exemption(
        self,
        transaction_id: str,
        ds_transaction_id: str,
        exemption_type: ExemptionType,
        start_time: float
    ) -> ThreeDSResponse:
        """Handle exempted transactions."""

        return ThreeDSResponse(
            status=TransactionStatus.SUCCESS,
            version=self.version,
            transaction_id=transaction_id,
            ds_transaction_id=ds_transaction_id,
            exemption_applied=exemption_type,
            liability_shift=True,  # Exemptions typically provide liability shift
            processing_time_ms=int((time.time() - start_time) * 1000)
        )

    async def complete_challenge(
        self,
        transaction_id: str,
        challenge_result: str
    ) -> ThreeDSResponse:
        """Complete challenge authentication."""
        start_time = time.time()

        # Simulate challenge completion
        # In production, this would process the CRes message from ACS

        if challenge_result == "success":
            authentication_value = self._generate_cavv()
            eci = "02"  # Authenticated

            return ThreeDSResponse(
                status=TransactionStatus.SUCCESS,
                version=self.version,
                transaction_id=transaction_id,
                ds_transaction_id=self._generate_ds_transaction_id(),
                authentication_value=authentication_value,
                eci=eci,
                challenge_required=False,
                liability_shift=True,
                processing_time_ms=int((time.time() - start_time) * 1000)
            )
        else:
            return ThreeDSResponse(
                status=TransactionStatus.REJECTED,
                version=self.version,
                transaction_id=transaction_id,
                ds_transaction_id=self._generate_ds_transaction_id(),
                challenge_required=False,
                liability_shift=False,
                processing_time_ms=int((time.time() - start_time) * 1000)
            )

    def _generate_transaction_id(self) -> str:
        """Generate 3DS transaction ID."""
        return f"3ds_{uuid.uuid4().hex[:16]}"

    def _generate_ds_transaction_id(self) -> str:
        """Generate Directory Server transaction ID."""
        return f"ds_{uuid.uuid4().hex[:16]}"

    def _generate_acs_transaction_id(self) -> str:
        """Generate ACS transaction ID."""
        return f"acs_{uuid.uuid4().hex[:16]}"

    def _generate_cavv(self) -> str:
        """Generate Cardholder Authentication Verification Value."""
        # Mock CAVV generation - production would use proper cryptographic methods
        cavv_data = secrets.token_bytes(20)
        return base64.b64encode(cavv_data).decode()

    def create_device_info(
        self,
        user_agent: str,
        accept_header: str,
        screen_width: int = 1920,
        screen_height: int = 1080
    ) -> DeviceInfo:
        """Helper to create DeviceInfo object."""
        return DeviceInfo(
            accept_header=accept_header,
            user_agent=user_agent,
            screen_width=screen_width,
            screen_height=screen_height,
            screen_color_depth=24,
            timezone="-300",  # EST
            language="en-US",
            java_enabled=False,
            javascript_enabled=True
        )

    def get_authentication_summary(self, response: ThreeDSResponse) -> Dict:
        """Get human-readable authentication summary."""
        return {
            "transaction_id": response.transaction_id,
            "status": response.status.value,
            "status_description": self._get_status_description(response.status),
            "liability_shift": response.liability_shift,
            "challenge_required": response.challenge_required,
            "exemption_applied": response.exemption_applied.value if response.exemption_applied else None,
            "risk_score": response.risk_score,
            "processing_time_ms": response.processing_time_ms,
            "recommendation": self._get_recommendation(response)
        }

    def _get_status_description(self, status: TransactionStatus) -> str:
        """Get human-readable status description."""
        descriptions = {
            TransactionStatus.SUCCESS: "Authentication successful",
            TransactionStatus.NOT_ENROLLED: "Card not enrolled in 3DS",
            TransactionStatus.UNAVAILABLE: "Authentication service unavailable",
            TransactionStatus.CHALLENGE: "Challenge authentication required",
            TransactionStatus.REJECTED: "Authentication rejected by cardholder",
            TransactionStatus.ATTEMPT: "Authentication attempted but not completed",
            TransactionStatus.INFORMATIONAL: "Informational response only"
        }
        return descriptions.get(status, "Unknown status")

    def _get_recommendation(self, response: ThreeDSResponse) -> str:
        """Get processing recommendation based on 3DS result."""
        if response.status == TransactionStatus.SUCCESS:
            return "Proceed with authorization - authentication successful"
        elif response.status == TransactionStatus.CHALLENGE:
            return "Present challenge to cardholder before proceeding"
        elif response.status == TransactionStatus.NOT_ENROLLED:
            return "Proceed without 3DS - card not enrolled"
        elif response.status == TransactionStatus.ATTEMPT:
            return "Proceed with caution - authentication attempted but not completed"
        else:
            return "Consider declining transaction - authentication failed or unavailable"


# Global 3DS authenticator instance
three_ds_authenticator = ThreeDSAuthenticator()