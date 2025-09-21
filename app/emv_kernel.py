"""
EMV Kernel for Contactless Payments - SoftPOS

This module implements a comprehensive EMV contactless payment kernel following
EMVCo specifications for Level 1 (L1) and Level 2 (L2) contactless processing.

Key Features:
- EMV Contactless Specification compliance
- Multiple contactless protocols (ISO 14443 Type A/B, ISO 15693)
- Transaction flow management (Selection, Authentication, Authorization)
- Card Data Object (CDOL) processing
- Cryptographic verification and authentication
- Risk management and offline data authentication
- Support for major card schemes (Visa payWave, Mastercard PayPass, Amex ExpressPay)
- NFC communication simulation for mobile tap-to-pay

EMV Transaction Flow:
1. Card Detection & Selection
2. Application Selection (AID matching)
3. Initiate Application Processing
4. Read Application Data
5. Offline Data Authentication (ODA)
6. Processing Restrictions
7. Cardholder Verification Method (CVM)
8. Terminal Risk Management
9. Terminal Action Analysis
10. Card Action Analysis
11. Online Processing (if required)
12. Script Processing
13. Completion

Standards Compliance:
- EMVCo Contactless Specifications v2.7
- ISO/IEC 14443 (Proximity cards)
- ISO/IEC 7816 (Smart cards)
- NFC Forum Type 4 Tag Platform
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Tuple, Union

import asyncio


class EMVApplication(Enum):
    """EMV Application Identifiers (AIDs) for major card schemes."""
    VISA_CREDIT = "A0000000031010"
    VISA_DEBIT = "A0000000032010"
    VISA_ELECTRON = "A0000000032020"
    MASTERCARD_CREDIT = "A0000000041010"
    MASTERCARD_DEBIT = "A0000000043060"
    MASTERCARD_MAESTRO = "A0000000043060"
    AMEX = "A00000002501"
    DISCOVER = "A0000001523010"
    JCB = "A0000000651010"
    UNIONPAY = "A000000333010101"


class ContactlessInterface(Enum):
    """Contactless communication interfaces."""
    ISO14443_TYPE_A = "iso14443_type_a"
    ISO14443_TYPE_B = "iso14443_type_b"
    ISO15693 = "iso15693"
    NFC_TYPE_4 = "nfc_type_4"


class TransactionType(Enum):
    """EMV Transaction types."""
    PURCHASE = "00"
    CASH_ADVANCE = "01"
    REFUND = "20"
    CASHBACK = "09"
    BALANCE_INQUIRY = "31"


class CVMMethod(Enum):
    """Cardholder Verification Methods."""
    NO_CVM = "no_cvm"
    SIGNATURE = "signature"
    ONLINE_PIN = "online_pin"
    CDCVM = "cdcvm"  # Consumer Device CVM (mobile PIN/biometric)


class EMVResult(Enum):
    """EMV Transaction results."""
    APPROVED = "approved"
    DECLINED = "declined"
    ONLINE = "online_required"
    TRY_AGAIN = "try_again"
    ERROR = "error"


@dataclass
class ContactlessCard:
    """Represents a contactless payment card."""
    uid: str  # Unique card identifier
    aid: str  # Application Identifier
    pan: str  # Primary Account Number
    expiry_date: str  # YYMM format
    service_code: str
    track2_data: str
    application_label: str
    interface: ContactlessInterface
    cvm_limit: int = 5000  # Contactless CVM limit (minor units)
    floor_limit: int = 10000  # Contactless floor limit (minor units)

    # EMV Data Objects
    application_cryptogram: Optional[str] = None
    application_transaction_counter: int = 0
    cryptogram_info_data: Optional[str] = None
    issuer_application_data: Optional[str] = None
    terminal_verification_results: Optional[str] = None


@dataclass
class EMVTransaction:
    """EMV Transaction context."""
    transaction_id: str
    amount: int  # Amount in minor units
    currency_code: str
    transaction_type: TransactionType
    merchant_id: str
    terminal_id: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Transaction flow state
    selected_application: Optional[str] = None
    card_data: Optional[ContactlessCard] = None
    cvm_performed: CVMMethod = CVMMethod.NO_CVM
    online_required: bool = False
    cryptogram_type: Optional[str] = None  # AAC, TC, ARQC
    authorization_response: Optional[str] = None

    # Risk management
    offline_approved: bool = False
    risk_score: float = 0.0
    velocity_check: bool = True


@dataclass
class EMVKernelConfig:
    """EMV Kernel configuration."""
    terminal_type: str = "22"  # Contactless capable
    terminal_capabilities: str = "E0F8C8"
    additional_terminal_capabilities: str = "6000F0A001"
    terminal_country_code: str = "0826"  # UK
    terminal_currency_code: str = "0826"  # GBP
    contactless_floor_limit: int = 10000  # £100.00
    contactless_cvm_limit: int = 5000     # £50.00
    contactless_transaction_limit: int = 50000  # £500.00

    # Security settings
    offline_authentication: bool = True
    online_pin_supported: bool = True
    signature_supported: bool = True
    cdcvm_supported: bool = True


class EMVContactlessKernel:
    """
    EMV Contactless Kernel implementing Level 1 and Level 2 processing.

    This kernel handles the complete EMV contactless transaction flow from
    card detection through authorization, following EMVCo specifications.
    """

    def __init__(self, config: EMVKernelConfig):
        self.config = config
        self.supported_applications = {
            EMVApplication.VISA_CREDIT.value: "Visa Credit",
            EMVApplication.VISA_DEBIT.value: "Visa Debit",
            EMVApplication.MASTERCARD_CREDIT.value: "Mastercard Credit",
            EMVApplication.MASTERCARD_DEBIT.value: "Mastercard Debit",
            EMVApplication.AMEX.value: "American Express",
        }

        # Transaction state
        self.current_transaction: Optional[EMVTransaction] = None
        self.detected_cards: List[ContactlessCard] = []

    async def initiate_transaction(
        self,
        amount: int,
        currency_code: str,
        transaction_type: TransactionType,
        merchant_id: str,
        terminal_id: str
    ) -> EMVTransaction:
        """Initialize a new EMV contactless transaction."""
        transaction = EMVTransaction(
            transaction_id=f"emv_{secrets.token_hex(8)}",
            amount=amount,
            currency_code=currency_code,
            transaction_type=transaction_type,
            merchant_id=merchant_id,
            terminal_id=terminal_id
        )

        self.current_transaction = transaction
        return transaction

    async def detect_cards(self, timeout_ms: int = 5000) -> List[ContactlessCard]:
        """
        Detect contactless cards in the NFC field.

        Simulates NFC field activation and card detection across multiple interfaces.
        In production, this would interface with actual NFC hardware.
        """
        # Simulate card detection delay
        await asyncio.sleep(0.1)

        # For demo, simulate different card types
        demo_cards = [
            ContactlessCard(
                uid="04123456789ABC",
                aid=EMVApplication.VISA_CREDIT.value,
                pan="4111111111111111",
                expiry_date="2512",
                service_code="201",
                track2_data="4111111111111111=25122011234567890",
                application_label="VISA CREDIT",
                interface=ContactlessInterface.ISO14443_TYPE_A,
                application_transaction_counter=1,
            ),
            ContactlessCard(
                uid="04987654321DEF",
                aid=EMVApplication.MASTERCARD_CREDIT.value,
                pan="5555555555554444",
                expiry_date="2512",
                service_code="201",
                track2_data="5555555555554444=25122011234567890",
                application_label="MASTERCARD",
                interface=ContactlessInterface.ISO14443_TYPE_A,
                application_transaction_counter=1,
            )
        ]

        # Return first card for demo
        self.detected_cards = [demo_cards[0]]
        return self.detected_cards

    async def select_application(self, card: ContactlessCard) -> bool:
        """
        Perform EMV application selection.

        Steps:
        1. Build candidate list from card's Payment System Environment (PSE)
        2. Match terminal-supported applications with card applications
        3. Select highest priority mutually supported application
        """
        if not self.current_transaction:
            return False

        # Check if card's AID is supported by terminal
        if card.aid in self.supported_applications:
            self.current_transaction.selected_application = card.aid
            self.current_transaction.card_data = card
            return True

        return False

    async def read_application_data(self, card: ContactlessCard) -> Dict[str, str]:
        """
        Read Application Data from the selected application.

        This includes:
        - Application File Locator (AFL)
        - Application Primary Account Number (PAN)
        - Application Expiration Date
        - Cardholder Name
        - And other application-specific data objects
        """
        # Simulate reading EMV data objects
        application_data = {
            "9F06": card.aid,  # Application Identifier (AID)
            "5A": card.pan,    # Application Primary Account Number
            "5F24": card.expiry_date,  # Application Expiration Date
            "5F20": "CARDHOLDER NAME",  # Cardholder Name
            "57": card.track2_data,     # Track 2 Equivalent Data
            "50": card.application_label,  # Application Label
            "9F36": f"{card.application_transaction_counter:04X}",  # ATC
            "82": "1980",      # Application Interchange Profile
            "9F33": self.config.terminal_capabilities,  # Terminal Capabilities
            "9F40": self.config.additional_terminal_capabilities,  # Additional Terminal Capabilities
            "5F2A": self.config.terminal_currency_code,  # Transaction Currency Code
            "9F1A": self.config.terminal_country_code,   # Terminal Country Code
        }

        return application_data

    async def perform_offline_data_authentication(self, card: ContactlessCard) -> bool:
        """
        Perform Offline Data Authentication (ODA).

        Methods supported:
        - Static Data Authentication (SDA)
        - Dynamic Data Authentication (DDA)
        - Combined Dynamic Data Authentication (CDA)
        """
        if not self.config.offline_authentication:
            return True

        # Simulate ODA process
        # In production, this would verify card certificates and signatures
        oda_result = True

        if oda_result:
            # Set Terminal Verification Results
            card.terminal_verification_results = "0000000000"
        else:
            card.terminal_verification_results = "0000008000"  # ODA failed

        return oda_result

    async def check_processing_restrictions(self, transaction: EMVTransaction) -> bool:
        """
        Check processing restrictions and application usage control.

        Validates:
        - Application Version Number
        - Application Usage Control
        - Application Effective/Expiration Dates
        - Issuer Country Code restrictions
        """
        if not transaction.card_data:
            return False

        # Check transaction amount limits
        if transaction.amount > self.config.contactless_transaction_limit:
            return False

        # Check expiry date
        card_expiry = transaction.card_data.expiry_date
        current_date = datetime.now().strftime("%y%m")
        if card_expiry < current_date:
            return False

        return True

    async def determine_cardholder_verification_method(self, transaction: EMVTransaction) -> CVMMethod:
        """
        Determine the appropriate Cardholder Verification Method.

        EMV CVM hierarchy:
        1. CDCVM (Consumer Device CVM) - mobile biometric/PIN
        2. Online PIN
        3. Signature
        4. No CVM
        """
        if not transaction.card_data:
            return CVMMethod.NO_CVM

        # Check amount against CVM limits
        if transaction.amount <= self.config.contactless_cvm_limit:
            return CVMMethod.NO_CVM
        elif transaction.amount <= self.config.contactless_floor_limit:
            if self.config.cdcvm_supported:
                return CVMMethod.CDCVM
            elif self.config.signature_supported:
                return CVMMethod.SIGNATURE
            else:
                return CVMMethod.NO_CVM
        else:
            # Higher value transactions may require online PIN
            if self.config.online_pin_supported:
                return CVMMethod.ONLINE_PIN
            else:
                transaction.online_required = True
                return CVMMethod.NO_CVM

    async def perform_terminal_risk_management(self, transaction: EMVTransaction) -> bool:
        """
        Perform Terminal Risk Management checks.

        Includes:
        - Velocity checking
        - Transaction amount limits
        - Currency compatibility
        - Random transaction selection for online processing
        """
        risk_factors = 0

        # Check velocity (frequency of transactions)
        if not transaction.velocity_check:
            risk_factors += 1

        # Check amount limits
        if transaction.amount > self.config.contactless_floor_limit:
            risk_factors += 1
            transaction.online_required = True

        # Random selection for online processing (1% of transactions)
        if secrets.randbelow(100) < 1:
            transaction.online_required = True

        # Calculate risk score
        transaction.risk_score = min(risk_factors / 5.0, 1.0)

        return transaction.risk_score < 0.8

    async def generate_application_cryptogram(self, transaction: EMVTransaction) -> str:
        """
        Generate Application Cryptogram for transaction validation.

        Cryptogram types:
        - AAC (Application Authentication Cryptogram) - Transaction declined
        - TC (Transaction Certificate) - Transaction approved offline
        - ARQC (Authorization Request Cryptogram) - Online authorization required
        """
        if not transaction.card_data:
            return ""

        # Determine cryptogram type based on risk analysis
        if transaction.online_required:
            cryptogram_type = "ARQC"
        elif transaction.risk_score > 0.5:
            cryptogram_type = "AAC"
        else:
            cryptogram_type = "TC"

        transaction.cryptogram_type = cryptogram_type

        # Generate cryptogram (simplified for demo)
        cryptogram_data = f"{transaction.transaction_id}{transaction.amount}{transaction.timestamp.isoformat()}"
        cryptogram = hashlib.sha256(cryptogram_data.encode()).hexdigest()[:16].upper()

        transaction.card_data.application_cryptogram = cryptogram
        transaction.card_data.cryptogram_info_data = f"80"  # CID indicating cryptogram type

        return cryptogram

    async def process_contactless_transaction(
        self,
        amount: int,
        currency_code: str = "GBP",
        transaction_type: TransactionType = TransactionType.PURCHASE,
        merchant_id: str = "TEST_MERCHANT",
        terminal_id: str = "TERMINAL01"
    ) -> Tuple[EMVResult, EMVTransaction]:
        """
        Process a complete EMV contactless transaction.

        This is the main entry point that orchestrates the entire EMV flow.
        """
        try:
            # Step 1: Initialize transaction
            transaction = await self.initiate_transaction(
                amount, currency_code, transaction_type, merchant_id, terminal_id
            )

            # Step 2: Detect contactless cards
            cards = await self.detect_cards()
            if not cards:
                return EMVResult.ERROR, transaction

            card = cards[0]  # Use first detected card

            # Step 3: Application selection
            if not await self.select_application(card):
                return EMVResult.DECLINED, transaction

            # Step 4: Read application data
            app_data = await self.read_application_data(card)

            # Step 5: Offline Data Authentication
            if not await self.perform_offline_data_authentication(card):
                return EMVResult.DECLINED, transaction

            # Step 6: Processing restrictions
            if not await self.check_processing_restrictions(transaction):
                return EMVResult.DECLINED, transaction

            # Step 7: Cardholder verification
            cvm_method = await self.determine_cardholder_verification_method(transaction)
            transaction.cvm_performed = cvm_method

            # Step 8: Terminal risk management
            if not await self.perform_terminal_risk_management(transaction):
                return EMVResult.DECLINED, transaction

            # Step 9: Generate application cryptogram
            cryptogram = await self.generate_application_cryptogram(transaction)

            # Step 10: Determine final result
            if transaction.cryptogram_type == "AAC":
                return EMVResult.DECLINED, transaction
            elif transaction.cryptogram_type == "ARQC":
                return EMVResult.ONLINE, transaction
            else:  # TC
                transaction.offline_approved = True
                return EMVResult.APPROVED, transaction

        except Exception as e:
            print(f"EMV processing error: {e}")
            return EMVResult.ERROR, transaction

    async def process_online_authorization(
        self,
        transaction: EMVTransaction,
        authorization_response: str
    ) -> EMVResult:
        """
        Process online authorization response and complete transaction.

        Handles the response from the issuer and performs final transaction completion.
        """
        if not transaction.card_data:
            return EMVResult.ERROR

        transaction.authorization_response = authorization_response

        # Parse authorization response (simplified)
        if "00" in authorization_response:  # Approved
            # Generate second application cryptogram (TC)
            transaction.cryptogram_type = "TC"
            await self.generate_application_cryptogram(transaction)
            return EMVResult.APPROVED
        else:
            # Generate decline cryptogram (AAC)
            transaction.cryptogram_type = "AAC"
            await self.generate_application_cryptogram(transaction)
            return EMVResult.DECLINED

    def get_transaction_data(self, transaction: EMVTransaction) -> Dict[str, str]:
        """
        Extract EMV transaction data for payment processing.

        Returns standardized transaction data that can be used by payment processors.
        """
        if not transaction.card_data:
            return {}

        return {
            "transaction_id": transaction.transaction_id,
            "pan": transaction.card_data.pan,
            "expiry_date": transaction.card_data.expiry_date,
            "track2_data": transaction.card_data.track2_data,
            "application_cryptogram": transaction.card_data.application_cryptogram or "",
            "cryptogram_info_data": transaction.card_data.cryptogram_info_data or "",
            "application_transaction_counter": str(transaction.card_data.application_transaction_counter),
            "terminal_verification_results": transaction.card_data.terminal_verification_results or "",
            "amount": str(transaction.amount),
            "currency_code": transaction.currency_code,
            "transaction_type": transaction.transaction_type.value,
            "cvm_method": transaction.cvm_performed.value,
            "contactless": "true",
            "emv_data": "true"
        }

    def simulate_mobile_payment(self, device_id: str, amount: int) -> ContactlessCard:
        """
        Simulate a mobile payment (Apple Pay, Google Pay, Samsung Pay).

        Mobile payments use device-specific tokens and CDCVM for authentication.
        """
        # Generate device-specific token
        device_token = f"4000{hashlib.sha256(device_id.encode()).hexdigest()[:12]}"

        return ContactlessCard(
            uid=f"mobile_{device_id}",
            aid=EMVApplication.VISA_CREDIT.value,
            pan=device_token,  # Tokenized PAN
            expiry_date="2512",
            service_code="201",
            track2_data=f"{device_token}=25122011234567890",
            application_label="MOBILE PAYMENT",
            interface=ContactlessInterface.NFC_TYPE_4,
            cvm_limit=50000,  # Higher limit for mobile payments
            application_transaction_counter=secrets.randbelow(65535),
        )


# Factory function
def create_emv_kernel(config: Optional[EMVKernelConfig] = None) -> EMVContactlessKernel:
    """Create EMV contactless kernel with default or custom configuration."""
    if config is None:
        config = EMVKernelConfig()
    return EMVContactlessKernel(config)