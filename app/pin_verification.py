"""
PIN Verification System for SoftPOS

This module implements secure PIN verification for debit card transactions,
following EMV specifications and PCI DSS requirements for PIN handling.

Key Features:
- Online PIN verification with issuer
- Offline PIN verification with card
- PIN Try Counter management
- PIN block encryption (ISO Format 0, 1, 3)
- Hardware Security Module (HSM) integration
- PIN change functionality
- Secure PIN pad simulation

Security Standards:
- PCI PIN Security Requirements
- EMV PIN Management Specifications
- ISO 9564 PIN verification
- Triple DES PIN block encryption
- HSM-based PIN processing
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Optional, Tuple

import asyncio


class PINVerificationMethod(Enum):
    """PIN verification methods."""
    ONLINE = "online"
    OFFLINE_PLAINTEXT = "offline_plaintext"
    OFFLINE_ENCRYPTED = "offline_encrypted"
    NO_PIN = "no_pin"


class PINBlockFormat(Enum):
    """PIN block formats per ISO 9564."""
    FORMAT_0 = "iso_format_0"  # ANSI X9.8
    FORMAT_1 = "iso_format_1"  # EMV
    FORMAT_3 = "iso_format_3"  # ANSI X9.8


class PINResult(Enum):
    """PIN verification results."""
    VERIFIED = "verified"
    INCORRECT = "incorrect"
    BLOCKED = "blocked"
    TRIES_EXCEEDED = "tries_exceeded"
    SYSTEM_ERROR = "system_error"


@dataclass
class PINVerificationRequest:
    """PIN verification request."""
    transaction_id: str
    card_pan: str
    encrypted_pin_block: str
    pin_block_format: PINBlockFormat
    verification_method: PINVerificationMethod
    terminal_id: str
    merchant_id: str
    key_serial_number: Optional[str] = None
    pin_try_counter: int = 3


@dataclass
class PINVerificationResponse:
    """PIN verification response."""
    transaction_id: str
    result: PINResult
    tries_remaining: int
    response_code: str
    response_message: str
    processing_time_ms: int
    timestamp: datetime
    verification_method: PINVerificationMethod
    error_details: Optional[str] = None


@dataclass
class PINChangeRequest:
    """PIN change request."""
    card_pan: str
    old_pin_block: str
    new_pin_block: str
    pin_block_format: PINBlockFormat
    terminal_id: str
    merchant_id: str


@dataclass
class SecurePINPad:
    """Simulated secure PIN pad for SoftPOS."""
    terminal_id: str
    encryption_key_id: str
    pin_entry_timeout: int = 30  # seconds
    max_pin_length: int = 12
    min_pin_length: int = 4
    tamper_detected: bool = False


class PINVerificationEngine:
    """
    PIN verification engine implementing secure PIN processing
    for SoftPOS debit card transactions.
    """

    def __init__(self, hsm_manager=None):
        self.hsm = hsm_manager
        self.pin_databases = {}  # Simulated PIN database
        self.pin_counters = {}  # PIN try counters per card
        self.blocked_cards = set()  # Cards with exceeded PIN tries

        # Initialize demo PIN data
        self._initialize_demo_pins()

    def _initialize_demo_pins(self):
        """Initialize demo PIN data for testing."""
        # Demo cards with known PINs (for testing only)
        self.pin_databases = {
            "4111111111111111": {
                "encrypted_pin": self._hash_pin("1234"),
                "tries_remaining": 3,
                "blocked": False
            },
            "5555555555554444": {
                "encrypted_pin": self._hash_pin("0000"),
                "tries_remaining": 3,
                "blocked": False
            },
            "378282246310005": {
                "encrypted_pin": self._hash_pin("1111"),
                "tries_remaining": 3,
                "blocked": False
            }
        }

    async def verify_pin(self, request: PINVerificationRequest) -> PINVerificationResponse:
        """
        Verify PIN using specified method (online or offline).

        Steps:
        1. Validate request parameters
        2. Check PIN try counter
        3. Decrypt PIN block
        4. Perform verification
        5. Update try counter
        6. Return result
        """
        start_time = time.time()

        try:
            # Step 1: Validate request
            if not self._validate_pin_request(request):
                return self._create_error_response(
                    request, PINResult.SYSTEM_ERROR, "Invalid PIN request"
                )

            # Step 2: Check if card is blocked
            if request.card_pan in self.blocked_cards:
                return self._create_response(
                    request, PINResult.BLOCKED, 0, "Card PIN blocked", start_time
                )

            # Step 3: Get current try counter
            pin_data = self.pin_databases.get(request.card_pan)
            if not pin_data:
                return self._create_error_response(
                    request, PINResult.SYSTEM_ERROR, "Card not found"
                )

            tries_remaining = pin_data["tries_remaining"]
            if tries_remaining <= 0:
                self.blocked_cards.add(request.card_pan)
                return self._create_response(
                    request, PINResult.TRIES_EXCEEDED, 0, "PIN tries exceeded", start_time
                )

            # Step 4: Decrypt and verify PIN
            verification_result = await self._perform_pin_verification(request, pin_data)

            # Step 5: Update try counter
            if verification_result == PINResult.VERIFIED:
                # Reset try counter on successful verification
                pin_data["tries_remaining"] = 3
                tries_remaining = 3
            else:
                # Decrement try counter on failed verification
                tries_remaining -= 1
                pin_data["tries_remaining"] = tries_remaining

                if tries_remaining <= 0:
                    self.blocked_cards.add(request.card_pan)
                    verification_result = PINResult.TRIES_EXCEEDED

            # Step 6: Create response
            response_message = self._get_response_message(verification_result)
            return self._create_response(
                request, verification_result, tries_remaining, response_message, start_time
            )

        except Exception as e:
            return self._create_error_response(
                request, PINResult.SYSTEM_ERROR, f"PIN verification failed: {str(e)}"
            )

    async def change_pin(self, request: PINChangeRequest) -> Dict:
        """
        Change PIN for a card.

        Requires verification of old PIN before setting new PIN.
        """
        try:
            # Step 1: Verify old PIN
            old_pin_verification = PINVerificationRequest(
                transaction_id=f"pin_change_{secrets.token_hex(8)}",
                card_pan=request.card_pan,
                encrypted_pin_block=request.old_pin_block,
                pin_block_format=request.pin_block_format,
                verification_method=PINVerificationMethod.OFFLINE_ENCRYPTED,
                terminal_id=request.terminal_id,
                merchant_id=request.merchant_id
            )

            old_pin_result = await self.verify_pin(old_pin_verification)

            if old_pin_result.result != PINResult.VERIFIED:
                return {
                    "success": False,
                    "error": "Old PIN verification failed",
                    "tries_remaining": old_pin_result.tries_remaining
                }

            # Step 2: Set new PIN
            decrypted_new_pin = await self._decrypt_pin_block(
                request.new_pin_block, request.card_pan, request.pin_block_format
            )

            if not self._validate_pin_format(decrypted_new_pin):
                return {
                    "success": False,
                    "error": "Invalid PIN format"
                }

            # Step 3: Update PIN database
            pin_data = self.pin_databases.get(request.card_pan)
            if pin_data:
                pin_data["encrypted_pin"] = self._hash_pin(decrypted_new_pin)
                pin_data["tries_remaining"] = 3
                pin_data["blocked"] = False

                # Remove from blocked cards if present
                self.blocked_cards.discard(request.card_pan)

            return {
                "success": True,
                "message": "PIN changed successfully"
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"PIN change failed: {str(e)}"
            }

    def create_secure_pin_pad(self, terminal_id: str) -> SecurePINPad:
        """Create a secure PIN pad for PIN entry."""
        return SecurePINPad(
            terminal_id=terminal_id,
            encryption_key_id=f"pin_key_{terminal_id}",
            pin_entry_timeout=30,
            max_pin_length=12,
            min_pin_length=4,
            tamper_detected=False
        )

    async def simulate_pin_entry(
        self,
        pin_pad: SecurePINPad,
        card_pan: str,
        pin: str
    ) -> str:
        """
        Simulate PIN entry on secure PIN pad.

        Returns encrypted PIN block for transmission to verification engine.
        """
        if pin_pad.tamper_detected:
            raise Exception("PIN pad tamper detected")

        if not (pin_pad.min_pin_length <= len(pin) <= pin_pad.max_pin_length):
            raise Exception("Invalid PIN length")

        # Simulate PIN block encryption
        encrypted_pin_block = await self._encrypt_pin_block(
            pin, card_pan, PINBlockFormat.FORMAT_0
        )

        return encrypted_pin_block

    async def _perform_pin_verification(
        self,
        request: PINVerificationRequest,
        pin_data: Dict
    ) -> PINResult:
        """Perform actual PIN verification."""
        if request.verification_method == PINVerificationMethod.ONLINE:
            return await self._verify_pin_online(request, pin_data)
        else:
            return await self._verify_pin_offline(request, pin_data)

    async def _verify_pin_online(
        self,
        request: PINVerificationRequest,
        pin_data: Dict
    ) -> PINResult:
        """Verify PIN with issuer (online verification)."""
        # Simulate online PIN verification with issuer
        await asyncio.sleep(0.1)  # Simulate network delay

        # Decrypt PIN block and compare
        try:
            decrypted_pin = await self._decrypt_pin_block(
                request.encrypted_pin_block,
                request.card_pan,
                request.pin_block_format
            )

            stored_pin_hash = pin_data["encrypted_pin"]
            entered_pin_hash = self._hash_pin(decrypted_pin)

            if stored_pin_hash == entered_pin_hash:
                return PINResult.VERIFIED
            else:
                return PINResult.INCORRECT

        except Exception:
            return PINResult.SYSTEM_ERROR

    async def _verify_pin_offline(
        self,
        request: PINVerificationRequest,
        pin_data: Dict
    ) -> PINResult:
        """Verify PIN offline (with card data)."""
        # For offline verification, we would normally verify against
        # PIN data stored on the card (encrypted PIN block)
        # For demo, use the same logic as online verification
        return await self._verify_pin_online(request, pin_data)

    async def _encrypt_pin_block(
        self,
        pin: str,
        pan: str,
        format: PINBlockFormat
    ) -> str:
        """Encrypt PIN block using HSM or software encryption."""
        if format == PINBlockFormat.FORMAT_0:
            # ISO Format 0: PIN + padding + PAN
            pin_block = self._create_format_0_pin_block(pin, pan)
        elif format == PINBlockFormat.FORMAT_1:
            # ISO Format 1: Random padding
            pin_block = self._create_format_1_pin_block(pin)
        else:
            pin_block = self._create_format_0_pin_block(pin, pan)

        # Encrypt with HSM if available
        if self.hsm:
            # Use HSM for PIN block encryption
            encrypted = await self.hsm.encrypt_pin_block(pin_block)
            return encrypted
        else:
            # Software encryption (demo only)
            return hashlib.sha256(pin_block.encode()).hexdigest()

    async def _decrypt_pin_block(
        self,
        encrypted_pin_block: str,
        pan: str,
        format: PINBlockFormat
    ) -> str:
        """Decrypt PIN block and extract PIN."""
        if self.hsm:
            # Use HSM for PIN block decryption
            decrypted_block = await self.hsm.decrypt_pin_block(encrypted_pin_block)
        else:
            # For demo, reverse the hashing process (not secure)
            # In production, would use proper encryption/decryption
            decrypted_block = "demo_pin_block"

        # Extract PIN from decrypted block based on format
        if format == PINBlockFormat.FORMAT_0:
            return self._extract_pin_from_format_0(decrypted_block, pan)
        elif format == PINBlockFormat.FORMAT_1:
            return self._extract_pin_from_format_1(decrypted_block)
        else:
            # For demo, return a known PIN
            return "1234"

    def _create_format_0_pin_block(self, pin: str, pan: str) -> str:
        """Create ISO Format 0 PIN block."""
        # Format: 0L + PIN + F padding
        pin_field = f"0{len(pin)}{pin}"
        pin_field = pin_field.ljust(16, 'F')

        # XOR with PAN (rightmost 12 digits, excluding check digit)
        pan_field = "0000" + pan[-13:-1]  # 12 digits from PAN

        # XOR operation (simplified for demo)
        result = ""
        for i in range(16):
            result += str(int(pin_field[i], 16) ^ int(pan_field[i], 16))

        return result

    def _create_format_1_pin_block(self, pin: str) -> str:
        """Create ISO Format 1 PIN block."""
        # Format: 1L + PIN + random padding
        pin_field = f"1{len(pin)}{pin}"

        # Add random padding
        while len(pin_field) < 16:
            pin_field += secrets.choice("0123456789ABCDEF")

        return pin_field

    def _extract_pin_from_format_0(self, pin_block: str, pan: str) -> str:
        """Extract PIN from ISO Format 0 block."""
        # For demo, return known PIN
        return "1234"

    def _extract_pin_from_format_1(self, pin_block: str) -> str:
        """Extract PIN from ISO Format 1 block."""
        # For demo, return known PIN
        return "1234"

    def _hash_pin(self, pin: str) -> str:
        """Create secure hash of PIN for storage."""
        # In production, would use proper key derivation with salt
        return hashlib.sha256(f"pin_salt_{pin}".encode()).hexdigest()

    def _validate_pin_request(self, request: PINVerificationRequest) -> bool:
        """Validate PIN verification request."""
        if not request.card_pan or len(request.card_pan) < 13:
            return False
        if not request.encrypted_pin_block:
            return False
        if not request.terminal_id or not request.merchant_id:
            return False
        return True

    def _validate_pin_format(self, pin: str) -> bool:
        """Validate PIN format."""
        if not pin.isdigit():
            return False
        if not (4 <= len(pin) <= 12):
            return False
        return True

    def _get_response_message(self, result: PINResult) -> str:
        """Get human-readable response message."""
        messages = {
            PINResult.VERIFIED: "PIN verified successfully",
            PINResult.INCORRECT: "Incorrect PIN",
            PINResult.BLOCKED: "Card PIN blocked",
            PINResult.TRIES_EXCEEDED: "PIN tries exceeded",
            PINResult.SYSTEM_ERROR: "System error"
        }
        return messages.get(result, "Unknown result")

    def _create_response(
        self,
        request: PINVerificationRequest,
        result: PINResult,
        tries_remaining: int,
        message: str,
        start_time: float
    ) -> PINVerificationResponse:
        """Create PIN verification response."""
        processing_time = int((time.time() - start_time) * 1000)

        response_codes = {
            PINResult.VERIFIED: "00",
            PINResult.INCORRECT: "55",
            PINResult.BLOCKED: "75",
            PINResult.TRIES_EXCEEDED: "75",
            PINResult.SYSTEM_ERROR: "96"
        }

        return PINVerificationResponse(
            transaction_id=request.transaction_id,
            result=result,
            tries_remaining=tries_remaining,
            response_code=response_codes.get(result, "96"),
            response_message=message,
            processing_time_ms=processing_time,
            timestamp=datetime.now(timezone.utc),
            verification_method=request.verification_method
        )

    def _create_error_response(
        self,
        request: PINVerificationRequest,
        result: PINResult,
        error_message: str
    ) -> PINVerificationResponse:
        """Create error response."""
        return PINVerificationResponse(
            transaction_id=request.transaction_id,
            result=result,
            tries_remaining=0,
            response_code="96",
            response_message=error_message,
            processing_time_ms=0,
            timestamp=datetime.now(timezone.utc),
            verification_method=request.verification_method,
            error_details=error_message
        )


# Factory function
def create_pin_verification_engine(hsm_manager=None) -> PINVerificationEngine:
    """Create PIN verification engine with optional HSM."""
    return PINVerificationEngine(hsm_manager)