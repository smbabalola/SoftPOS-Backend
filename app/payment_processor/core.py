"""
Custom Payment Processor Core Module

This module implements the core payment processing functionality
for the SoftPOS custom payment gateway.
"""

import asyncio
import hashlib
import hmac
import secrets
from datetime import datetime, timezone
from decimal import Decimal
from typing import Dict, List, Optional
from enum import Enum

import structlog
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = structlog.get_logger(__name__)


class TransactionStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DECLINED = "declined"
    FAILED = "failed"
    SETTLED = "settled"
    REFUNDED = "refunded"


class PaymentMethod(Enum):
    CARD_PRESENT = "card_present"
    CARD_NOT_PRESENT = "card_not_present"
    CONTACTLESS = "contactless"
    CHIP_AND_PIN = "chip_and_pin"


class CardType(Enum):
    VISA = "visa"
    MASTERCARD = "mastercard"
    AMEX = "amex"
    DISCOVER = "discover"
    UNKNOWN = "unknown"


class CardData:
    """Secure card data handling"""

    def __init__(self, pan: str, expiry_month: int, expiry_year: int, cvv: str):
        self.pan = pan
        self.expiry_month = expiry_month
        self.expiry_year = expiry_year
        self.cvv = cvv
        self._validate()

    def _validate(self):
        """Validate card data"""
        if not self._luhn_check(self.pan):
            raise ValueError("Invalid card number - failed Luhn check")

        if not (1 <= self.expiry_month <= 12):
            raise ValueError("Invalid expiry month")

        current_year = datetime.now().year % 100
        if self.expiry_year < current_year:
            raise ValueError("Card has expired")

    @staticmethod
    def _luhn_check(card_number: str) -> bool:
        """Luhn algorithm for card number validation"""
        digits = [int(d) for d in card_number.replace(" ", "")]
        checksum = sum(digits[-1::-2])

        for d in digits[-2::-2]:
            checksum += sum(divmod(d * 2, 10))

        return checksum % 10 == 0

    def get_card_type(self) -> CardType:
        """Determine card type from PAN"""
        first_digit = self.pan[0]
        first_two = self.pan[:2]
        first_four = self.pan[:4]

        if first_digit == "4":
            return CardType.VISA
        elif "51" <= first_two <= "55" or "2221" <= first_four <= "2720":
            return CardType.MASTERCARD
        elif first_two in ["34", "37"]:
            return CardType.AMEX
        elif first_four in ["6011"] or first_two == "65":
            return CardType.DISCOVER
        else:
            return CardType.UNKNOWN

    def get_masked_pan(self) -> str:
        """Return masked PAN for display"""
        return f"{self.pan[:6]}******{self.pan[-4:]}"


class SecurityManager:
    """Handle encryption and tokenization"""

    def __init__(self):
        self.key = self._generate_key()

    def _generate_key(self) -> bytes:
        """Generate encryption key"""
        password = b"softpos_payment_processor"
        salt = b"softpos_salt_2024"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(password)

    def encrypt_card_data(self, card_data: CardData) -> str:
        """Encrypt sensitive card data"""
        f = Fernet(self.key)
        data_string = f"{card_data.pan}|{card_data.expiry_month}|{card_data.expiry_year}|{card_data.cvv}"
        encrypted = f.encrypt(data_string.encode())
        return encrypted.decode()

    def decrypt_card_data(self, encrypted_data: str) -> CardData:
        """Decrypt card data"""
        f = Fernet(self.key)
        decrypted = f.decrypt(encrypted_data.encode()).decode()
        pan, exp_month, exp_year, cvv = decrypted.split("|")
        return CardData(pan, int(exp_month), int(exp_year), cvv)

    def tokenize_card(self, card_data: CardData) -> str:
        """Create a secure token for card storage"""
        # Create a non-reversible token
        token_data = f"{card_data.pan}{card_data.expiry_month}{card_data.expiry_year}"
        hash_obj = hashlib.sha256(token_data.encode())
        token_hash = hash_obj.hexdigest()

        # Create a displayable token
        masked_pan = card_data.get_masked_pan()
        return f"tok_{masked_pan}_{token_hash[:8]}"


class FraudDetector:
    """Real-time fraud detection"""

    def __init__(self):
        self.risk_rules = self._load_risk_rules()

    def _load_risk_rules(self) -> Dict:
        """Load fraud detection rules"""
        return {
            "max_single_transaction": 50000,  # £500
            "max_daily_amount": 200000,       # £2000
            "max_hourly_transactions": 10,
            "blocked_countries": ["XX", "YY"],
            "high_risk_amounts": [9999, 99999]  # Common fraud amounts
        }

    async def assess_risk(self, transaction_data: Dict) -> Dict:
        """Assess transaction risk"""
        risk_score = 0.0
        risk_factors = []

        amount = transaction_data.get("amount", 0)

        # High value check
        if amount > self.risk_rules["max_single_transaction"]:
            risk_score += 0.3
            risk_factors.append("HIGH_VALUE")

        # Suspicious amount patterns
        if amount in self.risk_rules["high_risk_amounts"]:
            risk_score += 0.4
            risk_factors.append("SUSPICIOUS_AMOUNT")

        # Velocity check (simplified)
        if transaction_data.get("recent_transaction_count", 0) > 5:
            risk_score += 0.2
            risk_factors.append("HIGH_VELOCITY")

        # Card type risk
        card_type = transaction_data.get("card_type")
        if card_type == CardType.UNKNOWN:
            risk_score += 0.1
            risk_factors.append("UNKNOWN_CARD_TYPE")

        # Determine risk level
        if risk_score >= 0.8:
            risk_level = "HIGH"
            recommendation = "DECLINE"
        elif risk_score >= 0.4:
            risk_level = "MEDIUM"
            recommendation = "REVIEW"
        else:
            risk_level = "LOW"
            recommendation = "APPROVE"

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "recommendation": recommendation
        }


class TransactionProcessor:
    """Core transaction processing logic"""

    def __init__(self):
        self.security_manager = SecurityManager()
        self.fraud_detector = FraudDetector()

    async def process_payment(
        self,
        amount: int,  # in pence
        card_data: CardData,
        merchant_id: str,
        terminal_id: str,
        currency: str = "GBP"
    ) -> Dict:
        """Process a payment transaction"""

        transaction_id = self._generate_transaction_id()

        try:
            logger.info(
                "Processing payment",
                transaction_id=transaction_id,
                amount=amount,
                merchant_id=merchant_id
            )

            # 1. Validate inputs
            if amount <= 0:
                raise ValueError("Amount must be positive")

            if amount > 1000000:  # £10,000 limit
                raise ValueError("Amount exceeds maximum limit")

            # 2. Fraud detection
            risk_assessment = await self.fraud_detector.assess_risk({
                "amount": amount,
                "card_type": card_data.get_card_type(),
                "merchant_id": merchant_id,
                "recent_transaction_count": 0  # TODO: Get from database
            })

            if risk_assessment["recommendation"] == "DECLINE":
                return {
                    "transaction_id": transaction_id,
                    "status": TransactionStatus.DECLINED.value,
                    "decline_reason": "Risk assessment failed",
                    "risk_score": risk_assessment["risk_score"]
                }

            # 3. Card validation
            card_type = card_data.get_card_type()
            if card_type == CardType.UNKNOWN:
                return {
                    "transaction_id": transaction_id,
                    "status": TransactionStatus.DECLINED.value,
                    "decline_reason": "Unsupported card type"
                }

            # 4. Process authorization (simulated for now)
            auth_result = await self._process_authorization(
                transaction_id, amount, card_data, merchant_id
            )

            if auth_result["approved"]:
                # 5. Create successful transaction
                transaction = {
                    "transaction_id": transaction_id,
                    "status": TransactionStatus.APPROVED.value,
                    "amount": amount,
                    "currency": currency,
                    "card_token": self.security_manager.tokenize_card(card_data),
                    "card_type": card_type.value,
                    "card_last_four": card_data.pan[-4:],
                    "merchant_id": merchant_id,
                    "terminal_id": terminal_id,
                    "authorization_code": auth_result["auth_code"],
                    "processor_reference": auth_result["processor_ref"],
                    "risk_score": risk_assessment["risk_score"],
                    "processing_fee": self._calculate_fee(amount),
                    "created_at": datetime.now(timezone.utc).isoformat()
                }

                logger.info(
                    "Payment approved",
                    transaction_id=transaction_id,
                    amount=amount,
                    auth_code=auth_result["auth_code"]
                )

                return transaction
            else:
                return {
                    "transaction_id": transaction_id,
                    "status": TransactionStatus.DECLINED.value,
                    "decline_reason": auth_result["decline_reason"]
                }

        except Exception as e:
            logger.error(
                "Payment processing failed",
                transaction_id=transaction_id,
                error=str(e)
            )

            return {
                "transaction_id": transaction_id,
                "status": TransactionStatus.FAILED.value,
                "error": str(e)
            }

    async def _process_authorization(
        self,
        transaction_id: str,
        amount: int,
        card_data: CardData,
        merchant_id: str
    ) -> Dict:
        """Process card authorization (placeholder for real bank integration)"""

        # Simulate processing delay
        await asyncio.sleep(0.1)

        # Simulate different responses based on card number
        if card_data.pan.endswith("0000"):
            return {
                "approved": False,
                "decline_reason": "Insufficient funds"
            }
        elif card_data.pan.endswith("1111"):
            return {
                "approved": False,
                "decline_reason": "Card blocked"
            }
        else:
            # Approve transaction
            return {
                "approved": True,
                "auth_code": self._generate_auth_code(),
                "processor_ref": f"REF_{transaction_id[:8]}"
            }

    def _generate_transaction_id(self) -> str:
        """Generate unique transaction ID"""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        random_part = secrets.token_hex(4).upper()
        return f"TXN_{timestamp}_{random_part}"

    def _generate_auth_code(self) -> str:
        """Generate authorization code"""
        return secrets.token_hex(3).upper()

    def _calculate_fee(self, amount: int) -> int:
        """Calculate processing fee"""
        # Example: 1.5% + 20p
        percentage_fee = int(amount * 0.015)
        fixed_fee = 20
        return percentage_fee + fixed_fee


# Global processor instance
payment_processor = TransactionProcessor()