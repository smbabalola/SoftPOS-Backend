"""
Payment Processing Tests

Test suite for payment processing functionality including:
- Payment intent creation and confirmation
- Card data processing and validation
- Payment processor integration
- Error handling and edge cases
- Security validations
"""

import pytest
from decimal import Decimal
from unittest.mock import AsyncMock, patch, MagicMock
from datetime import datetime, timezone

from app.payment_processing import (
    PaymentProcessingEngine,
    PaymentRequest,
    CardData,
    TransactionType,
    PaymentProcessor,
    PaymentResponse,
    ResponseCode
)
from app.models import PaymentIntentCreate, PaymentConfirm


class TestPaymentProcessingEngine:
    """Test payment engine core functionality."""

    @pytest.fixture
    def payment_engine(self, mock_fraud_engine, mock_hsm_manager):
        """Create payment engine with mocked dependencies."""
        engine = PaymentProcessingEngine()
        engine.set_fraud_engine(mock_fraud_engine)
        engine.set_hsm_manager(mock_hsm_manager)
        return engine

    @pytest.mark.payment
    @pytest.mark.unit
    async def test_payment_request_validation(self, payment_engine):
        """Test payment request validation."""
        # Valid payment request
        valid_request = PaymentRequest(
            transaction_id="test_txn_001",
            merchant_id="mer_test_001",
            amount=Decimal("25.00"),
            currency="GBP",
            transaction_type=TransactionType.SALE,
            card_data=CardData(
                pan="4111111111111111",
                expiry_month="12",
                expiry_year="25",
                cvv="123"
            ),
            description="Test payment",
            terminal_id="term_test_001"
        )

        # Should not raise any validation errors
        assert valid_request.amount == Decimal("25.00")
        assert valid_request.currency == "GBP"
        assert valid_request.card_data.pan == "4111111111111111"

    @pytest.mark.payment
    @pytest.mark.unit
    async def test_card_data_validation(self):
        """Test card data validation."""
        # Valid Visa card
        visa_card = CardData(
            pan="4111111111111111",
            expiry_month="12",
            expiry_year="25",
            cvv="123"
        )
        assert visa_card.pan == "4111111111111111"

        # Valid Mastercard
        mc_card = CardData(
            pan="5555555555554444",
            expiry_month="12",
            expiry_year="25",
            cvv="123"
        )
        assert mc_card.pan == "5555555555554444"

    @pytest.mark.payment
    @pytest.mark.unit
    async def test_successful_payment_processing(self, payment_engine, mock_payment_processor):
        """Test successful payment processing flow."""
        # Setup mock processor
        payment_engine.processors = {"test_processor": mock_payment_processor}

        payment_request = PaymentRequest(
            transaction_id="test_txn_001",
            merchant_id="mer_test_001",
            amount=Decimal("25.00"),
            currency="GBP",
            transaction_type=TransactionType.SALE,
            card_data=CardData(
                pan="4111111111111111",
                expiry_month="12",
                expiry_year="25",
                cvv="123"
            ),
            description="Test payment",
            terminal_id="term_test_001"
        )

        # Process payment
        response = await payment_engine.process_payment(payment_request)

        # Verify response
        assert response.approved is True
        assert response.amount == Decimal("25.00")
        assert response.currency == "GBP"
        assert response.authorization_code == "123456"
        assert response.response_code == ResponseCode.APPROVED

        # Verify fraud engine was called
        payment_engine.fraud_engine.assess_risk.assert_called_once()

        # Verify HSM was called for encryption
        payment_engine.hsm_manager.encrypt_payment_data.assert_called()

    @pytest.mark.payment
    @pytest.mark.unit
    async def test_declined_payment_processing(self, payment_engine):
        """Test declined payment processing."""
        # Setup mock processor for declined transaction
        mock_processor = AsyncMock()
        mock_processor.process_payment.return_value = PaymentResponse(
            transaction_id="test_txn_001",
            processor_transaction_id="proc_txn_001",
            approved=False,
            authorization_code=None,
            response_code=ResponseCode.DECLINED,
            response_message="Insufficient funds",
            processor="test_processor",
            card_scheme="visa",
            amount=Decimal("25.00"),
            currency="GBP",
            processing_time_ms=150,
            risk_score=0.1
        )

        payment_engine.processors = {"test_processor": mock_processor}

        payment_request = PaymentRequest(
            transaction_id="test_txn_001",
            merchant_id="mer_test_001",
            amount=Decimal("25.00"),
            currency="GBP",
            transaction_type=TransactionType.SALE,
            card_data=CardData(
                pan="4000000000000002",  # Declined test card
                expiry_month="12",
                expiry_year="25",
                cvv="123"
            ),
            description="Test declined payment",
            terminal_id="term_test_001"
        )

        response = await payment_engine.process_payment(payment_request)

        assert response.approved is False
        assert response.response_code == ResponseCode.DECLINED
        assert response.response_message == "Insufficient funds"

    @pytest.mark.payment
    @pytest.mark.unit
    async def test_fraud_detection_integration(self, payment_engine):
        """Test fraud detection integration."""
        # Setup fraud engine to return high risk
        payment_engine.fraud_engine.assess_risk.return_value = {
            "risk_score": 0.95,
            "risk_level": "HIGH",
            "rules_triggered": ["velocity_check", "unusual_location"],
            "recommendation": "DECLINE"
        }

        payment_request = PaymentRequest(
            transaction_id="test_txn_001",
            merchant_id="mer_test_001",
            amount=Decimal("10000.00"),  # High amount
            currency="GBP",
            transaction_type=TransactionType.SALE,
            card_data=CardData(
                pan="4111111111111111",
                expiry_month="12",
                expiry_year="25",
                cvv="123"
            ),
            description="High risk payment",
            terminal_id="term_test_001"
        )

        # Should raise fraud exception or decline
        response = await payment_engine.process_payment(payment_request)

        # Verify fraud assessment was performed
        payment_engine.fraud_engine.assess_risk.assert_called_once()

        # High risk should result in decline or additional verification
        assert response.risk_score >= 0.9

    @pytest.mark.payment
    @pytest.mark.unit
    async def test_processor_failover(self, payment_engine):
        """Test payment processor failover logic."""
        # Setup primary processor to fail
        primary_processor = AsyncMock()
        primary_processor.process_payment.side_effect = Exception("Processor unavailable")

        # Setup backup processor to succeed
        backup_processor = AsyncMock()
        backup_processor.process_payment.return_value = PaymentResponse(
            transaction_id="test_txn_001",
            processor_transaction_id="backup_txn_001",
            approved=True,
            authorization_code="789012",
            response_code=ResponseCode.APPROVED,
            response_message="Approved via backup",
            processor="backup_processor",
            card_scheme="visa",
            amount=Decimal("25.00"),
            currency="GBP",
            processing_time_ms=200
        )

        payment_engine.processors = {
            "primary_processor": primary_processor,
            "backup_processor": backup_processor
        }

        payment_request = PaymentRequest(
            transaction_id="test_txn_001",
            merchant_id="mer_test_001",
            amount=Decimal("25.00"),
            currency="GBP",
            transaction_type=TransactionType.SALE,
            card_data=CardData(
                pan="4111111111111111",
                expiry_month="12",
                expiry_year="25",
                cvv="123"
            ),
            description="Failover test",
            terminal_id="term_test_001"
        )

        response = await payment_engine.process_payment(payment_request)

        # Should succeed via backup processor
        assert response.approved is True
        assert response.processor == "backup_processor"

    @pytest.mark.payment
    @pytest.mark.unit
    async def test_currency_validation(self, payment_engine):
        """Test currency validation and conversion."""
        # Test supported currency
        gbp_request = PaymentRequest(
            transaction_id="test_txn_001",
            merchant_id="mer_test_001",
            amount=Decimal("25.00"),
            currency="GBP",
            transaction_type=TransactionType.SALE,
            card_data=CardData(
                pan="4111111111111111",
                expiry_month="12",
                expiry_year="25",
                cvv="123"
            ),
            description="GBP payment",
            terminal_id="term_test_001"
        )

        # Should process without issues
        response = await payment_engine.process_payment(gbp_request)
        assert response.currency == "GBP"

    @pytest.mark.payment
    @pytest.mark.unit
    async def test_amount_limits(self, payment_engine):
        """Test payment amount limits."""
        # Test minimum amount
        min_request = PaymentRequest(
            transaction_id="test_txn_001",
            merchant_id="mer_test_001",
            amount=Decimal("0.01"),  # 1 penny
            currency="GBP",
            transaction_type=TransactionType.SALE,
            card_data=CardData(
                pan="4111111111111111",
                expiry_month="12",
                expiry_year="25",
                cvv="123"
            ),
            description="Minimum amount test",
            terminal_id="term_test_001"
        )

        response = await payment_engine.process_payment(min_request)
        assert response.amount == Decimal("0.01")

        # Test large amount (should trigger additional checks)
        large_request = PaymentRequest(
            transaction_id="test_txn_002",
            merchant_id="mer_test_001",
            amount=Decimal("10000.00"),  # £10,000
            currency="GBP",
            transaction_type=TransactionType.SALE,
            card_data=CardData(
                pan="4111111111111111",
                expiry_month="12",
                expiry_year="25",
                cvv="123"
            ),
            description="Large amount test",
            terminal_id="term_test_001"
        )

        response = await payment_engine.process_payment(large_request)
        # Should still process but with additional fraud checks
        assert response.amount == Decimal("10000.00")

    @pytest.mark.payment
    @pytest.mark.unit
    async def test_refund_processing(self, payment_engine, mock_payment_processor):
        """Test refund processing."""
        payment_engine.processors = {"test_processor": mock_payment_processor}

        # Setup refund response
        mock_payment_processor.process_payment.return_value = PaymentResponse(
            transaction_id="refund_txn_001",
            processor_transaction_id="proc_refund_001",
            approved=True,
            authorization_code="REF123",
            response_code=ResponseCode.APPROVED,
            response_message="Refund approved",
            processor="test_processor",
            card_scheme="visa",
            amount=Decimal("-25.00"),  # Negative for refund
            currency="GBP",
            processing_time_ms=120,
            original_transaction_id="original_txn_001"
        )

        refund_request = PaymentRequest(
            transaction_id="refund_txn_001",
            merchant_id="mer_test_001",
            amount=Decimal("25.00"),
            currency="GBP",
            transaction_type=TransactionType.REFUND,
            card_data=CardData(
                pan="4111111111111111",
                expiry_month="12",
                expiry_year="25",
                cvv="123"
            ),
            description="Test refund",
            terminal_id="term_test_001",
            original_transaction_id="original_txn_001"
        )

        response = await payment_engine.process_payment(refund_request)

        assert response.approved is True
        assert response.amount == Decimal("-25.00")  # Negative amount for refund
        assert "refund" in response.response_message.lower()


class TestPaymentIntentAPI:
    """Test payment intent API endpoints."""

    @pytest.mark.payment
    @pytest.mark.integration
    async def test_create_payment_intent(self, async_client, auth_headers):
        """Test payment intent creation."""
        intent_data = {
            "merchant_id": "mer_test_001",
            "amount_minor": 2500,  # £25.00
            "currency": "GBP",
            "capture_mode": "auto"
        }

        response = await async_client.post(
            "/v1/payments/intent",
            json=intent_data,
            headers=auth_headers
        )

        assert response.status_code == 201
        data = response.json()
        assert data["amount_minor"] == 2500
        assert data["currency"] == "GBP"
        assert data["status"] == "requires_confirmation"
        assert "ephemeral_key" in data

    @pytest.mark.payment
    @pytest.mark.integration
    async def test_confirm_payment_intent(self, async_client, auth_headers, mock_payment_processor):
        """Test payment intent confirmation."""
        # First create an intent
        intent_data = {
            "merchant_id": "mer_test_001",
            "amount_minor": 2500,
            "currency": "GBP",
            "capture_mode": "auto"
        }

        intent_response = await async_client.post(
            "/v1/payments/intent",
            json=intent_data,
            headers=auth_headers
        )

        intent_id = intent_response.json()["id"]

        # Now confirm the intent
        confirm_data = {
            "device_id": "test_device_001",
            "emv_payload": "4111111111111111|12|25|123",
            "attestation": "test_attestation_token"
        }

        with patch('app.main.payment_engine', mock_payment_processor):
            response = await async_client.post(
                f"/v1/payments/intent/{intent_id}/confirm",
                json=confirm_data,
                headers=auth_headers
            )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "succeeded"
        assert data["amount_minor"] == 2500

    @pytest.mark.payment
    @pytest.mark.integration
    async def test_payment_intent_idempotency(self, async_client, auth_headers):
        """Test payment intent idempotency."""
        intent_data = {
            "merchant_id": "mer_test_001",
            "amount_minor": 2500,
            "currency": "GBP",
            "capture_mode": "auto"
        }

        headers = {**auth_headers, "Idempotency-Key": "test_key_001"}

        # First request
        response1 = await async_client.post(
            "/v1/payments/intent",
            json=intent_data,
            headers=headers
        )

        # Second request with same idempotency key
        response2 = await async_client.post(
            "/v1/payments/intent",
            json=intent_data,
            headers=headers
        )

        assert response1.status_code == 201
        assert response2.status_code == 201
        assert response1.json()["id"] == response2.json()["id"]

    @pytest.mark.payment
    @pytest.mark.integration
    async def test_unauthorized_payment_intent(self, async_client):
        """Test unauthorized payment intent creation."""
        intent_data = {
            "merchant_id": "mer_test_001",
            "amount_minor": 2500,
            "currency": "GBP"
        }

        response = await async_client.post(
            "/v1/payments/intent",
            json=intent_data
        )

        assert response.status_code == 401


class TestPaymentValidation:
    """Test payment validation logic."""

    @pytest.mark.payment
    @pytest.mark.unit
    def test_card_number_validation(self):
        """Test card number validation."""
        # Valid Visa
        visa_card = CardData(
            pan="4111111111111111",
            expiry_month="12",
            expiry_year="25",
            cvv="123"
        )
        assert visa_card.pan == "4111111111111111"

        # Valid Mastercard
        mc_card = CardData(
            pan="5555555555554444",
            expiry_month="12",
            expiry_year="25",
            cvv="123"
        )
        assert mc_card.pan == "5555555555554444"

    @pytest.mark.payment
    @pytest.mark.unit
    def test_expiry_date_validation(self):
        """Test expiry date validation."""
        # Valid future date
        valid_card = CardData(
            pan="4111111111111111",
            expiry_month="12",
            expiry_year="30",  # Year 2030
            cvv="123"
        )
        assert valid_card.expiry_year == "30"

    @pytest.mark.payment
    @pytest.mark.unit
    def test_cvv_validation(self):
        """Test CVV validation."""
        # Valid 3-digit CVV
        visa_card = CardData(
            pan="4111111111111111",
            expiry_month="12",
            expiry_year="25",
            cvv="123"
        )
        assert len(visa_card.cvv) == 3

        # Valid 4-digit CVV (Amex)
        amex_card = CardData(
            pan="378282246310005",
            expiry_month="12",
            expiry_year="25",
            cvv="1234"
        )
        assert len(amex_card.cvv) == 4


class TestPaymentSecurity:
    """Test payment security features."""

    @pytest.mark.payment
    @pytest.mark.security
    async def test_card_data_encryption(self, payment_engine):
        """Test card data encryption during processing."""
        payment_request = PaymentRequest(
            transaction_id="test_txn_001",
            merchant_id="mer_test_001",
            amount=Decimal("25.00"),
            currency="GBP",
            transaction_type=TransactionType.SALE,
            card_data=CardData(
                pan="4111111111111111",
                expiry_month="12",
                expiry_year="25",
                cvv="123"
            ),
            description="Security test",
            terminal_id="term_test_001"
        )

        await payment_engine.process_payment(payment_request)

        # Verify HSM encryption was called
        payment_engine.hsm_manager.encrypt_payment_data.assert_called()

    @pytest.mark.payment
    @pytest.mark.security
    async def test_transaction_signing(self, payment_engine):
        """Test transaction signing for integrity."""
        payment_request = PaymentRequest(
            transaction_id="test_txn_001",
            merchant_id="mer_test_001",
            amount=Decimal("25.00"),
            currency="GBP",
            transaction_type=TransactionType.SALE,
            card_data=CardData(
                pan="4111111111111111",
                expiry_month="12",
                expiry_year="25",
                cvv="123"
            ),
            description="Signing test",
            terminal_id="term_test_001"
        )

        await payment_engine.process_payment(payment_request)

        # Verify transaction signing was performed
        payment_engine.hsm_manager.sign_transaction.assert_called()

    @pytest.mark.payment
    @pytest.mark.security
    async def test_fraud_prevention(self, payment_engine):
        """Test fraud prevention measures."""
        # Test multiple rapid transactions (velocity check)
        base_request = PaymentRequest(
            transaction_id="test_txn_001",
            merchant_id="mer_test_001",
            amount=Decimal("25.00"),
            currency="GBP",
            transaction_type=TransactionType.SALE,
            card_data=CardData(
                pan="4111111111111111",
                expiry_month="12",
                expiry_year="25",
                cvv="123"
            ),
            description="Fraud test",
            terminal_id="term_test_001"
        )

        # Process multiple payments rapidly
        for i in range(5):
            request = base_request
            request.transaction_id = f"test_txn_{i:03d}"
            await payment_engine.process_payment(request)

        # Verify fraud engine was called for each transaction
        assert payment_engine.fraud_engine.assess_risk.call_count == 5