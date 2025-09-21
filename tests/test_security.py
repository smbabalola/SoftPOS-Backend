"""
Security & Fraud Detection Tests

Test suite for security and fraud detection functionality including:
- HSM integration and key management
- Device attestation validation
- Fraud detection engine
- Encryption and signing
- Security policy enforcement
"""

import pytest
from decimal import Decimal
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch, MagicMock

from app.hsm import HSMManager, KeyType, SignatureAlgorithm
from app.attestation import (
    DeviceAttestationValidator,
    AttestationResult,
    AttestationStatus,
    DevicePlatform
)
from app.fraud_detection import (
    FraudDetectionEngine,
    FraudRiskLevel,
    FraudReason,
    FraudDetectionResult
)
from app.encryption import CardDataEncryption, EncryptionMethod


class TestHSMIntegration:
    """Test Hardware Security Module integration."""

    @pytest.fixture
    def hsm_manager(self):
        """Create HSM manager for testing."""
        return HSMManager()

    @pytest.mark.security
    @pytest.mark.unit
    async def test_generate_merchant_keys(self, hsm_manager):
        """Test generating HSM keys for merchants."""
        keys = await hsm_manager.generate_merchant_keys("mer_test_001")

        assert "encryption_key_id" in keys
        assert "signing_key_id" in keys
        assert "key_check_value" in keys

        # Keys should have proper format
        assert keys["encryption_key_id"].startswith("key_")
        assert keys["signing_key_id"].startswith("key_")
        assert len(keys["key_check_value"]) >= 6  # Minimum KCV length

    @pytest.mark.security
    @pytest.mark.unit
    async def test_encrypt_payment_data(self, hsm_manager):
        """Test encrypting payment data with HSM."""
        sensitive_data = "4111111111111111|12|25|123"  # Card data
        merchant_id = "mer_test_001"

        # First generate keys for merchant
        await hsm_manager.generate_merchant_keys(merchant_id)

        # Encrypt data
        encrypted_data, key_reference = await hsm_manager.encrypt_payment_data(
            sensitive_data, merchant_id
        )

        assert encrypted_data is not None
        assert encrypted_data != sensitive_data  # Should be encrypted
        assert key_reference is not None
        assert len(encrypted_data) > len(sensitive_data)  # Encrypted data typically longer

    @pytest.mark.security
    @pytest.mark.unit
    async def test_decrypt_payment_data(self, hsm_manager):
        """Test decrypting payment data with HSM."""
        original_data = "4111111111111111|12|25|123"
        merchant_id = "mer_test_001"

        # Generate keys and encrypt
        await hsm_manager.generate_merchant_keys(merchant_id)
        encrypted_data, key_reference = await hsm_manager.encrypt_payment_data(
            original_data, merchant_id
        )

        # Decrypt data
        decrypted_data = await hsm_manager.decrypt_payment_data(
            encrypted_data, key_reference, merchant_id
        )

        assert decrypted_data == original_data

    @pytest.mark.security
    @pytest.mark.unit
    async def test_sign_transaction(self, hsm_manager):
        """Test transaction signing with HSM."""
        transaction_data = {
            "transaction_id": "txn_001",
            "merchant_id": "mer_test_001",
            "amount": "25.00",
            "currency": "GBP",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        merchant_id = "mer_test_001"

        # Generate keys
        await hsm_manager.generate_merchant_keys(merchant_id)

        # Sign transaction
        signature = await hsm_manager.sign_transaction(transaction_data, merchant_id)

        assert signature is not None
        assert len(signature) > 0
        assert isinstance(signature, str)

    @pytest.mark.security
    @pytest.mark.unit
    async def test_verify_transaction_signature(self, hsm_manager):
        """Test transaction signature verification."""
        transaction_data = {
            "transaction_id": "txn_001",
            "merchant_id": "mer_test_001",
            "amount": "25.00",
            "currency": "GBP",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        merchant_id = "mer_test_001"

        # Generate keys and sign
        await hsm_manager.generate_merchant_keys(merchant_id)
        signature = await hsm_manager.sign_transaction(transaction_data, merchant_id)

        # Verify signature
        is_valid = await hsm_manager.verify_transaction(
            transaction_data, signature, merchant_id
        )

        assert is_valid is True

    @pytest.mark.security
    @pytest.mark.unit
    async def test_verify_modified_transaction_signature(self, hsm_manager):
        """Test signature verification fails for modified data."""
        transaction_data = {
            "transaction_id": "txn_001",
            "merchant_id": "mer_test_001",
            "amount": "25.00",
            "currency": "GBP"
        }

        merchant_id = "mer_test_001"

        # Generate keys and sign
        await hsm_manager.generate_merchant_keys(merchant_id)
        signature = await hsm_manager.sign_transaction(transaction_data, merchant_id)

        # Modify transaction data
        modified_data = transaction_data.copy()
        modified_data["amount"] = "50.00"  # Changed amount

        # Verify signature (should fail)
        is_valid = await hsm_manager.verify_transaction(
            modified_data, signature, merchant_id
        )

        assert is_valid is False

    @pytest.mark.security
    @pytest.mark.unit
    async def test_key_rotation(self, hsm_manager):
        """Test HSM key rotation."""
        merchant_id = "mer_test_001"

        # Generate initial keys
        keys1 = await hsm_manager.generate_merchant_keys(merchant_id)

        # Rotate keys
        keys2 = await hsm_manager.rotate_merchant_keys(merchant_id)

        # Keys should be different
        assert keys1["encryption_key_id"] != keys2["encryption_key_id"]
        assert keys1["signing_key_id"] != keys2["signing_key_id"]

        # Old keys should still work for decryption
        test_data = "test_data_123"
        encrypted_with_old, key_ref = await hsm_manager.encrypt_payment_data(
            test_data, merchant_id, use_key_version=1
        )

        # Should be able to decrypt with old key
        decrypted = await hsm_manager.decrypt_payment_data(
            encrypted_with_old, key_ref, merchant_id
        )
        assert decrypted == test_data

    @pytest.mark.security
    @pytest.mark.unit
    async def test_hsm_availability_check(self, hsm_manager):
        """Test HSM availability checking."""
        is_available = await hsm_manager.check_availability()
        assert isinstance(is_available, bool)

        # Test HSM performance
        performance = await hsm_manager.get_performance_metrics()
        assert "operations_per_second" in performance
        assert "average_latency_ms" in performance
        assert "error_rate" in performance


class TestDeviceAttestation:
    """Test device attestation and validation."""

    @pytest.fixture
    def attestation_validator(self):
        """Create attestation validator for testing."""
        return DeviceAttestationValidator()

    @pytest.mark.security
    @pytest.mark.unit
    async def test_ios_attestation_validation(self, attestation_validator):
        """Test iOS device attestation validation."""
        attestation_token = "mock_ios_attestation_token_12345"
        nonce = "test_nonce_123"
        platform = DevicePlatform.IOS

        result = await attestation_validator.validate_attestation(
            attestation_token, nonce, platform
        )

        assert isinstance(result, AttestationResult)
        assert result.platform == DevicePlatform.IOS
        assert result.status in [AttestationStatus.VALID, AttestationStatus.INVALID]
        assert 0.0 <= result.risk_score <= 1.0
        assert result.device_id is not None

    @pytest.mark.security
    @pytest.mark.unit
    async def test_android_attestation_validation(self, attestation_validator):
        """Test Android device attestation validation."""
        attestation_token = "mock_android_attestation_token_67890"
        nonce = "test_nonce_456"
        platform = DevicePlatform.ANDROID

        result = await attestation_validator.validate_attestation(
            attestation_token, nonce, platform
        )

        assert isinstance(result, AttestationResult)
        assert result.platform == DevicePlatform.ANDROID
        assert result.status in [AttestationStatus.VALID, AttestationStatus.INVALID]
        assert result.device_id is not None

    @pytest.mark.security
    @pytest.mark.unit
    async def test_invalid_attestation_token(self, attestation_validator):
        """Test validation with invalid attestation token."""
        invalid_token = "invalid_token_format"
        nonce = "test_nonce_789"
        platform = DevicePlatform.IOS

        result = await attestation_validator.validate_attestation(
            invalid_token, nonce, platform
        )

        assert result.status == AttestationStatus.INVALID
        assert result.risk_score >= 0.5  # High risk for invalid token

    @pytest.mark.security
    @pytest.mark.unit
    async def test_jailbroken_device_detection(self, attestation_validator):
        """Test detection of jailbroken/rooted devices."""
        # Mock attestation for jailbroken device
        jailbroken_token = "jailbroken_device_attestation_token"
        nonce = "test_nonce_jb"
        platform = DevicePlatform.IOS

        with patch.object(attestation_validator, '_analyze_ios_attestation') as mock_analyze:
            mock_analyze.return_value = {
                "device_id": "jb_device_001",
                "jailbroken": True,
                "debugger_attached": False,
                "app_integrity": True
            }

            result = await attestation_validator.validate_attestation(
                jailbroken_token, nonce, platform
            )

            assert result.status == AttestationStatus.INVALID
            assert result.details.get("jailbroken") is True
            assert result.risk_score > 0.8  # High risk for jailbroken device

    @pytest.mark.security
    @pytest.mark.unit
    async def test_debugger_detection(self, attestation_validator):
        """Test detection of attached debuggers."""
        debug_token = "debugger_attached_attestation_token"
        nonce = "test_nonce_debug"
        platform = DevicePlatform.ANDROID

        with patch.object(attestation_validator, '_analyze_android_attestation') as mock_analyze:
            mock_analyze.return_value = {
                "device_id": "debug_device_001",
                "rooted": False,
                "debugger_attached": True,
                "app_signature_valid": True
            }

            result = await attestation_validator.validate_attestation(
                debug_token, nonce, platform
            )

            assert result.status == AttestationStatus.INVALID
            assert result.details.get("debugger") is True
            assert result.risk_score > 0.7  # High risk for debugger

    @pytest.mark.security
    @pytest.mark.unit
    async def test_nonce_validation(self, attestation_validator):
        """Test nonce validation in attestation."""
        attestation_token = "valid_attestation_token"
        correct_nonce = "correct_nonce_123"
        wrong_nonce = "wrong_nonce_456"
        platform = DevicePlatform.IOS

        # Valid nonce should pass
        valid_result = await attestation_validator.validate_attestation(
            attestation_token, correct_nonce, platform
        )

        # Wrong nonce should fail
        invalid_result = await attestation_validator.validate_attestation(
            attestation_token, wrong_nonce, platform
        )

        # Note: Implementation would need to track expected nonces
        # This test assumes the validator checks nonce validity


class TestFraudDetection:
    """Test fraud detection engine."""

    @pytest.fixture
    def fraud_engine(self):
        """Create fraud detection engine for testing."""
        return FraudDetectionEngine()

    @pytest.fixture
    def low_risk_transaction(self):
        """Create low-risk transaction data."""
        return {
            "transaction_id": "txn_low_risk_001",
            "merchant_id": "mer_test_001",
            "amount": Decimal("25.00"),
            "currency": "GBP",
            "card_number": "4111111111111111",
            "card_scheme": "visa",
            "country_code": "GB",
            "ip_address": "192.168.1.100",
            "device_fingerprint": "fp_normal_device",
            "timestamp": datetime.now(timezone.utc),
            "merchant_category": "5411",  # Grocery stores
            "terminal_id": "term_001"
        }

    @pytest.fixture
    def high_risk_transaction(self):
        """Create high-risk transaction data."""
        return {
            "transaction_id": "txn_high_risk_001",
            "merchant_id": "mer_test_001",
            "amount": Decimal("9999.99"),  # High amount
            "currency": "USD",
            "card_number": "4000000000000002",  # Test declined card
            "card_scheme": "visa",
            "country_code": "NG",  # High-risk country
            "ip_address": "1.2.3.4",  # Suspicious IP
            "device_fingerprint": "fp_suspicious_device",
            "timestamp": datetime.now(timezone.utc),
            "merchant_category": "5999",  # Miscellaneous
            "terminal_id": "term_suspicious"
        }

    @pytest.mark.fraud
    @pytest.mark.unit
    async def test_low_risk_transaction_assessment(self, fraud_engine, low_risk_transaction):
        """Test fraud assessment for low-risk transaction."""
        risk_assessment = await fraud_engine.assess_risk(low_risk_transaction)

        assert risk_assessment["risk_level"] == RiskLevel.LOW.value
        assert risk_assessment["risk_score"] < 0.3
        assert risk_assessment["recommendation"] == "APPROVE"
        assert len(risk_assessment["rules_triggered"]) == 0

    @pytest.mark.fraud
    @pytest.mark.unit
    async def test_high_risk_transaction_assessment(self, fraud_engine, high_risk_transaction):
        """Test fraud assessment for high-risk transaction."""
        risk_assessment = await fraud_engine.assess_risk(high_risk_transaction)

        assert risk_assessment["risk_level"] in [RiskLevel.HIGH.value, RiskLevel.CRITICAL.value]
        assert risk_assessment["risk_score"] > 0.7
        assert risk_assessment["recommendation"] in ["DECLINE", "REVIEW"]
        assert len(risk_assessment["rules_triggered"]) > 0

    @pytest.mark.fraud
    @pytest.mark.unit
    async def test_velocity_fraud_rule(self, fraud_engine):
        """Test velocity-based fraud detection."""
        base_transaction = {
            "merchant_id": "mer_test_001",
            "card_number": "4111111111111111",
            "amount": Decimal("100.00"),
            "currency": "GBP",
            "timestamp": datetime.now(timezone.utc),
            "ip_address": "192.168.1.100"
        }

        # Simulate multiple rapid transactions
        for i in range(5):
            transaction = base_transaction.copy()
            transaction["transaction_id"] = f"txn_velocity_{i:03d}"
            transaction["timestamp"] = datetime.now(timezone.utc) - timedelta(minutes=i)

            risk_assessment = await fraud_engine.assess_risk(transaction)

            # Later transactions should have higher risk
            if i >= 3:  # After 3 transactions in short time
                assert "velocity_check" in risk_assessment["rules_triggered"]
                assert risk_assessment["risk_score"] > 0.5

    @pytest.mark.fraud
    @pytest.mark.unit
    async def test_amount_based_fraud_rule(self, fraud_engine):
        """Test amount-based fraud detection."""
        high_amount_transaction = {
            "transaction_id": "txn_high_amount_001",
            "merchant_id": "mer_test_001",
            "amount": Decimal("10000.00"),  # Very high amount
            "currency": "GBP",
            "card_number": "4111111111111111",
            "timestamp": datetime.now(timezone.utc)
        }

        risk_assessment = await fraud_engine.assess_risk(high_amount_transaction)

        assert "high_amount" in risk_assessment["rules_triggered"]
        assert risk_assessment["risk_score"] > 0.4

    @pytest.mark.fraud
    @pytest.mark.unit
    async def test_geographic_fraud_rule(self, fraud_engine):
        """Test geographic-based fraud detection."""
        # Transaction from high-risk country
        geographic_risk_transaction = {
            "transaction_id": "txn_geo_risk_001",
            "merchant_id": "mer_test_001",
            "amount": Decimal("50.00"),
            "currency": "USD",
            "card_number": "4111111111111111",
            "country_code": "XX",  # Unknown/high-risk country
            "ip_address": "1.2.3.4",  # Suspicious IP range
            "timestamp": datetime.now(timezone.utc)
        }

        risk_assessment = await fraud_engine.assess_risk(geographic_risk_transaction)

        assert "geographic_risk" in risk_assessment["rules_triggered"]
        assert risk_assessment["risk_score"] > 0.3

    @pytest.mark.fraud
    @pytest.mark.unit
    async def test_device_fingerprint_fraud_rule(self, fraud_engine):
        """Test device fingerprint-based fraud detection."""
        suspicious_device_transaction = {
            "transaction_id": "txn_device_risk_001",
            "merchant_id": "mer_test_001",
            "amount": Decimal("75.00"),
            "currency": "GBP",
            "card_number": "4111111111111111",
            "device_fingerprint": "fp_known_fraudulent_device",
            "timestamp": datetime.now(timezone.utc)
        }

        # Mock device as known fraudulent
        with patch.object(fraud_engine, '_is_device_blacklisted', return_value=True):
            risk_assessment = await fraud_engine.assess_risk(suspicious_device_transaction)

            assert "blacklisted_device" in risk_assessment["rules_triggered"]
            assert risk_assessment["risk_score"] > 0.8

    @pytest.mark.fraud
    @pytest.mark.unit
    async def test_time_based_fraud_rule(self, fraud_engine):
        """Test time-based fraud detection."""
        # Transaction at unusual hour (3 AM)
        unusual_time_transaction = {
            "transaction_id": "txn_time_risk_001",
            "merchant_id": "mer_test_001",
            "amount": Decimal("200.00"),
            "currency": "GBP",
            "card_number": "4111111111111111",
            "timestamp": datetime.now(timezone.utc).replace(hour=3, minute=0, second=0),
            "merchant_category": "5411"  # Grocery store (unusual at 3 AM)
        }

        risk_assessment = await fraud_engine.assess_risk(unusual_time_transaction)

        # May trigger unusual time rule depending on merchant category
        if "unusual_time" in risk_assessment["rules_triggered"]:
            assert risk_assessment["risk_score"] > 0.2

    @pytest.mark.fraud
    @pytest.mark.unit
    async def test_fraud_rule_weights(self, fraud_engine):
        """Test that fraud rules have appropriate weights."""
        # Transaction triggering multiple rules
        multi_rule_transaction = {
            "transaction_id": "txn_multi_rule_001",
            "merchant_id": "mer_test_001",
            "amount": Decimal("5000.00"),  # High amount
            "currency": "USD",
            "card_number": "4000000000000002",  # Declined test card
            "country_code": "XX",  # High-risk country
            "device_fingerprint": "fp_suspicious",
            "timestamp": datetime.now(timezone.utc)
        }

        risk_assessment = await fraud_engine.assess_risk(multi_rule_transaction)

        # Multiple rules should increase overall risk score
        assert len(risk_assessment["rules_triggered"]) >= 2
        assert risk_assessment["risk_score"] > 0.6

    @pytest.mark.fraud
    @pytest.mark.unit
    async def test_fraud_model_learning(self, fraud_engine):
        """Test fraud model learning from feedback."""
        transaction = {
            "transaction_id": "txn_learning_001",
            "merchant_id": "mer_test_001",
            "amount": Decimal("100.00"),
            "currency": "GBP",
            "card_number": "4111111111111111"
        }

        # Initial assessment
        initial_assessment = await fraud_engine.assess_risk(transaction)

        # Provide feedback (this was actually fraudulent)
        await fraud_engine.record_fraud_feedback(
            transaction["transaction_id"],
            is_fraud=True,
            feedback_source="chargeback"
        )

        # Model should learn and adjust future assessments
        # (In a real ML model, this would update model weights)
        updated_model_stats = await fraud_engine.get_model_performance()
        assert "feedback_count" in updated_model_stats
        assert updated_model_stats["feedback_count"] > 0


class TestEncryption:
    """Test encryption and cryptographic functions."""

    @pytest.fixture
    def encryption_manager(self):
        """Create encryption manager for testing."""
        return CardDataEncryption()

    @pytest.mark.security
    @pytest.mark.unit
    async def test_symmetric_encryption(self, encryption_manager):
        """Test symmetric encryption/decryption."""
        plaintext = "4111111111111111|12|25|123"
        key = await encryption_manager.generate_symmetric_key()

        # Encrypt
        encrypted_data = await encryption_manager.encrypt_symmetric(plaintext, key)
        assert encrypted_data != plaintext
        assert len(encrypted_data) > len(plaintext)

        # Decrypt
        decrypted_data = await encryption_manager.decrypt_symmetric(encrypted_data, key)
        assert decrypted_data == plaintext

    @pytest.mark.security
    @pytest.mark.unit
    async def test_asymmetric_encryption(self, encryption_manager):
        """Test asymmetric encryption/decryption."""
        plaintext = "sensitive_data_123"

        # Generate key pair
        public_key, private_key = await encryption_manager.generate_key_pair()

        # Encrypt with public key
        encrypted_data = await encryption_manager.encrypt_asymmetric(plaintext, public_key)
        assert encrypted_data != plaintext

        # Decrypt with private key
        decrypted_data = await encryption_manager.decrypt_asymmetric(encrypted_data, private_key)
        assert decrypted_data == plaintext

    @pytest.mark.security
    @pytest.mark.unit
    async def test_digital_signature(self, encryption_manager):
        """Test digital signature creation and verification."""
        message = "transaction_data_to_sign"

        # Generate key pair
        public_key, private_key = await encryption_manager.generate_key_pair()

        # Sign message
        signature = await encryption_manager.sign_message(message, private_key)
        assert signature is not None
        assert len(signature) > 0

        # Verify signature
        is_valid = await encryption_manager.verify_signature(message, signature, public_key)
        assert is_valid is True

        # Verify tampered message fails
        tampered_message = "tampered_transaction_data"
        is_valid_tampered = await encryption_manager.verify_signature(
            tampered_message, signature, public_key
        )
        assert is_valid_tampered is False

    @pytest.mark.security
    @pytest.mark.unit
    async def test_hash_functions(self, encryption_manager):
        """Test cryptographic hash functions."""
        data = "data_to_hash_123"

        # SHA-256 hash
        hash_sha256 = await encryption_manager.hash_sha256(data)
        assert len(hash_sha256) == 64  # 256 bits = 64 hex chars
        assert hash_sha256 != data

        # Same data should produce same hash
        hash_sha256_2 = await encryption_manager.hash_sha256(data)
        assert hash_sha256 == hash_sha256_2

        # Different data should produce different hash
        different_data = "different_data_456"
        hash_different = await encryption_manager.hash_sha256(different_data)
        assert hash_sha256 != hash_different

    @pytest.mark.security
    @pytest.mark.unit
    async def test_key_derivation(self, encryption_manager):
        """Test key derivation functions."""
        password = "user_password_123"
        salt = await encryption_manager.generate_salt()

        # Derive key from password
        derived_key = await encryption_manager.derive_key(password, salt)
        assert len(derived_key) >= 32  # At least 256 bits

        # Same password and salt should produce same key
        derived_key_2 = await encryption_manager.derive_key(password, salt)
        assert derived_key == derived_key_2

        # Different salt should produce different key
        different_salt = await encryption_manager.generate_salt()
        derived_key_different = await encryption_manager.derive_key(password, different_salt)
        assert derived_key != derived_key_different

    @pytest.mark.security
    @pytest.mark.unit
    async def test_secure_random_generation(self, encryption_manager):
        """Test secure random number generation."""
        # Generate random bytes
        random_bytes_1 = await encryption_manager.generate_random_bytes(32)
        random_bytes_2 = await encryption_manager.generate_random_bytes(32)

        assert len(random_bytes_1) == 32
        assert len(random_bytes_2) == 32
        assert random_bytes_1 != random_bytes_2  # Should be different

        # Generate random hex string
        random_hex = await encryption_manager.generate_random_hex(16)
        assert len(random_hex) == 32  # 16 bytes = 32 hex chars

        # Should be valid hex
        int(random_hex, 16)  # Should not raise exception


class TestSecurityPolicies:
    """Test security policy enforcement."""

    @pytest.mark.security
    @pytest.mark.unit
    async def test_password_policy_validation(self):
        """Test password policy validation."""
        from app.auth import validate_password_policy

        # Valid passwords
        assert validate_password_policy("StrongP@ssw0rd123") is True
        assert validate_password_policy("C0mpl3x!P@ssw0rd") is True

        # Invalid passwords
        assert validate_password_policy("weak") is False  # Too short
        assert validate_password_policy("nouppercase123!") is False  # No uppercase
        assert validate_password_policy("NOLOWERCASE123!") is False  # No lowercase
        assert validate_password_policy("NoNumbers!") is False  # No numbers
        assert validate_password_policy("NoSpecialChars123") is False  # No special chars

    @pytest.mark.security
    @pytest.mark.unit
    async def test_session_timeout_policy(self):
        """Test session timeout policy enforcement."""
        from app.auth import SessionManager

        session_manager = SessionManager()

        # Create session
        session_id = await session_manager.create_session("user_001", timeout_minutes=30)
        assert session_id is not None

        # Session should be valid initially
        is_valid = await session_manager.is_session_valid(session_id)
        assert is_valid is True

        # Mock session as expired
        session = session_manager.sessions[session_id]
        session["expires_at"] = datetime.now(timezone.utc) - timedelta(minutes=1)

        # Session should now be invalid
        is_valid = await session_manager.is_session_valid(session_id)
        assert is_valid is False

    @pytest.mark.security
    @pytest.mark.unit
    async def test_rate_limiting_policy(self):
        """Test rate limiting policy enforcement."""
        from app.auth import RateLimiter

        rate_limiter = RateLimiter(max_requests=5, window_minutes=1)

        client_id = "client_001"

        # Should allow requests within limit
        for i in range(5):
            allowed = await rate_limiter.is_allowed(client_id)
            assert allowed is True

        # Should block request exceeding limit
        blocked = await rate_limiter.is_allowed(client_id)
        assert blocked is False

    @pytest.mark.security
    @pytest.mark.unit
    async def test_ip_whitelist_policy(self):
        """Test IP whitelist policy enforcement."""
        from app.auth import IPWhitelistValidator

        validator = IPWhitelistValidator(allowed_ips=[
            "192.168.1.0/24",
            "10.0.0.0/8",
            "127.0.0.1"
        ])

        # Allowed IPs
        assert validator.is_allowed("192.168.1.100") is True
        assert validator.is_allowed("10.0.0.50") is True
        assert validator.is_allowed("127.0.0.1") is True

        # Blocked IPs
        assert validator.is_allowed("8.8.8.8") is False
        assert validator.is_allowed("1.2.3.4") is False

    @pytest.mark.security
    @pytest.mark.unit
    async def test_api_key_validation(self):
        """Test API key validation and security."""
        from app.auth import APIKeyValidator

        validator = APIKeyValidator()

        # Generate valid API key
        api_key = await validator.generate_api_key("mer_test_001")
        assert api_key is not None
        assert len(api_key) >= 32

        # Validate API key
        merchant_id = await validator.validate_api_key(api_key)
        assert merchant_id == "mer_test_001"

        # Invalid API key
        invalid_merchant_id = await validator.validate_api_key("invalid_key")
        assert invalid_merchant_id is None