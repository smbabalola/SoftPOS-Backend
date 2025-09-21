"""
Test configuration and fixtures for SoftPOS API tests.
"""

import asyncio
import os
from datetime import datetime, timezone
from decimal import Decimal
from typing import AsyncGenerator, Dict, Generator
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from faker import Faker
from fastapi.testclient import TestClient
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

# Test database URL - use in-memory SQLite for fast tests
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

fake = Faker()

# Import RBAC models for testing
try:
    from app.models.users import User
    from app.models.rbac import Role, Permission
    RBAC_AVAILABLE = True
except ImportError:
    RBAC_AVAILABLE = False


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def async_engine():
    """Create test database engine."""
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)

    # Create tables
    from app.db_models import Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    # Cleanup
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.fixture
async def async_session(async_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create test database session."""
    async_session_maker = sessionmaker(
        async_engine, class_=AsyncSession, expire_on_commit=False
    )

    async with async_session_maker() as session:
        yield session
        await session.rollback()


@pytest.fixture
def client():
    """Create test client."""
    from app.main import app

    # Override dependencies for testing
    def override_get_db():
        return AsyncMock()

    app.dependency_overrides = {}

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides = {}


@pytest.fixture
async def async_client():
    """Create async test client."""
    from app.main import app

    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client


@pytest.fixture
def mock_merchant():
    """Create mock merchant data."""
    return {
        "id": "mer_test_001",
        "legal_name": "Test Merchant Ltd",
        "trading_name": "Test Store",
        "country": "GB",
        "mcc": "5411",
        "tier": "tier1",
        "kyc_status": "approved"
    }


@pytest.fixture
def mock_payment_intent():
    """Create mock payment intent."""
    return {
        "id": "pi_test_001",
        "merchant_id": "mer_test_001",
        "amount_minor": 2500,  # £25.00
        "currency": "GBP",
        "status": "requires_confirmation",
        "capture_mode": "auto",
        "ephemeral_key": "ek_test_123"
    }


@pytest.fixture
def mock_card_data():
    """Create mock card data for testing."""
    return {
        "pan": "4111111111111111",  # Test Visa card
        "expiry_month": "12",
        "expiry_year": "25",
        "cvv": "123",
        "cardholder_name": "John Doe"
    }


@pytest.fixture
def mock_terminal():
    """Create mock terminal data."""
    return {
        "terminal_id": "term_test_001",
        "merchant_id": "mer_test_001",
        "device_name": "Test Terminal",
        "device_model": "iPhone 13",
        "serial_number": "TEST123456",
        "status": "active",
        "capabilities": ["contactless", "chip_pin", "mobile_wallet"]
    }


@pytest.fixture
def mock_webhook_endpoint():
    """Create mock webhook endpoint."""
    return {
        "endpoint_id": "wh_test_001",
        "merchant_id": "mer_test_001",
        "url": "https://merchant.example.com/webhooks",
        "secret_key": "whsec_test_secret",
        "event_types": ["payment.successful", "payment.failed"],
        "active": True
    }


@pytest.fixture
def mock_payment_processor():
    """Mock payment processor for testing."""
    processor = AsyncMock()

    # Default successful response
    processor.process_payment.return_value = {
        "transaction_id": "test_txn_001",
        "processor_transaction_id": "proc_txn_001",
        "approved": True,
        "authorization_code": "123456",
        "response_code": "00",
        "response_message": "Approved",
        "processor": "test_processor",
        "card_scheme": "visa",
        "amount": Decimal("25.00"),
        "currency": "GBP",
        "processing_time_ms": 150,
        "network_transaction_id": "net_txn_001",
        "avs_result": "Y",
        "cvv_result": "M",
        "risk_score": 0.1
    }

    return processor


@pytest.fixture
def mock_hsm_manager():
    """Mock HSM manager for testing."""
    hsm = AsyncMock()

    hsm.generate_merchant_keys.return_value = {
        "encryption_key_id": "key_001",
        "signing_key_id": "key_002",
        "key_check_value": "ABC123"
    }

    hsm.encrypt_payment_data.return_value = ("encrypted_data", "key_ref_001")
    hsm.decrypt_payment_data.return_value = "decrypted_data"
    hsm.sign_transaction.return_value = "signature_001"
    hsm.verify_transaction.return_value = True

    return hsm


@pytest.fixture
def mock_fraud_engine():
    """Mock fraud detection engine."""
    fraud_engine = AsyncMock()

    fraud_engine.assess_risk.return_value = {
        "risk_score": 0.1,
        "risk_level": "LOW",
        "rules_triggered": [],
        "recommendation": "APPROVE"
    }

    return fraud_engine


@pytest.fixture
def mock_attestation_validator():
    """Mock device attestation validator."""
    validator = AsyncMock()

    from app.attestation import AttestationResult, AttestationStatus, DevicePlatform

    validator.validate_attestation.return_value = AttestationResult(
        status=AttestationStatus.VALID,
        device_id="test_device_001",
        platform=DevicePlatform.IOS,
        risk_score=0.1,
        details={"jailbroken": False, "debugger": False}
    )

    return validator


@pytest.fixture
def mock_redis():
    """Mock Redis client for testing."""
    redis_mock = AsyncMock()

    # Mock common Redis operations
    redis_mock.get.return_value = None
    redis_mock.set.return_value = True
    redis_mock.delete.return_value = 1
    redis_mock.exists.return_value = False
    redis_mock.expire.return_value = True
    redis_mock.ttl.return_value = -1

    return redis_mock


@pytest.fixture
def auth_headers():
    """Create authorization headers for testing."""
    from app.auth import create_access_token

    token = create_access_token(
        data={"sub": "mer_test_001", "scopes": ["payments:create", "payments:read"]}
    )

    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def sample_transaction_data():
    """Generate sample transaction data for testing."""
    return {
        "transaction_id": "txn_test_001",
        "merchant_id": "mer_test_001",
        "terminal_id": "term_test_001",
        "amount": Decimal("25.00"),
        "currency": "GBP",
        "card_scheme": "visa",
        "processor": "test_processor",
        "approved": True,
        "processing_time_ms": 150,
        "timestamp": datetime.now(timezone.utc),
        "fraud_score": 0.1,
        "payment_method": "contactless"
    }


@pytest.fixture
def mock_webhook_delivery():
    """Mock webhook delivery data."""
    return {
        "delivery_id": "del_test_001",
        "event_id": "evt_test_001",
        "endpoint_id": "wh_test_001",
        "status": "delivered",
        "url": "https://merchant.example.com/webhooks",
        "response_status": 200,
        "sent_at": datetime.now(timezone.utc),
        "completed_at": datetime.now(timezone.utc),
        "duration_ms": 150,
        "retry_count": 0
    }


@pytest.fixture
def mock_system_alert():
    """Mock system alert data."""
    return {
        "alert_id": "alert_test_001",
        "title": "Test Alert",
        "description": "This is a test alert",
        "severity": "warning",
        "component": "payment_processing",
        "timestamp": datetime.now(timezone.utc),
        "resolved": False,
        "metadata": {"test": True}
    }


@pytest.fixture
def mock_performance_metrics():
    """Mock performance metrics data."""
    return {
        "terminal_id": "term_test_001",
        "date": datetime.now(timezone.utc).date(),
        "transaction_count": 100,
        "transaction_volume": Decimal("2500.00"),
        "success_rate": 0.98,
        "average_response_time": 150.0,
        "error_count": 2,
        "uptime_percentage": 99.5,
        "peak_tps": 10.5,
        "revenue_generated": Decimal("50.00")
    }


@pytest.fixture(autouse=True)
def setup_test_environment(monkeypatch):
    """Setup test environment variables."""
    monkeypatch.setenv("TESTING", "true")
    monkeypatch.setenv("DATABASE_URL", TEST_DATABASE_URL)
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/15")  # Test DB


class AsyncContextManager:
    """Helper for async context manager mocking."""

    def __init__(self, return_value):
        self.return_value = return_value

    async def __aenter__(self):
        return self.return_value

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


@pytest.fixture
def mock_http_client():
    """Mock HTTP client for external API calls."""
    client = AsyncMock()

    # Mock successful response
    response = AsyncMock()
    response.status_code = 200
    response.json.return_value = {"status": "success"}
    response.text = '{"status": "success"}'
    response.headers = {"content-type": "application/json"}

    client.post.return_value = AsyncContextManager(response)
    client.get.return_value = AsyncContextManager(response)
    client.put.return_value = AsyncContextManager(response)
    client.delete.return_value = AsyncContextManager(response)

    return client


# ========== RBAC-SPECIFIC FIXTURES ==========

@pytest.fixture
def mock_user():
    """Create a mock user for RBAC testing"""
    if not RBAC_AVAILABLE:
        # Basic mock for when RBAC models aren't available
        from unittest.mock import Mock
        user = Mock()
        user.id = 1
        user.email = "test@example.com"
        user.first_name = "Test"
        user.last_name = "User"
        user.merchant_id = "mer_123"
        user.is_active = True
        return user

    return User(
        id=1,
        email="test@example.com",
        first_name="Test",
        last_name="User",
        merchant_id="mer_123",
        is_active=True
    )


@pytest.fixture
def mock_request():
    """Create a mock FastAPI request for RBAC testing"""
    from unittest.mock import Mock

    request = Mock()
    request.client.host = "192.168.1.100"
    request.url.path = "/test"
    request.method = "GET"
    request.path_params = {}
    request.headers = {}
    return request


@pytest.fixture
def mock_credentials():
    """Create mock HTTP credentials for RBAC testing"""
    from unittest.mock import Mock

    credentials = Mock()
    credentials.credentials = "test_token_123"
    return credentials


@pytest.fixture
def db_session():
    """Create a mock database session for RBAC testing"""
    from unittest.mock import Mock

    session = Mock()
    session.add = Mock()
    session.commit = Mock()
    session.flush = Mock()
    session.query = Mock()
    session.refresh = Mock()
    return session


@pytest.fixture
def auth_headers():
    """Create authorization headers for API testing"""
    return {
        "Authorization": "Bearer test_token_123",
        "Content-Type": "application/json"
    }