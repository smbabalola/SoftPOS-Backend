# SoftPOS API Testing Guide

Comprehensive testing documentation for the SoftPOS API, covering unit tests, integration tests, security tests, and performance testing.

## 🧪 Test Structure

```
tests/
├── conftest.py              # Test configuration and fixtures
├── test_payment_processing.py    # Payment processing tests
├── test_terminal_management.py   # Terminal management tests
├── test_webhooks.py              # Webhook system tests
├── test_monitoring.py            # Monitoring and analytics tests
├── test_security.py              # Security and fraud detection tests
└── test_integration.py           # End-to-end integration tests
```

## 🏃‍♂️ Running Tests

### Quick Start

```bash
# Install dependencies
poetry install --with dev

# Run all tests
python run_tests.py

# Or use make commands
make test
```

### Test Categories

```bash
# Unit tests (fast, isolated)
python run_tests.py --unit
make test-unit

# Integration tests (slower, with external dependencies)
python run_tests.py --integration
make test-integration

# Security tests
python run_tests.py --security
make test-security

# End-to-end tests
python run_tests.py --e2e
make test-e2e
```

### Specific Test Areas

```bash
# Payment processing tests
python run_tests.py --payment
make test-payment

# Terminal management tests
python run_tests.py --terminal
make test-terminal

# Webhook system tests
python run_tests.py --webhook
make test-webhook

# Monitoring and analytics tests
python run_tests.py --monitoring
make test-monitoring

# Fraud detection tests
python run_tests.py --fraud
```

### Coverage Reports

```bash
# Run tests with coverage
python run_tests.py --coverage
make test-coverage

# Open coverage report
open htmlcov/index.html
```

## 🏷️ Test Markers

Tests are organized using pytest markers:

- `@pytest.mark.unit` - Fast unit tests
- `@pytest.mark.integration` - Integration tests
- `@pytest.mark.e2e` - End-to-end tests
- `@pytest.mark.security` - Security-related tests
- `@pytest.mark.payment` - Payment processing tests
- `@pytest.mark.terminal` - Terminal management tests
- `@pytest.mark.webhook` - Webhook system tests
- `@pytest.mark.monitoring` - Monitoring tests
- `@pytest.mark.fraud` - Fraud detection tests
- `@pytest.mark.slow` - Slow tests (>10 seconds)

## 🔧 Test Configuration

### Environment Variables

Tests automatically set these environment variables:

```bash
TESTING=true
DATABASE_URL=sqlite+aiosqlite:///:memory:
REDIS_URL=redis://localhost:6379/15
```

### Test Database

Tests use an in-memory SQLite database by default for speed. For integration tests requiring PostgreSQL features, configure:

```bash
TEST_DATABASE_URL=postgresql://postgres:password@localhost:5432/softpos_test
```

### Mock Services

Tests include comprehensive mocks for external services:

- Payment processors (Stripe, Adyen, etc.)
- HSM services
- Redis cache
- Fraud detection APIs
- Device attestation services

## 📋 Test Coverage Areas

### Payment Processing Tests
- Payment intent creation and confirmation
- Card data validation and processing
- Payment processor integration
- Fraud detection integration
- Error handling and edge cases
- Refund and void operations
- Idempotency handling

### Terminal Management Tests
- Terminal registration and lifecycle
- Configuration management
- Health monitoring and heartbeats
- Fleet management and grouping
- Performance tracking
- Command sending and status updates

### Webhook System Tests
- Endpoint registration and management
- Event emission and delivery
- Retry logic with exponential backoff
- Circuit breaker functionality
- Rate limiting
- Security and signature verification

### Monitoring Tests
- Metrics collection and storage
- Alert creation and management
- Health check functionality
- System overview generation
- Performance analytics
- Real-time monitoring

### Security Tests
- HSM integration and key management
- Device attestation validation
- Fraud detection engine
- Encryption and digital signatures
- Security policy enforcement
- Authentication and authorization

### Integration Tests
- Complete payment flows
- Terminal registration workflows
- Webhook delivery scenarios
- Real-time monitoring integration
- Performance under load
- Error handling across systems

## 🎯 Writing Tests

### Test Structure

```python
import pytest
from unittest.mock import AsyncMock, patch

class TestPaymentProcessing:
    """Test payment processing functionality."""

    @pytest.mark.payment
    @pytest.mark.unit
    async def test_successful_payment(self, mock_payment_processor):
        """Test successful payment processing."""
        # Arrange
        payment_request = PaymentRequest(...)

        # Act
        response = await payment_engine.process_payment(payment_request)

        # Assert
        assert response.approved is True
        assert response.amount == expected_amount
```

### Using Fixtures

```python
# Use provided fixtures
async def test_with_fixtures(
    mock_merchant,
    mock_card_data,
    auth_headers,
    async_client
):
    """Test using common fixtures."""
    response = await async_client.post(
        "/v1/payments/intent",
        json=payment_data,
        headers=auth_headers
    )
    assert response.status_code == 201
```

### Async Testing

```python
@pytest.mark.asyncio
async def test_async_function():
    """Test async functionality."""
    result = await some_async_function()
    assert result is not None
```

### Mocking External Services

```python
@patch('app.payment_processing.payment_engine')
async def test_with_mock(mock_engine):
    """Test with mocked payment engine."""
    mock_engine.process_payment.return_value = mock_response
    # Test logic here
```

## 🚀 Performance Testing

### Load Testing

```python
@pytest.mark.slow
async def test_concurrent_payments():
    """Test system under concurrent load."""
    tasks = [process_payment(i) for i in range(100)]
    results = await asyncio.gather(*tasks)
    success_rate = sum(results) / len(results)
    assert success_rate >= 0.95  # 95% success rate
```

### Benchmarking

```bash
# Run performance benchmarks
make benchmark

# Or specific performance tests
python run_tests.py --slow
```

## 🔍 Test Data and Fixtures

### Mock Data

The test suite includes realistic mock data:

- Test card numbers (non-functional)
- Sample merchant data
- Mock transaction histories
- Simulated device information
- Sample webhook payloads

### Test Cards

```python
# Successful test cards
VISA_SUCCESS = "4111111111111111"
MASTERCARD_SUCCESS = "5555555555554444"

# Declined test cards
VISA_DECLINED = "4000000000000002"
INSUFFICIENT_FUNDS = "4000000000009995"

# Fraud test cards
HIGH_RISK_CARD = "4000000000000119"
```

### Sample Merchants

```python
TEST_MERCHANTS = {
    "mer_test_001": {
        "legal_name": "Test Merchant Ltd",
        "trading_name": "Test Store",
        "country": "GB",
        "mcc": "5411"
    }
}
```

## 🛠️ CI/CD Integration

### GitHub Actions

```yaml
name: Test Suite
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Tests
        run: |
          make install
          make ci-test
```

### Pre-commit Hooks

```bash
# Install pre-commit hooks
make pre-commit

# Hooks will run:
# - Linting with ruff
# - Code formatting
# - Basic security checks
# - Unit tests
```

## 📊 Test Metrics

### Coverage Goals

- **Overall Coverage**: >80%
- **Core Payment Logic**: >95%
- **Security Functions**: >95%
- **API Endpoints**: >90%

### Performance Targets

- **Unit Tests**: <5 seconds total
- **Integration Tests**: <30 seconds total
- **E2E Tests**: <60 seconds total
- **Individual Test**: <2 seconds

## 🔧 Troubleshooting

### Common Issues

**Tests failing with database errors:**
```bash
# Reset test database
make db-reset
```

**Import errors:**
```bash
# Reinstall dependencies
poetry install --with dev
```

**Redis connection errors:**
```bash
# Start Redis for integration tests
docker run -d -p 6379:6379 redis:alpine
```

**Slow test execution:**
```bash
# Run only fast tests
python run_tests.py --unit
```

### Debug Mode

```bash
# Run tests with detailed output
python run_tests.py --unit -v

# Run specific test with debugging
poetry run pytest tests/test_payment_processing.py::test_specific_function -v -s
```

### Test Isolation

Each test is isolated with:
- Fresh database for each test
- Mocked external services
- Clean application state
- Separate Redis test database

## 📝 Best Practices

### Test Naming

```python
def test_should_create_payment_intent_when_valid_data_provided():
    """Use descriptive test names that explain the behavior."""
    pass
```

### Test Organization

```python
class TestPaymentIntentCreation:
    """Group related tests in classes."""

    def test_successful_creation(self):
        """Test the happy path."""
        pass

    def test_invalid_amount_raises_error(self):
        """Test error conditions."""
        pass

    def test_unauthorized_access_denied(self):
        """Test security conditions."""
        pass
```

### Assertions

```python
# Good: Specific assertions
assert response.status_code == 201
assert response.json()["status"] == "succeeded"
assert len(response.json()["transactions"]) == 5

# Avoid: Vague assertions
assert response  # Too general
assert response.json()  # Could be anything
```

### Test Data

```python
# Good: Use fixtures and factories
def test_with_fixture(mock_merchant):
    assert mock_merchant["id"] == "mer_test_001"

# Good: Create data specific to test
def test_high_amount_payment():
    payment_data = {"amount_minor": 100000}  # £1,000
    # Test logic
```

## 🎯 Next Steps

1. **Run the test suite**: `make test`
2. **Check coverage**: `make test-coverage`
3. **Review failing tests**: Fix any issues
4. **Add new tests**: For new features
5. **Optimize performance**: Profile slow tests

For questions or issues with testing, check the test output or examine the test files for examples.