import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_endpoint():
    """Test the health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_create_payment_intent_requires_auth():
    """Test that payment intent creation requires authentication."""
    response = client.post(
        "/v1/payments/intent",
        json={
            "merchant_id": "mer_test",
            "amount_minor": 1000,
            "currency": "GBP",
            "channel": "card_present",
        }
    )
    assert response.status_code == 401


def test_confirm_payment_intent_requires_auth():
    """Test that payment confirmation requires authentication."""
    response = client.post(
        "/v1/payments/intent/pi_test/confirm",
        json={
            "device_id": "device_test",
        }
    )
    assert response.status_code == 401