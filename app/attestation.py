"""
Device Attestation Validation for SoftPOS Security

This module handles validation of device attestation tokens from iOS and Android devices
to ensure payments are processed only on genuine, uncompromised devices.

For production, this would integrate with:
- Apple App Attest API for iOS devices
- Google Play Integrity API for Android devices
- Hardware Security Module (HSM) for certificate validation
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


class DevicePlatform(Enum):
    IOS = "ios"
    ANDROID = "android"


class AttestationStatus(Enum):
    VALID = "valid"
    INVALID_SIGNATURE = "invalid_signature"
    INVALID_CERTIFICATE = "invalid_certificate"
    DEVICE_COMPROMISED = "device_compromised"
    EXPIRED = "expired"
    INVALID_APP = "invalid_app"
    REPLAY_ATTACK = "replay_attack"


@dataclass
class AttestationResult:
    status: AttestationStatus
    device_id: str
    platform: DevicePlatform
    app_id: str
    timestamp: int
    risk_score: float  # 0.0 = low risk, 1.0 = high risk
    details: Dict[str, any]


class DeviceAttestationValidator:
    """
    Validates device attestation tokens to ensure payment security.

    In production, this would:
    1. Validate certificate chains against Apple/Google root CAs
    2. Check device integrity (jailbreak/root detection)
    3. Verify app authenticity and version
    4. Detect replay attacks using nonce validation
    5. Risk scoring based on device behavior
    """

    def __init__(self):
        # In production, these would be loaded from secure storage/HSM
        self.trusted_app_ids = {
            "com.surepay.softpos.ios",
            "com.surepay.softpos.android"
        }
        self.max_attestation_age = 300  # 5 minutes
        self.used_nonces: set = set()  # In production, use Redis with TTL

    async def validate_attestation(
        self,
        attestation_token: str,
        expected_nonce: str,
        platform: DevicePlatform
    ) -> AttestationResult:
        """
        Validate device attestation token.

        Args:
            attestation_token: Base64 encoded attestation from device
            expected_nonce: Expected nonce to prevent replay attacks
            platform: Device platform (iOS/Android)

        Returns:
            AttestationResult with validation status and device info
        """
        try:
            if platform == DevicePlatform.IOS:
                return await self._validate_ios_attestation(attestation_token, expected_nonce)
            elif platform == DevicePlatform.ANDROID:
                return await self._validate_android_attestation(attestation_token, expected_nonce)
            else:
                return AttestationResult(
                    status=AttestationStatus.INVALID_SIGNATURE,
                    device_id="unknown",
                    platform=platform,
                    app_id="unknown",
                    timestamp=int(time.time()),
                    risk_score=1.0,
                    details={"error": "Unsupported platform"}
                )
        except Exception as e:
            return AttestationResult(
                status=AttestationStatus.INVALID_SIGNATURE,
                device_id="unknown",
                platform=platform,
                app_id="unknown",
                timestamp=int(time.time()),
                risk_score=1.0,
                details={"error": str(e)}
            )

    async def _validate_ios_attestation(
        self,
        attestation_token: str,
        expected_nonce: str
    ) -> AttestationResult:
        """
        Validate iOS App Attest token.

        Real implementation would:
        1. Decode CBOR attestation statement
        2. Validate certificate chain against Apple root CA
        3. Verify app ID and team ID
        4. Check device hardware attestation
        5. Validate nonce and timestamp
        """
        # Mock implementation - production would use Apple's App Attest API
        try:
            # Decode mock attestation (in production, this would be CBOR)
            decoded = base64.b64decode(attestation_token)
            mock_data = json.loads(decoded.decode())

            device_id = mock_data.get("device_id", "unknown")
            app_id = mock_data.get("app_id", "unknown")
            nonce = mock_data.get("nonce", "")
            timestamp = mock_data.get("timestamp", 0)
            jailbroken = mock_data.get("jailbroken", False)

            # Validate nonce (prevent replay attacks)
            if nonce != expected_nonce:
                return AttestationResult(
                    status=AttestationStatus.REPLAY_ATTACK,
                    device_id=device_id,
                    platform=DevicePlatform.IOS,
                    app_id=app_id,
                    timestamp=timestamp,
                    risk_score=1.0,
                    details={"error": "Invalid nonce"}
                )

            # Check if nonce was already used
            if nonce in self.used_nonces:
                return AttestationResult(
                    status=AttestationStatus.REPLAY_ATTACK,
                    device_id=device_id,
                    platform=DevicePlatform.IOS,
                    app_id=app_id,
                    timestamp=timestamp,
                    risk_score=1.0,
                    details={"error": "Nonce already used"}
                )

            # Validate app ID
            if app_id not in self.trusted_app_ids:
                return AttestationResult(
                    status=AttestationStatus.INVALID_APP,
                    device_id=device_id,
                    platform=DevicePlatform.IOS,
                    app_id=app_id,
                    timestamp=timestamp,
                    risk_score=1.0,
                    details={"error": "Untrusted app"}
                )

            # Check device integrity
            if jailbroken:
                return AttestationResult(
                    status=AttestationStatus.DEVICE_COMPROMISED,
                    device_id=device_id,
                    platform=DevicePlatform.IOS,
                    app_id=app_id,
                    timestamp=timestamp,
                    risk_score=0.9,
                    details={"error": "Jailbroken device detected"}
                )

            # Check timestamp freshness
            current_time = int(time.time())
            if current_time - timestamp > self.max_attestation_age:
                return AttestationResult(
                    status=AttestationStatus.EXPIRED,
                    device_id=device_id,
                    platform=DevicePlatform.IOS,
                    app_id=app_id,
                    timestamp=timestamp,
                    risk_score=0.7,
                    details={"error": "Attestation expired"}
                )

            # Mark nonce as used
            self.used_nonces.add(nonce)

            # Calculate risk score based on various factors
            risk_score = self._calculate_risk_score(mock_data)

            return AttestationResult(
                status=AttestationStatus.VALID,
                device_id=device_id,
                platform=DevicePlatform.IOS,
                app_id=app_id,
                timestamp=timestamp,
                risk_score=risk_score,
                details={
                    "ios_version": mock_data.get("ios_version"),
                    "device_model": mock_data.get("device_model"),
                    "app_version": mock_data.get("app_version")
                }
            )

        except Exception as e:
            return AttestationResult(
                status=AttestationStatus.INVALID_SIGNATURE,
                device_id="unknown",
                platform=DevicePlatform.IOS,
                app_id="unknown",
                timestamp=int(time.time()),
                risk_score=1.0,
                details={"error": f"iOS attestation validation failed: {str(e)}"}
            )

    async def _validate_android_attestation(
        self,
        attestation_token: str,
        expected_nonce: str
    ) -> AttestationResult:
        """
        Validate Android Play Integrity API token.

        Real implementation would:
        1. Verify JWT signature with Google's public key
        2. Validate app integrity verdict
        3. Check device integrity verdict
        4. Verify package name and certificate fingerprint
        5. Validate nonce and timestamp
        """
        # Mock implementation - production would use Google Play Integrity API
        try:
            # Decode mock JWT (in production, verify with Google's public key)
            decoded = jwt.decode(attestation_token, options={"verify_signature": False})

            device_id = decoded.get("device_id", "unknown")
            app_id = decoded.get("package_name", "unknown")
            nonce = decoded.get("nonce", "")
            timestamp = decoded.get("timestamp_ms", 0) // 1000

            # Device and app integrity verdicts from Play Integrity API
            device_verdict = decoded.get("device_integrity", {}).get("verdict", [])
            app_verdict = decoded.get("app_integrity", {}).get("verdict", "UNKNOWN")

            # Validate nonce
            if nonce != expected_nonce or nonce in self.used_nonces:
                return AttestationResult(
                    status=AttestationStatus.REPLAY_ATTACK,
                    device_id=device_id,
                    platform=DevicePlatform.ANDROID,
                    app_id=app_id,
                    timestamp=timestamp,
                    risk_score=1.0,
                    details={"error": "Invalid or reused nonce"}
                )

            # Validate app integrity
            if app_verdict != "PLAY_RECOGNIZED":
                return AttestationResult(
                    status=AttestationStatus.INVALID_APP,
                    device_id=device_id,
                    platform=DevicePlatform.ANDROID,
                    app_id=app_id,
                    timestamp=timestamp,
                    risk_score=0.8,
                    details={"error": f"App integrity failed: {app_verdict}"}
                )

            # Check device integrity
            if "MEETS_DEVICE_INTEGRITY" not in device_verdict:
                return AttestationResult(
                    status=AttestationStatus.DEVICE_COMPROMISED,
                    device_id=device_id,
                    platform=DevicePlatform.ANDROID,
                    app_id=app_id,
                    timestamp=timestamp,
                    risk_score=0.9,
                    details={"error": "Device integrity compromised"}
                )

            # Mark nonce as used
            self.used_nonces.add(nonce)

            risk_score = self._calculate_risk_score(decoded)

            return AttestationResult(
                status=AttestationStatus.VALID,
                device_id=device_id,
                platform=DevicePlatform.ANDROID,
                app_id=app_id,
                timestamp=timestamp,
                risk_score=risk_score,
                details={
                    "android_version": decoded.get("android_version"),
                    "device_model": decoded.get("device_model"),
                    "app_version": decoded.get("app_version_code")
                }
            )

        except Exception as e:
            return AttestationResult(
                status=AttestationStatus.INVALID_SIGNATURE,
                device_id="unknown",
                platform=DevicePlatform.ANDROID,
                app_id="unknown",
                timestamp=int(time.time()),
                risk_score=1.0,
                details={"error": f"Android attestation validation failed: {str(e)}"}
            )

    def _calculate_risk_score(self, attestation_data: Dict) -> float:
        """
        Calculate risk score based on device and app characteristics.

        Factors considered:
        - Device age and model
        - OS version (outdated = higher risk)
        - App version (outdated = higher risk)
        - Previous fraud history
        - Device location/behavior patterns
        """
        risk_score = 0.0

        # OS version risk (older versions = higher risk)
        os_version = attestation_data.get("os_version", "unknown")
        if os_version != "unknown":
            try:
                version_parts = [int(x) for x in os_version.split(".")]
                if version_parts[0] < 14:  # Very old OS
                    risk_score += 0.3
                elif version_parts[0] < 16:  # Somewhat old OS
                    risk_score += 0.1
            except:
                risk_score += 0.2  # Unknown version = moderate risk

        # App version risk
        app_version = attestation_data.get("app_version", "unknown")
        if app_version == "unknown":
            risk_score += 0.1

        # Device model risk (very old devices = higher risk)
        device_model = attestation_data.get("device_model", "")
        if "iPhone_6" in device_model or "iPhone_7" in device_model:
            risk_score += 0.2

        # Additional risk factors would be considered in production:
        # - Geolocation inconsistencies
        # - Unusual usage patterns
        # - Previous fraud indicators
        # - Device fingerprinting results

        return min(risk_score, 1.0)  # Cap at 1.0


# Global validator instance
attestation_validator = DeviceAttestationValidator()