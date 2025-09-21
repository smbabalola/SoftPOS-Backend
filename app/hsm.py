"""
Hardware Security Module (HSM) Integration for SoftPOS

This module provides secure key management using HSM for:
- Payment encryption keys
- Certificate signing
- Secure key generation and storage
- PCI DSS Level 1 compliance

In production, this would integrate with:
- AWS CloudHSM
- Azure Dedicated HSM
- Thales Network Attached Encryption (NAE)
- SafeNet Luna HSM
- Utimaco HSM
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional, Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class KeyType(Enum):
    PAYMENT_ENCRYPTION = "payment_encryption"
    MERCHANT_SIGNING = "merchant_signing"
    API_ENCRYPTION = "api_encryption"
    DEVICE_ATTESTATION = "device_attestation"


class HSMOperation(Enum):
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
    SIGN = "sign"
    VERIFY = "verify"
    GENERATE_KEY = "generate_key"


class SignatureAlgorithm(Enum):
    RSA_PKCS1_SHA256 = "rsa_pkcs1_sha256"
    RSA_PSS_SHA256 = "rsa_pss_sha256"
    ECDSA_SHA256 = "ecdsa_sha256"
    HMAC_SHA256 = "hmac_sha256"


@dataclass
class HSMKey:
    key_id: str
    key_type: KeyType
    algorithm: str
    created_at: int
    expires_at: Optional[int] = None
    status: str = "active"


@dataclass
class HSMResponse:
    success: bool
    data: Optional[bytes] = None
    key_id: Optional[str] = None
    error: Optional[str] = None


class MockHSM:
    """
    Mock HSM implementation for development/testing.

    In production, this would be replaced with actual HSM integration
    using PKCS#11 or vendor-specific APIs.
    """

    def __init__(self):
        # Simulate HSM secure key storage
        self._keys: Dict[str, Dict] = {}
        self._key_counter = 0

        # Master encryption key (in real HSM, this would be in hardware)
        self._master_key = os.getenv("HSM_MASTER_KEY", Fernet.generate_key())
        self._fernet = Fernet(self._master_key)

        # Initialize with some default keys
        self._initialize_default_keys()

    def _initialize_default_keys(self):
        """Initialize HSM with default keys for different operations."""

        # Payment encryption key (AES-256)
        payment_key = secrets.token_bytes(32)  # 256 bits
        self._store_key("payment_key_001", KeyType.PAYMENT_ENCRYPTION, payment_key, "AES-256")

        # Merchant signing key (RSA-2048)
        signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        signing_key_bytes = signing_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        self._store_key("merchant_signing_001", KeyType.MERCHANT_SIGNING, signing_key_bytes, "RSA-2048")

        # API encryption key for sensitive data
        api_key = secrets.token_bytes(32)
        self._store_key("api_encryption_001", KeyType.API_ENCRYPTION, api_key, "AES-256")

    def _store_key(self, key_id: str, key_type: KeyType, key_material: bytes, algorithm: str):
        """Store key material securely in mock HSM."""
        import time

        # Encrypt key material with master key
        encrypted_key = self._fernet.encrypt(key_material)

        self._keys[key_id] = {
            "key_id": key_id,
            "key_type": key_type,
            "algorithm": algorithm,
            "encrypted_material": encrypted_key,
            "created_at": int(time.time()),
            "status": "active"
        }

    def _get_key_material(self, key_id: str) -> Optional[bytes]:
        """Retrieve and decrypt key material."""
        if key_id not in self._keys:
            return None

        key_data = self._keys[key_id]
        if key_data["status"] != "active":
            return None

        # Decrypt key material
        return self._fernet.decrypt(key_data["encrypted_material"])

    async def generate_key(self, key_type: KeyType, algorithm: str = "AES-256") -> HSMResponse:
        """Generate a new cryptographic key in the HSM."""
        try:
            self._key_counter += 1
            key_id = f"{key_type.value}_{self._key_counter:03d}"

            if algorithm.startswith("AES"):
                # Generate AES key
                key_size = int(algorithm.split("-")[1]) // 8
                key_material = secrets.token_bytes(key_size)
            elif algorithm.startswith("RSA"):
                # Generate RSA key pair
                key_size = int(algorithm.split("-")[1])
                private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
                key_material = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            else:
                return HSMResponse(success=False, error=f"Unsupported algorithm: {algorithm}")

            self._store_key(key_id, key_type, key_material, algorithm)

            return HSMResponse(success=True, key_id=key_id)

        except Exception as e:
            return HSMResponse(success=False, error=f"Key generation failed: {str(e)}")

    async def encrypt(self, key_id: str, plaintext: bytes, algorithm: str = "AES-GCM") -> HSMResponse:
        """Encrypt data using specified key."""
        try:
            key_material = self._get_key_material(key_id)
            if not key_material:
                return HSMResponse(success=False, error="Key not found")

            if algorithm == "AES-GCM":
                # Generate random IV
                iv = secrets.token_bytes(12)  # 96 bits for GCM

                # Create cipher
                cipher = Cipher(algorithms.AES(key_material), modes.GCM(iv))
                encryptor = cipher.encryptor()

                # Encrypt data
                ciphertext = encryptor.update(plaintext) + encryptor.finalize()

                # Combine IV + tag + ciphertext
                result = iv + encryptor.tag + ciphertext

                return HSMResponse(success=True, data=result)

            else:
                return HSMResponse(success=False, error=f"Unsupported encryption algorithm: {algorithm}")

        except Exception as e:
            return HSMResponse(success=False, error=f"Encryption failed: {str(e)}")

    async def decrypt(self, key_id: str, ciphertext: bytes, algorithm: str = "AES-GCM") -> HSMResponse:
        """Decrypt data using specified key."""
        try:
            key_material = self._get_key_material(key_id)
            if not key_material:
                return HSMResponse(success=False, error="Key not found")

            if algorithm == "AES-GCM":
                # Extract IV, tag, and ciphertext
                iv = ciphertext[:12]
                tag = ciphertext[12:28]
                encrypted_data = ciphertext[28:]

                # Create cipher
                cipher = Cipher(algorithms.AES(key_material), modes.GCM(iv, tag))
                decryptor = cipher.decryptor()

                # Decrypt data
                plaintext = decryptor.update(encrypted_data) + decryptor.finalize()

                return HSMResponse(success=True, data=plaintext)

            else:
                return HSMResponse(success=False, error=f"Unsupported decryption algorithm: {algorithm}")

        except Exception as e:
            return HSMResponse(success=False, error=f"Decryption failed: {str(e)}")

    async def sign(self, key_id: str, data: bytes, algorithm: str = "RSA-PSS-SHA256") -> HSMResponse:
        """Sign data using specified key."""
        try:
            key_material = self._get_key_material(key_id)
            if not key_material:
                return HSMResponse(success=False, error="Key not found")

            if algorithm == "RSA-PSS-SHA256":
                # Load private key
                private_key = serialization.load_pem_private_key(key_material, password=None)

                # Sign data
                signature = private_key.sign(
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )

                return HSMResponse(success=True, data=signature)

            else:
                return HSMResponse(success=False, error=f"Unsupported signing algorithm: {algorithm}")

        except Exception as e:
            return HSMResponse(success=False, error=f"Signing failed: {str(e)}")

    async def verify(self, key_id: str, data: bytes, signature: bytes, algorithm: str = "RSA-PSS-SHA256") -> HSMResponse:
        """Verify signature using specified key."""
        try:
            key_material = self._get_key_material(key_id)
            if not key_material:
                return HSMResponse(success=False, error="Key not found")

            if algorithm == "RSA-PSS-SHA256":
                # Load private key and extract public key
                private_key = serialization.load_pem_private_key(key_material, password=None)
                public_key = private_key.public_key()

                # Verify signature
                try:
                    public_key.verify(
                        signature,
                        data,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    return HSMResponse(success=True, data=b"valid")
                except:
                    return HSMResponse(success=False, error="Invalid signature")

            else:
                return HSMResponse(success=False, error=f"Unsupported verification algorithm: {algorithm}")

        except Exception as e:
            return HSMResponse(success=False, error=f"Verification failed: {str(e)}")

    async def list_keys(self, key_type: Optional[KeyType] = None) -> list[HSMKey]:
        """List keys stored in HSM."""
        keys = []
        for key_data in self._keys.values():
            if key_type is None or key_data["key_type"] == key_type:
                keys.append(HSMKey(
                    key_id=key_data["key_id"],
                    key_type=key_data["key_type"],
                    algorithm=key_data["algorithm"],
                    created_at=key_data["created_at"],
                    status=key_data["status"]
                ))
        return keys

    async def get_public_key(self, key_id: str) -> HSMResponse:
        """Get public key for asymmetric key pair."""
        try:
            key_material = self._get_key_material(key_id)
            if not key_material:
                return HSMResponse(success=False, error="Key not found")

            # Load private key and extract public key
            private_key = serialization.load_pem_private_key(key_material, password=None)
            public_key = private_key.public_key()

            # Serialize public key
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            return HSMResponse(success=True, data=public_key_bytes)

        except Exception as e:
            return HSMResponse(success=False, error=f"Public key extraction failed: {str(e)}")


class HSMManager:
    """
    High-level HSM manager for SoftPOS operations.

    Provides secure key management for:
    - Payment data encryption
    - Transaction signing
    - API security
    - Certificate management
    """

    def __init__(self):
        # In production, this would connect to real HSM
        self.hsm = MockHSM()

    async def encrypt_payment_data(self, card_data: str, merchant_id: str) -> Tuple[str, str]:
        """
        Encrypt sensitive payment data using HSM.

        Returns:
            Tuple of (encrypted_data, key_reference)
        """
        # Use merchant-specific encryption key or default
        key_id = f"payment_key_{merchant_id}" if await self._key_exists(f"payment_key_{merchant_id}") else "payment_key_001"

        response = await self.hsm.encrypt(key_id, card_data.encode())
        if not response.success:
            raise Exception(f"Payment encryption failed: {response.error}")

        encrypted_data = base64.b64encode(response.data).decode()
        return encrypted_data, key_id

    async def decrypt_payment_data(self, encrypted_data: str, key_id: str) -> str:
        """Decrypt payment data using HSM."""
        ciphertext = base64.b64decode(encrypted_data)

        response = await self.hsm.decrypt(key_id, ciphertext)
        if not response.success:
            raise Exception(f"Payment decryption failed: {response.error}")

        return response.data.decode()

    async def sign_transaction(self, transaction_data: Dict, merchant_id: str) -> str:
        """Sign transaction for integrity verification."""
        # Use merchant-specific signing key or default
        key_id = f"merchant_signing_{merchant_id}" if await self._key_exists(f"merchant_signing_{merchant_id}") else "merchant_signing_001"

        # Create canonical representation of transaction
        canonical_data = self._canonicalize_transaction(transaction_data)

        response = await self.hsm.sign(key_id, canonical_data.encode())
        if not response.success:
            raise Exception(f"Transaction signing failed: {response.error}")

        return base64.b64encode(response.data).decode()

    async def verify_transaction(self, transaction_data: Dict, signature: str, merchant_id: str) -> bool:
        """Verify transaction signature."""
        key_id = f"merchant_signing_{merchant_id}" if await self._key_exists(f"merchant_signing_{merchant_id}") else "merchant_signing_001"

        canonical_data = self._canonicalize_transaction(transaction_data)
        signature_bytes = base64.b64decode(signature)

        response = await self.hsm.verify(key_id, canonical_data.encode(), signature_bytes)
        return response.success

    async def generate_merchant_keys(self, merchant_id: str) -> Dict[str, str]:
        """Generate dedicated keys for a new merchant."""
        keys = {}

        # Generate payment encryption key
        payment_response = await self.hsm.generate_key(KeyType.PAYMENT_ENCRYPTION, "AES-256")
        if payment_response.success:
            keys["payment_key"] = payment_response.key_id

        # Generate signing key
        signing_response = await self.hsm.generate_key(KeyType.MERCHANT_SIGNING, "RSA-2048")
        if signing_response.success:
            keys["signing_key"] = signing_response.key_id

        return keys

    async def _key_exists(self, key_id: str) -> bool:
        """Check if key exists in HSM."""
        keys = await self.hsm.list_keys()
        return any(key.key_id == key_id for key in keys)

    def _canonicalize_transaction(self, transaction_data: Dict) -> str:
        """Create canonical string representation of transaction for signing."""
        import json

        # Sort keys for consistent ordering
        sorted_data = {k: transaction_data[k] for k in sorted(transaction_data.keys())}
        return json.dumps(sorted_data, separators=(',', ':'), sort_keys=True)


# Global HSM manager instance
hsm_manager = HSMManager()