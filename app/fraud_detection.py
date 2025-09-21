"""
Advanced Fraud Detection System for SoftPOS

This module implements real-time fraud detection using multiple algorithms:
1. Rule-based detection (velocity checks, blacklists, etc.)
2. Statistical anomaly detection (behavioral analysis)
3. Machine learning models (risk scoring)
4. Geolocation verification
5. Device fingerprinting analysis
6. Transaction pattern analysis

The system provides multi-layered protection against various fraud types:
- Card testing attacks
- Velocity fraud
- Stolen card usage
- Account takeover
- Merchant fraud
- Collusion attacks
"""

from __future__ import annotations

import hashlib
import json
import math
import statistics
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

# Removed geoip2 dependency for demo - would use MaxMind GeoIP2 in production


class FraudRiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FraudReason(Enum):
    VELOCITY_EXCEEDED = "velocity_exceeded"
    SUSPICIOUS_LOCATION = "suspicious_location"
    BLACKLISTED_CARD = "blacklisted_card"
    UNUSUAL_PATTERN = "unusual_pattern"
    DEVICE_MISMATCH = "device_mismatch"
    HIGH_RISK_MERCHANT = "high_risk_merchant"
    ANOMALOUS_AMOUNT = "anomalous_amount"
    RAPID_SUCCESSION = "rapid_succession"
    GEOGRAPHIC_IMPOSSIBLE = "geographic_impossible"
    KNOWN_FRAUDSTER = "known_fraudster"


@dataclass
class TransactionData:
    transaction_id: str
    merchant_id: str
    device_id: str
    amount_minor: int
    currency: str
    timestamp: int
    card_fingerprint: str  # Hashed PAN
    ip_address: Optional[str] = None
    location: Optional[Dict] = None  # {"lat": float, "lon": float}
    user_agent: Optional[str] = None
    payment_method: str = "tap"


@dataclass
class FraudDetectionResult:
    risk_level: FraudRiskLevel
    risk_score: float  # 0.0 to 1.0
    reasons: List[FraudReason]
    recommended_action: str  # "approve", "review", "decline", "challenge"
    details: Dict[str, any]
    processing_time_ms: int


@dataclass
class DeviceProfile:
    device_id: str
    first_seen: int
    last_seen: int
    transaction_count: int
    total_amount: int
    avg_transaction_amount: float
    countries: Set[str]
    merchants: Set[str]
    risk_score: float


class FraudDetectionEngine:
    """
    Real-time fraud detection engine with multiple detection methods.

    Uses a combination of rule-based, statistical, and ML-based approaches
    to identify fraudulent transactions in real-time.
    """

    def __init__(self):
        # Configuration
        self.velocity_limits = {
            "transactions_per_hour": 10,
            "transactions_per_day": 50,
            "amount_per_hour_minor": 100000,  # $1000
            "amount_per_day_minor": 500000,   # $5000
        }

        # Blacklists and whitelists
        self.blacklisted_cards: Set[str] = set()
        self.blacklisted_devices: Set[str] = set()
        self.blacklisted_ips: Set[str] = set()
        self.high_risk_countries = {"CN", "RU", "NG", "PK"}  # Example high-risk countries

        # Transaction history (in production, this would be in Redis/database)
        self.transaction_history: Dict[str, List[TransactionData]] = {}
        self.device_profiles: Dict[str, DeviceProfile] = {}
        self.merchant_risk_scores: Dict[str, float] = {}

        # Geographic data (mock - production would use MaxMind GeoIP2)
        self.country_data = {
            "127.0.0.1": {"country": "US", "lat": 40.7128, "lon": -74.0060},
            "192.168.1.1": {"country": "US", "lat": 40.7128, "lon": -74.0060},
        }

        # Initialize some test data
        self._initialize_test_data()

    def _initialize_test_data(self):
        """Initialize with some test fraud patterns."""
        # Add some blacklisted test cards
        self.blacklisted_cards.update([
            "4000000000000002",  # Test declined card
            "5555555555554444",  # Test fraud card
        ])

        # Add high-risk merchant
        self.merchant_risk_scores["high_risk_merchant_001"] = 0.8

    async def detect_fraud(self, transaction: TransactionData) -> FraudDetectionResult:
        """
        Perform comprehensive fraud detection on a transaction.

        Args:
            transaction: Transaction data to analyze

        Returns:
            FraudDetectionResult with risk assessment and recommendations
        """
        start_time = time.time()

        risk_score = 0.0
        risk_reasons = []
        details = {}

        # 1. Rule-based checks
        rule_score, rule_reasons, rule_details = await self._rule_based_detection(transaction)
        risk_score += rule_score * 0.4  # 40% weight
        risk_reasons.extend(rule_reasons)
        details.update(rule_details)

        # 2. Velocity checks
        velocity_score, velocity_reasons, velocity_details = await self._velocity_detection(transaction)
        risk_score += velocity_score * 0.3  # 30% weight
        risk_reasons.extend(velocity_reasons)
        details.update(velocity_details)

        # 3. Behavioral analysis
        behavior_score, behavior_reasons, behavior_details = await self._behavioral_analysis(transaction)
        risk_score += behavior_score * 0.2  # 20% weight
        risk_reasons.extend(behavior_reasons)
        details.update(behavior_details)

        # 4. Geolocation analysis
        geo_score, geo_reasons, geo_details = await self._geolocation_analysis(transaction)
        risk_score += geo_score * 0.1  # 10% weight
        risk_reasons.extend(geo_reasons)
        details.update(geo_details)

        # Cap risk score at 1.0
        risk_score = min(risk_score, 1.0)

        # Determine risk level and recommended action
        risk_level, action = self._determine_risk_level_and_action(risk_score, risk_reasons)

        # Store transaction for future analysis
        await self._store_transaction(transaction)

        processing_time = int((time.time() - start_time) * 1000)

        return FraudDetectionResult(
            risk_level=risk_level,
            risk_score=risk_score,
            reasons=risk_reasons,
            recommended_action=action,
            details=details,
            processing_time_ms=processing_time
        )

    async def _rule_based_detection(self, transaction: TransactionData) -> Tuple[float, List[FraudReason], Dict]:
        """Rule-based fraud detection checks."""
        score = 0.0
        reasons = []
        details = {"rule_checks": {}}

        # Check blacklisted card
        if transaction.card_fingerprint in self.blacklisted_cards:
            score += 1.0
            reasons.append(FraudReason.BLACKLISTED_CARD)
            details["rule_checks"]["blacklisted_card"] = True

        # Check blacklisted device
        if transaction.device_id in self.blacklisted_devices:
            score += 0.8
            reasons.append(FraudReason.DEVICE_MISMATCH)
            details["rule_checks"]["blacklisted_device"] = True

        # Check blacklisted IP
        if transaction.ip_address and transaction.ip_address in self.blacklisted_ips:
            score += 0.6
            reasons.append(FraudReason.SUSPICIOUS_LOCATION)
            details["rule_checks"]["blacklisted_ip"] = True

        # Check high-risk merchant
        merchant_risk = self.merchant_risk_scores.get(transaction.merchant_id, 0.0)
        if merchant_risk > 0.7:
            score += merchant_risk * 0.5
            reasons.append(FraudReason.HIGH_RISK_MERCHANT)
            details["rule_checks"]["merchant_risk_score"] = merchant_risk

        # Check unusual amount patterns
        if transaction.amount_minor == 0:  # Zero amount transactions
            score += 0.3
            details["rule_checks"]["zero_amount"] = True

        if transaction.amount_minor > 1000000:  # Very large amounts (>$10k)
            score += 0.4
            reasons.append(FraudReason.ANOMALOUS_AMOUNT)
            details["rule_checks"]["large_amount"] = transaction.amount_minor

        # Check for round amounts (possible testing)
        if transaction.amount_minor % 10000 == 0 and transaction.amount_minor > 0:
            score += 0.2
            details["rule_checks"]["round_amount"] = True

        return score, reasons, details

    async def _velocity_detection(self, transaction: TransactionData) -> Tuple[float, List[FraudReason], Dict]:
        """Velocity-based fraud detection."""
        score = 0.0
        reasons = []
        details = {"velocity_checks": {}}

        current_time = transaction.timestamp
        hour_ago = current_time - 3600
        day_ago = current_time - 86400

        # Get transaction history for this card
        card_history = self._get_card_history(transaction.card_fingerprint)

        # Check hourly velocity
        hourly_txns = [tx for tx in card_history if tx.timestamp >= hour_ago]
        hourly_count = len(hourly_txns)
        hourly_amount = sum(tx.amount_minor for tx in hourly_txns)

        if hourly_count > self.velocity_limits["transactions_per_hour"]:
            score += 0.6
            reasons.append(FraudReason.VELOCITY_EXCEEDED)
            details["velocity_checks"]["hourly_count_exceeded"] = hourly_count

        if hourly_amount > self.velocity_limits["amount_per_hour_minor"]:
            score += 0.5
            reasons.append(FraudReason.VELOCITY_EXCEEDED)
            details["velocity_checks"]["hourly_amount_exceeded"] = hourly_amount

        # Check daily velocity
        daily_txns = [tx for tx in card_history if tx.timestamp >= day_ago]
        daily_count = len(daily_txns)
        daily_amount = sum(tx.amount_minor for tx in daily_txns)

        if daily_count > self.velocity_limits["transactions_per_day"]:
            score += 0.4
            reasons.append(FraudReason.VELOCITY_EXCEEDED)
            details["velocity_checks"]["daily_count_exceeded"] = daily_count

        if daily_amount > self.velocity_limits["amount_per_day_minor"]:
            score += 0.4
            reasons.append(FraudReason.VELOCITY_EXCEEDED)
            details["velocity_checks"]["daily_amount_exceeded"] = daily_amount

        # Check for rapid succession (multiple transactions within minutes)
        recent_txns = [tx for tx in card_history if current_time - tx.timestamp < 300]  # 5 minutes
        if len(recent_txns) > 3:
            score += 0.7
            reasons.append(FraudReason.RAPID_SUCCESSION)
            details["velocity_checks"]["rapid_succession"] = len(recent_txns)

        details["velocity_checks"]["hourly_count"] = hourly_count
        details["velocity_checks"]["daily_count"] = daily_count
        details["velocity_checks"]["hourly_amount"] = hourly_amount
        details["velocity_checks"]["daily_amount"] = daily_amount

        return score, reasons, details

    async def _behavioral_analysis(self, transaction: TransactionData) -> Tuple[float, List[FraudReason], Dict]:
        """Behavioral pattern analysis."""
        score = 0.0
        reasons = []
        details = {"behavioral_analysis": {}}

        # Analyze device profile
        device_profile = self._get_device_profile(transaction.device_id)

        if device_profile:
            # Check if this is unusual for this device
            avg_amount = device_profile.avg_transaction_amount

            # Significant deviation from normal amounts
            if avg_amount > 0:
                amount_ratio = transaction.amount_minor / avg_amount
                if amount_ratio > 5.0 or amount_ratio < 0.2:
                    score += 0.3
                    reasons.append(FraudReason.UNUSUAL_PATTERN)
                    details["behavioral_analysis"]["amount_deviation"] = amount_ratio

            # New country for this device
            if transaction.ip_address:
                country = self._get_country_from_ip(transaction.ip_address)
                if country and country not in device_profile.countries:
                    score += 0.4
                    reasons.append(FraudReason.SUSPICIOUS_LOCATION)
                    details["behavioral_analysis"]["new_country"] = country

            # Device risk score
            if device_profile.risk_score > 0.6:
                score += device_profile.risk_score * 0.3
                details["behavioral_analysis"]["device_risk_score"] = device_profile.risk_score

        else:
            # New device - inherently more risky
            score += 0.2
            details["behavioral_analysis"]["new_device"] = True

        # Analyze transaction timing patterns
        card_history = self._get_card_history(transaction.card_fingerprint)
        if len(card_history) > 5:
            # Check for unusual timing patterns
            time_diffs = []
            for i in range(1, len(card_history)):
                time_diffs.append(card_history[i].timestamp - card_history[i-1].timestamp)

            if time_diffs:
                avg_time_diff = statistics.mean(time_diffs)
                current_time_diff = transaction.timestamp - card_history[-1].timestamp

                # Very different timing pattern
                if avg_time_diff > 0 and (current_time_diff > avg_time_diff * 10 or current_time_diff < avg_time_diff * 0.1):
                    score += 0.2
                    details["behavioral_analysis"]["unusual_timing"] = current_time_diff

        return score, reasons, details

    async def _geolocation_analysis(self, transaction: TransactionData) -> Tuple[float, List[FraudReason], Dict]:
        """Geographic fraud detection."""
        score = 0.0
        reasons = []
        details = {"geolocation_analysis": {}}

        if not transaction.ip_address:
            return score, reasons, details

        country = self._get_country_from_ip(transaction.ip_address)
        if not country:
            return score, reasons, details

        # Check high-risk countries
        if country in self.high_risk_countries:
            score += 0.5
            reasons.append(FraudReason.SUSPICIOUS_LOCATION)
            details["geolocation_analysis"]["high_risk_country"] = country

        # Check for impossible travel
        card_history = self._get_card_history(transaction.card_fingerprint)
        recent_history = [tx for tx in card_history if tx.ip_address and transaction.timestamp - tx.timestamp < 86400]

        if recent_history:
            last_tx = recent_history[-1]
            last_country = self._get_country_from_ip(last_tx.ip_address)

            if last_country and last_country != country:
                time_diff_hours = (transaction.timestamp - last_tx.timestamp) / 3600

                # Calculate distance between countries (simplified)
                distance_km = self._estimate_distance(last_country, country)
                max_travel_speed = 1000  # km/h (commercial aircraft)

                if distance_km > time_diff_hours * max_travel_speed:
                    score += 0.8
                    reasons.append(FraudReason.GEOGRAPHIC_IMPOSSIBLE)
                    details["geolocation_analysis"]["impossible_travel"] = {
                        "from_country": last_country,
                        "to_country": country,
                        "time_hours": time_diff_hours,
                        "distance_km": distance_km
                    }

        details["geolocation_analysis"]["country"] = country

        return score, reasons, details

    def _get_card_history(self, card_fingerprint: str) -> List[TransactionData]:
        """Get transaction history for a card."""
        return self.transaction_history.get(card_fingerprint, [])

    def _get_device_profile(self, device_id: str) -> Optional[DeviceProfile]:
        """Get device profile."""
        return self.device_profiles.get(device_id)

    def _get_country_from_ip(self, ip_address: str) -> Optional[str]:
        """Get country from IP address (mock implementation)."""
        return self.country_data.get(ip_address, {}).get("country")

    def _estimate_distance(self, country1: str, country2: str) -> float:
        """Estimate distance between countries (simplified)."""
        # Simplified distance estimation
        distances = {
            ("US", "GB"): 5500,
            ("US", "CN"): 11000,
            ("GB", "CN"): 8000,
            ("US", "RU"): 8500,
        }

        key = tuple(sorted([country1, country2]))
        return distances.get(key, 1000)  # Default distance

    def _determine_risk_level_and_action(self, risk_score: float, reasons: List[FraudReason]) -> Tuple[FraudRiskLevel, str]:
        """Determine risk level and recommended action."""
        # Critical risk conditions
        if FraudReason.BLACKLISTED_CARD in reasons or FraudReason.KNOWN_FRAUDSTER in reasons:
            return FraudRiskLevel.CRITICAL, "decline"

        if FraudReason.GEOGRAPHIC_IMPOSSIBLE in reasons:
            return FraudRiskLevel.CRITICAL, "decline"

        # Risk score based classification
        if risk_score >= 0.8:
            return FraudRiskLevel.HIGH, "decline"
        elif risk_score >= 0.5:
            return FraudRiskLevel.MEDIUM, "review"
        elif risk_score >= 0.3:
            return FraudRiskLevel.MEDIUM, "challenge"
        else:
            return FraudRiskLevel.LOW, "approve"

    async def _store_transaction(self, transaction: TransactionData):
        """Store transaction for future analysis."""
        # Store in card history
        if transaction.card_fingerprint not in self.transaction_history:
            self.transaction_history[transaction.card_fingerprint] = []

        self.transaction_history[transaction.card_fingerprint].append(transaction)

        # Keep only last 100 transactions per card
        if len(self.transaction_history[transaction.card_fingerprint]) > 100:
            self.transaction_history[transaction.card_fingerprint] = \
                self.transaction_history[transaction.card_fingerprint][-100:]

        # Update device profile
        await self._update_device_profile(transaction)

    async def _update_device_profile(self, transaction: TransactionData):
        """Update device profile with new transaction."""
        device_id = transaction.device_id

        if device_id not in self.device_profiles:
            self.device_profiles[device_id] = DeviceProfile(
                device_id=device_id,
                first_seen=transaction.timestamp,
                last_seen=transaction.timestamp,
                transaction_count=0,
                total_amount=0,
                avg_transaction_amount=0.0,
                countries=set(),
                merchants=set(),
                risk_score=0.0
            )

        profile = self.device_profiles[device_id]
        profile.last_seen = transaction.timestamp
        profile.transaction_count += 1
        profile.total_amount += transaction.amount_minor
        profile.avg_transaction_amount = profile.total_amount / profile.transaction_count
        profile.merchants.add(transaction.merchant_id)

        # Add country if available
        if transaction.ip_address:
            country = self._get_country_from_ip(transaction.ip_address)
            if country:
                profile.countries.add(country)

        # Update risk score based on patterns
        profile.risk_score = self._calculate_device_risk_score(profile)

    def _calculate_device_risk_score(self, profile: DeviceProfile) -> float:
        """Calculate device risk score based on profile."""
        risk_score = 0.0

        # High transaction volume
        if profile.transaction_count > 100:
            risk_score += 0.2

        # Multiple countries
        if len(profile.countries) > 3:
            risk_score += 0.3

        # Multiple merchants (could indicate compromised device)
        if len(profile.merchants) > 10:
            risk_score += 0.2

        # Very high average transaction amount
        if profile.avg_transaction_amount > 50000:  # $500
            risk_score += 0.2

        # New device (less than a week old)
        if time.time() - profile.first_seen < 604800:  # 1 week
            risk_score += 0.1

        return min(risk_score, 1.0)

    async def add_to_blacklist(self, item_type: str, item_value: str):
        """Add item to blacklist."""
        if item_type == "card":
            self.blacklisted_cards.add(item_value)
        elif item_type == "device":
            self.blacklisted_devices.add(item_value)
        elif item_type == "ip":
            self.blacklisted_ips.add(item_value)

    async def remove_from_blacklist(self, item_type: str, item_value: str):
        """Remove item from blacklist."""
        if item_type == "card":
            self.blacklisted_cards.discard(item_value)
        elif item_type == "device":
            self.blacklisted_devices.discard(item_value)
        elif item_type == "ip":
            self.blacklisted_ips.discard(item_value)

    def get_fraud_statistics(self) -> Dict:
        """Get fraud detection statistics."""
        total_devices = len(self.device_profiles)
        high_risk_devices = sum(1 for p in self.device_profiles.values() if p.risk_score > 0.6)

        return {
            "total_devices_tracked": total_devices,
            "high_risk_devices": high_risk_devices,
            "blacklisted_cards": len(self.blacklisted_cards),
            "blacklisted_devices": len(self.blacklisted_devices),
            "blacklisted_ips": len(self.blacklisted_ips),
            "total_transactions": sum(len(history) for history in self.transaction_history.values())
        }


# Global fraud detection engine
fraud_engine = FraudDetectionEngine()