"""
Fraud Detection Module for Retail Application
Comprehensive fraud detection with AES-256-GCM encryption and audit logging
"""

import os
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
import structlog

# Cryptography imports for AES-256-GCM encryption
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import secrets

# Pydantic for validation
from pydantic import BaseModel, Field, field_validator
import bleach

# Initialize structured logger
logger = structlog.get_logger(__name__)


class FraudRiskLevel(str, Enum):
    """Risk levels for fraud detection"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TransactionRequest(BaseModel):
    """Transaction data for fraud analysis"""
    transaction_id: str = Field(..., max_length=100)
    customer_id: str = Field(..., max_length=100)
    amount: float = Field(..., gt=0)
    payment_method: str = Field(..., max_length=50)
    merchant_id: Optional[str] = Field(None, max_length=100)
    timestamp: Optional[str] = None
    items: Optional[List[Dict[str, Any]]] = None
    
    @field_validator('transaction_id', 'customer_id', 'payment_method', 'merchant_id')
    @classmethod
    def sanitize_string_fields(cls, v):
        """Sanitize string inputs to prevent XSS"""
        if v is None:
            return v
        return bleach.clean(str(v), tags=[], attributes={}, strip=True)


class FraudAnalysisResult(BaseModel):
    """Result of fraud detection analysis"""
    transaction_id: str
    risk_score: float = Field(..., ge=0, le=100)
    risk_level: FraudRiskLevel
    flags: List[str]
    analysis_timestamp: str
    recommendations: List[str]


class FraudRule(BaseModel):
    """Fraud detection rule configuration"""
    rule_id: str = Field(..., max_length=100)
    rule_name: str = Field(..., max_length=200)
    threshold: float = Field(..., gt=0)
    enabled: bool = True
    
    @field_validator('rule_id', 'rule_name')
    @classmethod
    def sanitize_fields(cls, v):
        """Sanitize string inputs"""
        return bleach.clean(str(v), tags=[], attributes={}, strip=True)


class EncryptionManager:
    """
    AES-256-GCM encryption manager for sensitive fraud detection data
    Provides secure encryption/decryption with authenticated encryption
    """
    
    def __init__(self, encryption_key: Optional[bytes] = None):
        """Initialize encryption manager with AES-256-GCM"""
        if encryption_key:
            self.key = encryption_key
        else:
            # Generate secure key from environment or create new one
            key_material = os.environ.get('FRAUD_ENCRYPTION_KEY', secrets.token_hex(32))
            self.key = self._derive_key(key_material.encode())
        
        self.aesgcm = AESGCM(self.key)
        logger.info("EncryptionManager initialized with AES-256-GCM")
    
    def _derive_key(self, key_material: bytes) -> bytes:
        """Derive 256-bit key using PBKDF2"""
        salt = b'fraud_detection_salt_v1'  # In production, use unique salt per deployment
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(key_material)
    
    def encrypt(self, plaintext: str) -> Dict[str, str]:
        """
        Encrypt sensitive data using AES-256-GCM
        Returns dict with nonce and ciphertext in hex format
        """
        try:
            # Generate random nonce (96 bits for GCM)
            nonce = secrets.token_bytes(12)
            
            # Encrypt with authenticated encryption
            ciphertext = self.aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
            
            logger.info("Data encrypted successfully", data_length=len(plaintext))
            
            return {
                'nonce': nonce.hex(),
                'ciphertext': ciphertext.hex()
            }
        except Exception as e:
            logger.error("Encryption failed", error=str(e))
            raise ValueError(f"Encryption error: {str(e)}")
    
    def decrypt(self, encrypted_data: Dict[str, str]) -> str:
        """
        Decrypt AES-256-GCM encrypted data
        Verifies authentication tag during decryption
        """
        try:
            nonce = bytes.fromhex(encrypted_data['nonce'])
            ciphertext = bytes.fromhex(encrypted_data['ciphertext'])
            
            # Decrypt and verify authentication tag
            plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)
            
            logger.info("Data decrypted successfully")
            
            return plaintext.decode('utf-8')
        except Exception as e:
            logger.error("Decryption failed", error=str(e))
            raise ValueError(f"Decryption error: {str(e)}")


class FraudDetectionEngine:
    """
    Comprehensive fraud detection engine with multiple detection mechanisms
    Includes transaction anomaly detection, pattern analysis, and risk scoring
    """
    
    def __init__(self):
        """Initialize fraud detection engine"""
        self.encryption_manager = EncryptionManager()
        
        # Fraud detection thresholds (configurable)
        self.thresholds = {
            'high_amount': 10000.0,
            'very_high_amount': 50000.0,
            'rapid_transactions_count': 5,
            'rapid_transactions_window_minutes': 10,
            'suspicious_amount_patterns': [99.99, 999.99, 9999.99],
        }
        
        # In-memory transaction history (in production, use Redis/DB)
        self.transaction_history: Dict[str, List[Dict]] = {}
        
        logger.info("FraudDetectionEngine initialized")
    
    def analyze_transaction(self, transaction: TransactionRequest) -> FraudAnalysisResult:
        """
        Comprehensive fraud analysis of a transaction
        Combines multiple detection methods for accurate risk assessment
        """
        flags = []
        risk_score = 0.0
        recommendations = []
        
        # Log fraud analysis attempt with audit trail
        logger.info(
            "Fraud analysis started",
            transaction_id=transaction.transaction_id,
            customer_id=transaction.customer_id,
            amount=transaction.amount
        )
        
        # 1. Transaction amount anomaly detection
        amount_risk = self._detect_amount_anomaly(transaction)
        flags.extend(amount_risk['flags'])
        risk_score += amount_risk['score']
        recommendations.extend(amount_risk['recommendations'])
        
        # 2. Purchase pattern analysis
        pattern_risk = self._analyze_purchase_pattern(transaction)
        flags.extend(pattern_risk['flags'])
        risk_score += pattern_risk['score']
        recommendations.extend(pattern_risk['recommendations'])
        
        # 3. Payment method verification
        payment_risk = self._verify_payment_method(transaction)
        flags.extend(payment_risk['flags'])
        risk_score += payment_risk['score']
        recommendations.extend(payment_risk['recommendations'])
        
        # 4. Customer behavior analysis
        behavior_risk = self._analyze_customer_behavior(transaction)
        flags.extend(behavior_risk['flags'])
        risk_score += behavior_risk['score']
        recommendations.extend(behavior_risk['recommendations'])
        
        # Cap risk score at 100
        risk_score = min(risk_score, 100.0)
        
        # Determine risk level
        risk_level = self._calculate_risk_level(risk_score)
        
        # Store transaction in history
        self._store_transaction(transaction)
        
        result = FraudAnalysisResult(
            transaction_id=transaction.transaction_id,
            risk_score=round(risk_score, 2),
            risk_level=risk_level,
            flags=flags,
            analysis_timestamp=datetime.utcnow().isoformat(),
            recommendations=recommendations
        )
        
        # Audit log the result
        logger.info(
            "Fraud analysis completed",
            transaction_id=transaction.transaction_id,
            risk_score=result.risk_score,
            risk_level=result.risk_level.value,
            flags_count=len(flags)
        )
        
        return result
    
    def _detect_amount_anomaly(self, transaction: TransactionRequest) -> Dict[str, Any]:
        """Detect unusually high or suspicious transaction amounts"""
        flags = []
        score = 0.0
        recommendations = []
        
        amount = transaction.amount
        
        # Check for very high amounts
        if amount >= self.thresholds['very_high_amount']:
            flags.append("VERY_HIGH_AMOUNT")
            score += 40.0
            recommendations.append("Require additional verification for very high amount")
        elif amount >= self.thresholds['high_amount']:
            flags.append("HIGH_AMOUNT")
            score += 20.0
            recommendations.append("Review high-value transaction")
        
        # Check for suspicious amount patterns (e.g., 99.99, 999.99)
        if any(abs(amount - pattern) < 0.01 for pattern in self.thresholds['suspicious_amount_patterns']):
            flags.append("SUSPICIOUS_AMOUNT_PATTERN")
            score += 15.0
            recommendations.append("Amount matches common fraud pattern")
        
        # Check for round numbers (often suspicious)
        if amount % 1000 == 0 and amount >= 5000:
            flags.append("ROUND_AMOUNT")
            score += 10.0
            recommendations.append("Large round amount requires verification")
        
        return {'flags': flags, 'score': score, 'recommendations': recommendations}
    
    def _analyze_purchase_pattern(self, transaction: TransactionRequest) -> Dict[str, Any]:
        """Analyze purchase patterns for suspicious behavior"""
        flags = []
        score = 0.0
        recommendations = []
        
        customer_history = self.transaction_history.get(transaction.customer_id, [])
        
        if customer_history:
            # Check for rapid multiple purchases
            recent_transactions = self._get_recent_transactions(
                customer_history,
                minutes=self.thresholds['rapid_transactions_window_minutes']
            )
            
            if len(recent_transactions) >= self.thresholds['rapid_transactions_count']:
                flags.append("RAPID_MULTIPLE_PURCHASES")
                score += 30.0
                recommendations.append(f"Customer made {len(recent_transactions)} transactions in {self.thresholds['rapid_transactions_window_minutes']} minutes")
            
            # Check for unusual purchase amount compared to history
            avg_amount = sum(t['amount'] for t in customer_history) / len(customer_history)
            if transaction.amount > avg_amount * 5:
                flags.append("UNUSUAL_AMOUNT_FOR_CUSTOMER")
                score += 25.0
                recommendations.append("Transaction amount significantly higher than customer average")
        
        # Check items if provided
        if transaction.items and len(transaction.items) > 20:
            flags.append("EXCESSIVE_ITEMS")
            score += 15.0
            recommendations.append("Unusually high number of items in single transaction")
        
        return {'flags': flags, 'score': score, 'recommendations': recommendations}
    
    def _verify_payment_method(self, transaction: TransactionRequest) -> Dict[str, Any]:
        """Verify payment method for suspicious patterns"""
        flags = []
        score = 0.0
        recommendations = []
        
        payment_method = transaction.payment_method.lower()
        
        # Flag high-risk payment methods for large transactions
        high_risk_methods = ['gift_card', 'prepaid_card', 'cryptocurrency', 'wire_transfer']
        
        if any(method in payment_method for method in high_risk_methods):
            if transaction.amount > 1000:
                flags.append("HIGH_RISK_PAYMENT_METHOD")
                score += 25.0
                recommendations.append(f"High-risk payment method ({payment_method}) used for large amount")
        
        # Check customer history for payment method changes
        customer_history = self.transaction_history.get(transaction.customer_id, [])
        if customer_history:
            previous_methods = [t['payment_method'] for t in customer_history[-5:]]
            if previous_methods and payment_method not in previous_methods:
                flags.append("NEW_PAYMENT_METHOD")
                score += 10.0
                recommendations.append("Customer using new payment method")
        
        return {'flags': flags, 'score': score, 'recommendations': recommendations}
    
    def _analyze_customer_behavior(self, transaction: TransactionRequest) -> Dict[str, Any]:
        """Analyze customer behavior for anomalies"""
        flags = []
        score = 0.0
        recommendations = []
        
        customer_history = self.transaction_history.get(transaction.customer_id, [])
        
        # New customer with high-value transaction
        if not customer_history and transaction.amount > 5000:
            flags.append("NEW_CUSTOMER_HIGH_VALUE")
            score += 30.0
            recommendations.append("New customer with high-value first transaction")
        
        # Check for velocity changes
        if len(customer_history) >= 3:
            recent_freq = len(self._get_recent_transactions(customer_history, minutes=60))
            if recent_freq > 3:
                flags.append("HIGH_TRANSACTION_VELOCITY")
                score += 20.0
                recommendations.append("Unusually high transaction frequency detected")
        
        return {'flags': flags, 'score': score, 'recommendations': recommendations}
    
    def _calculate_risk_level(self, risk_score: float) -> FraudRiskLevel:
        """Calculate risk level based on risk score"""
        if risk_score >= 75:
            return FraudRiskLevel.CRITICAL
        elif risk_score >= 50:
            return FraudRiskLevel.HIGH
        elif risk_score >= 25:
            return FraudRiskLevel.MEDIUM
        else:
            return FraudRiskLevel.LOW
    
    def _get_recent_transactions(self, history: List[Dict], minutes: int) -> List[Dict]:
        """Get transactions within specified time window"""
        cutoff = datetime.utcnow() - timedelta(minutes=minutes)
        recent = []
        
        for txn in history:
            txn_time = datetime.fromisoformat(txn.get('timestamp', '2000-01-01T00:00:00'))
            if txn_time >= cutoff:
                recent.append(txn)
        
        return recent
    
    def _store_transaction(self, transaction: TransactionRequest):
        """Store transaction in history for pattern analysis"""
        customer_id = transaction.customer_id
        
        if customer_id not in self.transaction_history:
            self.transaction_history[customer_id] = []
        
        # Store transaction data
        self.transaction_history[customer_id].append({
            'transaction_id': transaction.transaction_id,
            'amount': transaction.amount,
            'payment_method': transaction.payment_method,
            'timestamp': transaction.timestamp or datetime.utcnow().isoformat()
        })
        
        # Keep only last 100 transactions per customer
        if len(self.transaction_history[customer_id]) > 100:
            self.transaction_history[customer_id] = self.transaction_history[customer_id][-100:]
    
    def get_fraud_report(self, customer_id: Optional[str] = None, 
                         start_date: Optional[str] = None,
                         end_date: Optional[str] = None) -> Dict[str, Any]:
        """Generate fraud detection report"""
        logger.info("Generating fraud report", customer_id=customer_id)
        
        total_transactions = 0
        flagged_transactions = 0
        
        # In production, query from database
        # For now, use in-memory data
        for cust_id, transactions in self.transaction_history.items():
            if customer_id and cust_id != customer_id:
                continue
            total_transactions += len(transactions)
        
        report = {
            'report_id': secrets.token_hex(16),
            'generated_at': datetime.utcnow().isoformat(),
            'customer_id': customer_id,
            'total_transactions': total_transactions,
            'flagged_transactions': flagged_transactions,
            'fraud_rate': 0.0,
            'period': {
                'start': start_date or 'all_time',
                'end': end_date or datetime.utcnow().isoformat()
            }
        }
        
        logger.info("Fraud report generated", report_id=report['report_id'])
        
        return report
    
    def update_fraud_rule(self, rule: FraudRule) -> Dict[str, Any]:
        """Update fraud detection rules and thresholds"""
        logger.info(
            "Updating fraud rule",
            rule_id=rule.rule_id,
            rule_name=rule.rule_name,
            threshold=rule.threshold,
            enabled=rule.enabled
        )
        
        # Map rule_id to threshold keys
        rule_mapping = {
            'high_amount': 'high_amount',
            'very_high_amount': 'very_high_amount',
            'rapid_transactions': 'rapid_transactions_count'
        }
        
        if rule.rule_id in rule_mapping:
            threshold_key = rule_mapping[rule.rule_id]
            old_value = self.thresholds.get(threshold_key)
            
            if rule.enabled:
                self.thresholds[threshold_key] = rule.threshold
            
            logger.info(
                "Fraud rule updated",
                rule_id=rule.rule_id,
                old_value=old_value,
                new_value=rule.threshold
            )
            
            return {
                'rule_id': rule.rule_id,
                'status': 'updated',
                'old_threshold': old_value,
                'new_threshold': rule.threshold,
                'enabled': rule.enabled
            }
        
        return {
            'rule_id': rule.rule_id,
            'status': 'not_found',
            'message': 'Rule ID not recognized'
        }
    
    def encrypt_sensitive_data(self, data: str) -> Dict[str, str]:
        """Encrypt sensitive fraud detection data"""
        return self.encryption_manager.encrypt(data)
    
    def decrypt_sensitive_data(self, encrypted_data: Dict[str, str]) -> str:
        """Decrypt sensitive fraud detection data"""
        return self.encryption_manager.decrypt(encrypted_data)
