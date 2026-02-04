"""
Fraud Detection Agent for risk scoring and anomaly detection.
"""

import hashlib
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from .base_ekyc_agent import AgentConfig, AgentResult, BaseEKYCAgent, VerificationStatus
from .exceptions import FraudDetectionError, ValidationError

logger = logging.getLogger(__name__)


class FraudDetectionAgent(BaseEKYCAgent):
    """
    Agent for fraud detection and risk scoring.
    
    Responsibilities:
    - Device fingerprinting
    - Geolocation analysis
    - Velocity checks
    - Synthetic identity detection
    - Verification scoring (0-100)
    """

    AGENT_ID = "fraud-detection-agent"
    
    # Thresholds
    AUTO_APPROVE_THRESHOLD = 80
    AUTO_REJECT_THRESHOLD = 30
    MAX_ATTEMPTS_PER_DEVICE_24H = 3

    def __init__(self, config: Optional[AgentConfig] = None):
        super().__init__(self.AGENT_ID, config)
        # In-memory velocity tracking (use Redis/DynamoDB in production)
        self._velocity_cache: Dict[str, List[datetime]] = {}

    async def process(
        self, session_id: str, data: Dict[str, Any]
    ) -> AgentResult:
        """
        Process fraud detection request.
        
        Args:
            session_id: Verification session ID
            data: Session data for fraud analysis
            
        Returns:
            AgentResult with risk assessment
        """
        with self.measure_time() as timer:
            try:
                await self.validate_input(data)
                
                # Collect risk factors
                risk_factors = []
                risk_scores = []
                
                # Device fingerprint analysis
                device_risk = await self._analyze_device(data, risk_factors)
                risk_scores.append(device_risk)
                
                # Geolocation analysis
                geo_risk = await self._analyze_geolocation(data, risk_factors)
                risk_scores.append(geo_risk)
                
                # Velocity checks
                velocity_risk = await self._check_velocity(data, risk_factors)
                risk_scores.append(velocity_risk)
                
                # Synthetic identity detection
                synthetic_risk = await self._detect_synthetic(data, risk_factors)
                risk_scores.append(synthetic_risk)
                
                # Calculate final score (0-100, higher is safer)
                final_score = self._calculate_final_score(risk_scores)
                
                # Determine decision
                if final_score >= self.AUTO_APPROVE_THRESHOLD:
                    decision = "auto_approve"
                    status = VerificationStatus.COMPLETED
                    success = True
                elif final_score <= self.AUTO_REJECT_THRESHOLD:
                    decision = "auto_reject"
                    status = VerificationStatus.FAILED
                    success = False
                else:
                    decision = "manual_review"
                    status = VerificationStatus.MANUAL_REVIEW
                    success = False
                
                result_data = {
                    "verification_score": final_score,
                    "decision": decision,
                    "risk_factors": risk_factors,
                    "risk_breakdown": {
                        "device": device_risk,
                        "geolocation": geo_risk,
                        "velocity": velocity_risk,
                        "synthetic": synthetic_risk,
                    },
                }
                
                audit_id = self.log_audit_event(
                    "fraud_detection",
                    {
                        "session_id": session_id,
                        "score": final_score,
                        "decision": decision,
                        "risk_factors": risk_factors,
                    },
                    session_id,
                )

            except Exception as e:
                logger.error(f"Fraud detection failed: {e}")
                return AgentResult(
                    success=False,
                    agent_id=self.agent_id,
                    session_id=session_id,
                    errors=[str(e)],
                    status=VerificationStatus.FAILED,
                    processing_time_ms=timer.elapsed_ms,
                )

        return AgentResult(
            success=success,
            agent_id=self.agent_id,
            session_id=session_id,
            data=result_data,
            confidence_score=final_score,
            processing_time_ms=timer.elapsed_ms,
            warnings=risk_factors if risk_factors else None,
            audit_id=audit_id,
            status=status,
        )

    async def validate_input(self, data: Dict[str, Any]) -> bool:
        """Validate fraud detection input."""
        await super().validate_input(data)
        return True

    async def _analyze_device(
        self, data: Dict[str, Any], risk_factors: List[str]
    ) -> float:
        """Analyze device fingerprint."""
        device_info = data.get("device_info", {})
        score = 100.0
        
        # Check for missing device info
        if not device_info:
            risk_factors.append("missing_device_info")
            score -= 20
        
        # Check for known bad fingerprints (simulated)
        fingerprint = self._generate_fingerprint(device_info)
        
        # Check for emulator/VM indicators
        if device_info.get("is_emulator"):
            risk_factors.append("emulator_detected")
            score -= 30
        
        return max(0, score)

    async def _analyze_geolocation(
        self, data: Dict[str, Any], risk_factors: List[str]
    ) -> float:
        """Analyze geolocation for anomalies."""
        score = 100.0
        
        ip_address = data.get("ip_address")
        claimed_country = data.get("document_country")
        
        if not ip_address:
            risk_factors.append("missing_ip_address")
            score -= 15
            return max(0, score)
        
        # VPN/Proxy detection (simulated)
        if self._is_vpn_ip(ip_address):
            risk_factors.append("vpn_proxy_detected")
            score -= 25
        
        # Country mismatch check
        ip_country = self._get_ip_country(ip_address)
        if claimed_country and ip_country and claimed_country != ip_country:
            risk_factors.append("country_mismatch")
            score -= 20
        
        return max(0, score)

    async def _check_velocity(
        self, data: Dict[str, Any], risk_factors: List[str]
    ) -> float:
        """Check for velocity abuse."""
        score = 100.0
        
        device_id = data.get("device_id") or self._generate_fingerprint(
            data.get("device_info", {})
        )
        
        # Track this attempt
        now = datetime.utcnow()
        if device_id not in self._velocity_cache:
            self._velocity_cache[device_id] = []
        
        # Clean old entries
        cutoff = now - timedelta(hours=24)
        self._velocity_cache[device_id] = [
            t for t in self._velocity_cache[device_id] if t > cutoff
        ]
        
        # Check velocity
        attempts = len(self._velocity_cache[device_id])
        if attempts >= self.MAX_ATTEMPTS_PER_DEVICE_24H:
            risk_factors.append("velocity_limit_exceeded")
            score -= 40
        elif attempts >= 2:
            risk_factors.append("multiple_attempts_24h")
            score -= 15
        
        # Record this attempt
        self._velocity_cache[device_id].append(now)
        
        return max(0, score)

    async def _detect_synthetic(
        self, data: Dict[str, Any], risk_factors: List[str]
    ) -> float:
        """Detect synthetic identity indicators."""
        score = 100.0
        
        # Check for suspicious patterns (simulated ML)
        extracted_data = data.get("extracted_data", {})
        
        # Check SSN patterns, name patterns, etc. (simplified)
        if extracted_data.get("suspicious_pattern"):
            risk_factors.append("synthetic_identity_indicator")
            score -= 35
        
        return max(0, score)

    def _calculate_final_score(self, scores: List[float]) -> float:
        """Calculate weighted final score."""
        if not scores:
            return 50.0
        
        weights = [0.25, 0.25, 0.30, 0.20]  # device, geo, velocity, synthetic
        weighted_sum = sum(s * w for s, w in zip(scores, weights))
        return round(weighted_sum, 1)

    def _generate_fingerprint(self, device_info: Dict) -> str:
        """Generate device fingerprint hash."""
        fp_data = f"{device_info.get('user_agent', '')}{device_info.get('screen', '')}"
        return hashlib.sha256(fp_data.encode()).hexdigest()[:16]

    def _is_vpn_ip(self, ip: str) -> bool:
        """Check if IP is a known VPN/proxy (simulated)."""
        return False

    def _get_ip_country(self, ip: str) -> Optional[str]:
        """Get country from IP address (simulated)."""
        return "US"
