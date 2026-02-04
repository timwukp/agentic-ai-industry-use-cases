"""
Compliance Screening Agent for watchlist and PEP checks.
"""

import logging
from typing import Any, Dict, Optional

from .base_ekyc_agent import AgentConfig, AgentResult, BaseEKYCAgent, VerificationStatus
from .exceptions import ComplianceError, ValidationError
from ..models.screening import ScreeningResult, WatchlistType
from ..services.watchlist_service import WatchlistService

logger = logging.getLogger(__name__)


class ComplianceScreeningAgent(BaseEKYCAgent):
    """
    Agent for compliance screening against watchlists.
    
    Responsibilities:
    - OFAC, UN, EU, UK sanctions screening
    - PEP (Politically Exposed Persons) checks
    - Adverse media screening
    - 7-year audit trail maintenance
    """

    AGENT_ID = "compliance-screening-agent"
    
    # Match threshold for flagging (80% confidence)
    MATCH_THRESHOLD = 0.80
    
    # Processing target: 15 seconds
    MAX_PROCESSING_TIME_MS = 15000

    def __init__(self, config: Optional[AgentConfig] = None):
        super().__init__(self.AGENT_ID, config)
        self.watchlist_service = WatchlistService()

    async def process(
        self, session_id: str, data: Dict[str, Any]
    ) -> AgentResult:
        """
        Process compliance screening request.
        
        Args:
            session_id: Verification session ID
            data: Identity data to screen
            
        Returns:
            AgentResult with screening outcome
        """
        with self.measure_time() as timer:
            try:
                await self.validate_input(data)
                
                # Perform screening
                screening_result = await self.watchlist_service.screen(
                    session_id=session_id,
                    full_name=data["full_name"],
                    date_of_birth=data.get("date_of_birth"),
                    nationality=data.get("nationality"),
                    additional_names=data.get("aliases", []),
                )
                
                # Determine verification status
                if screening_result.has_matches:
                    status = VerificationStatus.MANUAL_REVIEW
                    success = False
                else:
                    status = VerificationStatus.COMPLETED
                    success = True
                
                result_data = {
                    "screening_id": screening_result.screening_id,
                    "has_matches": screening_result.has_matches,
                    "overall_risk": screening_result.overall_risk,
                    "watchlist_matches": len(screening_result.watchlist_matches),
                    "pep_matches": len(screening_result.pep_matches),
                    "adverse_media_matches": len(screening_result.adverse_media_matches),
                    "lists_screened": [lt.value for lt in screening_result.lists_screened],
                    "requires_review": screening_result.requires_review,
                }
                
                # Log audit event
                audit_id = self.log_audit_event(
                    "compliance_screening",
                    {
                        "session_id": session_id,
                        "screening_id": screening_result.screening_id,
                        "has_matches": screening_result.has_matches,
                        "risk_level": screening_result.overall_risk,
                    },
                    session_id,
                )

            except Exception as e:
                logger.error(f"Compliance screening failed: {e}")
                return AgentResult(
                    success=False,
                    agent_id=self.agent_id,
                    session_id=session_id,
                    errors=[str(e)],
                    status=VerificationStatus.FAILED,
                    processing_time_ms=timer.elapsed_ms,
                )

        # Calculate confidence (inverse of risk)
        risk_scores = {"low": 90, "medium": 60, "high": 30}
        confidence = risk_scores.get(screening_result.overall_risk, 50)

        return AgentResult(
            success=success,
            agent_id=self.agent_id,
            session_id=session_id,
            data=result_data,
            confidence_score=confidence,
            processing_time_ms=timer.elapsed_ms,
            audit_id=audit_id,
            status=status,
        )

    async def validate_input(self, data: Dict[str, Any]) -> bool:
        """Validate screening input data."""
        await super().validate_input(data)
        
        if not data.get("full_name"):
            raise ValidationError("full_name is required for compliance screening")
        
        if len(data["full_name"]) < 2:
            raise ValidationError("full_name must be at least 2 characters")
        
        return True
