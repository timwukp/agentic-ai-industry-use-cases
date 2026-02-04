"""
Strands Orchestrator for multi-agent workflow coordination.
"""

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from ..agents import (
    AgentConfig,
    AgentResult,
    BiometricVerificationAgent,
    ComplianceScreeningAgent,
    DocumentVerificationAgent,
    FraudDetectionAgent,
    ManualReviewAgent,
    VerificationStatus,
)
from ..agents.exceptions import EKYCException, TimeoutError
from ..models.session import RiskLevel, Session, SessionStatus

logger = logging.getLogger(__name__)


class WorkflowStep(str, Enum):
    """Workflow execution steps."""
    DOCUMENT_VERIFICATION = "document_verification"
    BIOMETRIC_VERIFICATION = "biometric_verification"
    COMPLIANCE_SCREENING = "compliance_screening"
    FRAUD_DETECTION = "fraud_detection"
    MANUAL_REVIEW = "manual_review"
    RESULT_AGGREGATION = "result_aggregation"


@dataclass
class WorkflowConfig:
    """Configuration for workflow execution."""
    timeout_seconds: int = 60  # Max workflow duration
    enable_parallel: bool = False  # Sequential by default
    skip_on_failure: bool = False
    auto_manual_review: bool = True


@dataclass
class WorkflowState:
    """Current state of a workflow execution."""
    session_id: str
    current_step: WorkflowStep
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_steps: List[WorkflowStep] = field(default_factory=list)
    step_results: Dict[str, AgentResult] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    final_status: Optional[SessionStatus] = None


class StrandsOrchestrator:
    """
    Orchestrates multi-agent verification workflow.
    
    Workflow order:
    1. Document Verification
    2. Biometric Verification
    3. Compliance Screening
    4. Fraud Detection
    5. Manual Review (conditional)
    6. Result Aggregation
    """

    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        workflow_config: Optional[WorkflowConfig] = None,
    ):
        self.agent_config = config or AgentConfig()
        self.workflow_config = workflow_config or WorkflowConfig()
        
        # Initialize agents
        self.document_agent = DocumentVerificationAgent(self.agent_config)
        self.biometric_agent = BiometricVerificationAgent(self.agent_config)
        self.compliance_agent = ComplianceScreeningAgent(self.agent_config)
        self.fraud_agent = FraudDetectionAgent(self.agent_config)
        self.manual_review_agent = ManualReviewAgent(self.agent_config)
        
        # Workflow states
        self._active_workflows: Dict[str, WorkflowState] = {}

    async def run_verification(
        self, session_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Run complete verification workflow.
        
        Args:
            session_id: Verification session ID
            data: All verification data
            
        Returns:
            Final verification result
        """
        state = WorkflowState(
            session_id=session_id,
            current_step=WorkflowStep.DOCUMENT_VERIFICATION,
        )
        self._active_workflows[session_id] = state
        
        try:
            # Run with timeout
            result = await asyncio.wait_for(
                self._execute_workflow(state, data),
                timeout=self.workflow_config.timeout_seconds,
            )
            return result
        except asyncio.TimeoutError:
            state.errors.append("Workflow timeout exceeded")
            state.final_status = SessionStatus.FAILED
            raise TimeoutError(
                "Verification workflow timeout",
                operation="workflow",
                timeout_seconds=self.workflow_config.timeout_seconds,
            )
        finally:
            # Cleanup
            if session_id in self._active_workflows:
                del self._active_workflows[session_id]

    async def _execute_workflow(
        self, state: WorkflowState, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute the verification workflow steps."""
        session_id = state.session_id
        
        # Step 1: Document Verification
        state.current_step = WorkflowStep.DOCUMENT_VERIFICATION
        doc_result = await self.document_agent.process(
            session_id, self._extract_document_data(data)
        )
        state.step_results["document"] = doc_result
        state.completed_steps.append(WorkflowStep.DOCUMENT_VERIFICATION)
        
        if not doc_result.success and not self.workflow_config.skip_on_failure:
            return self._build_failure_result(state, "Document verification failed")
        
        # Step 2: Biometric Verification
        state.current_step = WorkflowStep.BIOMETRIC_VERIFICATION
        bio_data = self._extract_biometric_data(data, doc_result)
        bio_result = await self.biometric_agent.process(session_id, bio_data)
        state.step_results["biometric"] = bio_result
        state.completed_steps.append(WorkflowStep.BIOMETRIC_VERIFICATION)
        
        if not bio_result.success and not self.workflow_config.skip_on_failure:
            if bio_result.status == VerificationStatus.MANUAL_REVIEW:
                return await self._route_to_manual_review(state, data, "Biometric verification requires review")
            return self._build_failure_result(state, "Biometric verification failed")
        
        # Step 3: Compliance Screening
        state.current_step = WorkflowStep.COMPLIANCE_SCREENING
        comp_data = self._extract_compliance_data(data, doc_result)
        comp_result = await self.compliance_agent.process(session_id, comp_data)
        state.step_results["compliance"] = comp_result
        state.completed_steps.append(WorkflowStep.COMPLIANCE_SCREENING)
        
        if comp_result.data.get("has_matches"):
            return await self._route_to_manual_review(state, data, "Watchlist match found")
        
        # Step 4: Fraud Detection
        state.current_step = WorkflowStep.FRAUD_DETECTION
        fraud_data = self._extract_fraud_data(data, doc_result, bio_result)
        fraud_result = await self.fraud_agent.process(session_id, fraud_data)
        state.step_results["fraud"] = fraud_result
        state.completed_steps.append(WorkflowStep.FRAUD_DETECTION)
        
        # Check if manual review needed based on fraud score
        decision = fraud_result.data.get("decision", "")
        if decision == "manual_review":
            return await self._route_to_manual_review(state, data, "Risk score requires review")
        elif decision == "auto_reject":
            return self._build_failure_result(state, "Fraud risk too high")
        
        # Step 5: Result Aggregation
        return self._aggregate_results(state)

    async def _route_to_manual_review(
        self, state: WorkflowState, data: Dict[str, Any], reason: str
    ) -> Dict[str, Any]:
        """Route session to manual review queue."""
        state.current_step = WorkflowStep.MANUAL_REVIEW
        
        review_data = {
            "action": "queue",
            "reason": reason,
            "priority": "high" if "watchlist" in reason.lower() else "normal",
            "risk_factors": self._collect_risk_factors(state),
            "document_data": state.step_results.get("document", {}).data if state.step_results.get("document") else None,
            "biometric_data": state.step_results.get("biometric", {}).data if state.step_results.get("biometric") else None,
            "screening_data": state.step_results.get("compliance", {}).data if state.step_results.get("compliance") else None,
            "verification_score": self._calculate_aggregate_score(state),
        }
        
        review_result = await self.manual_review_agent.process(state.session_id, review_data)
        state.step_results["manual_review"] = review_result
        state.completed_steps.append(WorkflowStep.MANUAL_REVIEW)
        state.final_status = SessionStatus.MANUAL_REVIEW
        
        return {
            "session_id": state.session_id,
            "status": "manual_review",
            "reason": reason,
            "queue_position": review_result.data.get("queue_position"),
            "verification_score": review_data["verification_score"],
            "processing_time_ms": self._calculate_total_time(state),
        }

    def _build_failure_result(
        self, state: WorkflowState, reason: str
    ) -> Dict[str, Any]:
        """Build failure result."""
        state.final_status = SessionStatus.REJECTED
        state.errors.append(reason)
        
        return {
            "session_id": state.session_id,
            "status": "rejected",
            "reason": reason,
            "verification_score": self._calculate_aggregate_score(state),
            "completed_steps": [s.value for s in state.completed_steps],
            "processing_time_ms": self._calculate_total_time(state),
        }

    def _aggregate_results(self, state: WorkflowState) -> Dict[str, Any]:
        """Aggregate results from all agents."""
        state.current_step = WorkflowStep.RESULT_AGGREGATION
        state.final_status = SessionStatus.APPROVED
        
        final_score = self._calculate_aggregate_score(state)
        risk_level = self._determine_risk_level(final_score)
        
        return {
            "session_id": state.session_id,
            "status": "approved",
            "verification_score": final_score,
            "risk_level": risk_level.value,
            "completed_steps": [s.value for s in state.completed_steps],
            "step_scores": {
                step: result.confidence_score
                for step, result in state.step_results.items()
            },
            "processing_time_ms": self._calculate_total_time(state),
        }

    def _calculate_aggregate_score(self, state: WorkflowState) -> float:
        """Calculate aggregate verification score."""
        weights = {
            "document": 0.25,
            "biometric": 0.30,
            "compliance": 0.20,
            "fraud": 0.25,
        }
        
        weighted_sum = 0.0
        total_weight = 0.0
        
        for step, weight in weights.items():
            if step in state.step_results:
                weighted_sum += state.step_results[step].confidence_score * weight
                total_weight += weight
        
        return round(weighted_sum / total_weight, 1) if total_weight > 0 else 0.0

    def _calculate_total_time(self, state: WorkflowState) -> int:
        """Calculate total processing time."""
        return sum(r.processing_time_ms for r in state.step_results.values())

    def _determine_risk_level(self, score: float) -> RiskLevel:
        """Determine risk level from score."""
        if score >= 80:
            return RiskLevel.LOW
        elif score >= 60:
            return RiskLevel.MEDIUM
        elif score >= 40:
            return RiskLevel.HIGH
        return RiskLevel.CRITICAL

    def _collect_risk_factors(self, state: WorkflowState) -> List[str]:
        """Collect risk factors from all steps."""
        factors = []
        for result in state.step_results.values():
            if result.warnings:
                factors.extend(result.warnings)
            if result.data.get("risk_factors"):
                factors.extend(result.data["risk_factors"])
        return list(set(factors))

    def _extract_document_data(self, data: Dict) -> Dict[str, Any]:
        """Extract document-specific data."""
        return {
            "image_bytes": data.get("document_image_bytes"),
            "s3_key": data.get("document_s3_key"),
            "document_type": data.get("document_type", "passport"),
            "country_code": data.get("country_code", "US"),
        }

    def _extract_biometric_data(self, data: Dict, doc_result: AgentResult) -> Dict[str, Any]:
        """Extract biometric-specific data."""
        return {
            "selfie_bytes": data.get("selfie_bytes"),
            "selfie_s3_key": data.get("selfie_s3_key"),
            "document_photo_bytes": data.get("document_photo_bytes"),
            "document_photo_s3_key": doc_result.data.get("front_image_s3_uri"),
        }

    def _extract_compliance_data(self, data: Dict, doc_result: AgentResult) -> Dict[str, Any]:
        """Extract compliance screening data."""
        extracted = doc_result.data.get("extracted_data", {})
        return {
            "full_name": f"{extracted.get('first_name', '')} {extracted.get('last_name', '')}".strip() or data.get("full_name", "Unknown"),
            "date_of_birth": extracted.get("date_of_birth"),
            "nationality": extracted.get("nationality") or data.get("nationality"),
        }

    def _extract_fraud_data(self, data: Dict, doc_result: AgentResult, bio_result: AgentResult) -> Dict[str, Any]:
        """Extract fraud detection data."""
        return {
            "device_info": data.get("device_info", {}),
            "device_id": data.get("device_id"),
            "ip_address": data.get("ip_address"),
            "document_country": doc_result.data.get("country_code"),
            "extracted_data": doc_result.data.get("extracted_data", {}),
        }

    async def get_workflow_status(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get current status of an active workflow."""
        if session_id in self._active_workflows:
            state = self._active_workflows[session_id]
            return {
                "session_id": session_id,
                "current_step": state.current_step.value,
                "completed_steps": [s.value for s in state.completed_steps],
                "started_at": state.started_at.isoformat(),
            }
        return None
