"""
Manual Review Agent for compliance officer workflow.
"""

import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from .base_ekyc_agent import AgentConfig, AgentResult, BaseEKYCAgent, VerificationStatus
from .exceptions import SessionError, ValidationError

logger = logging.getLogger(__name__)


class ReviewDecision:
    """Review decision constants."""
    APPROVE = "approve"
    REJECT = "reject"
    REQUEST_INFO = "request_info"


class ManualReviewAgent(BaseEKYCAgent):
    """
    Agent for manual review workflow.
    
    Responsibilities:
    - Review queue management
    - Compliance officer interface support
    - Decision recording with audit trail
    - Customer notification coordination
    """

    AGENT_ID = "manual-review-agent"
    
    # SLA: 5 minutes for notification after decision
    NOTIFICATION_SLA_SECONDS = 300

    def __init__(self, config: Optional[AgentConfig] = None):
        super().__init__(self.AGENT_ID, config)
        # In-memory queue (use DynamoDB in production)
        self._review_queue: Dict[str, Dict] = {}
        self._decisions: Dict[str, Dict] = {}

    async def process(
        self, session_id: str, data: Dict[str, Any]
    ) -> AgentResult:
        """
        Process manual review workflow action.
        
        Supports actions:
        - queue: Add session to review queue
        - get_queue: Get pending reviews
        - decide: Record review decision
        - get_status: Get review status
        
        Args:
            session_id: Verification session ID
            data: Action data
            
        Returns:
            AgentResult with action outcome
        """
        with self.measure_time() as timer:
            try:
                action = data.get("action", "queue")
                
                if action == "queue":
                    result = await self._add_to_queue(session_id, data)
                elif action == "get_queue":
                    result = await self._get_queue(data)
                elif action == "decide":
                    result = await self._record_decision(session_id, data)
                elif action == "get_status":
                    result = await self._get_status(session_id)
                else:
                    raise ValidationError(f"Unknown action: {action}")
                
                success = result.get("success", True)
                status = VerificationStatus.MANUAL_REVIEW

            except Exception as e:
                logger.error(f"Manual review action failed: {e}")
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
            data=result,
            confidence_score=0,  # N/A for manual review
            processing_time_ms=timer.elapsed_ms,
            status=status,
        )

    async def _add_to_queue(
        self, session_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add session to review queue."""
        queue_entry = {
            "session_id": session_id,
            "queued_at": datetime.utcnow().isoformat(),
            "priority": data.get("priority", "normal"),
            "reason": data.get("reason", "flagged_for_review"),
            "risk_factors": data.get("risk_factors", []),
            "document_data": data.get("document_data"),
            "biometric_data": data.get("biometric_data"),
            "screening_data": data.get("screening_data"),
            "verification_score": data.get("verification_score"),
            "status": "pending",
            "assigned_to": None,
        }
        
        self._review_queue[session_id] = queue_entry
        
        self.log_audit_event(
            "added_to_review_queue",
            {"reason": queue_entry["reason"], "priority": queue_entry["priority"]},
            session_id,
        )
        
        return {
            "success": True,
            "queue_position": len(self._review_queue),
            "queued_at": queue_entry["queued_at"],
        }

    async def _get_queue(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Get pending reviews."""
        status_filter = data.get("status", "pending")
        limit = data.get("limit", 50)
        
        entries = [
            {
                "session_id": sid,
                "queued_at": entry["queued_at"],
                "priority": entry["priority"],
                "reason": entry["reason"],
                "status": entry["status"],
            }
            for sid, entry in self._review_queue.items()
            if entry["status"] == status_filter
        ][:limit]
        
        # Sort by priority and queue time
        priority_order = {"high": 0, "normal": 1, "low": 2}
        entries.sort(key=lambda x: (priority_order.get(x["priority"], 1), x["queued_at"]))
        
        return {
            "success": True,
            "queue_depth": len(entries),
            "entries": entries,
        }

    async def _record_decision(
        self, session_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Record compliance officer decision."""
        if session_id not in self._review_queue:
            raise SessionError(f"Session {session_id} not in review queue", session_id=session_id)
        
        decision = data.get("decision")
        if decision not in [ReviewDecision.APPROVE, ReviewDecision.REJECT, ReviewDecision.REQUEST_INFO]:
            raise ValidationError(f"Invalid decision: {decision}")
        
        officer_id = data.get("officer_id")
        if not officer_id:
            raise ValidationError("officer_id is required")
        
        decision_record = {
            "session_id": session_id,
            "decision": decision,
            "officer_id": officer_id,
            "decided_at": datetime.utcnow().isoformat(),
            "notes": data.get("notes"),
            "additional_info_requested": data.get("additional_info") if decision == ReviewDecision.REQUEST_INFO else None,
        }
        
        # Update queue entry
        self._review_queue[session_id]["status"] = "decided"
        self._review_queue[session_id]["decision"] = decision
        
        # Store decision
        self._decisions[session_id] = decision_record
        
        # Log audit event
        self.log_audit_event(
            "review_decision",
            {
                "decision": decision,
                "officer_id": officer_id,
            },
            session_id,
        )
        
        # Determine final status
        if decision == ReviewDecision.APPROVE:
            final_status = "approved"
        elif decision == ReviewDecision.REJECT:
            final_status = "rejected"
        else:
            final_status = "pending_info"
        
        return {
            "success": True,
            "decision": decision,
            "final_status": final_status,
            "decided_at": decision_record["decided_at"],
            "notification_pending": True,
        }

    async def _get_status(self, session_id: str) -> Dict[str, Any]:
        """Get review status for a session."""
        if session_id in self._decisions:
            return {
                "success": True,
                "status": "decided",
                "decision": self._decisions[session_id],
            }
        elif session_id in self._review_queue:
            entry = self._review_queue[session_id]
            return {
                "success": True,
                "status": entry["status"],
                "queued_at": entry["queued_at"],
                "assigned_to": entry["assigned_to"],
            }
        else:
            return {
                "success": True,
                "status": "not_found",
            }

    async def get_queue_stats(self) -> Dict[str, Any]:
        """Get queue statistics."""
        pending = sum(1 for e in self._review_queue.values() if e["status"] == "pending")
        decided = len(self._decisions)
        
        return {
            "pending_reviews": pending,
            "decided_today": decided,
            "avg_wait_time_minutes": 0,  # Would calculate from timestamps
        }
