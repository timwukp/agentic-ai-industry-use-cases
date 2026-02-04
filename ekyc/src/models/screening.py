"""
Compliance screening data models for watchlist and PEP checks.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class WatchlistType(str, Enum):
    """Watchlist types for compliance screening."""
    OFAC = "ofac"
    UN_SANCTIONS = "un_sanctions"
    EU_SANCTIONS = "eu_sanctions"
    UK_SANCTIONS = "uk_sanctions"
    PEP = "pep"
    ADVERSE_MEDIA = "adverse_media"


class MatchConfidence(str, Enum):
    """Match confidence levels."""
    HIGH = "high"      # >= 90%
    MEDIUM = "medium"  # 80-89%
    LOW = "low"        # < 80%


class WatchlistEntry(BaseModel):
    """Watchlist database entry."""
    entry_id: str
    name: str
    aliases: List[str] = Field(default_factory=list)
    date_of_birth: Optional[str] = None
    nationality: Optional[str] = None
    list_type: WatchlistType
    added_date: datetime
    source: str
    source_url: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class WatchlistMatch(BaseModel):
    """Individual watchlist match result."""
    entry_id: str
    list_type: WatchlistType
    matched_name: str
    match_score: float = Field(..., ge=0, le=1.0)
    matched_fields: List[str] = Field(default_factory=list)
    confidence: MatchConfidence
    entry_details: Optional[Dict[str, Any]] = None


class ScreeningRequest(BaseModel):
    """Request for compliance screening."""
    session_id: str
    full_name: str
    date_of_birth: Optional[str] = None
    nationality: Optional[str] = None
    document_number: Optional[str] = None
    additional_names: List[str] = Field(default_factory=list)


class ScreeningResult(BaseModel):
    """Compliance screening result."""
    screening_id: str
    session_id: str
    screened_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Overall result
    has_matches: bool = False
    requires_review: bool = False
    overall_risk: str = Field(default="low", description="low, medium, high")
    
    # Watchlist matches
    watchlist_matches: List[WatchlistMatch] = Field(default_factory=list)
    pep_matches: List[WatchlistMatch] = Field(default_factory=list)
    adverse_media_matches: List[WatchlistMatch] = Field(default_factory=list)
    
    # Processing info
    lists_screened: List[WatchlistType] = Field(default_factory=list)
    processing_time_ms: int = 0
    
    # Audit trail
    audit_id: Optional[str] = None

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class AuditLogEntry(BaseModel):
    """Audit log entry for compliance screening."""
    audit_id: str
    session_id: str
    screening_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    action: str
    actor_id: Optional[str] = None
    actor_type: str = Field(default="system")
    details: Dict[str, Any] = Field(default_factory=dict)
    ip_address: Optional[str] = None
    
    # Retention: 7 years as per compliance requirements
    retention_years: int = Field(default=7)
    archive_date: Optional[datetime] = None
