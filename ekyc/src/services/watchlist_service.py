"""
Watchlist service for compliance screening.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..models.screening import (
    MatchConfidence,
    ScreeningResult,
    WatchlistMatch,
    WatchlistType,
)

logger = logging.getLogger(__name__)


class WatchlistService:
    """Service for screening against watchlists and sanctions databases."""

    # Match threshold for flagging (80% as per requirements)
    MATCH_THRESHOLD = 0.80

    def __init__(self, dynamodb_table: str = "ekyc-watchlist"):
        """Initialize watchlist service."""
        self.dynamodb_table = dynamodb_table
        # In production, these would connect to actual databases
        self._watchlists: Dict[WatchlistType, List[Dict]] = {
            WatchlistType.OFAC: [],
            WatchlistType.UN_SANCTIONS: [],
            WatchlistType.EU_SANCTIONS: [],
            WatchlistType.UK_SANCTIONS: [],
            WatchlistType.PEP: [],
            WatchlistType.ADVERSE_MEDIA: [],
        }

    async def screen(
        self,
        session_id: str,
        full_name: str,
        date_of_birth: Optional[str] = None,
        nationality: Optional[str] = None,
        additional_names: Optional[List[str]] = None,
    ) -> ScreeningResult:
        """
        Screen individual against all configured watchlists.
        
        Args:
            session_id: Verification session ID
            full_name: Full name to screen
            date_of_birth: Date of birth (YYYY-MM-DD)
            nationality: Country code
            additional_names: Aliases to also screen
            
        Returns:
            ScreeningResult with any matches found
        """
        import uuid
        
        screening_id = str(uuid.uuid4())
        start_time = datetime.utcnow()
        
        all_names = [full_name] + (additional_names or [])
        watchlist_matches = []
        pep_matches = []
        adverse_media_matches = []
        
        # Screen against each watchlist type
        for name in all_names:
            # Sanctions lists
            for list_type in [
                WatchlistType.OFAC,
                WatchlistType.UN_SANCTIONS,
                WatchlistType.EU_SANCTIONS,
                WatchlistType.UK_SANCTIONS,
            ]:
                matches = await self._search_list(
                    list_type, name, date_of_birth, nationality
                )
                watchlist_matches.extend(matches)
            
            # PEP screening
            pep = await self._search_list(
                WatchlistType.PEP, name, date_of_birth, nationality
            )
            pep_matches.extend(pep)
            
            # Adverse media
            media = await self._search_list(
                WatchlistType.ADVERSE_MEDIA, name, date_of_birth, nationality
            )
            adverse_media_matches.extend(media)

        # Calculate processing time
        processing_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        
        # Determine overall risk
        has_matches = bool(watchlist_matches or pep_matches or adverse_media_matches)
        overall_risk = self._calculate_risk(
            watchlist_matches, pep_matches, adverse_media_matches
        )
        
        return ScreeningResult(
            screening_id=screening_id,
            session_id=session_id,
            has_matches=has_matches,
            requires_review=has_matches,
            overall_risk=overall_risk,
            watchlist_matches=watchlist_matches,
            pep_matches=pep_matches,
            adverse_media_matches=adverse_media_matches,
            lists_screened=list(WatchlistType),
            processing_time_ms=processing_time,
        )

    async def _search_list(
        self,
        list_type: WatchlistType,
        name: str,
        date_of_birth: Optional[str],
        nationality: Optional[str],
    ) -> List[WatchlistMatch]:
        """Search a specific watchlist using fuzzy matching."""
        matches = []
        entries = self._watchlists.get(list_type, [])
        
        for entry in entries:
            score = self._calculate_match_score(
                name, entry.get("name", ""), date_of_birth, entry.get("dob")
            )
            if score >= self.MATCH_THRESHOLD:
                matches.append(
                    WatchlistMatch(
                        entry_id=entry.get("id", ""),
                        list_type=list_type,
                        matched_name=entry.get("name", ""),
                        match_score=score,
                        matched_fields=["name"],
                        confidence=self._score_to_confidence(score),
                        entry_details=entry,
                    )
                )
        return matches

    def _calculate_match_score(
        self,
        query_name: str,
        entry_name: str,
        query_dob: Optional[str],
        entry_dob: Optional[str],
    ) -> float:
        """Calculate fuzzy match score."""
        # Simple implementation - in production use proper fuzzy matching
        query_normalized = query_name.lower().strip()
        entry_normalized = entry_name.lower().strip()
        
        if query_normalized == entry_normalized:
            return 1.0
        
        # Check for partial matches
        query_parts = set(query_normalized.split())
        entry_parts = set(entry_normalized.split())
        
        if not query_parts or not entry_parts:
            return 0.0
        
        overlap = len(query_parts & entry_parts)
        total = len(query_parts | entry_parts)
        name_score = overlap / total if total > 0 else 0.0
        
        # Boost score if DOB matches
        if query_dob and entry_dob and query_dob == entry_dob:
            name_score = min(1.0, name_score + 0.2)
        
        return name_score

    def _score_to_confidence(self, score: float) -> MatchConfidence:
        """Convert match score to confidence level."""
        if score >= 0.90:
            return MatchConfidence.HIGH
        elif score >= 0.80:
            return MatchConfidence.MEDIUM
        return MatchConfidence.LOW

    def _calculate_risk(
        self,
        watchlist_matches: List[WatchlistMatch],
        pep_matches: List[WatchlistMatch],
        adverse_media_matches: List[WatchlistMatch],
    ) -> str:
        """Calculate overall risk level."""
        if any(m.confidence == MatchConfidence.HIGH for m in watchlist_matches):
            return "high"
        if watchlist_matches or any(m.confidence == MatchConfidence.HIGH for m in pep_matches):
            return "medium"
        if pep_matches or adverse_media_matches:
            return "low"
        return "low"

    async def add_entry(
        self, list_type: WatchlistType, entry: Dict[str, Any]
    ) -> None:
        """Add entry to watchlist (for testing/initialization)."""
        if list_type not in self._watchlists:
            self._watchlists[list_type] = []
        self._watchlists[list_type].append(entry)

    async def refresh_lists(self) -> None:
        """Refresh watchlist data from external sources."""
        # In production, this would fetch from actual sanctions databases
        logger.info("Refreshing watchlist data...")
