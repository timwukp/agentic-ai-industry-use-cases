"""
eKYC Python SDK

A Python client library for the eKYC verification API.
"""

import base64
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx


@dataclass
class Session:
    """Verification session."""
    session_id: str
    status: str
    created_at: datetime
    expires_at: Optional[datetime] = None


@dataclass
class VerificationResult:
    """Verification result."""
    session_id: str
    status: str
    verification_score: float
    risk_level: str
    decision: str
    risk_factors: List[str]


class EKYCClient:
    """
    Python client for the eKYC API.
    
    Example usage:
        client = EKYCClient(api_key="your-api-key")
        
        # Create session
        session = client.create_session(organization_id="org-123")
        
        # Upload document
        with open("passport.jpg", "rb") as f:
            client.upload_document(
                session.session_id,
                document_type="passport",
                country_code="US",
                image_data=f.read()
            )
        
        # Upload selfie
        with open("selfie.jpg", "rb") as f:
            client.upload_selfie(session.session_id, image_data=f.read())
        
        # Get result
        result = client.get_result(session.session_id)
        print(f"Status: {result.status}, Score: {result.verification_score}")
    """

    DEFAULT_BASE_URL = "https://api.ekyc.example.com"

    def __init__(
        self,
        api_key: str,
        base_url: Optional[str] = None,
        timeout: float = 60.0,
    ):
        """
        Initialize eKYC client.
        
        Args:
            api_key: Your API key
            base_url: API base URL (optional)
            timeout: Request timeout in seconds
        """
        self.api_key = api_key
        self.base_url = (base_url or self.DEFAULT_BASE_URL).rstrip("/")
        self.timeout = timeout
        self._client = httpx.Client(
            base_url=self.base_url,
            headers={"X-API-Key": api_key},
            timeout=timeout,
        )

    def _request(
        self,
        method: str,
        path: str,
        json: Optional[Dict] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Make HTTP request."""
        response = self._client.request(method, path, json=json, **kwargs)
        response.raise_for_status()
        if response.status_code == 204:
            return {}
        return response.json()

    def create_session(
        self,
        organization_id: str,
        customer_id: Optional[str] = None,
        callback_url: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ) -> Session:
        """Create a verification session."""
        data = self._request(
            "POST",
            "/v1/sessions",
            json={
                "organization_id": organization_id,
                "customer_id": customer_id,
                "callback_url": callback_url,
                "metadata": metadata,
            },
        )
        return Session(
            session_id=data["session_id"],
            status=data["status"],
            created_at=datetime.fromisoformat(data["created_at"].replace("Z", "+00:00")),
            expires_at=datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00")) if data.get("expires_at") else None,
        )

    def get_session(self, session_id: str) -> Session:
        """Get session status."""
        data = self._request("GET", f"/v1/sessions/{session_id}")
        return Session(
            session_id=data["session_id"],
            status=data["status"],
            created_at=datetime.fromisoformat(data["created_at"].replace("Z", "+00:00")),
        )

    def delete_session(self, session_id: str) -> None:
        """Delete session and associated data."""
        self._request("DELETE", f"/v1/sessions/{session_id}")

    def upload_document(
        self,
        session_id: str,
        document_type: str,
        country_code: str,
        image_data: bytes,
        side: str = "front",
    ) -> Dict[str, Any]:
        """Upload identity document."""
        image_base64 = base64.b64encode(image_data).decode()
        return self._request(
            "POST",
            f"/v1/sessions/{session_id}/document",
            json={
                "document_type": document_type,
                "country_code": country_code,
                "side": side,
                "image_base64": image_base64,
            },
        )

    def upload_selfie(
        self,
        session_id: str,
        image_data: bytes,
    ) -> Dict[str, Any]:
        """Upload selfie for biometric verification."""
        image_base64 = base64.b64encode(image_data).decode()
        return self._request(
            "POST",
            f"/v1/sessions/{session_id}/selfie",
            json={"image_base64": image_base64},
        )

    def get_result(self, session_id: str) -> VerificationResult:
        """Get verification result."""
        data = self._request("GET", f"/v1/sessions/{session_id}/result")
        return VerificationResult(
            session_id=data["session_id"],
            status=data["status"],
            verification_score=data["verification_score"],
            risk_level=data["risk_level"],
            decision=data["decision"],
            risk_factors=data.get("risk_factors", []),
        )

    def register_webhook(
        self,
        url: str,
        events: List[str],
        secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Register webhook for event notifications."""
        return self._request(
            "POST",
            "/v1/webhooks",
            json={"url": url, "events": events, "secret": secret},
        )

    def get_analytics(self, organization_id: str) -> Dict[str, Any]:
        """Get verification analytics."""
        return self._request("GET", f"/v1/organizations/{organization_id}/analytics")

    def close(self) -> None:
        """Close the client connection."""
        self._client.close()

    def __enter__(self) -> "EKYCClient":
        return self

    def __exit__(self, *args) -> None:
        self.close()


# Async client
class AsyncEKYCClient:
    """Async Python client for the eKYC API."""

    DEFAULT_BASE_URL = "https://api.ekyc.example.com"

    def __init__(
        self,
        api_key: str,
        base_url: Optional[str] = None,
        timeout: float = 60.0,
    ):
        self.api_key = api_key
        self.base_url = (base_url or self.DEFAULT_BASE_URL).rstrip("/")
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={"X-API-Key": api_key},
            timeout=timeout,
        )

    async def _request(
        self,
        method: str,
        path: str,
        json: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        response = await self._client.request(method, path, json=json)
        response.raise_for_status()
        if response.status_code == 204:
            return {}
        return response.json()

    async def create_session(
        self,
        organization_id: str,
        customer_id: Optional[str] = None,
    ) -> Session:
        data = await self._request(
            "POST",
            "/v1/sessions",
            json={"organization_id": organization_id, "customer_id": customer_id},
        )
        return Session(
            session_id=data["session_id"],
            status=data["status"],
            created_at=datetime.fromisoformat(data["created_at"].replace("Z", "+00:00")),
        )

    async def upload_document(
        self,
        session_id: str,
        document_type: str,
        country_code: str,
        image_data: bytes,
    ) -> Dict[str, Any]:
        image_base64 = base64.b64encode(image_data).decode()
        return await self._request(
            "POST",
            f"/v1/sessions/{session_id}/document",
            json={
                "document_type": document_type,
                "country_code": country_code,
                "image_base64": image_base64,
            },
        )

    async def upload_selfie(self, session_id: str, image_data: bytes) -> Dict[str, Any]:
        image_base64 = base64.b64encode(image_data).decode()
        return await self._request(
            "POST",
            f"/v1/sessions/{session_id}/selfie",
            json={"image_base64": image_base64},
        )

    async def get_result(self, session_id: str) -> VerificationResult:
        data = await self._request("GET", f"/v1/sessions/{session_id}/result")
        return VerificationResult(
            session_id=data["session_id"],
            status=data["status"],
            verification_score=data["verification_score"],
            risk_level=data["risk_level"],
            decision=data["decision"],
            risk_factors=data.get("risk_factors", []),
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "AsyncEKYCClient":
        return self

    async def __aexit__(self, *args) -> None:
        await self.close()
