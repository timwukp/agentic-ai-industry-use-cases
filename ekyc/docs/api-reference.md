# API Reference

This document provides detailed documentation for the eKYC System REST API.

## Base URL

```
Production: https://api.ekyc.example.com/api/v1
Staging: https://api-staging.ekyc.example.com/api/v1
```

## Authentication

All API requests require authentication using either:
- **API Key**: Pass in the `X-API-Key` header
- **OAuth 2.0**: Pass a Bearer token in the `Authorization` header

```bash
# API Key authentication
curl -H "X-API-Key: your-api-key" https://api.ekyc.example.com/api/v1/sessions

# OAuth 2.0 authentication
curl -H "Authorization: Bearer your-token" https://api.ekyc.example.com/api/v1/sessions
```

## Rate Limiting

- **Default**: 1,000 requests per minute per organization
- **Burst**: Up to 100 requests per second
- Rate limit headers are included in all responses:
  - `X-RateLimit-Limit`: Maximum requests per window
  - `X-RateLimit-Remaining`: Remaining requests in current window
  - `X-RateLimit-Reset`: Unix timestamp when the window resets

## Endpoints

### Sessions

#### Create Session

Creates a new verification session.

```http
POST /api/v1/sessions
Content-Type: application/json

{
  "organization_id": "org-123",
  "reference_id": "customer-456",
  "callback_url": "https://your-app.com/webhook",
  "verification_type": "full",
  "country_code": "US",
  "metadata": {
    "custom_field": "value"
  }
}
```

**Response:**

```json
{
  "id": "sess_abc123",
  "organization_id": "org-123",
  "reference_id": "customer-456",
  "status": "pending",
  "verification_type": "full",
  "created_at": "2024-01-15T10:30:00Z",
  "expires_at": "2024-01-15T10:31:00Z",
  "links": {
    "self": "/api/v1/sessions/sess_abc123",
    "documents": "/api/v1/sessions/sess_abc123/documents",
    "selfie": "/api/v1/sessions/sess_abc123/selfie"
  }
}
```

#### Get Session

Retrieves the current status of a verification session.

```http
GET /api/v1/sessions/{session_id}
```

**Response:**

```json
{
  "id": "sess_abc123",
  "status": "completed",
  "verification_type": "full",
  "created_at": "2024-01-15T10:30:00Z",
  "completed_at": "2024-01-15T10:30:45Z",
  "result": {
    "decision": "approved",
    "risk_score": 15,
    "confidence": 0.95
  },
  "steps": {
    "document": "completed",
    "biometric": "completed",
    "compliance": "completed",
    "fraud": "completed"
  }
}
```

### Documents

#### Upload Document

Uploads an identity document for verification.

```http
POST /api/v1/sessions/{session_id}/documents
Content-Type: multipart/form-data

document_type: passport
document_front: <binary data>
document_back: <binary data> (optional)
```

**Response:**

```json
{
  "id": "doc_xyz789",
  "session_id": "sess_abc123",
  "document_type": "passport",
  "status": "processing",
  "created_at": "2024-01-15T10:30:05Z"
}
```

#### Get Document Result

Retrieves the document verification result.

```http
GET /api/v1/sessions/{session_id}/documents/{document_id}
```

**Response:**

```json
{
  "id": "doc_xyz789",
  "status": "completed",
  "document_type": "passport",
  "country_code": "US",
  "extracted_data": {
    "full_name": "John Doe",
    "date_of_birth": "1990-05-15",
    "document_number": "123456789",
    "expiry_date": "2030-05-14",
    "nationality": "USA"
  },
  "authenticity": {
    "is_authentic": true,
    "confidence": 0.98,
    "checks": {
      "hologram": "passed",
      "watermark": "passed",
      "microprinting": "passed"
    }
  },
  "quality": {
    "score": 0.95,
    "issues": []
  }
}
```

### Biometric

#### Upload Selfie

Uploads a selfie image for face matching.

```http
POST /api/v1/sessions/{session_id}/selfie
Content-Type: multipart/form-data

selfie: <binary data>
```

**Response:**

```json
{
  "id": "bio_def456",
  "session_id": "sess_abc123",
  "status": "processing",
  "created_at": "2024-01-15T10:30:10Z"
}
```

#### Submit Liveness Challenge

Submits a liveness challenge response.

```http
POST /api/v1/sessions/{session_id}/liveness
Content-Type: application/json

{
  "challenge_id": "chal_123",
  "challenge_type": "head_turn_left",
  "video_data": "<base64 encoded video>",
  "frames": [
    "<base64 encoded frame 1>",
    "<base64 encoded frame 2>"
  ]
}
```

#### Get Biometric Result

Retrieves the biometric verification result.

```http
GET /api/v1/sessions/{session_id}/biometric
```

**Response:**

```json
{
  "id": "bio_def456",
  "status": "completed",
  "face_match": {
    "is_match": true,
    "confidence": 0.97,
    "similarity_score": 0.96
  },
  "liveness": {
    "is_live": true,
    "confidence": 0.99,
    "challenges_passed": 3,
    "challenges_total": 3
  }
}
```

### Results

#### Get Verification Result

Retrieves the complete verification result.

```http
GET /api/v1/sessions/{session_id}/result
```

**Response:**

```json
{
  "session_id": "sess_abc123",
  "decision": "approved",
  "risk_score": 15,
  "completed_at": "2024-01-15T10:30:45Z",
  "document_verification": {
    "status": "passed",
    "document_type": "passport",
    "confidence": 0.98
  },
  "biometric_verification": {
    "status": "passed",
    "face_match_confidence": 0.97,
    "liveness_confidence": 0.99
  },
  "compliance_screening": {
    "status": "clear",
    "watchlist_matches": [],
    "pep_matches": [],
    "adverse_media_matches": []
  },
  "fraud_analysis": {
    "risk_level": "low",
    "risk_score": 15,
    "signals": []
  }
}
```

### Webhooks

#### Register Webhook

Registers a webhook endpoint for notifications.

```http
POST /api/v1/webhooks
Content-Type: application/json

{
  "url": "https://your-app.com/ekyc-webhook",
  "events": ["session.completed", "session.failed", "review.required"],
  "secret": "your-webhook-secret"
}
```

**Response:**

```json
{
  "id": "whk_abc123",
  "url": "https://your-app.com/ekyc-webhook",
  "events": ["session.completed", "session.failed", "review.required"],
  "status": "active",
  "created_at": "2024-01-15T10:00:00Z"
}
```

## Error Handling

### Error Response Format

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid document type",
    "details": {
      "field": "document_type",
      "reason": "must be one of: passport, drivers_license, national_id"
    }
  },
  "request_id": "req_xyz789"
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `VALIDATION_ERROR` | 400 | Invalid request parameters |
| `AUTHENTICATION_ERROR` | 401 | Invalid or missing authentication |
| `AUTHORIZATION_ERROR` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Internal server error |
| `SERVICE_UNAVAILABLE` | 503 | Service temporarily unavailable |

## Webhook Events

| Event | Description |
|-------|-------------|
| `session.created` | New verification session created |
| `session.completed` | Verification completed successfully |
| `session.failed` | Verification failed |
| `session.expired` | Session expired before completion |
| `review.required` | Manual review required |
| `review.completed` | Manual review completed |

## SDKs

For easier integration, use our official SDKs:

- [Python SDK](../sdk/python/README.md)
- [JavaScript SDK](../sdk/javascript/README.md)
