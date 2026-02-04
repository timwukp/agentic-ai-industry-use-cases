# Integration Guide

This guide provides step-by-step instructions for integrating the eKYC System into your application.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [Authentication Setup](#authentication-setup)
4. [Basic Integration](#basic-integration)
5. [Advanced Integration](#advanced-integration)
6. [Webhook Configuration](#webhook-configuration)
7. [Error Handling](#error-handling)
8. [Best Practices](#best-practices)
9. [Troubleshooting](#troubleshooting)

## Prerequisites

Before integrating with the eKYC System, ensure you have:

- [ ] An active organization account with API credentials
- [ ] API Key or OAuth 2.0 client credentials
- [ ] HTTPS endpoint for webhooks (production environments)
- [ ] Understanding of your compliance requirements (GDPR, AML/KYC)

## Quick Start

### 1. Install the SDK

**Python:**
```bash
pip install ekyc-client
```

**JavaScript/TypeScript:**
```bash
npm install @ekyc/client
```

### 2. Initialize the Client

**Python:**
```python
from ekyc_client import EKYCClient

client = EKYCClient(
    api_key="your-api-key",
    base_url="https://api.ekyc.example.com"
)
```

**JavaScript:**
```javascript
import { EKYCClient } from '@ekyc/client';

const client = new EKYCClient({
    apiKey: 'your-api-key',
    baseUrl: 'https://api.ekyc.example.com'
});
```

### 3. Create a Verification Session

**Python:**
```python
session = await client.create_session(
    organization_id="your-org-id",
    reference_id="customer-123",
    verification_type="full"
)
print(f"Session ID: {session.id}")
```

**JavaScript:**
```javascript
const session = await client.createSession({
    organizationId: 'your-org-id',
    referenceId: 'customer-123',
    verificationType: 'full'
});
console.log(`Session ID: ${session.id}`);
```

## Authentication Setup

### API Key Authentication

API Keys are the simplest way to authenticate. Include your API key in the request header:

```
X-API-Key: your-api-key
```

**Security recommendations for API Keys:**
- Store API keys securely (environment variables, secrets manager)
- Rotate API keys regularly
- Use different keys for development and production
- Never expose API keys in client-side code

### OAuth 2.0 Authentication

For enhanced security, use OAuth 2.0 with client credentials flow:

**1. Obtain Access Token:**
```bash
curl -X POST https://auth.ekyc.example.com/oauth/token \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials" \
    -d "client_id=your-client-id" \
    -d "client_secret=your-client-secret" \
    -d "scope=ekyc:verify ekyc:read"
```

**2. Use Access Token:**
```
Authorization: Bearer your-access-token
```

## Basic Integration

### Complete Verification Flow

```python
from ekyc_client import EKYCClient
import base64

async def verify_customer(document_path: str, selfie_path: str):
    client = EKYCClient(api_key="your-api-key")
    
    # Step 1: Create session
    session = await client.create_session(
        organization_id="org-123",
        reference_id="customer-456",
        callback_url="https://your-app.com/webhook"
    )
    
    # Step 2: Upload document
    with open(document_path, "rb") as f:
        document_data = f.read()
    
    doc_result = await client.upload_document(
        session_id=session.id,
        document_type="passport",
        document_front=document_data
    )
    
    # Step 3: Upload selfie
    with open(selfie_path, "rb") as f:
        selfie_data = f.read()
    
    bio_result = await client.upload_selfie(
        session_id=session.id,
        selfie=selfie_data
    )
    
    # Step 4: Poll for result (or wait for webhook)
    result = await client.get_result(
        session_id=session.id,
        wait=True,  # Block until verification completes
        timeout=60
    )
    
    return result

# Usage
result = await verify_customer("passport.jpg", "selfie.jpg")
print(f"Decision: {result.decision}")
print(f"Risk Score: {result.risk_score}")
```

### Handling Different Document Types

```python
# Passport
await client.upload_document(
    session_id=session.id,
    document_type="passport",
    document_front=passport_image
)

# Driver's License (front and back)
await client.upload_document(
    session_id=session.id,
    document_type="drivers_license",
    document_front=license_front,
    document_back=license_back
)

# National ID
await client.upload_document(
    session_id=session.id,
    document_type="national_id",
    document_front=id_front,
    document_back=id_back  # Optional for some countries
)
```

## Advanced Integration

### Custom Verification Flow

For applications requiring more control over the verification process:

```python
from ekyc_client import EKYCClient, VerificationType

client = EKYCClient(api_key="your-api-key")

# Create session with specific options
session = await client.create_session(
    organization_id="org-123",
    reference_id="customer-456",
    verification_type=VerificationType.DOCUMENT_ONLY,  # Skip biometric
    country_code="US",
    document_types=["passport", "drivers_license"],
    skip_compliance=False,
    metadata={
        "user_tier": "premium",
        "application_id": "app-789"
    }
)
```

### Liveness Detection

For enhanced security, implement active liveness detection:

```python
# Get liveness challenge
challenge = await client.get_liveness_challenge(session_id=session.id)
print(f"Challenge: {challenge.type}")  # e.g., "head_turn_left"

# Submit challenge response (video frames)
liveness_result = await client.submit_liveness_response(
    session_id=session.id,
    challenge_id=challenge.id,
    video_frames=video_frames  # List of base64-encoded frames
)
```

### Batch Verification

For high-volume applications:

```python
from ekyc_client import BatchClient

batch_client = BatchClient(api_key="your-api-key")

# Submit batch verification
batch = await batch_client.create_batch(
    organization_id="org-123",
    verifications=[
        {"reference_id": "cust-1", "document": doc1, "selfie": selfie1},
        {"reference_id": "cust-2", "document": doc2, "selfie": selfie2},
        # ... more verifications
    ]
)

# Check batch status
status = await batch_client.get_batch_status(batch_id=batch.id)
```

## Webhook Configuration

### Setting Up Webhooks

Webhooks provide real-time notifications when verification events occur.

**Register a webhook:**
```python
webhook = await client.register_webhook(
    url="https://your-app.com/ekyc-webhook",
    events=["session.completed", "session.failed", "review.required"],
    secret="your-webhook-secret"
)
```

### Webhook Payload

```json
{
    "event": "session.completed",
    "timestamp": "2024-01-15T10:30:45Z",
    "data": {
        "session_id": "sess_abc123",
        "reference_id": "customer-456",
        "decision": "approved",
        "risk_score": 15
    },
    "signature": "sha256=..."
}
```

### Verifying Webhook Signatures

```python
import hmac
import hashlib

def verify_webhook_signature(payload: bytes, signature: str, secret: str) -> bool:
    expected = hmac.new(
        secret.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    received = signature.replace("sha256=", "")
    return hmac.compare_digest(expected, received)
```

### Webhook Best Practices

1. **Always verify signatures** before processing webhooks
2. **Respond quickly** (within 5 seconds) with 2xx status
3. **Process asynchronously** - queue webhooks for background processing
4. **Implement idempotency** - handle duplicate webhook deliveries
5. **Use HTTPS** for webhook endpoints

## Error Handling

### Common Error Scenarios

```python
from ekyc_client import (
    EKYCClient,
    ValidationError,
    AuthenticationError,
    RateLimitError,
    SessionExpiredError
)

client = EKYCClient(api_key="your-api-key")

try:
    result = await client.get_result(session_id="sess_abc123")
except ValidationError as e:
    print(f"Invalid request: {e.message}")
    print(f"Field: {e.field}, Reason: {e.reason}")
except AuthenticationError as e:
    print(f"Authentication failed: {e.message}")
except RateLimitError as e:
    print(f"Rate limited. Retry after: {e.retry_after} seconds")
except SessionExpiredError as e:
    print(f"Session expired: {e.session_id}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

### Retry Logic

The SDK includes built-in retry logic with exponential backoff:

```python
client = EKYCClient(
    api_key="your-api-key",
    max_retries=3,
    retry_delay=1.0,  # Initial delay in seconds
    retry_backoff=2.0  # Exponential backoff multiplier
)
```

## Best Practices

### Security

1. **Secure credential storage**
   - Use environment variables or secrets managers
   - Never commit credentials to version control

2. **Data handling**
   - Don't store raw document images longer than necessary
   - Implement proper data retention policies
   - Encrypt sensitive data at rest

3. **Network security**
   - Always use HTTPS
   - Implement request signing for additional security
   - Use VPC endpoints for AWS deployments

### Performance

1. **Connection pooling**
   ```python
   # Reuse client instances
   client = EKYCClient(api_key="your-api-key")
   # Use the same client for multiple requests
   ```

2. **Async operations**
   ```python
   # Use async client for concurrent operations
   from ekyc_client import AsyncEKYCClient
   
   async_client = AsyncEKYCClient(api_key="your-api-key")
   results = await asyncio.gather(
       async_client.get_result("sess_1"),
       async_client.get_result("sess_2"),
       async_client.get_result("sess_3")
   )
   ```

3. **Image optimization**
   - Compress images before upload (maintain quality)
   - Target resolution: 1920x1080 for documents
   - Target file size: < 5MB per image

### User Experience

1. **Provide clear instructions** for document capture
2. **Implement real-time feedback** for image quality
3. **Handle edge cases gracefully** (poor lighting, blurry images)
4. **Support retry flows** for failed verifications

## Troubleshooting

### Common Issues

| Issue | Possible Cause | Solution |
|-------|---------------|----------|
| "Invalid document" error | Poor image quality | Ensure good lighting, avoid glare |
| Face match failure | Different lighting conditions | Use consistent lighting for document and selfie |
| Session timeout | Slow network | Reduce image sizes, check network |
| Rate limit exceeded | Too many requests | Implement request queuing |
| Webhook not received | Firewall blocking | Whitelist eKYC IP ranges |

### Debug Mode

Enable debug logging for troubleshooting:

```python
import logging

logging.basicConfig(level=logging.DEBUG)

client = EKYCClient(
    api_key="your-api-key",
    debug=True
)
```

### Support

If you encounter issues:

1. Check the [API Reference](api-reference.md) for correct usage
2. Review error messages and codes
3. Enable debug logging for detailed information
4. Contact support at support@ekyc.example.com

---

For more information, see:
- [API Reference](api-reference.md)
- [Architecture Guide](architecture.md)
- [Python SDK Documentation](../sdk/python/README.md)
- [JavaScript SDK Documentation](../sdk/javascript/README.md)
