# Next-Generation eKYC System

A comprehensive electronic Know Your Customer (eKYC) system built with AWS services, featuring multi-agent architecture for automated identity verification, compliance screening, and fraud detection.

## Overview

The Next-Generation eKYC System provides enterprise-grade digital identity verification capabilities through a sophisticated multi-agent architecture. Built on AWS Strands for orchestration, AWS Bedrock AgentCore for deployment, and AWS Nova ACT for testing, this system delivers fast, accurate, and compliant identity verification at scale.

### Key Features

- **Multi-Agent Architecture**: 5 specialized AI agents working in concert for comprehensive verification
- **AWS Native**: Deep integration with AWS Textract, Rekognition, KMS, and DynamoDB
- **Global Coverage**: Support for 150+ countries and document types
- **Real-time Processing**: End-to-end verification in under 60 seconds
- **Compliance Built-in**: GDPR, AML/KYC, SOX, and PCI DSS compliant
- **Enterprise Security**: AES-256 encryption, OAuth 2.0, and comprehensive audit trails
- **Scalable Infrastructure**: Supports 10,000+ concurrent verification sessions

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              API Gateway                                      │
│                    (REST API + OAuth 2.0 + Rate Limiting)                    │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        AWS Strands Orchestrator                              │
│                   (Workflow State Machine + Event Bus)                       │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
          ┌───────────────────────────┼───────────────────────────┐
          │                           │                           │
          ▼                           ▼                           ▼
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│   Document      │       │   Biometric     │       │   Compliance    │
│   Verification  │       │   Verification  │       │   Screening     │
│   Agent         │       │   Agent         │       │   Agent         │
│                 │       │                 │       │                 │
│ • OCR Extraction│       │ • Face Matching │       │ • OFAC/UN/EU    │
│ • Authenticity  │       │ • Liveness      │       │ • PEP Check     │
│ • 150+ Countries│       │ • AES-256       │       │ • Adverse Media │
└─────────────────┘       └─────────────────┘       └─────────────────┘
          │                           │                           │
          └───────────────────────────┼───────────────────────────┘
                                      │
          ┌───────────────────────────┼───────────────────────────┐
          │                                                       │
          ▼                                                       ▼
┌─────────────────┐                                   ┌─────────────────┐
│   Fraud         │                                   │   Manual        │
│   Detection     │                                   │   Review        │
│   Agent         │                                   │   Agent         │
│                 │                                   │                 │
│ • Device FP     │                                   │ • Review Queue  │
│ • Velocity      │                                   │ • Dashboard     │
│ • ML Scoring    │                                   │ • SLA Tracking  │
└─────────────────┘                                   └─────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            AWS Services Layer                                │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│   │ Textract │  │Rekognit° │  │   KMS    │  │ DynamoDB │  │    S3    │    │
│   │   OCR    │  │  Faces   │  │ Encrypt  │  │  Store   │  │  Archive │    │
│   └──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.10+
- AWS Account with appropriate IAM permissions
- AWS CLI configured with credentials

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/agentic-ai-industry-use-cases.git
cd agentic-ai-industry-use-cases/ekyc

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -e .

# Configure AWS credentials
aws configure
```

### Running the API Server

```bash
# Development mode
uvicorn src.api.routes:app --reload --port 8000

# Production mode
uvicorn src.api.routes:app --host 0.0.0.0 --port 8000 --workers 4
```

### Basic Usage

```python
from ekyc_client import EKYCClient

# Initialize client
client = EKYCClient(
    api_key="your-api-key",
    base_url="https://api.ekyc.example.com"
)

# Create verification session
session = await client.create_session(
    organization_id="org-123",
    callback_url="https://your-app.com/webhook"
)

# Upload document
doc_result = await client.upload_document(
    session_id=session.id,
    document_type="passport",
    image_data=document_bytes
)

# Upload selfie
bio_result = await client.upload_selfie(
    session_id=session.id,
    image_data=selfie_bytes
)

# Get verification result
result = await client.get_result(session_id=session.id)
print(f"Verification Status: {result.status}")
print(f"Risk Score: {result.risk_score}")
```

## Core Components

### 1. Document Verification Agent

Handles document capture, OCR extraction, and authenticity verification.

- **AWS Textract Integration**: 3-second OCR extraction target
- **Document Types**: Passport, Driver's License, National ID, Residence Permit
- **Country Support**: 150+ countries with region-specific validation rules
- **Authenticity Checks**: Hologram detection, watermark validation, microprinting analysis

### 2. Biometric Verification Agent

Performs face matching and liveness detection.

- **Face Matching**: 95% accuracy threshold with AWS Rekognition
- **Active Liveness**: Random challenges (head movements, expressions, blinking)
- **Passive Liveness**: Texture analysis, depth estimation, micro-movement detection
- **Performance**: 5-second face matching, 10-second liveness verification

### 3. Compliance Screening Agent

Executes watchlist screening and compliance checks.

- **Watchlists**: OFAC, UN, EU, UK sanctions databases
- **PEP Screening**: Politically Exposed Persons with relationship mapping
- **Adverse Media**: News and media screening with sentiment analysis
- **Fuzzy Matching**: 80% confidence threshold with phonetic algorithms
- **Performance**: 15-second parallel screening target

### 4. Fraud Detection Agent

Analyzes behavioral and device signals for fraud indicators.

- **Device Fingerprinting**: Browser and device attribute collection
- **Geolocation Analysis**: VPN/proxy detection, location consistency
- **Velocity Checks**: 24-hour rolling window tracking
- **ML Scoring**: Synthetic identity detection model
- **Risk Scoring**: 0-100 scale with configurable thresholds

### 5. Manual Review Agent

Manages human-in-the-loop review for edge cases.

- **Review Queue**: Priority-based DynamoDB queue system
- **Dashboard Interface**: Side-by-side document and selfie comparison
- **SLA Tracking**: 5-minute notification with escalation triggers
- **Decision Recording**: Mandatory reason codes with full audit trail

### AWS Strands Orchestration

Coordinates all agents through a state machine workflow.

- **Execution Order**: Document → Biometric → Compliance → Fraud → Manual Review
- **Timeout Handling**: 60-second workflow timeout with graceful degradation
- **Error Recovery**: Automatic retry logic with circuit breakers
- **Event Bus**: Inter-agent communication and result aggregation

## Performance Targets

| Metric | Target | Description |
|--------|--------|-------------|
| Concurrent Sessions | 10,000+ | Maximum simultaneous verification sessions |
| End-to-End Time | < 60 seconds | Total verification workflow completion |
| OCR Extraction | < 3 seconds | Document text extraction time |
| Face Matching | < 5 seconds | Biometric comparison time |
| Liveness Detection | < 10 seconds | Active/passive liveness check |
| Compliance Screening | < 15 seconds | All watchlist checks |
| System Uptime | 99.9% | Service availability SLA |

## Security & Compliance

### Data Protection

- **Encryption at Rest**: AES-256-GCM for all sensitive data
- **Encryption in Transit**: TLS 1.3 for all API communications
- **Key Management**: AWS KMS with automatic key rotation
- **Biometric Security**: Encrypted storage with configurable retention

### Regulatory Compliance

- **GDPR**: Data subject rights, consent management, right to erasure
- **AML/KYC**: Anti-money laundering and know-your-customer regulations
- **SOX**: Audit trail requirements for financial institutions
- **PCI DSS**: Payment card industry data security standards

### Audit & Monitoring

- **Audit Logs**: 7-year retention with S3 Glacier archival
- **Real-time Monitoring**: AWS X-Ray distributed tracing
- **Compliance Reports**: Automated regulatory reporting
- **Security Alerts**: CloudWatch alarms for anomaly detection

## API Endpoints

### Session Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/sessions` | Create new verification session |
| GET | `/api/v1/sessions/{id}` | Get session status and details |
| DELETE | `/api/v1/sessions/{id}` | Cancel verification session |

### Document Verification

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/sessions/{id}/documents` | Upload identity document |
| GET | `/api/v1/sessions/{id}/documents/{doc_id}` | Get document verification result |

### Biometric Verification

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/sessions/{id}/selfie` | Upload selfie for face matching |
| POST | `/api/v1/sessions/{id}/liveness` | Submit liveness challenge response |
| GET | `/api/v1/sessions/{id}/biometric` | Get biometric verification result |

### Results & Analytics

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/sessions/{id}/result` | Get complete verification result |
| GET | `/api/v1/analytics/summary` | Get verification analytics |
| GET | `/api/v1/analytics/reports` | Generate compliance reports |

### Webhooks

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/webhooks` | Register webhook endpoint |
| GET | `/api/v1/webhooks` | List registered webhooks |
| DELETE | `/api/v1/webhooks/{id}` | Remove webhook registration |

## Client SDKs

### Python SDK

```bash
pip install ekyc-client
```

```python
from ekyc_client import EKYCClient, AsyncEKYCClient

# Synchronous client
client = EKYCClient(api_key="your-key")
result = client.verify(document, selfie)

# Async client
async_client = AsyncEKYCClient(api_key="your-key")
result = await async_client.verify(document, selfie)
```

### JavaScript/TypeScript SDK

```bash
npm install @ekyc/client
```

```typescript
import { EKYCClient } from '@ekyc/client';

const client = new EKYCClient({ apiKey: 'your-key' });
const result = await client.verify(document, selfie);
```

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test categories
pytest tests/unit/
pytest tests/integration/
pytest tests/nova_act/
```

### Code Quality

```bash
# Linting
ruff check src/

# Type checking
mypy src/

# Formatting
black src/ tests/
```

## Deployment

### AWS CloudFormation

```bash
# Deploy infrastructure
aws cloudformation deploy \
    --template-file infrastructure/cloudformation/ekyc-stack.yaml \
    --stack-name ekyc-production \
    --capabilities CAPABILITY_IAM

# Deploy agents to AgentCore
python deployment/deploy_agents.py --env production
```

### Docker

```bash
# Build image
docker build -t ekyc-system:latest .

# Run container
docker run -p 8000:8000 ekyc-system:latest
```

## Documentation

- [API Reference](docs/api-reference.md) - Detailed API documentation
- [Architecture Guide](docs/architecture.md) - System architecture and design
- [Integration Guide](docs/integration-guide.md) - Step-by-step integration instructions

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

## Support

For support and questions:
- GitHub Issues: [Create an issue](https://github.com/your-org/agentic-ai-industry-use-cases/issues)
- Documentation: [docs/](docs/)
- Security Issues: security@example.com

---

**Built with ❤️ using AWS Strands, Bedrock AgentCore, and Nova ACT**
