"""
FastAPI application factory and main entry point.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routes import router


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    app = FastAPI(
        title="Next-Generation eKYC API",
        description="""
## Electronic Know Your Customer (eKYC) Verification API

This API provides digital identity verification services including:
- Document verification (passport, driver's license, national ID)
- Biometric facial verification with liveness detection
- Compliance screening (OFAC, UN, EU, UK sanctions, PEP)
- Fraud detection and risk scoring

### Authentication
All endpoints require API key authentication via the `X-API-Key` header.

### Workflow
1. Create a verification session
2. Upload identity document
3. Upload selfie for biometric verification
4. Retrieve verification result

### Performance
- Document OCR: <3 seconds
- Face matching: <5 seconds
- End-to-end verification: <60 seconds (95th percentile)
        """,
        version="0.1.0",
        openapi_url="/v1/openapi.json",
        docs_url="/v1/docs",
        redoc_url="/v1/redoc",
    )
    
    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure appropriately for production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Include routers
    app.include_router(router)
    
    return app


# Application instance
app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
