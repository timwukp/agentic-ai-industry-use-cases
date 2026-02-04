/**
 * eKYC JavaScript/TypeScript SDK
 * 
 * A client library for the eKYC verification API.
 */

interface Session {
  sessionId: string;
  status: string;
  createdAt: Date;
  expiresAt?: Date;
}

interface VerificationResult {
  sessionId: string;
  status: string;
  verificationScore: number;
  riskLevel: string;
  decision: string;
  riskFactors: string[];
}

interface DocumentUploadResponse {
  documentId: string;
  sessionId: string;
  documentType: string;
  isAuthentic?: boolean;
  qualityIssues: string[];
}

interface SelfieUploadResponse {
  biometricId: string;
  sessionId: string;
  livenessPassed: boolean;
  faceMatchPassed: boolean;
}

interface EKYCClientOptions {
  apiKey: string;
  baseUrl?: string;
  timeout?: number;
}

class EKYCClient {
  private apiKey: string;
  private baseUrl: string;
  private timeout: number;

  constructor(options: EKYCClientOptions) {
    this.apiKey = options.apiKey;
    this.baseUrl = (options.baseUrl || 'https://api.ekyc.example.com').replace(/\/$/, '');
    this.timeout = options.timeout || 60000;
  }

  private async request<T>(
    method: string,
    path: string,
    body?: Record<string, unknown>
  ): Promise<T> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': this.apiKey,
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error?.message || `HTTP ${response.status}`);
      }

      if (response.status === 204) {
        return {} as T;
      }

      return response.json();
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Create a verification session
   */
  async createSession(params: {
    organizationId: string;
    customerId?: string;
    callbackUrl?: string;
    metadata?: Record<string, unknown>;
  }): Promise<Session> {
    const data = await this.request<{
      session_id: string;
      status: string;
      created_at: string;
      expires_at?: string;
    }>('POST', '/v1/sessions', {
      organization_id: params.organizationId,
      customer_id: params.customerId,
      callback_url: params.callbackUrl,
      metadata: params.metadata,
    });

    return {
      sessionId: data.session_id,
      status: data.status,
      createdAt: new Date(data.created_at),
      expiresAt: data.expires_at ? new Date(data.expires_at) : undefined,
    };
  }

  /**
   * Get session status
   */
  async getSession(sessionId: string): Promise<Session> {
    const data = await this.request<{
      session_id: string;
      status: string;
      created_at: string;
    }>('GET', `/v1/sessions/${sessionId}`);

    return {
      sessionId: data.session_id,
      status: data.status,
      createdAt: new Date(data.created_at),
    };
  }

  /**
   * Delete session and associated data
   */
  async deleteSession(sessionId: string): Promise<void> {
    await this.request<void>('DELETE', `/v1/sessions/${sessionId}`);
  }

  /**
   * Upload identity document
   */
  async uploadDocument(
    sessionId: string,
    params: {
      documentType: string;
      countryCode: string;
      imageData: ArrayBuffer | Blob;
      side?: string;
    }
  ): Promise<DocumentUploadResponse> {
    let imageBase64: string;
    
    if (params.imageData instanceof Blob) {
      const buffer = await params.imageData.arrayBuffer();
      imageBase64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
    } else {
      imageBase64 = btoa(String.fromCharCode(...new Uint8Array(params.imageData)));
    }

    const data = await this.request<{
      document_id: string;
      session_id: string;
      document_type: string;
      is_authentic?: boolean;
      quality_issues: string[];
    }>('POST', `/v1/sessions/${sessionId}/document`, {
      document_type: params.documentType,
      country_code: params.countryCode,
      side: params.side || 'front',
      image_base64: imageBase64,
    });

    return {
      documentId: data.document_id,
      sessionId: data.session_id,
      documentType: data.document_type,
      isAuthentic: data.is_authentic,
      qualityIssues: data.quality_issues,
    };
  }

  /**
   * Upload selfie for biometric verification
   */
  async uploadSelfie(
    sessionId: string,
    imageData: ArrayBuffer | Blob
  ): Promise<SelfieUploadResponse> {
    let imageBase64: string;
    
    if (imageData instanceof Blob) {
      const buffer = await imageData.arrayBuffer();
      imageBase64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
    } else {
      imageBase64 = btoa(String.fromCharCode(...new Uint8Array(imageData)));
    }

    const data = await this.request<{
      biometric_id: string;
      session_id: string;
      liveness_passed: boolean;
      face_match_passed: boolean;
    }>('POST', `/v1/sessions/${sessionId}/selfie`, {
      image_base64: imageBase64,
    });

    return {
      biometricId: data.biometric_id,
      sessionId: data.session_id,
      livenessPassed: data.liveness_passed,
      faceMatchPassed: data.face_match_passed,
    };
  }

  /**
   * Get verification result
   */
  async getResult(sessionId: string): Promise<VerificationResult> {
    const data = await this.request<{
      session_id: string;
      status: string;
      verification_score: number;
      risk_level: string;
      decision: string;
      risk_factors: string[];
    }>('GET', `/v1/sessions/${sessionId}/result`);

    return {
      sessionId: data.session_id,
      status: data.status,
      verificationScore: data.verification_score,
      riskLevel: data.risk_level,
      decision: data.decision,
      riskFactors: data.risk_factors || [],
    };
  }

  /**
   * Register webhook for event notifications
   */
  async registerWebhook(params: {
    url: string;
    events: string[];
    secret?: string;
  }): Promise<{ webhookId: string; url: string; events: string[] }> {
    const data = await this.request<{
      webhook_id: string;
      url: string;
      events: string[];
    }>('POST', '/v1/webhooks', {
      url: params.url,
      events: params.events,
      secret: params.secret,
    });

    return {
      webhookId: data.webhook_id,
      url: data.url,
      events: data.events,
    };
  }
}

// Export for different module systems
export { EKYCClient, Session, VerificationResult, DocumentUploadResponse, SelfieUploadResponse };
export default EKYCClient;
