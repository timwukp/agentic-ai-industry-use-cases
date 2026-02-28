"""OpenTelemetry observability setup for AgentCore agents."""
import os
import logging

logger = logging.getLogger(__name__)


def setup_observability(
    service_name: str,
    environment: str = "development",
) -> None:
    """Setup OpenTelemetry tracing for an agent.

    Configures OTEL with the AgentCore Observability service for:
    - Distributed tracing across agent invocations
    - Tool execution spans
    - Model inference latency tracking
    - Custom business metrics

    Args:
        service_name: Name of the service (e.g., "finance-TradingAssistant").
        environment: Deployment environment (development, staging, production).
    """
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.resources import Resource

        resource = Resource.create({
            "service.name": service_name,
            "deployment.environment": environment,
            "cloud.provider": "aws",
            "cloud.platform": "aws_bedrock_agentcore",
        })

        provider = TracerProvider(resource=resource)
        trace.set_tracer_provider(provider)

        # If OTEL endpoint is configured, add the exporter
        otel_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
        if otel_endpoint:
            from opentelemetry.sdk.trace.export import BatchSpanProcessor
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

            exporter = OTLPSpanExporter(endpoint=otel_endpoint)
            provider.add_span_processor(BatchSpanProcessor(exporter))
            logger.info(f"OTEL tracing enabled for {service_name} -> {otel_endpoint}")
        else:
            logger.info(f"OTEL tracing configured for {service_name} (no exporter endpoint set)")

    except ImportError:
        logger.warning("OpenTelemetry packages not installed. Tracing disabled.")
    except Exception as e:
        logger.warning(f"Failed to setup observability: {e}")
