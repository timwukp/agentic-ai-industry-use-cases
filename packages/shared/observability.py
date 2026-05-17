"""OpenTelemetry observability setup for AgentCore agents."""
import os
import logging
from contextlib import contextmanager

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

    If a non-default tracer provider is already configured (e.g., by strands-agents
    built-in OTEL support), this function will not override it.

    Args:
        service_name: Name of the service (e.g., "finance-TradingAssistant").
        environment: Deployment environment (development, staging, production).
    """
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.resources import Resource

        # Check if a non-default tracer provider is already set
        current_provider = trace.get_tracer_provider()
        if current_provider and not isinstance(current_provider, trace.ProxyTracerProvider):
            logger.info(f"Tracer provider already configured for {service_name}, skipping setup.")
            return

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


def create_custom_metric(name: str, value: float, unit: str = "", attributes: dict = None) -> None:
    """Record a custom metric value using OpenTelemetry.

    Args:
        name: Metric name (e.g., "trade.execution_time").
        value: Metric value.
        unit: Optional unit of measurement (e.g., "ms", "count").
        attributes: Optional dictionary of metric attributes/labels.
    """
    try:
        from opentelemetry import metrics

        meter = metrics.get_meter(__name__)
        gauge = meter.create_gauge(name, unit=unit, description=f"Custom metric: {name}")
        gauge.set(value, attributes=attributes or {})
    except ImportError:
        logger.debug(f"OpenTelemetry metrics not available. Skipping metric: {name}={value}")
    except Exception as e:
        logger.warning(f"Failed to record metric {name}: {e}")


@contextmanager
def create_span(name: str, attributes: dict = None):
    """Context manager for creating custom business spans.

    Usage:
        with create_span("process_trade", {"trade_id": "123"}):
            # ... business logic ...

    Args:
        name: Span name.
        attributes: Optional dictionary of span attributes.

    Yields:
        The span object (or None if OTEL is not available).
    """
    try:
        from opentelemetry import trace

        tracer = trace.get_tracer(__name__)
        with tracer.start_as_current_span(name, attributes=attributes or {}) as span:
            yield span
    except ImportError:
        logger.debug(f"OpenTelemetry not available. Skipping span: {name}")
        yield None
    except Exception as e:
        logger.warning(f"Failed to create span {name}: {e}")
        yield None
