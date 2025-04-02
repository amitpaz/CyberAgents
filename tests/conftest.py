"""Test configuration and fixtures."""

import pytest
from fastapi.testclient import TestClient
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import ConsoleSpanExporter
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

from api.agents.base_agent import AgentConfig
from api.main import app


@pytest.fixture
def client():
    """Create a test client for the FastAPI application."""
    return TestClient(app)


@pytest.fixture
def sample_agent_config():
    """Create a sample agent configuration for testing."""
    return AgentConfig(
        name="Test Agent",
        role="Test Role",
        goal="Test Goal",
        backstory="Test Backstory",
        tools=[],
        verbose=True,
        allow_delegation=False,
    )


@pytest.fixture(scope="session", autouse=True)
def setup_telemetry():
    """Set up OpenTelemetry for testing."""
    trace.set_tracer_provider(TracerProvider())
    span_processor = SimpleSpanProcessor(ConsoleSpanExporter())
    trace.get_tracer_provider().add_span_processor(span_processor)
    return trace.get_tracer(__name__)
