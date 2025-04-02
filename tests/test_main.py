"""Test suite for the main FastAPI application."""

from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)


def test_root_endpoint():
    """Test the root endpoint returns a welcome message."""
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Welcome to the CyberAgents API"}


def test_api_docs_available():
    """Test that API documentation endpoints are available."""
    response = client.get("/docs")
    assert response.status_code == 200

    response = client.get("/redoc")
    assert response.status_code == 200


def test_cors_headers():
    """Test that CORS headers are properly set."""
    response = client.get("/")
    assert response.headers["access-control-allow-origin"] == "*"
    assert response.headers["access-control-allow-methods"] == "*"
    assert response.headers["access-control-allow-headers"] == "*"


def test_404_response():
    """Test that non-existent endpoints return 404."""
    response = client.get("/nonexistent")
    assert response.status_code == 404
    assert "detail" in response.json()
