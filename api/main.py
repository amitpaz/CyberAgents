"""Main FastAPI application module."""

import os  # Import os to access environment variables

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routers import agents

# Load environment variables
load_dotenv()

# Get allowed origins from environment variable
# Expects a comma-separated string, e.g., "http://localhost:3000,https://myapp.com"
allowed_origins_str = os.getenv("ALLOWED_ORIGINS", "")
allowed_origins = [
    origin.strip() for origin in allowed_origins_str.split(",") if origin.strip()
]
# Default to empty list if variable is not set or empty, which is safer than ["*"]
if not allowed_origins:
    # You might want to log a warning here in a real application
    # print("Warning: ALLOWED_ORIGINS environment variable not set. CORS will be restrictive.")
    pass  # Keep allowed_origins as []

# Create FastAPI app
app = FastAPI(
    title="Agent API",
    description="API for managing and interacting with AI agents",
    version="1.0.0",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,  # Use the variable here
    allow_credentials=True,
    allow_methods=[
        "*"
    ],  # Consider restricting methods (e.g., ["GET", "POST"]) in production
    allow_headers=["*"],  # Consider restricting headers in production
)

# Include routers
app.include_router(agents.router, prefix="/api/v1/agents", tags=["agents"])


@app.get("/health")
async def health_check() -> dict:
    """Check the health status of the API.

    Returns:
        Dictionary containing health status information
    """
    return {"status": "healthy"}


@app.get("/")
async def root() -> dict:
    """Return a welcome message for the API root endpoint.

    Returns:
        Dictionary containing a welcome message
    """
    return {"message": "Welcome to CyberAgents API"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
