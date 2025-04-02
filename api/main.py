"""Main FastAPI application module."""

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routers import agents

# Load environment variables
load_dotenv()

# Create FastAPI app
app = FastAPI(
    title="Agent API",
    description="API for managing and interacting with AI agents",
    version="1.0.0",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
