from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from .routers import agents

# Load environment variables
load_dotenv()

# Create FastAPI app
app = FastAPI(
    title="CyberAgents API",
    description="API for managing and orchestrating AI-powered cybersecurity agents",
    version="0.1.0",
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
app.include_router(agents.router)


@app.get("/")
async def root():
    return {"message": "Welcome to CyberAgents API"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
