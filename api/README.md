# CyberAgents API

A FastAPI-based API for managing and orchestrating AI-powered cybersecurity agents using CrewAI.

## Setup

1. Create a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Copy the environment file:

```bash
cp .env.example .env
```

4. Update the `.env` file with your configuration:

- Set your OpenAI API key
- Configure CORS origins if needed
- Adjust other settings as required

## Running the API

Start the development server:

```bash
uvicorn api.main:app --reload
```

The API will be available at `http://localhost:8000`

## API Documentation

- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## Available Endpoints

### Agents

- `POST /agents/` - Create a new agent
- `GET /agents/` - List all agents

## Testing

Run the test suite:

```bash
pytest tests/
```

## Development

- Follow the FastAPI guidelines in the project documentation
- Use type hints for all functions
- Write tests for new features
- Update documentation as needed
