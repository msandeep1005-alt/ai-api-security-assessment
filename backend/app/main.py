from fastapi import FastAPI

from backend.app.api.routes import router as api_router


app = FastAPI(
    title="AI-Assisted API Security Assessment",
    version="0.1.0",
    description=(
        "AI-assisted API security assessment platform "
        "for OpenAPI-based API testing."
    ),
)


app.include_router(api_router)


@app.get("/")
def root():
    return {
        "name": "AI-Assisted API Security Assessment",
        "status": "running",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
    }
