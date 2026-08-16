from fastapi import FastAPI

app = FastAPI(
    title="AI-Assisted API Security Assessment",
    version="0.1.0"
)

@app.get("/")
def root():
    return {
        "name": "AI-Assisted API Security Assessment",
        "status": "running"
    }

@app.get("/health")
def health():
    return {"status": "healthy"}
