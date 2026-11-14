"""
Guardian-Sentinel: FastAPI Microservice Entry Point
High-throughput REST API with interactive Swagger docs.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from guardian.api.routes import router
from config import API_HOST, API_PORT

app = FastAPI(
    title="Guardian-Sentinel: Autonomous IDS/IPS API",
    description="High-throughput inference, Zero-Day anomaly detection, and live network flow classification.",
    version="2.0.0"
)

# Enable CORS for Streamlit and external SOC dashboards
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routes
app.include_router(router)

@app.get("/")
def root():
    return {
        "system": "Guardian-Sentinel",
        "role": "Autonomous IDS/IPS Microservice",
        "docs_url": "/docs",
        "api_version": "v1"
    }

@app.get("/health")
def healthcheck():
    return {
        "status": "HEALTHY",
        "service": "Guardian-Sentinel Backend"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("guardian.api.main:app", host=API_HOST, port=API_PORT, reload=True)
