from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .startup import startup

app = FastAPI(title="SoftPOS API", version="1.0.0")

# Add CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    await startup()


@app.get("/health")
async def health() -> dict:
    return {
        "status": "healthy",
        "message": "SoftPOS API is running",
        "version": "1.0.0"
    }


@app.get("/")
async def root():
    return {"message": "SoftPOS API", "docs": "/docs"}