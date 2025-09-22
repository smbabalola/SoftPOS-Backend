from __future__ import annotations
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Try to import startup, fallback to basic setup if it fails
try:
    from .startup import startup
    HAS_DATABASE = True
except ImportError:
    HAS_DATABASE = False

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
    if HAS_DATABASE:
        try:
            await startup()
        except Exception as e:
            print(f"Database startup failed: {e}")
            # Continue without database for now


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