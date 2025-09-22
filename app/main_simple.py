from __future__ import annotations
import os

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Try to import startup, fallback to basic setup if it fails
try:
    from .startup import startup
    HAS_DATABASE = True
except ImportError:
    HAS_DATABASE = False

# Import payment processing endpoints
try:
    from .endpoints.payments import router as payments_router
    from .simple_auth import create_access_token
    HAS_PAYMENTS = True
except ImportError:
    HAS_PAYMENTS = False

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

# Include payment endpoints if available
if HAS_PAYMENTS:
    app.include_router(payments_router, prefix="/v1")


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


class LoginRequest(BaseModel):
    email: str
    password: str


@app.post("/v1/auth/login")
async def login(request: LoginRequest):
    """Simple login for testing payments"""
    # Demo credentials
    if request.email == "demo@softpos.com" and request.password == "demo123":
        token = create_access_token({
            "sub": "demo_user",
            "merchant_id": "demo_merchant_001",
            "scopes": ["payments:create", "payments:read"]
        })
        return {"access_token": token, "token_type": "bearer"}
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")


@app.get("/")
async def root():
    return {"message": "SoftPOS API", "docs": "/docs"}