from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .database import get_db
from .db_models import MerchantTable

# Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Bearer token extraction
security = HTTPBearer()


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    merchant_id: Optional[str] = None
    scopes: list[str] = []


class CurrentUser(BaseModel):
    merchant_id: str
    scopes: list[str]


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password."""
    return pwd_context.hash(password)


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(
    token: str = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> CurrentUser:
    """Extract and validate current user from JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        merchant_id: str = payload.get("sub")
        scopes: list[str] = payload.get("scopes", [])

        if merchant_id is None:
            raise credentials_exception

        token_data = TokenData(merchant_id=merchant_id, scopes=scopes)
    except JWTError:
        raise credentials_exception

    # Verify merchant exists
    result = await db.execute(
        select(MerchantTable).where(MerchantTable.id == token_data.merchant_id)
    )
    merchant = result.scalar_one_or_none()
    if merchant is None:
        raise credentials_exception

    return CurrentUser(merchant_id=token_data.merchant_id, scopes=token_data.scopes)


def require_scope(required_scope: str):
    """Dependency to require a specific scope."""
    def scope_checker(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if required_scope not in current_user.scopes and "admin" not in current_user.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation requires '{required_scope}' scope"
            )
        return current_user
    return scope_checker


# Common scope requirements
require_payments_create = require_scope("payments:create")
require_payments_read = require_scope("payments:read")
require_admin = require_scope("admin")