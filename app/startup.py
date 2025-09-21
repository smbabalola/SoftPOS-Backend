from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncEngine

from .database import Base, engine


async def create_tables(engine: AsyncEngine) -> None:
    """Create all tables in the database."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def startup() -> None:
    """Application startup tasks."""
    await create_tables(engine)