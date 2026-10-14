from collections.abc import Iterator
from functools import lru_cache
from typing import Annotated

from fastapi import Depends
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings


@lru_cache(maxsize=4)
def get_engine(database_url: str) -> Engine:
    return create_engine(database_url, pool_pre_ping=True, connect_args={"connect_timeout": 3})


def get_db_session(settings: Annotated[Settings, Depends(get_settings)]) -> Iterator[Session]:
    if settings.database_url is None:
        raise RuntimeError("BAXTERSEC_DATABASE_URL is not configured")

    with Session(get_engine(str(settings.database_url))) as session:
        yield session
