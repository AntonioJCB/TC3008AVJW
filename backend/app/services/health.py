from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.db.session import get_engine


def database_is_ready(database_url: str) -> bool:
    try:
        with get_engine(database_url).connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError:
        return False

    return True
