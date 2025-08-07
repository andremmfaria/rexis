from rexis.utils.config import settings

DATABASE_CONNECTION_CONNSTRING: str = (
    f"postgresql://{settings.db.user}:{settings.db.password}@{settings.db.host}:{settings.db.port}/{settings.db.name}"
)
