from rexis.utils.config import config

DATABASE_CONNECTION_CONNSTRING: str = (
    f"postgresql://{config.db.user}:{config.db.password}@{config.db.host}:{config.db.port}/{config.db.name}"
)
