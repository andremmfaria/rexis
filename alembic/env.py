import os
import sys
from logging.config import fileConfig

from alembic import context
from rexis.utils.constants import DATABASE_MIGRATIONS_CONNSTRING
from sqlalchemy import engine_from_config, pool

# Add the 'src' directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

# Import Dynaconf settings and SQLAlchemy metadata
from rexis.data.model import Document

# Alembic Config object
config = context.config

# Configure Python logging via .ini file
fileConfig(config.config_file_name)

# Inject database URL from Dynaconf into Alembic config
config.set_main_option("sqlalchemy.url", DATABASE_MIGRATIONS_CONNSTRING)

# Target metadata (used for autogenerate)
target_metadata = Document.metadata


def run_migrations_offline():
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    """Run migrations in 'online' mode."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )
        with context.begin_transaction():
            context.run_migrations()


# Entrypoint
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
