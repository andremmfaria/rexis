from typing import Tuple
from rexis.utils.config import config

DATABASE_CONNECTION_CONNSTRING: str = (
    f"postgresql://{config.db.user}:{config.db.password}@{config.db.host}:{config.db.port}/{config.db.name}"
)

SOCIAL_DOMAINS: Tuple[str, ...] = (
    "twitter.com",
    "x.com",
    "t.co",
    "youtube.com",
    "youtu.be",
    "facebook.com",
    "fb.com",
    "instagram.com",
    "linkedin.com",
    "lnkd.in",
    "reddit.com",
    "medium.com",
    "tiktok.com",
    "discord.com",
    "discord.gg",
    "telegram.me",
    "t.me",
)
