from dynaconf import Dynaconf
from rexis.utils.constants import CONFIG_PATH

settings = Dynaconf(
    envvar_prefix="REXIS",
    root_path=CONFIG_PATH,
    settings_files=["settings.toml", ".secrets.toml"],
)
