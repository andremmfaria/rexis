from dynaconf import Dynaconf

CONFIG_PATH: str = "config"

config = Dynaconf(
    envvar_prefix="REXIS",
    root_path=CONFIG_PATH,
    settings_files=["settings.toml", ".secrets.toml"],
)
