"""Runtime configuration. Loads .env, exposes typed settings + paths."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv
from platformdirs import user_data_dir

APP_NAME = "mytools-osint"
APP_AUTHOR = "MarsIT"

_DATA_DIR = Path(user_data_dir(APP_NAME, APP_AUTHOR))
_DATA_DIR.mkdir(parents=True, exist_ok=True)


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int(value: str | None, default: int) -> int:
    try:
        return int(value) if value else default
    except ValueError:
        return default


@dataclass(slots=True, frozen=True)
class Settings:
    """All runtime settings. Immutable per process; reload via load_settings()."""

    hibp_api_key: str = ""
    numverify_api_key: str = ""
    ipinfo_api_token: str = ""
    leakcheck_api_key: str = ""
    dehashed_email: str = ""
    dehashed_api_key: str = ""

    telegram_api_id: int = 0
    telegram_api_hash: str = ""
    telegram_phone: str = ""
    telegram_session_name: str = "mytools"

    http_timeout_sec: float = 10.0
    http_concurrency: int = 40
    username_retry: int = 1

    data_dir: Path = field(default=_DATA_DIR)
    db_path: Path = field(default=_DATA_DIR / "mytools.sqlite3")
    telethon_dir: Path = field(default=_DATA_DIR / "telethon")
    cache_dir: Path = field(default=_DATA_DIR / "cache")
    exports_dir: Path = field(default=_DATA_DIR / "exports")

    @property
    def has_hibp(self) -> bool:
        return bool(self.hibp_api_key)

    @property
    def has_numverify(self) -> bool:
        return bool(self.numverify_api_key)

    @property
    def has_ipinfo(self) -> bool:
        return bool(self.ipinfo_api_token)

    @property
    def has_telegram(self) -> bool:
        return bool(self.telegram_api_id and self.telegram_api_hash and self.telegram_phone)

    @property
    def has_leakcheck(self) -> bool:
        return bool(self.leakcheck_api_key)

    @property
    def has_dehashed(self) -> bool:
        return bool(self.dehashed_email and self.dehashed_api_key)


_settings: Settings | None = None


def user_config_path() -> Path:
    """Per-user config — written by `osint config`. Always at this path."""
    return _DATA_DIR / "config.env"


def load_settings(env_file: Path | str | None = None) -> Settings:
    """Read .env files and return a Settings snapshot. Memoised.

    Precedence (later wins):
      1. Project .env (CWD/.env or repo-root .env) — dev / source-run convenience
      2. User config.env at %LOCALAPPDATA%\\mytools-osint\\config.env — what `osint config` writes
      3. Explicit env_file argument
      4. Existing process environment variables (always win)
    """
    global _settings

    # 1. project .env
    local = Path.cwd() / ".env"
    if local.exists():
        load_dotenv(local, override=False)
    else:
        up = Path(__file__).resolve().parents[2] / ".env"
        if up.exists():
            load_dotenv(up, override=False)

    # 2. user config (overrides project .env on conflict)
    user_cfg = user_config_path()
    if user_cfg.exists():
        load_dotenv(user_cfg, override=True)

    # 3. explicit override
    if env_file:
        load_dotenv(env_file, override=True)

    s = Settings(
        hibp_api_key=os.getenv("HIBP_API_KEY", ""),
        numverify_api_key=os.getenv("NUMVERIFY_API_KEY", ""),
        ipinfo_api_token=os.getenv("IPINFO_API_TOKEN", ""),
        leakcheck_api_key=os.getenv("LEAKCHECK_API_KEY", ""),
        dehashed_email=os.getenv("DEHASHED_EMAIL", ""),
        dehashed_api_key=os.getenv("DEHASHED_API_KEY", ""),
        telegram_api_id=_int(os.getenv("TELEGRAM_API_ID"), 0),
        telegram_api_hash=os.getenv("TELEGRAM_API_HASH", ""),
        telegram_phone=os.getenv("TELEGRAM_PHONE", ""),
        telegram_session_name=os.getenv("TELEGRAM_SESSION_NAME", "mytools"),
        http_timeout_sec=float(os.getenv("HTTP_TIMEOUT_SEC", "10")),
        http_concurrency=_int(os.getenv("HTTP_CONCURRENCY"), 40),
        username_retry=_int(os.getenv("USERNAME_RETRY"), 1),
    )
    for d in (s.data_dir, s.telethon_dir, s.cache_dir, s.exports_dir):
        d.mkdir(parents=True, exist_ok=True)
    # Telethon session files grant full Telegram-account access — keep the
    # directory owner-only so the session secret isn't world-readable.
    try:
        os.chmod(s.telethon_dir, 0o700)
    except OSError:
        pass
    _settings = s
    return s


def settings() -> Settings:
    """Return cached settings; loads from .env on first call."""
    if _settings is None:
        return load_settings()
    return _settings
