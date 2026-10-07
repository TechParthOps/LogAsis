from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path

from ai.secure_store import delete_secret, read_secret, write_secret

APP_DIR = Path(os.getenv("APPDATA", str(Path.home()))) / "LogAsis"
CONFIG_PATH = APP_DIR / "ai_provider.json"
CREDENTIAL_TARGET = "LogAsis/LiveAI/APIKey"

LIVE_AI_DEFAULTS = {
    "OpenAI": ("gpt-4o-mini", "https://api.openai.com/v1"),
    "Google Gemini": ("gemini-3.5-flash", "https://generativelanguage.googleapis.com/v1beta/openai"),
    "NVIDIA NIM": ("nvidia/nemotron-3-ultra-550b-a55b", "https://integrate.api.nvidia.com/v1"),
    "OpenAI-Compatible": ("", ""),
}




class _LiveAIPreset(tuple):
    """Tuple-compatible preset with named fields for older integrations."""
    def __new__(cls, model: str, base_url: str):
        return super().__new__(cls, (model, base_url))
    def __getitem__(self, key):
        if key == "model":
            return tuple.__getitem__(self, 0)
        if key in {"base_url", "endpoint"}:
            return tuple.__getitem__(self, 1)
        return tuple.__getitem__(self, key)


LIVE_AI_PRESETS = {name: _LiveAIPreset(*value) for name, value in LIVE_AI_DEFAULTS.items()}


@dataclass
class LiveAIConfig:
    provider: str = "OpenAI"
    model: str = "gpt-4o-mini"
    base_url: str = "https://api.openai.com/v1"
    configured: bool = False


def load_live_config() -> LiveAIConfig:
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        return LiveAIConfig(
            provider=str(data.get("provider", "OpenAI")),
            model=str(data.get("model", "gpt-4o-mini")),
            base_url=str(data.get("base_url", "https://api.openai.com/v1")),
            configured=bool(data.get("configured", False)),
        )
    except (FileNotFoundError, json.JSONDecodeError, OSError, TypeError, ValueError):
        return LiveAIConfig()


def save_live_config(config: LiveAIConfig, api_key: str) -> None:
    if not api_key.strip():
        raise ValueError("API key cannot be empty.")
    APP_DIR.mkdir(parents=True, exist_ok=True)
    write_secret(CREDENTIAL_TARGET, api_key.strip())

    # Deliberately contains no API key or secret material.
    data = asdict(config)
    data["configured"] = True
    tmp = CONFIG_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(CONFIG_PATH)


def get_api_key() -> str | None:
    return read_secret(CREDENTIAL_TARGET)


def clear_live_config() -> None:
    try:
        delete_secret(CREDENTIAL_TARGET)
    except Exception:
        pass
    try:
        CONFIG_PATH.unlink()
    except FileNotFoundError:
        pass
