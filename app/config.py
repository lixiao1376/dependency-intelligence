"""Environment-backed application configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    github_token: str | None = os.getenv("GITHUB_TOKEN")
    openai_api_key: str | None = os.getenv("OPENAI_API_KEY")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
    request_timeout_seconds: float = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "20"))
    max_source_files: int = int(os.getenv("MAX_SOURCE_FILES", "5000"))
    allowed_project_root: str | None = os.getenv("ALLOWED_PROJECT_ROOT")


settings = Settings()

