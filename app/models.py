"""Public request, evidence, and report models."""

from __future__ import annotations

from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field, field_validator


class Ecosystem(str, Enum):
    PYPI = "PyPI"
    NPM = "npm"


class Verdict(str, Enum):
    SAFE = "safe"
    REVIEW = "needs_review"
    RISKY = "risky"


class UpgradeRequest(BaseModel):
    package: str = Field(min_length=1, max_length=214, examples=["pydantic"])
    current_version: str = Field(min_length=1, max_length=64, examples=["1.10.13"])
    target_version: str = Field(default="latest", min_length=1, max_length=64)
    project_path: str = Field(examples=["/workspace/my-project"])
    ecosystem: Ecosystem = Ecosystem.PYPI
    github_repo: str | None = Field(default=None, pattern=r"^[\w.-]+/[\w.-]+$")
    import_names: list[str] = Field(default_factory=list)
    use_llm: bool = False

    @field_validator("package", "current_version", "target_version")
    @classmethod
    def no_control_characters(cls, value: str) -> str:
        value = value.strip()
        if not value or any(ord(char) < 32 for char in value):
            raise ValueError("must be non-empty and contain no control characters")
        return value

    @field_validator("project_path")
    @classmethod
    def existing_project_directory(cls, value: str) -> str:
        path = Path(value).expanduser().resolve()
        if not path.is_dir():
            raise ValueError(f"project directory does not exist: {path}")
        return str(path)


class PackageInfo(BaseModel):
    package: str
    ecosystem: Ecosystem
    current_version: str
    target_version: str
    latest_version: str
    repository: str | None = None
    import_names: list[str] = Field(default_factory=list)
    source_url: str


class ReleaseEvidence(BaseModel):
    version: str
    title: str
    published_at: str | None = None
    url: str
    excerpts: list[str] = Field(default_factory=list)
    changed_symbols: list[str] = Field(default_factory=list)
    signals: list[str] = Field(default_factory=list)


class VulnerabilityEvidence(BaseModel):
    id: str
    summary: str
    aliases: list[str] = Field(default_factory=list)
    severity: str = "unknown"
    fixed_versions: list[str] = Field(default_factory=list)
    affects_current: bool = True
    affects_target: bool = False
    url: str


class CodeUsage(BaseModel):
    file: str
    line: int
    symbol: str
    snippet: str
    language: str


class ImpactFinding(BaseModel):
    usage: CodeUsage
    matched_change: str
    evidence_url: str
    evidence_excerpt: str = ""
    confidence: str


class SourceReference(BaseModel):
    kind: str
    url: str


class UpgradeReport(BaseModel):
    package: str
    current_version: str
    target_version: str
    ecosystem: Ecosystem
    verdict: Verdict
    executive_summary: str
    releases: list[ReleaseEvidence]
    vulnerabilities: list[VulnerabilityEvidence]
    code_usages: list[CodeUsage]
    impacted_usages: list[ImpactFinding]
    recommendations: list[str]
    verification_steps: list[str]
    evidence_gaps: list[str]
    sources: list[SourceReference]
    stats: dict[str, int]

