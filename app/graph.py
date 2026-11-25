"""LangGraph workflow for evidence collection, source scanning, validation, and reporting."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from .code_scanner import scan_project
from .config import Settings, settings
from .evidence import EvidenceGateway
from .llm import enhance_summary
from .models import (
    CodeUsage,
    PackageInfo,
    ReleaseEvidence,
    SourceReference,
    UpgradeReport,
    UpgradeRequest,
    VulnerabilityEvidence,
)
from .reporting import build_report
from .reporting import correlate_impacts


class UpgradeState(TypedDict, total=False):
    request: UpgradeRequest
    package: PackageInfo
    releases: list[ReleaseEvidence]
    vulnerabilities: list[VulnerabilityEvidence]
    usages: list[CodeUsage]
    gaps: list[str]
    sources: list[SourceReference]
    retry_count: int
    needs_retry: bool
    report: UpgradeReport


class UpgradeAnalyzer:
    def __init__(self, gateway: EvidenceGateway | None = None, app_settings: Settings = settings):
        self.gateway = gateway or EvidenceGateway(app_settings)
        self.settings = app_settings
        self.graph = self._build_graph()

    def _check_allowed_path(self, path: str) -> None:
        if not self.settings.allowed_project_root:
            return
        allowed = Path(self.settings.allowed_project_root).expanduser().resolve()
        requested = Path(path).resolve()
        if not requested.is_relative_to(allowed):
            raise ValueError(f"project_path must be inside ALLOWED_PROJECT_ROOT ({allowed})")

    async def _resolve(self, state: UpgradeState) -> dict[str, Any]:
        self._check_allowed_path(state["request"].project_path)
        package = await self.gateway.resolve_package(state["request"])
        return {"package": package, "retry_count": 0, "gaps": []}

    async def _collect(self, state: UpgradeState, broaden: bool = False) -> dict[str, Any]:
        releases_result, osv_result = await asyncio.gather(
            self.gateway.github_releases(state["package"], broaden=broaden),
            self.gateway.osv_vulnerabilities(state["package"]),
        )
        releases, release_gaps = releases_result
        vulnerabilities, osv_gaps = osv_result
        gaps = [*release_gaps, *osv_gaps]
        sources = self.gateway.sources(state["package"], releases, vulnerabilities)
        return {
            "releases": releases,
            "vulnerabilities": vulnerabilities,
            "gaps": gaps,
            "sources": sources,
            "retry_count": state.get("retry_count", 0) + (1 if broaden else 0),
        }

    async def _scan(self, state: UpgradeState) -> dict[str, Any]:
        request, package = state["request"], state["package"]
        usages = await asyncio.to_thread(
            scan_project,
            request.project_path,
            package.import_names,
            package.package,
            self.settings.max_source_files,
        )
        return {"usages": usages}

    async def _validate(self, state: UpgradeState) -> dict[str, Any]:
        releases = state.get("releases", [])
        has_target_evidence = any(item.version == state["package"].target_version for item in releases)
        has_exact_impact = bool(correlate_impacts(state.get("usages", []), releases))
        needs_more_detail = bool(state.get("usages")) and not has_exact_impact
        needs_retry = (
            state.get("retry_count", 0) < 1
            and bool(state["package"].repository)
            and (not releases or not has_target_evidence or needs_more_detail)
        )
        return {"needs_retry": needs_retry}

    async def _retry(self, state: UpgradeState) -> dict[str, Any]:
        return await self._collect(state, broaden=True)

    async def _report(self, state: UpgradeState) -> dict[str, Any]:
        report = build_report(
            package=state["package"],
            releases=state.get("releases", []),
            vulnerabilities=state.get("vulnerabilities", []),
            usages=state.get("usages", []),
            gaps=state.get("gaps", []),
            sources=state.get("sources", []),
        )
        if state["request"].use_llm:
            try:
                summary = await enhance_summary(report, self.settings)
                report = report.model_copy(update={"executive_summary": summary})
            except Exception as exc:
                report = report.model_copy(
                    update={"evidence_gaps": [*report.evidence_gaps, f"Optional LLM summary failed: {exc}"]}
                )
        return {"report": report}

    @staticmethod
    def _route_validation(state: UpgradeState) -> str:
        return "retry" if state.get("needs_retry") else "report"

    def _build_graph(self):
        builder = StateGraph(UpgradeState)
        builder.add_node("resolve_package", self._resolve)
        builder.add_node("collect_evidence", self._collect)
        builder.add_node("scan_project", self._scan)
        builder.add_node("validate_evidence", self._validate)
        builder.add_node("retry_evidence", self._retry)
        builder.add_node("build_report", self._report)
        builder.add_edge(START, "resolve_package")
        builder.add_edge("resolve_package", "collect_evidence")
        builder.add_edge("collect_evidence", "scan_project")
        builder.add_edge("scan_project", "validate_evidence")
        builder.add_conditional_edges(
            "validate_evidence",
            self._route_validation,
            {"retry": "retry_evidence", "report": "build_report"},
        )
        builder.add_edge("retry_evidence", "build_report")
        builder.add_edge("build_report", END)
        return builder.compile()

    async def analyze(self, request: UpgradeRequest) -> UpgradeReport:
        result = await self.graph.ainvoke({"request": request})
        return result["report"]

