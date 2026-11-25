"""MCP server exposing the complete upgrade-analysis workflow as one tool."""

from __future__ import annotations

import json

from .graph import UpgradeAnalyzer
from .models import UpgradeRequest


def main() -> None:
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise SystemExit("Install the MCP extra first: pip install -e '.[mcp]'") from exc

    server = FastMCP("dependency-intelligence")
    analyzer = UpgradeAnalyzer()

    @server.tool()
    async def analyze_dependency_upgrade(
        package: str,
        current_version: str,
        target_version: str,
        project_path: str,
        ecosystem: str = "PyPI",
        github_repo: str = "",
    ) -> str:
        """Analyze an upgrade using registry, GitHub, OSV, and local code evidence."""
        request = UpgradeRequest(
            package=package,
            current_version=current_version,
            target_version=target_version,
            project_path=project_path,
            ecosystem=ecosystem,
            github_repo=github_repo or None,
        )
        report = await analyzer.analyze(request)
        return json.dumps(report.model_dump(mode="json"), ensure_ascii=False, indent=2)

    server.run(transport="stdio")


if __name__ == "__main__":
    main()

