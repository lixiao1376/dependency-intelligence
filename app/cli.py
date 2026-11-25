"""Command-line entry point."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from pydantic import ValidationError

from .graph import UpgradeAnalyzer
from .models import Ecosystem, UpgradeRequest
from .reporting import render_markdown


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description="Analyze the impact of a dependency upgrade.")
    command.add_argument("package")
    command.add_argument("current_version")
    command.add_argument("target_version")
    command.add_argument("project_path")
    command.add_argument("--ecosystem", choices=[item.value for item in Ecosystem], default=Ecosystem.PYPI.value)
    command.add_argument("--github-repo", help="Override repository as owner/repo")
    command.add_argument("--import-name", action="append", default=[], help="Import/module name; may be repeated")
    command.add_argument("--use-llm", action="store_true", help="Use OpenAI for the final summary")
    command.add_argument("--format", choices=["markdown", "json"], default="markdown")
    return command


async def _run(arguments: argparse.Namespace) -> int:
    try:
        request = UpgradeRequest(
            package=arguments.package,
            current_version=arguments.current_version,
            target_version=arguments.target_version,
            project_path=arguments.project_path,
            ecosystem=arguments.ecosystem,
            github_repo=arguments.github_repo,
            import_names=arguments.import_name,
            use_llm=arguments.use_llm,
        )
        report = await UpgradeAnalyzer().analyze(request)
    except (ValidationError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if arguments.format == "json":
        print(json.dumps(report.model_dump(mode="json"), ensure_ascii=False, indent=2))
    else:
        print(render_markdown(report), end="")
    return 0


def main() -> None:
    raise SystemExit(asyncio.run(_run(parser().parse_args())))


if __name__ == "__main__":
    main()

