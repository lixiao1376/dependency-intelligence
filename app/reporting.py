"""Deterministic impact correlation and report rendering."""

from __future__ import annotations

import re

from .models import (
    CodeUsage,
    ImpactFinding,
    PackageInfo,
    ReleaseEvidence,
    UpgradeReport,
    Verdict,
    VulnerabilityEvidence,
)
from .versioning import parse_version


def _leaf(symbol: str) -> str:
    return symbol.lower().strip("`'").rsplit(".", 1)[-1]


def correlate_impacts(usages: list[CodeUsage], releases: list[ReleaseEvidence]) -> list[ImpactFinding]:
    findings: list[ImpactFinding] = []
    seen: set[tuple[str, int, str]] = set()
    for release in releases:
        # Prefer the shortest canonical spelling and collapse fully-qualified aliases
        # such as ``pydantic.class_validators.validator`` and ``validator``.
        for changed in sorted(release.changed_symbols, key=len):
            changed_leaf = _leaf(changed)
            if len(changed_leaf) < 3:
                continue
            for usage in usages:
                usage_leaf = _leaf(usage.symbol)
                if usage_leaf == changed_leaf or usage.symbol.lower().endswith(changed.lower()):
                    key = (usage.file, usage.line, changed_leaf)
                    if key not in seen:
                        seen.add(key)
                        exact_symbol = re.compile(rf"`@?{re.escape(changed_leaf)}`", re.IGNORECASE)
                        matching_excerpts = [
                            excerpt for excerpt in release.excerpts if exact_symbol.search(excerpt)
                        ]
                        guidance_terms = ("replaced", "use ", "renamed", "deprecated", "removed")
                        matching_excerpts.sort(
                            key=lambda excerpt: (
                                next(
                                    (index for index, term in enumerate(guidance_terms) if term in excerpt.lower()),
                                    len(guidance_terms),
                                ),
                                len(excerpt),
                            )
                        )
                        findings.append(
                            ImpactFinding(
                                usage=usage,
                                matched_change=changed,
                                evidence_url=release.url,
                                evidence_excerpt=matching_excerpts[0] if matching_excerpts else "",
                                confidence="high" if usage_leaf == changed_leaf else "medium",
                            )
                        )
    return findings


def _is_major_upgrade(package: PackageInfo) -> bool:
    current = parse_version(package.current_version)
    target = parse_version(package.target_version)
    return bool(current and target and current.major != target.major)


def build_report(
    package: PackageInfo,
    releases: list[ReleaseEvidence],
    vulnerabilities: list[VulnerabilityEvidence],
    usages: list[CodeUsage],
    gaps: list[str],
    sources,
) -> UpgradeReport:
    impacts = correlate_impacts(usages, releases)
    signals = {signal for release in releases for signal in release.signals}
    unresolved_vulnerabilities = [item for item in vulnerabilities if item.affects_target]
    fixed_vulnerabilities = [item for item in vulnerabilities if not item.affects_target]
    major = _is_major_upgrade(package)

    if unresolved_vulnerabilities or impacts or ("breaking" in signals and usages):
        verdict = Verdict.RISKY
    elif signals or vulnerabilities or major or gaps:
        verdict = Verdict.REVIEW
    else:
        verdict = Verdict.SAFE

    summary_parts = [f"Analyzed {package.package} {package.current_version} → {package.target_version}."]
    if impacts:
        summary_parts.append(f"Found {len(impacts)} source location(s) matching documented changed symbols.")
    elif usages:
        summary_parts.append(f"Found {len(usages)} package usage(s), but none matched an explicitly named changed symbol.")
    else:
        summary_parts.append("No package usages were found in the scanned source files.")
    if fixed_vulnerabilities:
        summary_parts.append(f"The target no longer matches {len(fixed_vulnerabilities)} vulnerability record(s) affecting the current version.")
    if unresolved_vulnerabilities:
        summary_parts.append(f"Warning: {len(unresolved_vulnerabilities)} vulnerability record(s) also affect the target.")

    recommendations: list[str] = []
    for impact in impacts[:20]:
        recommendations.append(
            f"Review {impact.usage.file}:{impact.usage.line}; `{impact.usage.symbol}` matches the documented change `{impact.matched_change}`."
        )
        if impact.evidence_excerpt:
            recommendations.append(f"Documented migration guidance: {impact.evidence_excerpt}")
    if major:
        recommendations.append("Upgrade in a dedicated branch because this crosses a major-version boundary.")
    if fixed_vulnerabilities:
        ids = ", ".join(item.id for item in fixed_vulnerabilities[:5])
        recommendations.append(f"Prioritize the upgrade because it removes exposure to: {ids}.")
    if unresolved_vulnerabilities:
        ids = ", ".join(item.id for item in unresolved_vulnerabilities[:5])
        recommendations.append(f"Choose a different target or apply mitigations; the target is still affected by: {ids}.")
    if not recommendations:
        recommendations.append("Upgrade in a branch, regenerate the lockfile, and review the dependency diff.")

    languages = {usage.language for usage in usages}
    verification = [
        "Install the target version in an isolated branch or environment and regenerate the lockfile.",
        "Run the project's complete automated test suite before merging.",
    ]
    if "python" in languages:
        verification.append("Run static type checks and import the application to catch removed Python symbols.")
    if "javascript" in languages:
        verification.append("Run TypeScript type-checking and the production build to catch changed exports.")
    if impacts:
        verification.append("Add or run focused tests covering every file listed under impacted usages.")

    return UpgradeReport(
        package=package.package,
        current_version=package.current_version,
        target_version=package.target_version,
        ecosystem=package.ecosystem,
        verdict=verdict,
        executive_summary=" ".join(summary_parts),
        releases=releases,
        vulnerabilities=vulnerabilities,
        code_usages=usages,
        impacted_usages=impacts,
        recommendations=recommendations,
        verification_steps=verification,
        evidence_gaps=list(dict.fromkeys(gaps)),
        sources=sources,
        stats={
            "releases_checked": len(releases),
            "vulnerabilities_found": len(vulnerabilities),
            "code_usages_found": len(usages),
            "impacted_usages_found": len(impacts),
        },
    )


def render_markdown(report: UpgradeReport) -> str:
    lines = [
        f"# Upgrade report: {report.package}",
        "",
        f"**Version:** {report.current_version} → {report.target_version}",
        f"**Verdict:** {report.verdict.value}",
        "",
        report.executive_summary,
        "",
        "## Impacted code",
    ]
    if report.impacted_usages:
        for finding in report.impacted_usages:
            usage = finding.usage
            lines.append(
                f"- `{usage.file}:{usage.line}` — `{usage.symbol}` matches `{finding.matched_change}` ([evidence]({finding.evidence_url}))"
            )
            if finding.evidence_excerpt:
                lines.append(f"  - Evidence: {finding.evidence_excerpt}")
    else:
        lines.append("- No exact documented-symbol matches found.")
    lines.extend(["", "## Recommendations"])
    lines.extend(f"- {item}" for item in report.recommendations)
    lines.extend(["", "## Verification"])
    lines.extend(f"- {item}" for item in report.verification_steps)
    if report.evidence_gaps:
        lines.extend(["", "## Evidence gaps"])
        lines.extend(f"- {item}" for item in report.evidence_gaps)
    lines.extend(["", "## Sources"])
    lines.extend(f"- [{item.kind}]({item.url})" for item in report.sources)
    return "\n".join(lines) + "\n"

