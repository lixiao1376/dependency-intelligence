"""Registry, GitHub, and OSV evidence collection."""

from __future__ import annotations

import base64
import re
from typing import Any
from urllib.parse import quote

import httpx

from .config import Settings, settings
from .models import (
    Ecosystem,
    PackageInfo,
    ReleaseEvidence,
    SourceReference,
    UpgradeRequest,
    VulnerabilityEvidence,
)
from .versioning import in_upgrade_range, parse_version, stable_versions


GITHUB_REPO = re.compile(r"github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?(?:[/#?]|$)", re.I)
SIGNALS = {
    "breaking": ("breaking", "backward incompatible", "migration required"),
    "removed": ("removed", "no longer supports", "dropped support"),
    "deprecated": ("deprecated", "deprecation", "will be removed"),
    "renamed": ("renamed", "replaced by", "use instead"),
    "security": ("security", "vulnerability", "cve-"),
}
CHANGE_TERMS = tuple(term for terms in SIGNALS.values() for term in terms)
CODE_SYMBOL = re.compile(r"`@?([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)`")


def _github_repo(urls: list[str]) -> str | None:
    for url in urls:
        if match := GITHUB_REPO.search(url or ""):
            return f"{match.group(1)}/{match.group(2)}".removesuffix(".git")
    return None


def _change_excerpts(body: str, limit: int = 12) -> tuple[list[str], list[str], list[str]]:
    excerpts: list[str] = []
    signals: set[str] = set()
    symbols: set[str] = set()
    for raw in body.splitlines():
        line = re.sub(r"\s+", " ", raw.strip(" -*#\t"))
        lowered = line.lower()
        matched = [name for name, terms in SIGNALS.items() if any(term in lowered for term in terms)]
        if line and matched:
            excerpts.append(line[:500])
            signals.update(matched)
            symbols.update(CODE_SYMBOL.findall(line))
        if len(excerpts) >= limit:
            break
    return excerpts, sorted(symbols), sorted(signals)


class EvidenceGateway:
    """Async gateway with explicit, traceable public data sources."""

    def __init__(self, app_settings: Settings = settings, client: httpx.AsyncClient | None = None):
        self.settings = app_settings
        self._external_client = client

    def _client(self) -> httpx.AsyncClient:
        headers = {"User-Agent": "dependency-intelligence-agent/0.1"}
        if self.settings.github_token:
            headers["Authorization"] = f"Bearer {self.settings.github_token}"
        return self._external_client or httpx.AsyncClient(
            timeout=self.settings.request_timeout_seconds,
            follow_redirects=True,
            headers=headers,
        )

    async def resolve_package(self, request: UpgradeRequest) -> PackageInfo:
        client = self._client()
        close = self._external_client is None
        try:
            if request.ecosystem == Ecosystem.PYPI:
                url = f"https://pypi.org/pypi/{quote(request.package, safe='')}/json"
                response = await client.get(url)
                response.raise_for_status()
                payload = response.json()
                versions = stable_versions(list(payload.get("releases", {})))
                if not versions:
                    raise ValueError(f"PyPI returned no stable versions for {request.package}")
                latest = str(versions[-1])
                target = latest if request.target_version.lower() == "latest" else request.target_version
                if parse_version(target) not in versions:
                    raise ValueError(f"target version {target} was not found on PyPI")
                info = payload.get("info", {})
                project_urls = list((info.get("project_urls") or {}).values())
                project_urls.extend([info.get("home_page") or "", info.get("project_url") or ""])
                repository = request.github_repo or _github_repo(project_urls)
                imports = request.import_names or [request.package.replace("-", "_")]
            else:
                encoded = quote(request.package, safe="@")
                url = f"https://registry.npmjs.org/{encoded}"
                response = await client.get(url)
                response.raise_for_status()
                payload = response.json()
                versions = stable_versions(list(payload.get("versions", {})))
                if not versions:
                    raise ValueError(f"npm returned no stable versions for {request.package}")
                latest = str(versions[-1])
                target = latest if request.target_version.lower() == "latest" else request.target_version
                if parse_version(target) not in versions:
                    raise ValueError(f"target version {target} was not found on npm")
                repository_data = payload.get("repository") or {}
                repository_url = repository_data.get("url", "") if isinstance(repository_data, dict) else str(repository_data)
                repository = request.github_repo or _github_repo([repository_url, payload.get("homepage", "")])
                imports = request.import_names or [request.package]
            current = parse_version(request.current_version)
            resolved_target = parse_version(target)
            if not current or not resolved_target:
                raise ValueError("current and target must be valid versions")
            if resolved_target <= current:
                raise ValueError(f"target version {resolved_target} must be newer than current version {current}")
            return PackageInfo(
                package=request.package,
                ecosystem=request.ecosystem,
                current_version=str(current),
                target_version=str(resolved_target),
                latest_version=latest,
                repository=repository,
                import_names=imports,
                source_url=url,
            )
        finally:
            if close:
                await client.aclose()

    async def github_releases(self, package: PackageInfo, broaden: bool = False) -> tuple[list[ReleaseEvidence], list[str]]:
        if not package.repository:
            return [], ["Package metadata did not identify a GitHub repository."]
        client = self._client()
        close = self._external_client is None
        gaps: list[str] = []
        try:
            url = f"https://api.github.com/repos/{package.repository}/releases?per_page=100"
            response = await client.get(url)
            response.raise_for_status()
            payload = response.json()
            releases: list[ReleaseEvidence] = []
            for item in payload if isinstance(payload, list) else []:
                if item.get("draft") or item.get("prerelease"):
                    continue
                tag = str(item.get("tag_name") or item.get("name") or "")
                version = parse_version(tag)
                if not version or not in_upgrade_range(str(version), package.current_version, package.target_version):
                    continue
                excerpts, symbols, signals = _change_excerpts(str(item.get("body") or ""))
                releases.append(
                    ReleaseEvidence(
                        version=str(version),
                        title=str(item.get("name") or tag),
                        published_at=item.get("published_at"),
                        url=str(item.get("html_url") or url),
                        excerpts=excerpts,
                        changed_symbols=symbols,
                        signals=signals,
                    )
                )
            releases.sort(key=lambda item: parse_version(item.version) or parse_version("0.0.0"))
            if releases and not broaden:
                return releases, gaps
            if not releases and not broaden:
                return [], ["No GitHub release notes covered the requested version range."]

            # A package can publish many GitHub releases without publishing a release for the
            # major target itself. On the validation retry, discover versioned migration guides
            # from the repository tree before falling back to commit messages.
            target = parse_version(package.target_version)
            refs = [f"v{package.target_version}", package.target_version]
            if target:
                refs.extend([f"v{target.major}.{target.minor}", f"{target.major}.{target.minor}"])
            migration_evidence: list[ReleaseEvidence] = []
            for ref in dict.fromkeys(refs):
                # Try conventional locations first. This is faster and avoids downloading a
                # large recursive Git tree for repositories that keep a standard migration file.
                conventional_paths = (
                    "docs/migration.md",
                    "docs/migration.rst",
                    "MIGRATION.md",
                    "MIGRATING.md",
                    "UPGRADING.md",
                    "docs/upgrade.md",
                )
                for path in conventional_paths:
                    contents_url = (
                        f"https://api.github.com/repos/{package.repository}/contents/"
                        f"{quote(path, safe='/')}?ref={quote(ref, safe='')}"
                    )
                    contents_response = await client.get(contents_url)
                    if contents_response.status_code != 200:
                        continue
                    contents_payload = contents_response.json()
                    encoded = str(contents_payload.get("content") or "").replace("\n", "")
                    if not encoded:
                        continue
                    try:
                        document = base64.b64decode(encoded).decode("utf-8")
                    except (ValueError, UnicodeDecodeError):
                        continue
                    excerpts, symbols, signals = _change_excerpts(document, limit=80)
                    if excerpts:
                        migration_evidence.append(
                            ReleaseEvidence(
                                version=package.target_version,
                                title=f"Migration guide: {path}",
                                url=f"https://github.com/{package.repository}/blob/{ref}/{path}",
                                excerpts=excerpts,
                                changed_symbols=symbols,
                                signals=signals,
                            )
                        )
                        break
                if migration_evidence:
                    gaps.append("A versioned repository migration guide was used to supplement GitHub Releases.")
                    return [*releases, *migration_evidence], gaps

                tree_url = f"https://api.github.com/repos/{package.repository}/git/trees/{quote(ref, safe='')}?recursive=1"
                tree_response = await client.get(tree_url)
                if tree_response.status_code == 404:
                    continue
                tree_response.raise_for_status()
                paths = []
                for entry in tree_response.json().get("tree", []):
                    path = str(entry.get("path") or "")
                    lowered = path.lower()
                    filename = lowered.rsplit("/", 1)[-1]
                    if (
                        entry.get("type") == "blob"
                        and lowered.endswith((".md", ".rst", ".txt"))
                        and any(term in filename for term in ("migration", "migrating", "upgrade", "breaking"))
                    ):
                        paths.append(path)
                for path in paths[:5]:
                    raw_url = f"https://raw.githubusercontent.com/{package.repository}/{quote(ref, safe='')}/{quote(path, safe='/')}"
                    raw_response = await client.get(raw_url)
                    if raw_response.status_code != 200:
                        continue
                    excerpts, symbols, signals = _change_excerpts(raw_response.text, limit=80)
                    if excerpts:
                        migration_evidence.append(
                            ReleaseEvidence(
                                version=package.target_version,
                                title=f"Migration guide: {path}",
                                url=f"https://github.com/{package.repository}/blob/{ref}/{path}",
                                excerpts=excerpts,
                                changed_symbols=symbols,
                                signals=signals,
                            )
                        )
                if migration_evidence:
                    gaps.append("A versioned repository migration guide was used to supplement GitHub Releases.")
                    return [*releases, *migration_evidence], gaps

            compare_url = (
                f"https://api.github.com/repos/{package.repository}/compare/"
                f"v{package.current_version}...v{package.target_version}"
            )
            compare = await client.get(compare_url)
            if compare.status_code == 404:
                compare_url = (
                    f"https://api.github.com/repos/{package.repository}/compare/"
                    f"{package.current_version}...{package.target_version}"
                )
                compare = await client.get(compare_url)
            compare.raise_for_status()
            data = compare.json()
            messages = [str(commit.get("commit", {}).get("message", "")).splitlines()[0] for commit in data.get("commits", [])]
            body = "\n".join(messages)
            excerpts, symbols, signals = _change_excerpts(body)
            gaps.append("GitHub had no matching releases; commit comparison was used as fallback evidence.")
            return [*releases,
                ReleaseEvidence(
                    version=package.target_version,
                    title=f"Git comparison {package.current_version}...{package.target_version}",
                    url=str(data.get("html_url") or compare_url),
                    excerpts=excerpts or messages[:12],
                    changed_symbols=symbols,
                    signals=signals,
                )
            ], gaps
        except (httpx.HTTPError, ValueError) as exc:
            preserved = locals().get("releases", [])
            return preserved, [f"GitHub evidence could not be fully collected: {type(exc).__name__}: {exc!r}"]
        finally:
            if close:
                await client.aclose()

    async def osv_vulnerabilities(self, package: PackageInfo) -> tuple[list[VulnerabilityEvidence], list[str]]:
        client = self._client()
        close = self._external_client is None
        url = "https://api.osv.dev/v1/query"
        try:
            async def query(version: str) -> dict[str, Any]:
                response = await client.post(
                    url,
                    json={"package": {"name": package.package, "ecosystem": package.ecosystem.value}, "version": version},
                )
                response.raise_for_status()
                return response.json()

            current_payload = await query(package.current_version)
            target_payload = await query(package.target_version)
            target_ids = {item.get("id") for item in target_payload.get("vulns", [])}
            results: list[VulnerabilityEvidence] = []
            for item in current_payload.get("vulns", []):
                vuln_id = str(item.get("id") or "unknown")
                fixed_versions: set[str] = set()
                for affected in item.get("affected", []):
                    for version_range in affected.get("ranges", []):
                        for event in version_range.get("events", []):
                            if event.get("fixed"):
                                fixed_versions.add(str(event["fixed"]))
                severity_entries = item.get("severity") or []
                severity = str(severity_entries[0].get("score", "unknown")) if severity_entries else str(item.get("database_specific", {}).get("severity", "unknown"))
                results.append(
                    VulnerabilityEvidence(
                        id=vuln_id,
                        summary=str(item.get("summary") or item.get("details") or "No summary provided")[:500],
                        aliases=[str(alias) for alias in item.get("aliases", [])],
                        severity=severity,
                        fixed_versions=sorted(fixed_versions),
                        affects_target=vuln_id in target_ids,
                        url=f"https://osv.dev/vulnerability/{vuln_id}",
                    )
                )
            return results, []
        except (httpx.HTTPError, ValueError) as exc:
            return [], [f"OSV evidence could not be collected: {exc}"]
        finally:
            if close:
                await client.aclose()

    @staticmethod
    def sources(package: PackageInfo, releases: list[ReleaseEvidence], vulnerabilities: list[VulnerabilityEvidence]) -> list[SourceReference]:
        sources = [SourceReference(kind="registry", url=package.source_url)]
        sources.extend(SourceReference(kind="release", url=item.url) for item in releases)
        sources.extend(SourceReference(kind="vulnerability", url=item.url) for item in vulnerabilities)
        unique: dict[str, SourceReference] = {item.url: item for item in sources}
        return list(unique.values())

