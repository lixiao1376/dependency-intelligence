from app.graph import UpgradeAnalyzer
from app.models import (
    Ecosystem,
    PackageInfo,
    ReleaseEvidence,
    SourceReference,
    UpgradeRequest,
    VulnerabilityEvidence,
)


class FakeGateway:
    def __init__(self):
        self.broaden_calls = []

    async def resolve_package(self, request):
        return PackageInfo(
            package=request.package,
            ecosystem=Ecosystem.PYPI,
            current_version="1.0.0",
            target_version="2.0.0",
            latest_version="2.0.0",
            repository="example/demo",
            import_names=["demo"],
            source_url="https://registry.test/demo",
        )

    async def github_releases(self, package, broaden=False):
        self.broaden_calls.append(broaden)
        if not broaden:
            return [], ["No release notes."]
        return [
            ReleaseEvidence(
                version="2.0.0",
                title="Demo 2",
                url="https://github.test/example/demo/releases/2",
                excerpts=["Breaking: `old_api` was removed."],
                changed_symbols=["old_api"],
                signals=["breaking", "removed"],
            )
        ], ["Used comparison fallback."]

    async def osv_vulnerabilities(self, package):
        return [
            VulnerabilityEvidence(
                id="OSV-TEST",
                summary="Fixed issue",
                affects_target=False,
                url="https://osv.dev/OSV-TEST",
            )
        ], []

    @staticmethod
    def sources(package, releases, vulnerabilities):
        return [SourceReference(kind="registry", url=package.source_url)]


async def test_graph_retries_evidence_and_matches_source(tmp_path):
    (tmp_path / "main.py").write_text("from demo import old_api\nold_api()\n", encoding="utf-8")
    gateway = FakeGateway()
    analyzer = UpgradeAnalyzer(gateway=gateway)
    request = UpgradeRequest(
        package="demo",
        current_version="1.0.0",
        target_version="2.0.0",
        project_path=str(tmp_path),
    )

    report = await analyzer.analyze(request)

    assert gateway.broaden_calls == [False, True]
    assert report.impacted_usages[0].usage.file == "main.py"
    assert report.vulnerabilities[0].id == "OSV-TEST"

