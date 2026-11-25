from app.models import (
    CodeUsage,
    Ecosystem,
    PackageInfo,
    ReleaseEvidence,
    SourceReference,
    Verdict,
    VulnerabilityEvidence,
)
from app.reporting import build_report, correlate_impacts, render_markdown


def package():
    return PackageInfo(
        package="pydantic",
        ecosystem=Ecosystem.PYPI,
        current_version="1.10.13",
        target_version="2.0.0",
        latest_version="2.0.0",
        repository="pydantic/pydantic",
        import_names=["pydantic"],
        source_url="https://pypi.org/pypi/pydantic/json",
    )


def test_exact_changed_symbol_is_correlated_to_source_usage():
    usage = CodeUsage(file="app.py", line=8, symbol="pydantic.validator", snippet="@validator('x')", language="python")
    release = ReleaseEvidence(
        version="2.0.0",
        title="2.0",
        url="https://example.test/release",
        changed_symbols=["validator"],
        signals=["deprecated"],
    )

    findings = correlate_impacts([usage], [release])

    assert len(findings) == 1
    assert findings[0].usage.file == "app.py"


def test_report_becomes_risky_and_preserves_sources():
    usage = CodeUsage(file="app.py", line=8, symbol="pydantic.validator", snippet="@validator('x')", language="python")
    release = ReleaseEvidence(
        version="2.0.0",
        title="2.0",
        url="https://example.test/release",
        changed_symbols=["validator"],
        signals=["breaking"],
    )
    vulnerability = VulnerabilityEvidence(
        id="PYSEC-1",
        summary="Example",
        affects_target=False,
        url="https://osv.dev/vulnerability/PYSEC-1",
    )
    report = build_report(
        package(),
        [release],
        [vulnerability],
        [usage],
        [],
        [SourceReference(kind="release", url=release.url)],
    )

    assert report.verdict == Verdict.RISKY
    assert report.stats["impacted_usages_found"] == 1
    assert "app.py:8" in render_markdown(report)

