"""FastAPI surface for upgrade analysis."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException

from . import __version__
from .graph import UpgradeAnalyzer
from .models import UpgradeReport, UpgradeRequest


app = FastAPI(
    title="Dependency Intelligence Agent",
    version=__version__,
    description="Evidence-grounded dependency upgrade impact analysis.",
)
analyzer = UpgradeAnalyzer()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.post("/v1/upgrades/analyze", response_model=UpgradeReport)
async def analyze_upgrade(request: UpgradeRequest) -> UpgradeReport:
    try:
        return await analyzer.analyze(request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Evidence collection failed: {exc}") from exc

