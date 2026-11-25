"""Optional OpenAI summary enhancement that is constrained to collected evidence."""

from __future__ import annotations

import json

import httpx

from .config import Settings, settings
from .models import UpgradeReport


async def enhance_summary(report: UpgradeReport, app_settings: Settings = settings) -> str:
    if not app_settings.openai_api_key:
        raise RuntimeError("use_llm=true requires OPENAI_API_KEY")
    evidence = {
        "package": report.package,
        "current": report.current_version,
        "target": report.target_version,
        "verdict": report.verdict.value,
        "release_excerpts": [
            {"version": item.version, "excerpts": item.excerpts, "url": item.url}
            for item in report.releases
        ],
        "vulnerabilities": [item.model_dump() for item in report.vulnerabilities],
        "impacted_usages": [item.model_dump() for item in report.impacted_usages],
        "evidence_gaps": report.evidence_gaps,
    }
    prompt = (
        "Write a concise dependency-upgrade executive summary in the same language as the package notes when clear, "
        "otherwise English. Use only the supplied JSON evidence. Do not invent API changes. Mention uncertainty. "
        "Return plain text under 120 words.\n\n" + json.dumps(evidence, ensure_ascii=False)
    )
    async with httpx.AsyncClient(timeout=app_settings.request_timeout_seconds) as client:
        response = await client.post(
            "https://api.openai.com/v1/responses",
            headers={"Authorization": f"Bearer {app_settings.openai_api_key}"},
            json={"model": app_settings.openai_model, "input": prompt},
        )
        response.raise_for_status()
        payload = response.json()
    if payload.get("output_text"):
        return str(payload["output_text"]).strip()
    chunks = []
    for output in payload.get("output", []):
        for content in output.get("content", []):
            if content.get("type") == "output_text":
                chunks.append(str(content.get("text", "")))
    if not chunks:
        raise RuntimeError("OpenAI returned no output text")
    return "\n".join(chunks).strip()

