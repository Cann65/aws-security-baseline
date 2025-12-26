from __future__ import annotations
from typing import Any, Dict, List


def _badge(status: str) -> str:
    return {"PASS": "✅ PASS", "WARN": "⚠️ WARN", "FAIL": "❌ FAIL"}.get(status, status)


def render_markdown(data: Dict[str, Any]) -> str:
    meta = data.get("meta", {})
    summary = data.get("summary", {})
    findings: List[Dict[str, Any]] = data.get("findings", [])

    lines: List[str] = []
    lines.append("# AWS Security Baseline Audit Report")
    lines.append("")
    lines.append("## Metadata")
    lines.append(f"- Profile: `{meta.get('profile','')}`")
    lines.append(f"- Region: `{meta.get('region','')}`")
    lines.append(f"- Generated (UTC): `{meta.get('generated_at_utc','')}`")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- PASS: **{summary.get('pass',0)}**")
    lines.append(f"- WARN: **{summary.get('warn',0)}**")
    lines.append(f"- FAIL: **{summary.get('fail',0)}**")
    lines.append("")
    lines.append("## Findings")
    lines.append("")

    for f in findings:
        lines.append(f"### {_badge(f.get('status'))} — {f.get('title')}")
        lines.append(f"- ID: `{f.get('id')}`")
        lines.append(f"- Details: {f.get('details')}")
        ev = f.get("evidence", {})
        if ev:
            lines.append("")
            lines.append("Evidence:")
            lines.append("```json")
            import json
            lines.append(json.dumps(ev, indent=2, ensure_ascii=False))
            lines.append("```")
        lines.append("")

    return "\n".join(lines)
