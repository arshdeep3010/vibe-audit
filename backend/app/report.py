"""Render a ScanResult as Markdown or a standalone, self-contained HTML report."""
from __future__ import annotations

import html

from app.models.findings import Finding, ScanResult


def _origin(f: Finding) -> str:
    """Which tool(s) reported a finding, e.g. "semgrep js-sql-built-from-strings" or "model + semgrep"."""
    if f.source.value == "llm":
        return " + ".join(["model", *f.corroborated_by])
    return f"{f.source.value} {f.rule_id}".strip() if f.rule_id else f.source.value

_SEV_BORDER = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#0284c7",
    "info": "#64748b",
}


def to_markdown(res: ScanResult) -> str:
    out: list[str] = []
    add = out.append
    add(f"# VibeAudit report — {res.input.name}")
    add("")
    add(f"- **Grade:** {res.risk_grade}  (risk {res.risk_score}/100)")
    add(f"- **Status:** {res.status}")
    add(f"- **Input:** {res.input.kind} — {res.input.detail or res.input.name}")
    if res.input.commit:
        add(f"- **Commit:** {res.input.commit}")
    c = res.counts or {}
    if c:
        add(f"- **Findings:** {c.get('total', 0)}  —  {c.get('by_severity', {})}")
    if res.triage and (res.triage.app_type or res.triage.frameworks):
        add("")
        add(f"**App type:** {res.triage.app_type or 'unknown'}")
        if res.triage.frameworks:
            add(f"**Frameworks:** {', '.join(res.triage.frameworks)}")
    add("")
    add("---")
    add("")

    if not res.findings:
        add("_No findings._")

    for f in res.findings:
        loc = f":{f.line_start}" if f.line_start else ""
        add(f"## [{f.severity.value.upper()}] {f.title}")
        meta = f"`{f.category.value}` · `{f.file}{loc}` · confidence {int(f.confidence * 100)}%"
        if f.cwe:
            meta += f" · {f.cwe}"
        meta += f" · found by {_origin(f)}"
        if f.verdict.value in ("confirmed", "plausible"):
            meta += f" · {f.verdict.value}"
        add(meta)
        add("")
        if f.description:
            add(f"**What:** {f.description}")
        if f.impact:
            add(f"**Impact:** {f.impact}")
        if f.recommendation:
            add(f"**Fix:** {f.recommendation}")
        if f.judge_note:
            add(f"**Model's verdict:** {f.judge_note}")
        if f.code_snippet:
            add("")
            add("```")
            add(f.code_snippet)
            add("```")
        add("")
    if res.dismissed:
        add("## Scanner hits dismissed by the model")
        add("")
        for d in res.dismissed:
            loc = f":{d.line_start}" if d.line_start else ""
            add(f"- **{d.title}** · `{d.file}{loc}` · {_origin(d)} — {d.judge_note or 'dropped by verification'}")
        add("")
    return "\n".join(out)


def to_html(res: ScanResult) -> str:
    cards = []
    for f in res.findings:
        loc = f":{f.line_start}" if f.line_start else ""
        border = _SEV_BORDER.get(f.severity.value, "#64748b")
        snippet = (
            f"<pre>{html.escape(f.code_snippet)}</pre>" if f.code_snippet else ""
        )
        cwe = f"<span class='pill'>{html.escape(f.cwe)}</span>" if f.cwe else ""
        cards.append(
            f"""<div class="finding" style="border-left-color:{border}">
  <div class="row">
    <span class="sev" style="background:{border}">{f.severity.value.upper()}</span>
    <span class="pill">{f.category.value}</span>
    <span class="loc">{html.escape(f.file)}{loc}</span>
    <span class="pill">{int(f.confidence * 100)}%</span>{cwe}
    <span class="pill">{html.escape(_origin(f))}</span>
  </div>
  <h3>{html.escape(f.title)}</h3>
  {f'<p><b>What:</b> {html.escape(f.description)}</p>' if f.description else ''}
  {f'<p><b>Impact:</b> {html.escape(f.impact)}</p>' if f.impact else ''}
  {f'<p><b>Fix:</b> {html.escape(f.recommendation)}</p>' if f.recommendation else ''}
  {f"<p><b>Model's verdict:</b> {html.escape(f.judge_note)}</p>" if f.judge_note else ''}
  {snippet}
</div>"""
        )
    body = "\n".join(cards) or "<p>No findings.</p>"
    if res.dismissed:
        items = "".join(
            f"<li><b>{html.escape(d.title)}</b> · <span class='loc'>{html.escape(d.file)}"
            f"{':' + str(d.line_start) if d.line_start else ''}</span> · {html.escape(_origin(d))} — "
            f"{html.escape(d.judge_note or 'dropped by verification')}</li>"
            for d in res.dismissed
        )
        body += f"<h2>Scanner hits dismissed by the model</h2><ul>{items}</ul>"
    c = res.counts or {}
    sev = c.get("by_severity", {})
    chips = " ".join(
        f"<span class='chip'>{k}: {v}</span>" for k, v in sev.items() if v
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VibeAudit — {html.escape(res.input.name)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    max-width: 900px; margin: 0 auto; padding: 32px 20px; line-height: 1.5;
    background: #0b1020; color: #e5e7eb; }}
  h1 {{ margin: 0 0 4px; }}
  .grade {{ font-size: 44px; font-weight: 800; }}
  .meta {{ color: #9ca3af; margin-bottom: 18px; }}
  .chip, .pill {{ display: inline-block; background: #1f2937; color: #cbd5e1;
    border-radius: 999px; padding: 2px 10px; font-size: 12px; margin-right: 6px; }}
  .finding {{ background: #111827; border-left: 5px solid #64748b; border-radius: 10px;
    padding: 14px 16px; margin: 12px 0; }}
  .finding h3 {{ margin: 8px 0; }}
  .row {{ display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }}
  .sev {{ color: #fff; font-weight: 700; font-size: 11px; border-radius: 6px; padding: 2px 8px; }}
  .loc {{ font-family: ui-monospace, Menlo, Consolas, monospace; color: #93c5fd; font-size: 13px; }}
  pre {{ background: #0b1020; border: 1px solid #1f2937; border-radius: 8px; padding: 10px;
    overflow: auto; font-size: 12.5px; }}
  p {{ margin: 6px 0; }}
</style></head><body>
  <h1>VibeAudit</h1>
  <div class="grade">Grade {res.risk_grade} <span style="font-size:16px;color:#9ca3af">· risk {res.risk_score}/100</span></div>
  <div class="meta">{html.escape(res.input.name)} · {res.input.kind}{f" · {html.escape(res.input.commit)}" if res.input.commit else ""} · {c.get('total', 0)} findings</div>
  <div style="margin-bottom:18px">{chips}</div>
  {body}
</body></html>"""
