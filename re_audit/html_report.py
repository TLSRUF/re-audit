"""Render an audit report dict (from report.audit_file) as a self-contained,
dependency-free HTML page -- a readable alternative to raw JSON that can be
opened in a browser or embedded in a bug-bounty write-up.
"""
from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Any

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _severity_of(finding: str) -> str:
    for sev in _SEVERITY_ORDER:
        if finding.upper().startswith(sev):
            return sev
    return "INFO"


def _esc(value: Any) -> str:
    return html.escape(str(value))


def _findings_html(findings: list[str]) -> str:
    if not findings:
        return '<p class="muted">No heuristic findings flagged.</p>'
    rows = []
    for f in sorted(findings, key=lambda x: _SEVERITY_ORDER.index(_severity_of(x))):
        sev = _severity_of(f)
        text = f.split(":", 1)[1].strip() if ":" in f else f
        rows.append(
            f'<li class="finding sev-{sev.lower()}"><span class="badge">{_esc(sev)}</span>'
            f"<span>{_esc(text)}</span></li>"
        )
    return f'<ul class="findings-list">{"".join(rows)}</ul>'


def _mitigations_table(mitigations: dict) -> str:
    rows = []
    labels = {
        "nx": "NX / DEP",
        "pie_or_aslr": "PIE / ASLR",
        "relro": "RELRO",
        "stack_canary": "Stack canary",
        "cfg": "Control Flow Guard",
        "safe_seh": "SafeSEH",
        "signed": "Code signed",
        "stripped": "Symbols stripped",
    }
    for key, label in labels.items():
        val = mitigations.get(key)
        if val is None:
            continue
        ok = val in (True, "full")
        bad = val in (False, "none")
        cls = "ok" if ok else "bad" if bad else "warn"
        rows.append(f'<tr><td>{_esc(label)}</td><td class="status-{cls}">{_esc(val)}</td></tr>')
    if not rows:
        return '<p class="muted">Not applicable.</p>'
    return f'<table class="mitigations">{"".join(rows)}</table>'


def _list_block(title: str, items: list[str], empty_text: str = "none") -> str:
    if not items:
        return f"<details><summary>{_esc(title)} (0)</summary><p class='muted'>{_esc(empty_text)}</p></details>"
    li = "".join(f"<li><code>{_esc(i)}</code></li>" for i in items[:100])
    more = f"<li class='muted'>... {len(items) - 100} more</li>" if len(items) > 100 else ""
    return f"<details><summary>{_esc(title)} ({len(items)})</summary><ul class='code-list'>{li}{more}</ul></details>"


def render(report: dict) -> str:
    path = report.get("path", "unknown")
    detected_type = report.get("detected_type", "unknown")
    size = report.get("size_bytes", 0)
    findings = report.get("summary_findings", [])
    sections = report.get("sections", {})
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    severity_counts = {s: 0 for s in _SEVERITY_ORDER}
    for f in findings:
        severity_counts[_severity_of(f)] += 1
    stat_cards = "".join(
        f'<div class="stat sev-{s.lower()}"><div class="stat-num">{severity_counts[s]}</div>'
        f'<div class="stat-label">{s}</div></div>'
        for s in _SEVERITY_ORDER
        if severity_counts[s] > 0
    ) or '<div class="stat sev-info"><div class="stat-num">0</div><div class="stat-label">FINDINGS</div></div>'

    extra_sections = []

    if "binary" in sections:
        b = sections["binary"]
        extra_sections.append(
            f"""<section class="card">
            <h2>Binary mitigations</h2>
            <p class="muted">Format: {_esc(b.get('format'))} &middot; Arch: {_esc(b.get('arch'))}</p>
            {_mitigations_table(b.get('mitigations', {}))}
            {_list_block('Risky imports', b.get('risky_imports', []))}
            {_list_block('All imports', b.get('imports', []))}
            {_list_block('Sections', b.get('sections', []))}
            </section>"""
        )

    if "apk" in sections:
        a = sections["apk"]
        extra_sections.append(
            f"""<section class="card">
            <h2>Android APK</h2>
            <p class="muted">Package: <code>{_esc(a.get('package'))}</code> &middot;
            version {_esc(a.get('version_name'))} &middot; minSdk {_esc(a.get('min_sdk'))} &middot;
            targetSdk {_esc(a.get('target_sdk'))} &middot; signed: {_esc(a.get('is_signed'))}</p>
            {_list_block('Dangerous permissions', a.get('dangerous_permissions', []))}
            {_list_block('Exported activities', a.get('exported_activities', []))}
            {_list_block('Exported services', a.get('exported_services', []))}
            {_list_block('Exported receivers', a.get('exported_receivers', []))}
            {_list_block('Exported providers', a.get('exported_providers', []))}
            </section>"""
        )

    if "secrets" in sections:
        s = sections["secrets"]
        pattern_matches = s.get("pattern_matches", [])
        rows = "".join(
            f"<tr><td>{_esc(m['label'])}</td><td><code>{_esc(m['match'])}</code></td>"
            f"<td class='muted'>{_esc(m['context'])}</td></tr>"
            for m in pattern_matches
        )
        table = (
            f"<table class='secrets'><thead><tr><th>Type</th><th>Match (redacted)</th><th>Context</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>"
            if pattern_matches
            else '<p class="muted">No secret-like patterns found.</p>'
        )
        extra_sections.append(f'<section class="card"><h2>Secrets scan</h2>{table}</section>')

    if "strings" in sections:
        st = sections["strings"]
        extra_sections.append(
            f"""<section class="card">
            <h2>Strings</h2>
            <p class="muted">{_esc(st.get('total_strings', 0))} total strings extracted</p>
            {_list_block('URLs', st.get('urls', []))}
            {_list_block('IP addresses', st.get('ips', []))}
            {_list_block('Risky symbols referenced', st.get('risky_symbols', []))}
            </section>"""
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>re-audit report</title>
<style>
  :root {{
    --bg: #0f1115; --card: #1a1d24; --text: #e6e8eb; --muted: #8b92a0;
    --border: #2a2e38; --critical: #ff4d4f; --high: #ff7a45; --medium: #ffc53d;
    --low: #40a9ff; --info: #52c41a; --accent: #7c5cff;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 32px 16px; background: var(--bg); color: var(--text);
    font-family: -apple-system, 'Segoe UI', Roboto, sans-serif; line-height: 1.5;
  }}
  .wrap {{ max-width: 900px; margin: 0 auto; }}
  header {{ margin-bottom: 24px; }}
  h1 {{ font-size: 1.4rem; margin: 0 0 4px; }}
  .path {{
    font-family: 'Cascadia Mono', 'Cascadia Code', Consolas, 'SF Mono', monospace;
    color: var(--muted); word-break: break-all;
  }}
  .meta {{ color: var(--muted); font-size: 0.85rem; margin-top: 4px; }}
  .disclaimer {{
    background: #241f33; border: 1px solid var(--accent); border-radius: 8px;
    padding: 12px 16px; font-size: 0.85rem; color: #cfc8ff; margin: 16px 0 24px;
  }}
  .stats {{ display: flex; gap: 12px; margin-bottom: 24px; flex-wrap: wrap; }}
  .stat {{
    background: var(--card); border: 1px solid var(--border); border-radius: 10px;
    padding: 12px 20px; text-align: center; min-width: 90px;
  }}
  .stat-num {{ font-size: 1.6rem; font-weight: 700; }}
  .stat-label {{ font-size: 0.7rem; color: var(--muted); letter-spacing: 0.05em; }}
  .stat.sev-critical .stat-num {{ color: var(--critical); }}
  .stat.sev-high .stat-num {{ color: var(--high); }}
  .stat.sev-medium .stat-num {{ color: var(--medium); }}
  .stat.sev-low .stat-num {{ color: var(--low); }}
  .stat.sev-info .stat-num {{ color: var(--info); }}
  .card {{
    background: var(--card); border: 1px solid var(--border); border-radius: 10px;
    padding: 20px; margin-bottom: 16px;
  }}
  .card h2 {{ margin: 0 0 12px; font-size: 1rem; }}
  .findings-list {{ list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 8px; }}
  .finding {{
    display: flex; gap: 10px; align-items: baseline; padding: 8px 12px;
    border-radius: 6px; background: #14161c; border-left: 3px solid var(--border);
  }}
  .finding.sev-critical {{ border-left-color: var(--critical); }}
  .finding.sev-high {{ border-left-color: var(--high); }}
  .finding.sev-medium {{ border-left-color: var(--medium); }}
  .finding.sev-low {{ border-left-color: var(--low); }}
  .finding.sev-info {{ border-left-color: var(--info); }}
  .badge {{
    font-size: 0.65rem; font-weight: 700; padding: 2px 8px; border-radius: 4px;
    background: var(--border); color: var(--text); flex-shrink: 0;
  }}
  .muted {{ color: var(--muted); font-size: 0.85rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  table td, table th {{ padding: 6px 8px; border-bottom: 1px solid var(--border); text-align: left; }}
  .status-ok {{ color: var(--info); font-weight: 600; }}
  .status-bad {{ color: var(--critical); font-weight: 600; }}
  .status-warn {{ color: var(--medium); font-weight: 600; }}
  details {{ margin-top: 8px; }}
  summary {{ cursor: pointer; font-size: 0.85rem; color: var(--muted); }}
  .code-list {{ margin: 8px 0 0; padding-left: 18px; font-size: 0.8rem; max-height: 220px; overflow-y: auto; }}
  code {{ font-family: 'Cascadia Mono', 'Cascadia Code', Consolas, 'SF Mono', monospace; font-size: 0.85em; }}
  footer {{ color: var(--muted); font-size: 0.75rem; text-align: center; margin-top: 32px; }}
  @media (prefers-color-scheme: light) {{
    :root:not([data-theme="dark"]) {{
      --bg: #f5f6f8; --card: #ffffff; --text: #1a1d24; --muted: #6b7280; --border: #e2e4e9;
    }}
    :root:not([data-theme="dark"]) .finding {{ background: #f9fafb; }}
  }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>re-audit report</h1>
    <div class="path">{_esc(path)}</div>
    <div class="meta">type: {_esc(detected_type)} &middot; {int(size):,} bytes &middot; generated {_esc(generated)}</div>
  </header>
  <div class="disclaimer">{_esc(report.get('scope_disclaimer', ''))}</div>
  <div class="stats">{stat_cards}</div>
  <section class="card">
    <h2>Findings</h2>
    {_findings_html(findings)}
  </section>
  {''.join(extra_sections)}
  <footer>Generated by re-audit -- static analysis only, no network requests, no execution of the target.</footer>
</div>
</body>
</html>"""
