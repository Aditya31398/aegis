"""Single-file HTML report.

Same content as the Markdown, for the person who approves the invoice rather
than the person who fixes the code. One file, no network, no build step: it
opens from a mail attachment or a shared drive.

Security note, because this renderer is the one place untrusted text becomes
markup: every value in this report -- tool names, descriptions, witnesses --
comes from a manifest or a server we did not write, and a witness is by
definition an attacker-shaped string. Everything is escaped through
`html.escape(quote=True)`, the page declares a restrictive CSP, and the only
styling is an inline <style> block. No script runs, and there is nothing for
one to hook into. `test_html_report_escapes_hostile_content` plants a payload
in a manifest and asserts it renders inert.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import date
from html import escape
from pathlib import Path

from aegis.adapters.mcp import McpServer

from .loopholes import SEVERITIES, AuditReport, Finding

_CSS = """
:root { --bg:#ffffff; --fg:#14161a; --muted:#5b6472; --line:#e3e6ea; --card:#f7f8fa;
        --critical:#b3261e; --high:#c2610c; --medium:#8a6d0b; --low:#3a6b35; --info:#44506b; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#14161a; --fg:#e8eaed; --muted:#9aa4b2; --line:#2a2f37; --card:#1b1f25;
          --critical:#f2857c; --high:#f0a860; --medium:#dcc069; --low:#8fd08a; --info:#a8b6d8; }
}
* { box-sizing:border-box; }
body { margin:0; padding:2.5rem 1rem 4rem; background:var(--bg); color:var(--fg);
       font:16px/1.6 ui-sans-serif,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
main { max-width:64rem; margin:0 auto; }
h1 { font-size:1.9rem; margin:0 0 .25rem; letter-spacing:-.02em; }
h2 { font-size:1.25rem; margin:2.5rem 0 .75rem; padding-bottom:.35rem; border-bottom:1px solid var(--line); }
h3 { font-size:1rem; margin:0 0 .35rem; }
.sub { color:var(--muted); margin:0 0 1.5rem; }
.cards { display:flex; flex-wrap:wrap; gap:.75rem; margin:1rem 0 1.5rem; }
.card { flex:1 1 7rem; background:var(--card); border:1px solid var(--line);
        border-radius:.6rem; padding:.75rem .9rem; }
.card .n { font-size:1.6rem; font-weight:650; line-height:1.2; }
.card .k { color:var(--muted); font-size:.8rem; text-transform:uppercase; letter-spacing:.05em; }
table { width:100%; border-collapse:collapse; margin:.5rem 0 1rem; font-size:.94rem; }
th,td { text-align:left; padding:.5rem .6rem; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-weight:600; font-size:.8rem; text-transform:uppercase; letter-spacing:.04em; }
.finding { border:1px solid var(--line); border-left:4px solid var(--line);
           border-radius:.5rem; padding:.9rem 1rem; margin:.75rem 0; background:var(--card); }
.finding.critical { border-left-color:var(--critical); }
.finding.high { border-left-color:var(--high); }
.finding.medium { border-left-color:var(--medium); }
.finding.low { border-left-color:var(--low); }
.finding.info { border-left-color:var(--info); }
.tag { display:inline-block; font-size:.72rem; font-weight:650; text-transform:uppercase;
       letter-spacing:.06em; padding:.1rem .45rem; border-radius:.3rem; border:1px solid currentColor; }
.tag.critical { color:var(--critical); } .tag.high { color:var(--high); }
.tag.medium { color:var(--medium); } .tag.low { color:var(--low); } .tag.info { color:var(--info); }
.conf { display:inline-block; margin-left:.4rem; font-size:.72rem; color:var(--muted);
         text-transform:uppercase; letter-spacing:.06em; }
.where { color:var(--muted); font-size:.85rem; margin:.1rem 0 .5rem; }
.where code, pre code { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
pre { background:var(--bg); border:1px solid var(--line); border-radius:.4rem;
      padding:.55rem .7rem; overflow-x:auto; margin:.5rem 0 0; font-size:.86rem; }
.accepted { opacity:.72; }
.accepted-note { color:var(--muted); font-size:.85rem; margin-top:.5rem; }
footer { color:var(--muted); font-size:.85rem; margin-top:3rem;
         border-top:1px solid var(--line); padding-top:1rem; }
"""


def _e(value: object) -> str:
    """The only way text reaches this document."""
    return escape(str(value), quote=True)


def _finding_block(f: Finding, accepted_reason: str | None) -> str:
    where = f.tool + (f".{f.arg}" if f.arg else "")
    out = [f'<article class="finding {_e(f.severity)}'
           f'{" accepted" if accepted_reason else ""}">',
           f'<span class="tag {_e(f.severity)}">{_e(f.severity)}</span>',
           f'<span class="conf">{_e(f.confidence)}</span>',
           f"<h3>{_e(f.title)}</h3>"]
    if where:
        out.append(f'<p class="where"><code>{_e(where)}</code> · '
                   f"{_e(f.category)} · {_e(f.fingerprint)}</p>")
    else:
        out.append(f'<p class="where">{_e(f.category)} · {_e(f.fingerprint)}</p>')
    out.append(f"<p>{_e(f.detail)}</p>")
    if f.witness:
        out.append("<p class=\"where\">Reproducing input</p>"
                   f"<pre><code>{_e(f.witness)}</code></pre>")
    if accepted_reason:
        out.append(f'<p class="accepted-note">Accepted in the baseline: '
                   f"{_e(accepted_reason)}</p>")
    out.append("</article>")
    return "\n".join(out)


def render_html(report: AuditReport, servers: list[McpServer], *,
                client: str = "", hardened_path: str = "") -> str:
    buckets: dict[str, list[Finding]] = defaultdict(list)
    for f in report.findings:
        buckets[f.severity].append(f)
    tools = sum(len(s.tools) for s in servers)
    title = "Agent tool-surface audit" + (f" — {client}" if client else "")

    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        # No scripts, no remote loads: this file renders the same offline and
        # cannot be turned into a delivery vehicle by a hostile manifest.
        '<meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">",
        f"<title>{_e(title)}</title>",
        f"<style>{_CSS}</style></head><body><main>",
        f"<h1>{_e(title)}</h1>",
        f'<p class="sub">{_e(date.today().isoformat())} · {len(servers)} server(s), '
        f"{tools} tools examined · {len(report.findings)} findings</p>",
        '<div class="cards">',
    ]
    for sev in SEVERITIES:
        if buckets[sev]:
            parts.append(f'<div class="card"><div class="n tag {_e(sev)}" '
                         f'style="border:0">{len(buckets[sev])}</div>'
                         f'<div class="k">{_e(sev)}</div></div>')
    parts.append("</div>")

    crit, high = len(buckets["critical"]), len(buckets["high"])
    parts.append("<p>" + (
        f"<strong>{crit} critical and {high} high-severity findings.</strong> "
        "Each one below includes the exact input that reproduces it."
        if crit or high else
        "No critical or high-severity findings. Medium and low items below are "
        "worth scheduling, not worth paging anyone.") + "</p>")
    parts.append("<p>Each finding carries a confidence: <em>confirmed</em> means "
                 "the input was pushed through the real decision path and "
                 "admitted, or the schema literally says so; <em>likely</em> "
                 "means two signals or one inference step; <em>possible</em> "
                 "means a pattern that depends on context outside this audit. "
                 "Nothing is hidden by confidence.</p>")
    parts.append("<p>Findings come from structural analysis of the declared "
                 "schemas, adversarial payload probing against the real "
                 "decision path, and meaning-preserving mutation of inputs that "
                 "are supposed to be refused. <strong>Nothing in this audit "
                 "executed a tool against your infrastructure.</strong></p>")

    parts.append("<h2>Surface inventory</h2>")
    parts.append("<table><thead><tr><th>Server</th><th>Tools</th>"
                 "<th>Transport</th></tr></thead><tbody>")
    for s in servers:
        parts.append(f"<tr><td>{_e(s.name)}</td><td>{len(s.tools)}</td>"
                     f"<td>{_e(s.transport)}</td></tr>")
    parts.append("</tbody></table>")

    parts.append("<h2>Findings</h2>")
    if not report.findings:
        parts.append("<p>Nothing to report.</p>")
    for sev in SEVERITIES:
        for f in buckets[sev]:
            parts.append(_finding_block(f, report.accepted.get(f.fingerprint)))

    if hardened_path:
        parts.append("<h2>What to do</h2>")
        parts.append("<p>A tightened policy generated from this run is in "
                     f"<code>{_e(hardened_path)}</code>. Every "
                     "<code>REPLACE_WITH_*</code> placeholder in it needs a "
                     "human decision before use.</p>")

    parts.append("</main><footer>Generated by aegis. Findings describe what a "
                 "declared schema permits; they are not a penetration test of a "
                 "running service.</footer></body></html>")
    return "\n".join(parts) + "\n"


def write_html(report: AuditReport, servers: list[McpServer], path: str | Path,
               **kw) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(report, servers, **kw), encoding="utf-8")
    return path
