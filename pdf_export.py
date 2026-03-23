#!/usr/bin/env python3
"""
PDF export for evidence2html.

Two modes:
  - 16:9  : one section per page at 338×190mm, preserves HTML visual style
  - din5008: A4 portrait, structured pentest report following professional
             audit report conventions (cover, executive summary, per-finding
             sections, port table, evidence appendix).
             Rule: only data present in the XML is written; nothing is
             invented or padded with generic text.
"""

import datetime
import html
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


# ---------------------------------------------------------------------------
# Chromium driver
# ---------------------------------------------------------------------------

def _chromium_bin():
    for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        try:
            result = subprocess.run(["which", name], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            continue
    return None


def _html_to_pdf(html_path: str, pdf_path: str) -> bool:
    chrom = _chromium_bin()
    if not chrom:
        print("[-] No Chromium/Chrome found. Install with: sudo apt install chromium")
        return False
    cmd = [
        chrom,
        "--headless",
        "--disable-gpu",
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--run-all-compositor-stages-before-draw",
        f"--print-to-pdf={pdf_path}",
        "--print-to-pdf-no-header",
        f"file://{os.path.abspath(html_path)}",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 0:
            return True
        print(f"[-] Chromium exited {result.returncode}: {result.stderr[:300]}")
        return False
    except subprocess.TimeoutExpired:
        print("[-] Chromium timed out after 120s")
        return False
    except Exception as exc:
        print(f"[-] Chromium error: {exc}")
        return False


# ---------------------------------------------------------------------------
# 16:9 PDF
# ---------------------------------------------------------------------------

_PRINT_CSS_16x9 = """
<style id="pdf-print-override">
@page {
    size: 338mm 190mm;
    margin: 8mm 10mm;
}
@media print {
    /* hide interactive chrome */
    .box-btn-remove, .box-btn-reset, .box-header-actions,
    .section-edit-btn, .section-edit-hint, .editor-toolbar,
    .editor-palette, #global-edit-toggle, #section-restore-zone,
    .drag-handle, nav, .hud-toolbar { display: none !important; }

    body { background: #0a0a0a !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }

    /* each top-level section = new page */
    .box-level-1, .overview-16x9 {
        page-break-before: always;
        page-break-inside: avoid;
        break-before: page;
        margin: 0 !important;
        width: 100% !important;
        max-height: none !important;
        overflow: visible !important;
    }
    /* first child — no blank page at start */
    .box-level-1:first-of-type, .overview-16x9:first-of-type {
        page-break-before: auto;
        break-before: auto;
    }
    /* evidence items — allow page breaks inside */
    .box-level-1 .evidence-item, .evidence-raw { page-break-inside: auto; }
    /* tables */
    table { width: 100% !important; }
    pre, code { white-space: pre-wrap !important; word-break: break-all !important; }
}
</style>
"""

_PRINT_PREPARE_JS_16x9 = """
<script id="pdf-print-prepare">
(function () {
  function run() {
    // Expand all evidence/details so analyst comments are visible in PDF.
    document.querySelectorAll('details').forEach(function (d) { d.open = true; });

    // Ensure sections hidden in UI are printed as well.
    document.querySelectorAll('.box-level-1, .overview-16x9').forEach(function (el) {
      if (el && el.style && el.style.display === 'none') {
        el.style.display = '';
      }
    });

    // Remove edit locking classes to avoid accidental hidden content rules.
    document.querySelectorAll('.section-edit-locked').forEach(function (el) {
      el.classList.remove('section-edit-locked');
    });

    // Persist analyst comments/notes into HTML for export
    function persistAnalystData() {
      // Evidence comments
      document.querySelectorAll('[data-evidence-key]').forEach(function (node) {
        var key = node.getAttribute('data-evidence-key');
        if (!key) return;
        try {
          var stored = localStorage.getItem('cosmicAnal:v1:evidence:' + key);
          if (stored) {
            var data = JSON.parse(stored);
            // Update title
            var titleEl = node.querySelector('[data-evidence-title-input="' + key + '"]');
            if (titleEl && data.title) titleEl.textContent = data.title;
            // Update summary  
            var sumEl = node.querySelector('[data-evidence-summary-input="' + key + '"]');
            if (sumEl && data.summary) sumEl.textContent = data.summary;
            // Update raw
            var rawEl = node.querySelector('[data-evidence-raw-input="' + key + '"]');
            if (rawEl && data.raw) rawEl.textContent = data.raw;
            // Update comment
            var commentEl = node.querySelector('[data-evidence-comment-input="' + key + '"]');
            if (commentEl && data.comment) commentEl.textContent = data.comment;
          }
        } catch (e) {}
      });

      // Hero notes
      try {
        var heroKey = 'cosmicAnal:v1:heroNote:section-overview';
        var heroNote = localStorage.getItem(heroKey);
        var heroEl = document.querySelector('[data-hero-note-input]');
        if (heroEl && heroNote) heroEl.textContent = heroNote;
      } catch (e) {}

      // Port analyst notes
      document.querySelectorAll('[data-port-key]').forEach(function (row) {
        var portKey = row.getAttribute('data-port-key');
        if (!portKey) return;
        try {
          var portNote = localStorage.getItem('cosmicAnal:v1:' + portKey);
          var portEl = row.querySelector('[data-port-analyst-input="' + portKey + '"]');
          if (portEl && portNote) portEl.textContent = portNote;
        } catch (e) {}
      });

      // Scoped editing elements
      document.querySelectorAll('[data-scope-key]').forEach(function (el) {
        var scopeKey = el.getAttribute('data-scope-key');
        if (!scopeKey) return;
        try {
          var scopeVal = localStorage.getItem('cosmicAnal:v1:scope:' + scopeKey);
          if (scopeVal) el.textContent = scopeVal;
        } catch (e) {}
      });
    }

    persistAnalystData();
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', run);
  } else {
    run();
  }
})();
</script>
"""


def generate_16x9_pdf(html_path: str, pdf_path: str) -> bool:
    print("[*] Generating 16:9 PDF …")
    try:
        with open(html_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception as exc:
        print(f"[-] Cannot read HTML: {exc}")
        return False

    inject = _PRINT_CSS_16x9 + _PRINT_PREPARE_JS_16x9
    if "<head>" in content:
        content = content.replace("<head>", "<head>" + inject, 1)
    else:
        content = inject + content

    with tempfile.NamedTemporaryFile(suffix=".html", mode="w", encoding="utf-8",
                                     delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        ok = _html_to_pdf(tmp_path, pdf_path)
        if ok:
            print(f"[+] 16:9 PDF → {pdf_path}")
        return ok
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# DIN 5008 — XML parsing helpers
# ---------------------------------------------------------------------------

def _meta(root) -> dict:
    """Extract summary attributes from cosmicmeta/summary."""
    el = root.find("cosmicmeta/summary")
    if el is None:
        return {}
    return dict(el.attrib)


def _hosts(root) -> list:
    """Return list of (ip, os_guess, ports_list) tuples."""
    results = []
    for host in root.findall("host"):
        addr = host.find("address[@addrtype='ipv4']")
        if addr is None:
            addr = host.find("address")
        ip = addr.get("addr", "") if addr is not None else ""
        if not ip:
            continue

        # OS guess
        os_guess = ""
        osclass = host.find(".//osmatch")
        if osclass is not None:
            os_guess = osclass.get("name", "")

        # Ports
        ports = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            service = port.find("service")
            if state is not None and state.get("state") in ("open", "filtered"):
                ports.append({
                    "portid":   port.get("portid", ""),
                    "protocol": port.get("protocol", ""),
                    "state":    state.get("state", ""),
                    "service":  service.get("name", "") if service is not None else "",
                    "product":  service.get("product", "") if service is not None else "",
                    "version":  service.get("version", "") if service is not None else "",
                })
        results.append({"ip": ip, "os": os_guess, "ports": ports,
                         "risk_score": host.get("risk_score", "0")})
    return results


def _findings(root) -> list:
    """Return structured findings from cosmicinsights."""
    results = []
    insights = root.find("cosmicinsights")
    if insights is None:
        return results
    for f in insights.findall("finding"):
        entry = dict(f.attrib)
        results.append(entry)
    return results


def _evidence_items(root) -> list:
    """Return evidence items with non-empty raw content."""
    results = []
    ev_root = root.find("cosmicevidence")
    if ev_root is None:
        return results
    for item in ev_root.findall("item"):
        if item.get("status") in ("EMPTY",):
            continue
        raw_el = item.find("raw")
        raw = (raw_el.text or "").strip() if raw_el is not None else ""
        if not raw:
            continue
        
        # Extract analyst comments from cosmicanalyst section if present
        analyst_comment = ""
        analyst_el = item.find("cosmicanalyst")
        if analyst_el is not None:
            comment_el = analyst_el.find("comment")
            if comment_el is not None and comment_el.text:
                analyst_comment = comment_el.text.strip()
        
        results.append({
            "file":      item.get("file", ""),
            "timestamp": item.get("timestamp", ""),
            "category":  item.get("category", "other"),
            "tool":      item.get("tool", "unknown"),
            "status":    item.get("status", "OK"),
            "summary":   item.get("summary", ""),
            "raw":       raw,
            "comment":   analyst_comment,
        })
    return results


def _scan_commands(root) -> list:
    cmds = []
    for scan in root.findall("cosmiccommands/scan"):
        cmds.append({
            "file":     scan.get("file", ""),
            "args":     scan.get("args", ""),
            "flags":    scan.get("flags", ""),
            "startstr": scan.get("startstr", ""),
        })
    return cmds


def _severity_order(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(sev.lower(), 5)


def _sev_badge(sev: str) -> str:
    colors = {
        "critical": "#c0392b", "high": "#e67e22",
        "medium":   "#f39c12", "low": "#27ae60", "info": "#2980b9",
    }
    bg = colors.get(sev.lower(), "#555")
    return (f'<span style="background:{bg};color:#fff;padding:2px 8px;border-radius:3px;'
            f'font-size:10pt;font-weight:bold;letter-spacing:1px;">'
            f'{html.escape(sev.upper())}</span>')


# ---------------------------------------------------------------------------
# DIN 5008 — HTML builder
# ---------------------------------------------------------------------------

_DIN_CSS = """
@page {
    size: A4 portrait;
    margin: 25mm 20mm 20mm 25mm;
    @top-right  { content: "Confidential"; font-size: 8pt; color: #888; }
    @bottom-right { content: "Page " counter(page) " of " counter(pages);
                    font-size: 8pt; color: #888; }
}
* { box-sizing: border-box; }
body {
    font-family: 'Helvetica Neue', Arial, sans-serif;
    font-size: 10pt;
    color: #1a1a1a;
    line-height: 1.5;
    margin: 0;
    padding: 0;
}
h1 { font-size: 18pt; font-weight: bold; margin: 0 0 8pt; }
h2 { font-size: 13pt; font-weight: bold; margin: 20pt 0 6pt;
     border-bottom: 1.5pt solid #1a1a1a; padding-bottom: 3pt; }
h3 { font-size: 11pt; font-weight: bold; margin: 14pt 0 4pt; }
h4 { font-size: 10pt; font-weight: bold; text-transform: uppercase;
     letter-spacing: 0.5pt; color: #444; margin: 10pt 0 3pt; }
p  { margin: 4pt 0; }
table { width: 100%; border-collapse: collapse; margin: 8pt 0; font-size: 9pt; }
th { background: #1a1a1a; color: #fff; padding: 5pt 8pt; text-align: left; }
td { padding: 4pt 8pt; border-bottom: 0.5pt solid #ccc; vertical-align: top; }
tr:nth-child(even) td { background: #f8f8f8; }
pre {
    background: #f4f4f4;
    border-left: 3pt solid #ccc;
    padding: 8pt;
    font-size: 7.5pt;
    font-family: 'Courier New', monospace;
    white-space: pre-wrap;
    word-break: break-all;
    margin: 6pt 0;
    page-break-inside: auto;
}
.cover  { page-break-after: always; }
.toc    { page-break-after: always; }
.finding-block { page-break-inside: avoid; margin-bottom: 20pt; }
.finding-heading { font-size: 12pt; font-weight: bold; margin: 0 0 8pt; }
.field-label {
    font-weight: bold;
    text-transform: uppercase;
    font-size: 8.5pt;
    letter-spacing: 0.5pt;
    color: #444;
    margin: 10pt 0 2pt;
}
.field-value { margin: 0 0 6pt; }
.empty-field { color: #999; font-style: italic; }
hr { border: none; border-top: 0.5pt solid #ccc; margin: 12pt 0; }
.stat-table td { font-size: 10pt; }
.stat-table .sev-num { font-weight: bold; font-size: 12pt; }
"""


def _cover_html(meta: dict, hosts: list, generated: str) -> str:
    target = ", ".join(h["ip"] for h in hosts) if hosts else ""
    report_date = meta.get("report_generated", generated)
    version = "1.0"

    rows = ""
    if target:
        rows += f"<tr><td><strong>Target</strong></td><td>{html.escape(target)}</td></tr>"
    rows += f"<tr><td><strong>Report date</strong></td><td>{html.escape(report_date)}</td></tr>"
    rows += f"<tr><td><strong>Version</strong></td><td>{html.escape(version)}</td></tr>"

    return f"""
<div class="cover">
  <br><br><br>
  <h1>Security Assessment Report</h1>
  <hr>
  <table class="stat-table" style="width:auto;min-width:320pt;">
    {rows}
  </table>
</div>
"""


def _toc_html(sections: list) -> str:
    if not sections:
        return ""
    items = "".join(f"<li>{html.escape(s)}</li>" for s in sections)
    return f"""
<div class="toc">
  <h2>Contents</h2>
  <ol>{items}</ol>
</div>
"""


def _exec_summary_html(meta: dict, findings: list) -> str:
    threat_keys = ["critical", "high", "medium", "low", "info"]
    counts = {}
    for k in threat_keys:
        v = meta.get(f"threat_{k}", "0")
        try:
            counts[k] = int(v)
        except ValueError:
            counts[k] = 0

    total = sum(counts.values())
    if total == 0 and not findings:
        return ""

    rows = ""
    for k in threat_keys:
        n = counts.get(k, 0)
        rows += (f"<tr><td>{_sev_badge(k)}</td>"
                 f'<td class="sev-num">{n}</td></tr>')

    hosts_count = meta.get("hosts", "")
    ports_count = meta.get("ports", "")
    ev_count    = meta.get("evidence_files", "")
    stats_extra = ""
    if hosts_count or ports_count or ev_count:
        parts = []
        if hosts_count:
            parts.append(f"hosts: {hosts_count}")
        if ports_count:
            parts.append(f"open ports: {ports_count}")
        if ev_count:
            parts.append(f"evidence files: {ev_count}")
        stats_extra = f'<p style="margin-top:8pt;">Scan statistics — {", ".join(parts)}.</p>'

    return f"""
<h2>Executive Summary</h2>
<table class="stat-table" style="width:auto;min-width:200pt;">
  <tr><th>Severity</th><th>Count</th></tr>
  {rows}
</table>
{stats_extra}
"""


def _finding_html(f: dict, idx: int) -> str:
    sev     = f.get("severity", "")
    ftype   = f.get("type", "")
    tool    = f.get("tool", "")
    host    = f.get("host", "")
    port    = f.get("port", "")
    url     = f.get("url", "")
    target  = f.get("target", "")
    detail  = f.get("detail", "")
    finding = f.get("finding", "")
    cve     = f.get("cve", "")
    param   = f.get("param", "")

    title_parts = []
    if ftype:
        title_parts.append(ftype.replace("_", " ").title())
    if tool and tool != "unknown":
        title_parts.append(f"({tool})")
    title = " ".join(title_parts) if title_parts else "Finding"

    badge = _sev_badge(sev) if sev else ""
    heading = f'<div class="finding-heading">{badge} {html.escape(title)}</div>'

    def field(label: str, value: str, pre: bool = False) -> str:
        if not value or not value.strip():
            return ""
        v = f"<pre>{html.escape(value)}</pre>" if pre else f"<p>{html.escape(value)}</p>"
        return f'<div class="field-label">{label}</div><div class="field-value">{v}</div>'

    location_parts = [p for p in [host, port, url, target] if p]
    location = "  ·  ".join(location_parts)

    body = ""
    body += field("Summary", finding or detail)
    body += field("Parameter", param)
    body += field("CVE", cve)
    body += field("Location", location)

    return f'<div class="finding-block"><hr>{heading}{body}</div>'


def _ports_html(hosts: list) -> str:
    if not hosts:
        return ""
    sections = ""
    for h in hosts:
        if not h["ports"]:
            continue
        rows = ""
        for p in h["ports"]:
            svc = p["service"]
            ver = " ".join(x for x in [p["product"], p["version"]] if x)
            rows += (f"<tr><td>{html.escape(p['portid'])}/{html.escape(p['protocol'])}</td>"
                     f"<td>{html.escape(p['state'])}</td>"
                     f"<td>{html.escape(svc)}</td>"
                     f"<td>{html.escape(ver)}</td></tr>")
        os_line = f" &nbsp;·&nbsp; OS: {html.escape(h['os'])}" if h["os"] else ""
        sections += f"""
<h3>{html.escape(h['ip'])}{os_line}</h3>
<table>
  <tr><th>Port / Proto</th><th>State</th><th>Service</th><th>Version</th></tr>
  {rows}
</table>
"""
    if not sections:
        return ""
    return f"<h2>Network Services</h2>{sections}"


def _evidence_html(items: list) -> str:
    if not items:
        return ""
    by_cat: dict = {}
    for item in items:
        cat = item["category"]
        by_cat.setdefault(cat, []).append(item)

    body = ""
    for cat, group in sorted(by_cat.items()):
        body += f'<h3>{html.escape(cat.replace("-", " ").title())}</h3>'
        for item in group:
            ts_line = f" &nbsp;·&nbsp; {html.escape(item['timestamp'])}" if item["timestamp"] else ""
            body += (f'<p><strong>{html.escape(item["file"])}</strong>'
                     f' — tool: {html.escape(item["tool"])}{ts_line}</p>')
            
            # Add analyst comment if present
            if item.get("comment"):
                body += f'<div style="background:#f9f9f9;border-left:3pt solid #2980b9;padding:6pt 8pt;margin:4pt 0;font-style:italic;">'
                body += f'<strong>Analyst Note:</strong> {html.escape(item["comment"])}</div>'
            
            # Truncate very large raw blocks in the PDF for readability
            raw = item["raw"]
            if len(raw) > 4000:
                raw = raw[:4000] + f"\n\n[… truncated {len(item['raw']) - 4000} chars …]"
            body += f"<pre>{html.escape(raw)}</pre>"

    return f"<h2>Evidence Appendix</h2>{body}"


def _scans_html(cmds: list) -> str:
    if not cmds:
        return ""
    rows = ""
    for c in cmds:
        rows += (f"<tr><td>{html.escape(c['file'])}</td>"
                 f"<td>{html.escape(c['startstr'])}</td>"
                 f"<td><code>{html.escape(c['flags'] or c['args'][:80])}</code></td></tr>")
    return f"""
<h2>Scan Commands</h2>
<table>
  <tr><th>File</th><th>Started</th><th>Flags</th></tr>
  {rows}
</table>
"""


def generate_din5008_pdf(xml_path: str, pdf_path: str) -> bool:
    print("[*] Generating DIN 5008 PDF …")
    try:
        tree = ET.parse(xml_path)
    except Exception as exc:
        print(f"[-] Cannot parse XML: {exc}")
        return False

    root = tree.getroot()
    meta       = _meta(root)
    hosts      = _hosts(root)
    findings   = sorted(_findings(root), key=lambda f: _severity_order(f.get("severity", "")))
    ev_items   = _evidence_items(root)
    cmds       = _scan_commands(root)
    generated  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    toc_sections = []
    if findings:
        toc_sections.append("Executive Summary")
        for i, f in enumerate(findings, 1):
            sev   = f.get("severity", "?").upper()
            ftype = f.get("type", "finding").replace("_", " ")
            toc_sections.append(f"[{sev}] {ftype}")
    if any(h["ports"] for h in hosts):
        toc_sections.append("Network Services")
    if cmds:
        toc_sections.append("Scan Commands")
    if ev_items:
        toc_sections.append("Evidence Appendix")

    cover    = _cover_html(meta, hosts, generated)
    toc      = _toc_html(toc_sections) if toc_sections else ""
    exec_sum = _exec_summary_html(meta, findings)
    finds    = "".join(_finding_html(f, i) for i, f in enumerate(findings, 1))
    finds_sec = f"<h2>Findings</h2>{finds}" if finds else ""
    ports_sec = _ports_html(hosts)
    scans_sec = _scans_html(cmds)
    ev_sec    = _evidence_html(ev_items)

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Assessment Report</title>
<style>
{_DIN_CSS}
</style>
</head>
<body>
{cover}
{toc}
{exec_sum}
{finds_sec}
{ports_sec}
{scans_sec}
{ev_sec}
</body>
</html>"""

    with tempfile.NamedTemporaryFile(suffix=".html", mode="w", encoding="utf-8",
                                     delete=False) as tmp:
        tmp.write(doc)
        tmp_path = tmp.name

    try:
        ok = _html_to_pdf(tmp_path, pdf_path)
        if ok:
            print(f"[+] DIN 5008 PDF → {pdf_path}")
        return ok
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
