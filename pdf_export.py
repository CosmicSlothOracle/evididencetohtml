#!/usr/bin/env python3
"""
PDF export for evidence2html.

Modes:
  - 16:9  : one section per page at 338×190mm, preserves HTML visual style
  - reader: A4 portrait, same DOM structure as the report; reader-first
            typography (strong hierarchy, muted palette). Block patterns
            (sections, evidence, tables, ASCII) stay visually parallel to the
            interactive HTML, without screen-chrome or theme excess.
  - din5008: A4 portrait, structured pentest report following professional
             audit report conventions (cover, executive summary, per-finding
             sections, port table, evidence appendix).
             Rule: only data present in the XML is written; nothing is
             invented or padded with generic text.
"""

import datetime
import html
import json
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from typing import Optional

# Try to import risk_metrics for enhanced SVG diagrams
try:
    # First try local import (same directory)
    from risk_metrics import (
        build_din_risk_annexes_html,
        compute_cvss_effective,
        eval_readiness,
    )
    _RISK_METRICS_AVAILABLE = True
except ImportError:
    try:
        # Fallback to cosmic_workflow_core
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "cosmic_workflow_core"))
        from risk_metrics import (
            build_din_risk_annexes_html,
            compute_cvss_effective,
            eval_readiness,
        )
        _RISK_METRICS_AVAILABLE = True
    except ImportError:
        _RISK_METRICS_AVAILABLE = False


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
# Reader A4 PDF (structure-faithful, hierarchy-first)
# ---------------------------------------------------------------------------

_PRINT_CSS_READER = """
<style id="pdf-print-reader">
@page {
  size: A4 portrait;
  margin: 14mm 16mm 18mm 18mm;
}
@media print {
  :root {
    color-scheme: light;
    --reader-fg: #0f172a;
    --reader-muted: #475569;
    --reader-border: #cbd5e1;
    --reader-accent: #1d4ed8;
    --reader-fill: #f8fafc;
    --reader-code-bg: #f1f5f9;
  }
  /* chrome */
  .box-btn-remove, .box-btn-reset, .box-header-actions,
  .section-edit-btn, .section-edit-hint, .editor-toolbar,
  .editor-palette, #global-edit-toggle, #section-restore-zone,
  .drag-handle, .box-drag-handle, .evidence-drag-handle,
  nav, .hud-toolbar,
  .export-menu-wrap, #pdf-export-panel,
  .port-controls, .port-main-actions, .btn-subtle-remove, .subrow-btn-reset,
  .report-actions .report-btn, .report-link-action,
  .analysis-add-btn, .eval-toggle-btn, .eval-suggest-btn,
  .eval-nvd-fetch-btn, .eval-export-row, .eval-nvd-fetch-row,
  .port-mini-btn, .section-restore-zone { display: none !important; }

  html, body {
    background: #fff !important;
    color: var(--reader-fg) !important;
    font-family: "Segoe UI", "Helvetica Neue", Arial, system-ui, sans-serif !important;
    font-size: 9.5pt !important;
    line-height: 1.45 !important;
    -webkit-print-color-adjust: exact !important;
    print-color-adjust: exact !important;
  }

  .hud-grid { display: block !important; }
  .hud-grid > .hud-card { width: 100% !important; max-width: 100% !important; margin: 0 0 10pt 0 !important; }
  .hud-grid .theme-card { display: none !important; }

  /* Overview = cover strip: ASCII + note + DIN fields */
  .overview-16x9 {
    page-break-after: always;
    break-after: page;
    border: 1pt solid var(--reader-border) !important;
    border-radius: 0 !important;
    padding: 10pt 12pt !important;
    background: var(--reader-fill) !important;
    box-shadow: none !important;
    max-height: none !important;
    overflow: visible !important;
  }
  .hero-sloth-block {
    border-left: 3pt solid var(--reader-accent) !important;
    padding-left: 10pt !important;
    margin-bottom: 8pt !important;
  }
  #hero-ascii-art.branding, #hero-ascii-art.ascii-editor {
    background: var(--reader-code-bg) !important;
    color: var(--reader-fg) !important;
    border: 0.5pt solid var(--reader-border) !important;
    font-family: "Consolas", "Courier New", monospace !important;
    font-size: 5.5pt !important;
    line-height: 1.08 !important;
    white-space: pre !important;
    padding: 6pt !important;
    max-height: none !important;
    overflow: visible !important;
  }
  #hero-note-input.analysis-inline-editor {
    font-size: 9pt !important;
    color: var(--reader-fg) !important;
    text-align: left !important;
    border: 0.5pt dashed var(--reader-border) !important;
    padding: 6pt !important;
    min-height: 0 !important;
  }
  .inline-cell-editor[contenteditable] {
    border-bottom: 0.5pt solid var(--reader-border) !important;
    color: var(--reader-fg) !important;
  }

  /* Major sections: same cards as HTML, simplified */
  .box-level-1 {
    page-break-before: always;
    break-before: page;
    border: 1pt solid var(--reader-border) !important;
    border-left: 4pt solid var(--reader-accent) !important;
    border-radius: 0 !important;
    padding: 12pt 14pt !important;
    margin: 0 0 12pt 0 !important;
    background: #fff !important;
    box-shadow: none !important;
    max-height: none !important;
    overflow: visible !important;
  }
  .box-level-1:first-of-type { page-break-before: auto; break-before: auto; }

  .box-level-1 h2, .box-level-1 > div > h2 {
    font-size: 13pt !important;
    font-weight: 700 !important;
    color: var(--reader-fg) !important;
    margin: 0 0 8pt 0 !important;
    padding-bottom: 4pt !important;
    border-bottom: 1pt solid var(--reader-border) !important;
  }
  .box-level-1 h3, .box-level-1 h4 {
    font-size: 10pt !important;
    font-weight: 600 !important;
    color: var(--reader-muted) !important;
    margin: 10pt 0 4pt 0 !important;
  }

  .hint-text { color: var(--reader-muted) !important; font-size: 8.5pt !important; }

  /* Port matrix */
  #port-matrix { width: 100% !important; border-collapse: collapse !important; font-size: 8pt !important; }
  #port-matrix th {
    background: var(--reader-fg) !important;
    color: #fff !important;
    font-weight: 600 !important;
    padding: 4pt 6pt !important;
    text-align: left !important;
  }
  #port-matrix td {
    border-bottom: 0.5pt solid var(--reader-border) !important;
    padding: 3pt 6pt !important;
    vertical-align: top !important;
  }
  .row-open td { background: #eff6ff !important; }
  .row-filtered td, .row-mixed td { background: #fffbeb !important; }
  .row-closed td { background: #f8fafc !important; color: #64748b !important; }
  .badge, .badge.open, .badge.closed, .badge.teal, .proto-tcp, .proto-udp {
    background: var(--reader-code-bg) !important;
    color: var(--reader-fg) !important;
    border: 0.5pt solid var(--reader-border) !important;
    font-size: 7pt !important;
    font-weight: 600 !important;
    padding: 1pt 4pt !important;
  }

  /* Tactical / findings */
  #section-tactical table, .box-level-1 table {
    width: 100% !important;
    border-collapse: collapse !important;
    font-size: 8pt !important;
  }
  #section-tactical th, .box-level-1 thead th {
    background: var(--reader-muted) !important;
    color: #fff !important;
    padding: 4pt 6pt !important;
  }
  tr[data-finding-severity="critical"] td { border-left: 3pt solid #b91c1c !important; }
  tr[data-finding-severity="high"] td { border-left: 3pt solid #c2410c !important; }
  tr[data-finding-severity="medium"] td { border-left: 3pt solid #a16207 !important; }
  tr[data-finding-severity="low"] td { border-left: 3pt solid #15803d !important; }
  tr[data-finding-severity="info"] td { border-left: 3pt solid #0369a1 !important; }

  /* Evidence blocks */
  details.evidence-block {
    border: 0.5pt solid var(--reader-border) !important;
    padding: 8pt !important;
    margin: 0 0 8pt 0 !important;
    background: var(--reader-fill) !important;
    page-break-inside: auto !important;
  }
  details.evidence-block summary {
    list-style: none !important;
    font-weight: 600 !important;
    color: var(--reader-fg) !important;
    cursor: default !important;
  }
  details.evidence-block summary::-webkit-details-marker { display: none !important; }
  .evidence-raw-edit, .evidence-raw {
    font-family: "Consolas", "Courier New", monospace !important;
    font-size: 7.5pt !important;
    line-height: 1.35 !important;
    background: var(--reader-code-bg) !important;
    border: 0.5pt solid var(--reader-border) !important;
    padding: 6pt !important;
    white-space: pre-wrap !important;
    word-break: break-word !important;
    color: var(--reader-fg) !important;
  }
  .evidence-eval-panel {
    border-top: 1pt solid var(--reader-border) !important;
    margin-top: 8pt !important;
    padding-top: 8pt !important;
  }
  .eval-std-form { display: block !important; margin-bottom: 10pt !important; }
  .eval-form-grid label { color: var(--reader-muted) !important; font-size: 8pt !important; }
  .eval-form-row input, .eval-form-row textarea, .eval-techref-block textarea {
    border: 0.5pt solid var(--reader-border) !important;
    background: #fff !important;
    color: var(--reader-fg) !important;
    font-size: 8pt !important;
  }

  pre, code, .cmd-preview {
    font-family: "Consolas", "Courier New", monospace !important;
    font-size: 7.5pt !important;
    background: var(--reader-code-bg) !important;
    color: var(--reader-fg) !important;
    border: 0.5pt solid var(--reader-border) !important;
    white-space: pre-wrap !important;
    word-break: break-word !important;
  }

  a { color: var(--reader-accent) !important; text-decoration: underline !important; }
}
</style>
"""

_PRINT_PREPARE_JS_READER = """
<script id="pdf-print-prepare-reader">
(function () {
  function run() {
    document.querySelectorAll('details').forEach(function (d) { d.open = true; });
    document.querySelectorAll('.box-level-1, .overview-16x9').forEach(function (el) {
      if (el && el.style && el.style.display === 'none') el.style.display = '';
    });
    document.querySelectorAll('.section-edit-locked').forEach(function (el) {
      el.classList.remove('section-edit-locked');
    });
    document.querySelectorAll('.eval-std-form').forEach(function (el) {
      el.style.display = 'block';
    });
    function persistAnalystData() {
      document.querySelectorAll('[data-evidence-key]').forEach(function (node) {
        var key = node.getAttribute('data-evidence-key');
        if (!key) return;
        try {
          var stored = localStorage.getItem('cosmicAnal:v1:evidence:' + key);
          if (stored) {
            var data = JSON.parse(stored);
            var titleEl = node.querySelector('[data-evidence-title-input="' + key + '"]');
            if (titleEl && data.title) titleEl.textContent = data.title;
            var sumEl = node.querySelector('[data-evidence-summary-input="' + key + '"]');
            if (sumEl && data.summary) sumEl.textContent = data.summary;
            var rawEl = node.querySelector('[data-evidence-raw-input="' + key + '"]');
            if (rawEl && data.raw) rawEl.textContent = data.raw;
            var commentEl = node.querySelector('[data-evidence-comment-input="' + key + '"]');
            if (commentEl && data.comment) commentEl.textContent = data.comment;
          }
        } catch (e) {}
      });
      try {
        var heroNote = localStorage.getItem('cosmicAnal:v1:heroNote:section-overview');
        var heroEl = document.querySelector('[data-hero-note-input]');
        if (heroEl && heroNote) heroEl.textContent = heroNote;
      } catch (e) {}
      document.querySelectorAll('[data-port-key]').forEach(function (row) {
        var portKey = row.getAttribute('data-port-key');
        if (!portKey) return;
        try {
          var portNote = localStorage.getItem('cosmicAnal:v1:' + portKey);
          var portEl = row.querySelector('[data-port-analyst-input="' + portKey + '"]');
          if (portEl && portNote) portEl.textContent = portNote;
        } catch (e) {}
      });
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


def generate_reader_pdf(html_path: str, pdf_path: str) -> bool:
    """A4 reader PDF: same report structure as HTML, reduced palette and clear hierarchy."""
    print("[*] Generating reader A4 PDF …")
    try:
        with open(html_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception as exc:
        print(f"[-] Cannot read HTML: {exc}")
        return False

    inject = _PRINT_CSS_READER + _PRINT_PREPARE_JS_READER
    if "<head>" in content:
        content = content.replace("<head>", "<head>" + inject, 1)
    else:
        content = inject + content

    with tempfile.NamedTemporaryFile(
        suffix=".html", mode="w", encoding="utf-8", delete=False
    ) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        ok = _html_to_pdf(tmp_path, pdf_path)
        if ok:
            print(f"[+] Reader A4 PDF → {pdf_path}")
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


def _is_ffuf_web_discovery(f: dict) -> bool:
    t = (f.get("type") or "").lower().replace(" ", "_")
    tool = (f.get("tool") or "").lower()
    return t == "web_discovery" and "ffuf" in tool


def _partition_ffuf_web_findings(findings: list) -> tuple:
    """Split mass ffuf directory hits from other structured findings (printable DIN annex)."""
    noise = [f for f in findings if _is_ffuf_web_discovery(f)]
    rest = [f for f in findings if not _is_ffuf_web_discovery(f)]
    return rest, noise


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
    margin: 25mm 20mm 22mm 25mm;
    @top-right {
        content: "Confidential";
        font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
        font-size: 8pt;
        color: rgba(100, 116, 139, 0.88);
    }
    @bottom-right {
        content: counter(page, upper-roman) " of " counter(pages, upper-roman);
        font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
        font-size: 8pt;
        font-weight: 500;
        color: rgba(100, 116, 139, 0.88);
    }
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


def _exec_summary_html(meta: dict, findings: list, ffuf_omitted: int = 0) -> str:
    """
    Executive summary: optional severity histogram when threat_* in XML is populated.
    If those counts are all zero (typical), skip the empty table and keep scan statistics
    plus a short note when structured findings exist.
    ffuf_omitted: count of ffuf web_discovery rows dropped from the Findings section.
    """
    threat_keys = ["critical", "high", "medium", "low", "info"]
    counts = {}
    for k in threat_keys:
        v = meta.get(f"threat_{k}", "0")
        try:
            counts[k] = int(v)
        except ValueError:
            counts[k] = 0

    total = sum(counts.values())

    hosts_count = meta.get("hosts", "") or ""
    ports_count = meta.get("ports", "") or ""
    ev_count = meta.get("evidence_files", "") or ""
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

    if total == 0 and not findings and not stats_extra and not ffuf_omitted:
        return ""

    table_html = ""
    if total > 0:
        rows = ""
        for k in threat_keys:
            n = counts.get(k, 0)
            rows += (
                f"<tr><td>{_sev_badge(k)}</td>"
                f'<td class="sev-num">{n}</td></tr>'
            )
        table_html = (
            '<table class="stat-table" style="width:auto;min-width:200pt;">'
            "<tr><th>Severity</th><th>Count</th></tr>"
            f"{rows}</table>"
        )

    intro = ""
    if total == 0 and findings:
        intro = (
            f'<p style="margin-top:0;">{len(findings)} structured finding(s) below. '
            "Aggregate severity totals are not stored in merged scan metadata (threat_*); "
            "see each finding for its severity.</p>"
        )
    elif total == 0 and ffuf_omitted and not findings:
        intro = (
            "<p style=\"margin-top:0;\">"
            + html.escape(
                "Printable findings exclude mass ffuf web-discovery rows; see note below."
            )
            + "</p>"
        )

    ffuf_note = ""
    if ffuf_omitted:
        ffuf_note = (
            '<p style="margin-top:8pt;font-size:9pt;color:#444;">'
            + html.escape(
                f"Automated ffuf web discovery: {ffuf_omitted} directory/path hits are omitted "
                "from the Findings section to keep this PDF readable. "
                "Open the HTML report tactical matrix for the full list."
            )
            + "</p>"
        )

    return f"""
<h2>Executive Summary</h2>
{intro}
{table_html}
{ffuf_note}
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
            
            # Add analyst comment if present (preserve line breaks from XML / CLI path)
            if item.get("comment"):
                com = html.escape(item["comment"]).replace("\n", "<br>\n")
                body += (
                    '<div style="background:#f9f9f9;border-left:3pt solid #2980b9;'
                    'padding:6pt 8pt;margin:4pt 0;">'
                    f"<strong>Analyst Note:</strong> <span>{com}</span></div>"
                )
            
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


def _row_annex_export_ok(row: dict, std: str) -> bool:
    inc = row.get("exportInclude") or {}
    return inc.get(std) is not False


def _risk_exec_blurb_from_eval(eval_payload: Optional[dict]) -> str:
    """
    One paragraph for the executive summary: counts of evidence rows that will
    appear in risk annexes (aligned with browser DIN export).
    """
    if not eval_payload or not isinstance(eval_payload, dict):
        return ""
    flags = eval_payload.get("pdfInclude") or {}
    evals = eval_payload.get("evaluations") or {}
    if not isinstance(evals, dict) or not evals:
        return ""

    def has_cvss(row: dict) -> bool:
        cv = row.get("cvss") or {}
        return bool(str(cv.get("vector") or "").strip()) or cv.get("baseScore") not in (None, "")

    def has_iso(row: dict) -> bool:
        iso = row.get("iso27005") or {}
        return bool(iso.get("likelihood") and iso.get("impact"))

    def has_bsi(row: dict) -> bool:
        b = row.get("bsi") or {}
        return bool(b.get("protectionNeed"))

    def has_nist(row: dict) -> bool:
        n = row.get("nist") or {}
        return bool(n.get("likelihood") and n.get("impact"))

    bits: list[str] = []
    if flags.get("cvss"):
        n = sum(
            1
            for r in evals.values()
            if isinstance(r, dict) and has_cvss(r) and _row_annex_export_ok(r, "cvss")
        )
        if n:
            bits.append(f"CVSS technical reference: {n} evidence item(s)")
    if flags.get("iso"):
        n = sum(
            1
            for r in evals.values()
            if isinstance(r, dict) and has_iso(r) and _row_annex_export_ok(r, "iso")
        )
        if n:
            bits.append(f"ISO 27005: {n}")
    if flags.get("bsi"):
        n = sum(
            1
            for r in evals.values()
            if isinstance(r, dict) and has_bsi(r) and _row_annex_export_ok(r, "bsi")
        )
        if n:
            bits.append(f"BSI IT-Grundschutz: {n}")
    if flags.get("nist"):
        n = sum(
            1
            for r in evals.values()
            if isinstance(r, dict) and has_nist(r) and _row_annex_export_ok(r, "nist")
        )
        if n:
            bits.append(f"NIST SP 800-30: {n}")
    if not bits:
        return ""
    joined = "; ".join(bits)
    return (
        f'<p style="margin-top:10pt;"><strong>Risk assessment summary:</strong> '
        f"{html.escape(joined)}. "
        f"Detailed tables and figures are in the annexes at the end of this document.</p>"
    )


def _din_eval_annexes_from_export(payload: dict) -> str:
    """
    Render risk annex tables/diagrams from the JSON shape written to
    #cosmic-eval-export in the browser (Export HTML).
    
    When risk_metrics module is available, includes SVG diagrams (CVSS bar,
    ISO 5×5 matrix, BSI traffic light, NIST summary). Otherwise falls back
    to table-only rendering.
    """
    if not payload or not isinstance(payload, dict):
        return ""
    flags = payload.get("pdfInclude") or {}
    if not any(flags.get(k) for k in ("cvss", "iso", "bsi", "nist")):
        return ""
    evals = payload.get("evaluations") or {}

    def rows_sorted():
        out = []
        for key, row in evals.items():
            if not isinstance(row, dict):
                continue
            r = dict(row)
            r["key"] = key
            r["file"] = key.split("|")[0] if "|" in key else key
            try:
                r["index"] = int(r.get("evidenceIndex") or "999")
            except ValueError:
                r["index"] = 999
            if "eid" not in r:
                r["eid"] = f"E{r['index']}"
            out.append(r)
        out.sort(key=lambda x: x["index"])
        return out

    rows = rows_sorted()
    
    if _RISK_METRICS_AVAILABLE:
        for r in rows:
            cvss = r.get("cvss") or {}
            eff = compute_cvss_effective(cvss)
            cvss["effectiveBase"] = eff["base"]
            cvss["effectiveSeverity"] = eff["severity"]
            cvss["effectiveSource"] = eff["source"]
            r["cvss"] = cvss
        
        return build_din_risk_annexes_html(rows, flags, include_svg=True)
    
    parts = [
        "<h2>Risk evaluation annexes (JSON snapshot)</h2>",
        "<p>Generated from <code>cosmic-eval-export</code> data. "
        "For SVG figures use the in-browser <strong>Export DIN 5008 PDF</strong>.</p>",
    ]
    if flags.get("cvss"):
        parts.append("<h3>Annex CVSS</h3><table>")
        parts.append("<tr><th>Ref</th><th>Base</th><th>Severity</th><th>Source</th><th>Vector (trunc.)</th></tr>")
        any_row = False
        for r in rows:
            if not _row_annex_export_ok(r, "cvss"):
                continue
            cv = r.get("cvss") or {}
            base = cv.get("effectiveBase")
            vec = (cv.get("vector") or "").strip()
            if base is None and not vec:
                continue
            any_row = True
            eid = html.escape(str(r.get("eid") or "?"))
            parts.append(
                "<tr><td><strong>"
                + eid
                + "</strong></td><td>"
                + html.escape("" if base is None else str(base))
                + "</td><td>"
                + html.escape(str(cv.get("effectiveSeverity") or ""))
                + "</td><td>"
                + html.escape(str(cv.get("effectiveSource") or ""))
                + "</td><td>"
                + html.escape(vec[:120])
                + "</td></tr>"
            )
        if not any_row:
            parts.append("<tr><td colspan='5'>No CVSS fields.</td></tr>")
        parts.append("</table>")
    if flags.get("iso"):
        parts.append("<h3>Annex ISO 27005 (style)</h3><table>")
        parts.append("<tr><th>Ref</th><th>L</th><th>I</th><th>Treatment</th></tr>")
        for r in rows:
            if not _row_annex_export_ok(r, "iso"):
                continue
            iso = r.get("iso27005") or {}
            if not iso.get("likelihood") or not iso.get("impact"):
                continue
            eid = html.escape(str(r.get("eid") or "?"))
            parts.append(
                f"<tr><td><strong>{eid}</strong></td><td>{html.escape(str(iso.get('likelihood')))}</td>"
                f"<td>{html.escape(str(iso.get('impact')))}</td>"
                f"<td>{html.escape(str(iso.get('treatment') or '')[:200])}</td></tr>"
            )
        parts.append("</table>")
    if flags.get("bsi"):
        parts.append("<h3>Annex BSI (style)</h3><table>")
        parts.append("<tr><th>Ref</th><th>Module</th><th>Need</th><th>Gap</th></tr>")
        for r in rows:
            if not _row_annex_export_ok(r, "bsi"):
                continue
            b = r.get("bsi") or {}
            if not b.get("protectionNeed") or not b.get("gap"):
                continue
            eid = html.escape(str(r.get("eid") or "?"))
            parts.append(
                f"<tr><td><strong>{eid}</strong></td><td>{html.escape(str(b.get('module') or '')[:80])}</td>"
                f"<td>{html.escape(str(b.get('protectionNeed')))}</td>"
                f"<td>{html.escape(str(b.get('gap') or '')[:300])}</td></tr>"
            )
        parts.append("</table>")
    if flags.get("nist"):
        parts.append("<h3>Annex NIST (style)</h3><table>")
        parts.append("<tr><th>Ref</th><th>Likelihood</th><th>Impact</th><th>CSF</th></tr>")
        for r in rows:
            if not _row_annex_export_ok(r, "nist"):
                continue
            n = r.get("nist") or {}
            if not n.get("likelihood") or not n.get("impact"):
                continue
            eid = html.escape(str(r.get("eid") or "?"))
            parts.append(
                f"<tr><td><strong>{eid}</strong></td><td>{html.escape(str(n.get('likelihood'))[:120])}</td>"
                f"<td>{html.escape(str(n.get('impact'))[:120])}</td>"
                f"<td>{html.escape(str(n.get('csfSubcategory') or '')[:60])}</td></tr>"
            )
        parts.append("</table>")
    return "\n".join(parts)


def resolve_din_xml_source(input_path: str) -> str:
    """
    DIN 5008 export needs the merged Nmap XML (e.g. merged_scan.xml), not the HTML report.
    If the user passes .html / .htm / extensionless file, look for merged_scan.xml nearby.
    """
    p = os.path.abspath(input_path)
    low = p.lower()
    if low.endswith(".xml"):
        return p
    d = os.path.dirname(p)
    candidates = [
        os.path.join(d, "merged_scan.xml"),
        os.path.join(os.getcwd(), "merged_scan.xml"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            print(f"[*] DIN 5008: using merged Nmap XML (not HTML): {c}")
            return c
    return p


def _load_eval_json(eval_json_path: Optional[str]) -> Optional[dict]:
    """Load and validate evaluation JSON file."""
    if not eval_json_path or not os.path.exists(eval_json_path):
        return None
    try:
        with open(eval_json_path, "r", encoding="utf-8") as f:
            payload = json.loads(f.read())
        if not isinstance(payload, dict):
            return None
        if "evaluations" not in payload:
            return None
        return payload
    except Exception as exc:
        print(f"[-] Failed to load eval JSON: {exc}")
        return None


def generate_din5008_pdf(
    xml_path: str, pdf_path: str, eval_json_path: Optional[str] = None
) -> bool:
    print("[*] Generating DIN 5008 PDF …")
    xml_path = resolve_din_xml_source(xml_path)
    try:
        tree = ET.parse(xml_path)
    except Exception as exc:
        print(f"[-] Cannot parse XML: {exc}")
        print(
            "[-] DIN export needs merged_scan.xml (merged Nmap), not report.html. "
            "Check the path, or run: python3 pdf_export.py --din --eval risk_evaluations.json merged_scan.xml"
        )
        return False

    root = tree.getroot()
    meta       = _meta(root)
    hosts      = _hosts(root)
    findings_all = sorted(_findings(root), key=lambda f: _severity_order(f.get("severity", "")))
    findings, ffuf_noise = _partition_ffuf_web_findings(findings_all)
    ffuf_n = len(ffuf_noise)
    ev_items   = _evidence_items(root)
    cmds       = _scan_commands(root)
    generated  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    toc_sections = []
    if findings or ffuf_n:
        toc_sections.append("Executive Summary")
    if findings:
        for i, f in enumerate(findings, 1):
            sev   = f.get("severity", "?").upper()
            ftype = f.get("type", "finding").replace("_", " ")
            toc_sections.append(f"[{sev}] {ftype}")
    if ffuf_n:
        toc_sections.append(f"Web discovery (ffuf), {ffuf_n} hits — HTML tactical matrix only")
    if any(h["ports"] for h in hosts):
        toc_sections.append("Network Services")
    if cmds:
        toc_sections.append("Scan Commands")
    if ev_items:
        toc_sections.append("Evidence Appendix")

    cover    = _cover_html(meta, hosts, generated)
    eval_payload_early = _load_eval_json(eval_json_path)
    exec_sum = _exec_summary_html(meta, findings, ffuf_n)
    risk_blurb = _risk_exec_blurb_from_eval(eval_payload_early)
    if risk_blurb:
        if exec_sum.strip():
            exec_sum = exec_sum + risk_blurb
        else:
            exec_sum = "<h2>Executive Summary</h2>\n" + risk_blurb
    if exec_sum.strip() and "Executive Summary" not in toc_sections:
        toc_sections.insert(0, "Executive Summary")
    toc      = _toc_html(toc_sections) if toc_sections else ""
    finds    = "".join(_finding_html(f, i) for i, f in enumerate(findings, 1))
    finds_sec = f"<h2>Findings</h2>{finds}" if finds else ""
    ports_sec = _ports_html(hosts)
    scans_sec = _scans_html(cmds)
    ev_sec    = _evidence_html(ev_items)

    eval_extra = ""
    eval_payload = eval_payload_early
    if eval_payload:
        eval_extra = _din_eval_annexes_from_export(eval_payload)
        # Add annex titles to TOC
        flags = eval_payload.get("pdfInclude", {})
        evals = eval_payload.get("evaluations", {})
        if flags.get("cvss") and any(e.get("cvss", {}).get("vector") or e.get("cvss", {}).get("baseScore") for e in evals.values()):
            toc_sections.append("Annex: CVSS assessments")
        if flags.get("iso") and any(e.get("iso27005", {}).get("likelihood") and e.get("iso27005", {}).get("impact") for e in evals.values()):
            toc_sections.append("Annex: ISO 27005 risk matrix")
        if flags.get("bsi") and any(e.get("bsi", {}).get("protectionNeed") for e in evals.values()):
            toc_sections.append("Annex: BSI IT-Grundschutz")
        if flags.get("nist") and any(e.get("nist", {}).get("likelihood") and e.get("nist", {}).get("impact") for e in evals.values()):
            toc_sections.append("Annex: NIST SP 800-30")

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
{eval_extra}
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


# ---------------------------------------------------------------------------
# CLI interface
# ---------------------------------------------------------------------------

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="PDF export for evidence2html reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 pdf_export.py report.html
  python3 pdf_export.py --16x9 report.html
  python3 pdf_export.py --reader report.html
  python3 pdf_export.py --din merged_scan.xml
  python3 pdf_export.py --din --eval risk_evaluations.json merged_scan.xml
  # (report.html is resolved to merged_scan.xml when that file sits alongside it)
        """
    )
    parser.add_argument("input", help="Input HTML or XML file")
    parser.add_argument("-o", "--output", help="Output PDF path (default: auto-generated)")
    parser.add_argument("--16x9", dest="mode_16x9", action="store_true",
                        help="Generate 16:9 PDF (default if input is HTML)")
    parser.add_argument("--reader", dest="mode_reader", action="store_true",
                        help="Generate reader A4 PDF from HTML (structure-faithful, muted palette)")
    parser.add_argument("--din", dest="mode_din", action="store_true",
                        help="Generate DIN 5008 PDF (default if input is XML)")
    parser.add_argument("--eval", dest="eval_json", 
                        help="Path to risk_evaluations.json for DIN 5008 annexes")
    
    args = parser.parse_args()
    
    input_path = os.path.abspath(args.input)
    if not os.path.exists(input_path):
        print(f"[-] Input file not found: {input_path}")
        sys.exit(1)
    
    # Determine mode based on file extension if not specified
    is_xml = input_path.lower().endswith(".xml")
    is_html = input_path.lower().endswith(".html") or input_path.lower().endswith(".htm")
    
    if not args.mode_16x9 and not args.mode_reader and not args.mode_din:
        if is_xml:
            args.mode_din = True
        else:
            args.mode_16x9 = True
    
    stem = os.path.splitext(input_path)[0]
    active = int(args.mode_16x9) + int(args.mode_reader) + int(args.mode_din)
    single_out = args.output if active == 1 else None

    if args.mode_16x9:
        out_16 = single_out if single_out else f"{stem}_16x9.pdf"
        if generate_16x9_pdf(input_path, out_16):
            print(f"[✓] 16:9 PDF generated: {out_16}")
        else:
            print("[-] Failed to generate 16:9 PDF")
            sys.exit(1)

    if args.mode_reader:
        if not is_html:
            print("[-] --reader requires an HTML report path")
            sys.exit(1)
        out_r = single_out if single_out else f"{stem}_reader.pdf"
        if generate_reader_pdf(input_path, out_r):
            print(f"[✓] Reader A4 PDF generated: {out_r}")
        else:
            print("[-] Failed to generate reader PDF")
            sys.exit(1)

    if args.mode_din:
        output_path = single_out if single_out else f"{stem}_din5008.pdf"
        eval_path = args.eval_json
        
        # Auto-detect eval JSON if not specified
        if not eval_path:
            auto_eval = os.path.join(os.path.dirname(input_path), "risk_evaluations.json")
            if os.path.exists(auto_eval):
                print(f"[*] Auto-detected risk evaluations: {auto_eval}")
                eval_path = auto_eval
        
        if generate_din5008_pdf(input_path, output_path, eval_path):
            print(f"[✓] DIN 5008 PDF generated: {output_path}")
        else:
            print("[-] Failed to generate DIN 5008 PDF")
            sys.exit(1)


if __name__ == "__main__":
    main()
