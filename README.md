# evidence2html

Collect pen-test tool output in one folder, run a short interactive CLI, get a **single self-contained HTML report** (Nmap merge + evidence + optional ASCII banner). Optional **PDFs**: 16:9 slide-style from the HTML, and **DIN-style A4** matching `pdf_export.py` (same sections: cover, contents, executive summary, findings, services, scans, evidence).

![Scan summary, theme, ASCII banner, export menu](readme_png/2026-03-25_21-02.png)

## Requirements

- Python 3.8+
- `xsltproc` (e.g. `sudo apt install xsltproc` on Debian/Kali)
- For PDF: Chromium or Chrome on the PATH (`chromium`, `google-chrome`, …)

No pip dependencies.

## Quick start

```bash
git clone https://github.com/CosmicSlothOracle/evidence2html.git
cd evididencetohtml
python3 evidence2html.py
```

You’ll be prompted for the evidence directory and output name. The script finds Nmap XMLs, evidence files, optional `nuclei.json`, merges to `merged_scan.xml`, runs `xsltproc` with `cosmic_clean.xsl`, and can offer **16:9** and **DIN 5008** PDFs via Chromium.

## What the HTML report does

- **Scope block**: target, scan time, counts, tools list — fields are editable; values are stored in the browser (`localStorage`) for your session.
- **ASCII art**: optional `ascii_arts/*.txt` next to the repo or under your evidence folder; themes in the sidebar swap palette and pick a matching banner when available.
- **Port matrix**: per-port status, service, version, **extra info**, **analyst notes**, and scan command rows with editable notes. DIN 5008 cover fields live in the header area for browser PDF export.

![Port matrix, cover fields, command context, evidence refs](readme_png/2026-03-25_21-00.png)

- **Evidence**: each artifact is expandable; you can edit title, summary, raw text, and **comments**. References `E1`…`En` can be used in notes for jump links. Optional per-finding **risk** panels (CVSS, ISO 27005, BSI, NIST) tie into annex material when you export `risk_evaluations.json` / use the PDF panel.

![Evidence, risk assessment UI, ISO 27005 annex in PDF](readme_png/2026-03-25_20-55.png)

- **Export HTML**: downloads the current page (including your edits in the DOM at click time).
- **Export DIN 5008 PDF**: opens a **print** window whose layout matches the Python `generate_din5008_pdf` output. Before building, it **pulls in `localStorage`** (evidence edits, port/command notes, scope, hero note, DIN cover fields) so the PDF reflects what you typed in the browser.

![DIN-style PDF: structure, summary tables, services, evidence](readme_png/2026-03-25_21-03.png)

CLI-generated DIN PDF uses the same structure from `merged_scan.xml`; browser export adds your **live annotations** on top.

## Evidence layout (typical)

```
my_run/
  scan_tcp.xml
  scan_udp.xml
  nuclei.json          # optional
  evidence_ffuf_*.json
  evidence_*.txt
  ascii_arts/          # optional; or use repo’s ascii_arts/
    alice.txt
```

## Naming hints

Files are classified by prefix (`evidence_ffuf_*`, `evidence_sqlmap_*`, `banner_*`, …). See `evidence2html.py` (`infer_tool` / collectors) if you need the full list.

## Repo layout

| File | Role |
|------|------|
| `evidence2html.py` | Interactive pipeline, merge, optional PDFs |
| `cosmic_clean.xsl` | HTML + in-browser export logic |
| `pdf_export.py` | Chromium PDF helpers (16:9 + DIN from XML) |
| `risk_metrics.py`, `vuln_ref_lookup.py`, `nvd_cve_lookup.py` | Risk annexes + CVE reference lookup |

## License

MIT
