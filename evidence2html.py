#!/usr/bin/env python3
"""
evidence2html — collect pen-test evidence files, merge with optional Nmap XML,
and produce a single self-contained HTML report via xsltproc + XSL stylesheet.

Risk annex workflow (CVSS / ISO 27005 / BSI / NIST):
    1. Open the generated HTML: use **Export ▾** in the overview (or per-evidence risk panels).
       From the browser: full HTML export, DIN 5008 print/PDF, 16:9 print/PDF,
       reader A4 print/PDF, and risk_evaluations.json — aligned with pdf_export.py.
    2. Optional CLI: place risk_evaluations.json next to the report for auto-detect when
       generating DIN PDF from this script.
    3. CVE technical reference (NVD + EPSS + CISA KEV): run
       ``python3 vuln_ref_lookup.py CVE-… --json`` and paste into the report CVSS panel
       (technical reference only — separate from ISO/BSI/NIST organizational fields).
    4. Reader A4 PDF (optional): ``--reader-pdf`` — same report structure as HTML,
       hierarchy-first typography and muted palette (Chromium); see pdf_export.generate_reader_pdf.

Usage:
    python3 evidence2html.py                                    # interactive wizard (8 steps)
    python3 evidence2html.py path/to/evidence/ -o report.html   # non-interactive batch
    python3 evidence2html.py path/to/evidence/ --no-pdf
    python3 evidence2html.py path/to/evidence/ --eval-json risk_evaluations.json
    python3 evidence2html.py path/to/evidence/ -o report.html --fetch-cve-refs  # CVE bundle, no prompt
    python3 evidence2html.py path/to/evidence/ -o report.html --reader-pdf      # + reader A4 PDF
"""

import argparse
import datetime
import glob
import importlib.util
import shutil
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import xml.etree.ElementTree as ET
from typing import List, Optional
from urllib.parse import urlparse

try:
    from pdf_export import generate_16x9_pdf, generate_din5008_pdf, generate_reader_pdf
    _PDF_AVAILABLE = True
except ImportError:
    _PDF_AVAILABLE = False

DEFAULT_CYBERSTEPPER_ART = r"""
   ______      __                _____ __                             
  / ____/_  __/ /_  ___  _____  / ___// /____  ____  ____  ___  _____
 / /   / / / / __ \/ _ \/ ___/  \__ \/ __/ _ \/ __ \/ __ \/ _ \/ ___/
/ /___/ /_/ / /_/ /  __/ /     ___/ / /_/  __/ /_/ / /_/ /  __/ /    
\____/\__, /_.___/\___/_/     /____/\__/\___/ .___/ .___/\___/_/     
     /____/                                 /_/   /_/                 
"""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _terminal_columns(fallback: int = 80) -> int:
    """Best-effort terminal width for CLI banner fit checks."""
    try:
        w = shutil.get_terminal_size().columns
        return max(40, w)
    except Exception:
        return fallback


def _banner_max_display_width(text: str) -> int:
    return max((len(line.expandtabs(8)) for line in text.splitlines()), default=0)


def _load_optional_custom_cli_banner(script_dir: str) -> str:
    """Load example_ascii.py → example_ascii.txt if present; empty string on failure."""
    loader = os.path.join(script_dir, "example_ascii.py")
    if not os.path.isfile(loader):
        return ""
    try:
        spec = importlib.util.spec_from_file_location(
            "_evidence2html_cli_banner", loader
        )
        if spec is None or spec.loader is None:
            return ""
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        fn = getattr(mod, "get_cli_banner", None)
        if not callable(fn):
            return ""
        return str(fn() or "").strip()
    except Exception:
        return ""


def _print_cli_banner(script_dir: str) -> None:
    """
    Print a startup banner. Custom art (example_ascii.txt via example_ascii.py) is
    used only if every line fits the current terminal width; otherwise fall back to
    DEFAULT_CYBERSTEPPER_ART. For portable art, keep lines ≤ 72–80 characters.
    """
    custom = _load_optional_custom_cli_banner(script_dir)
    term_w = _terminal_columns()
    if custom and _banner_max_display_width(custom) <= term_w:
        print(custom, flush=True)
    else:
        print(DEFAULT_CYBERSTEPPER_ART.strip("\n"), flush=True)
    print(flush=True)


def safe_read_text(path, max_chars=120_000):
    binary_ext = {".pcap", ".pcapng", ".cap", ".zip", ".7z", ".burp", ".sqlite", ".db"}
    ext = os.path.splitext(path)[1].lower()
    if ext in binary_ext:
        try:
            size = os.path.getsize(path)
        except OSError:
            size = -1
        return f"[binary-evidence] {os.path.basename(path)} ({size} bytes)"
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(max_chars)
    except Exception as exc:
        return f"[read-error] {exc}"


def sanitize_for_xml(text):
    if not text:
        return ""
    result = []
    for c in text:
        code = ord(c)
        if code in (0x9, 0xA, 0xD) or 0x20 <= code <= 0xD7FF \
                or 0xE000 <= code <= 0xFFFD or 0x10000 <= code <= 0x10FFFF:
            result.append(c)
        else:
            result.append("\uFFFD")
    return "".join(result)


def compact_flags(args):
    if not args:
        return ""
    try:
        toks = shlex.split(args)
    except ValueError:
        toks = args.split()
    if not toks:
        return ""

    no_value = {
        "-Pn", "-n", "-sV", "-sS", "-sU", "-O", "-A", "-v", "-vv",
        "--privileged", "--reason", "--open", "--disable-arp-ping", "--top-ports",
    }
    skip_value = {"-oX", "-oN", "-oG", "-oA", "--stylesheet"}
    flags = []
    i = 0
    while i < len(toks):
        tok = toks[i]
        if tok.startswith("-"):
            if "=" in tok:
                if tok.startswith("--stylesheet="):
                    i += 1
                    continue
                flags.append(tok)
            elif tok in no_value:
                flags.append(tok)
            else:
                if tok in skip_value:
                    if i + 1 < len(toks) and not toks[i + 1].startswith("-"):
                        i += 1
                    i += 1
                    continue
                flags.append(tok)
                if i + 1 < len(toks) and not toks[i + 1].startswith("-"):
                    flags.append(toks[i + 1])
                    i += 1
        i += 1
    return " ".join(flags).strip()


def summarize_text(content):
    for line in content.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped[:200]
    return "No non-empty lines"


def normalize_evidence_for_dedup(content: str) -> str:
    if not content:
        return ""
    if content.strip().startswith(("[binary-evidence]", "[read-error]")):
        return content.strip()
    return " ".join(content.split()).lower()


# ---------------------------------------------------------------------------
# Evidence collection
# ---------------------------------------------------------------------------

def _evidence_search_roots(evidence_dir: str) -> list:
    roots = [evidence_dir]
    try:
        for name in sorted(os.listdir(evidence_dir)):
            p = os.path.join(evidence_dir, name)
            if os.path.isdir(p):
                roots.append(p)
    except OSError:
        pass
    return roots


def _gather_evidence_paths(evidence_dir: str, patterns: list) -> list:
    paths = []
    for root in _evidence_search_roots(evidence_dir):
        for pattern in patterns:
            paths.extend(glob.glob(os.path.join(root, pattern)))
    return paths


def infer_tool(filename):
    name = os.path.basename(filename).lower()
    tool_map = [
        ("evidence_ffuf", "ffuf"), ("evidence_sqlmap", "sqlmap"),
        ("evidence_tshark", "tshark"), ("evidence_wireshark", "tshark"),
        ("evidence_testssl", "testssl.sh"), ("evidence_amass", "amass"),
        ("evidence_nikto", "nikto"), ("evidence_msf", "metasploit"),
        ("evidence_cme", "netexec"), ("evidence_nxc", "netexec"),
        ("evidence_bh", "bloodhound"), ("evidence_burp", "burp"),
        ("evidence_dns", "dig"), ("evidence_subfinder", "subfinder"),
        ("evidence_httpx", "httpx"), ("evidence_nuclei", "nuclei"),
        ("evidence_subdomains", "subdomain_hunt"),
        ("evidence_naabu", "naabu"), ("evidence_validation", "validation"),
        ("evidence_searchsploit", "searchsploit"), ("evidence_katana", "katana"),
        ("evidence_gowitness", "gowitness"), ("evidence_trufflehog", "trufflehog"),
        ("evidence_lynis", "lynis"), ("evidence_unfurl", "unfurl"),
        ("evidence_patterns", "gf/grep"), ("evidence_shodan", "shodan"),
        ("evidence_yara", "yara"),
        ("banner_", "bash/nc"), ("ttl_check", "nmap"),
        ("stealth_ping", "nmap"), ("socks5_probe", "nc"),
        ("rdp_probe", "nc"),
    ]
    for prefix, tool in tool_map:
        if name.startswith(prefix):
            return tool
    if name.endswith(".hex"):
        return "nc/xxd"
    return "unknown"


def evidence_status(content, filepath):
    if not content or not content.strip():
        return "EMPTY"
    if content.strip().startswith("[read-error]"):
        return "ERROR"
    if content.strip().startswith("[binary-evidence]"):
        return "BINARY"
    return "OK"


def classify_evidence(filename):
    name = os.path.basename(filename).lower()
    categories = [
        ("evidence_ffuf", "fuzzing"), ("evidence_sqlmap", "sqli"),
        ("evidence_tshark", "packet-analysis"), ("evidence_wireshark", "packet-analysis"),
        ("evidence_testssl", "tls-analysis"), ("evidence_amass", "asset-enum"),
        ("evidence_nikto", "web-vuln-scan"), ("evidence_msf", "exploitation-framework"),
        ("evidence_cme", "lateral-movement"), ("evidence_nxc", "lateral-movement"),
        ("evidence_bh", "ad-graph"), ("evidence_burp", "web-manual-testing"),
        ("evidence_searchsploit", "exploitation"), ("evidence_katana", "fuzzing"),
        ("evidence_gowitness", "recon"), ("evidence_trufflehog", "secrets"),
        ("evidence_lynis", "defensive-audit"), ("evidence_unfurl", "traceability"),
        ("evidence_patterns", "pattern-hunt"), ("evidence_shodan", "internet-recon"),
        ("evidence_yara", "threat-hunt"), ("evidence_dns", "dns"),
        ("evidence_subfinder", "passive-enum"), ("evidence_httpx", "web-fingerprint"),
        ("evidence_nuclei", "vulnerability"), ("evidence_subdomains", "subdomains"),
        ("banner_", "banner"), ("ttl_check", "packet-analysis"),
        ("stealth_ping", "connectivity"),
    ]
    for prefix, cat in categories:
        if name.startswith(prefix):
            return cat
    if name.endswith(".hex") or "probe" in name:
        return "protocol-probe"
    return "other"


# ---------------------------------------------------------------------------
# Evidence parsers  (structured extraction for known tool outputs)
# ---------------------------------------------------------------------------

FFUF_MAX_INSIGHT_ROWS = 500


def parse_ffuf_dict(data, max_results=FFUF_MAX_INSIGHT_ROWS):
    """Build tactical findings from ffuf JSON object (full result set may be huge)."""
    findings = []
    try:
        results = data.get("results") or []
        non404 = [r for r in results if r.get("status", 0) != 404]

        def _interest_score(res):
            s = int(res.get("status", 0) or 0)
            if s == 200:
                return 0
            if 300 <= s < 400:
                return 1
            if s in (401, 403):
                return 2
            if s >= 500:
                return 3
            return 4

        non404.sort(key=_interest_score)
        for res in non404[:max_results]:
            status = res.get("status", 0)
            findings.append({
                "tool": "ffuf", "type": "web_discovery",
                "host": res.get("host", ""), "url": res.get("url", ""),
                "status": str(status), "length": str(res.get("length", 0)),
                "words": str(res.get("words", 0)), "lines": str(res.get("lines", 0)),
                "content_type": res.get("content-type", ""),
                "dedup_key": f"{res.get('url', '')}_{status}",
            })
    except Exception:
        pass
    return findings


def parse_ffuf(content, filename):
    try:
        data = json.loads(content)
    except Exception:
        return []
    return parse_ffuf_dict(data, max_results=FFUF_MAX_INSIGHT_ROWS)


def parse_testssl(content, filename):
    findings = []
    try:
        data = json.loads(content)
        result_list = []
        if isinstance(data, dict):
            result_list = data.get("scanResult", data.get("findings", data.get("vulnerabilities", [])))
            if isinstance(result_list, dict):
                result_list = list(result_list.values()) if result_list else []
            if not isinstance(result_list, list):
                result_list = []
        elif isinstance(data, list):
            result_list = data
        for res in result_list:
            severity = res.get("severity", "").upper()
            if severity in ("HIGH", "CRITICAL", "MEDIUM"):
                findings.append({
                    "tool": "testssl", "type": "tls_vuln",
                    "host": res.get("ip", "").split("/")[0],
                    "port": res.get("port", ""), "severity": severity,
                    "finding": res.get("finding", ""), "id": res.get("id", ""),
                    "cve": res.get("cve", ""),
                    "dedup_key": f"{res.get('id', '')}_{res.get('ip', '')}_{res.get('port', '')}",
                })
    except Exception:
        pass
    return findings


def parse_sqlmap(content, filename):
    findings = []
    target_match = re.search(r"Target:\s*(https?://[^\s]+)", content)
    host = ""
    if target_match:
        try:
            host = urlparse(target_match.group(1)).hostname or ""
        except Exception:
            host = target_match.group(1)
    for m in re.finditer(r"parameter '([^']+)' (?:appears to be|is) '(.*?)' injectable", content, re.IGNORECASE):
        findings.append({
            "tool": "sqlmap", "type": "sqli", "host": host,
            "target": target_match.group(1) if target_match else "",
            "param": m.group(1), "detail": m.group(2), "severity": "CRITICAL",
            "dedup_key": f"{host}_{m.group(1)}_{m.group(2)}",
        })
    return findings


def parse_netexec(content, filename):
    findings = []
    for m in re.finditer(
        r"(SMB|WINRM|SSH|MSSQL|LDAP|RDP)\s+([0-9a-fA-F:\.]+)\s+(\d+)\s+([^\s]+)\s+\[\+\]\s+(.*)", content
    ):
        severity = "CRITICAL" if "Pwn3d!" in m.group(5) else "HIGH"
        findings.append({
            "tool": "netexec", "type": "ad_auth", "host": m.group(2),
            "port": m.group(3), "protocol": m.group(1),
            "target_name": m.group(4), "detail": m.group(5), "severity": severity,
            "dedup_key": f"{m.group(2)}_{m.group(1)}_{m.group(5)}",
        })
    return findings


def parse_msf(content, filename):
    findings = []
    rhost_match = re.search(r"RHOST(?:S)?\s*=>\s*([0-9a-fA-F:\.]+)", content)
    host = rhost_match.group(1) if rhost_match else ""
    for m in re.finditer(r"(Meterpreter session|Command shell session)\s+\d+\s+opened\s+\(([^\)]+)\)", content):
        target = host
        if not target and "->" in m.group(2):
            target = m.group(2).strip()
        findings.append({
            "tool": "metasploit", "type": "exploit", "host": target,
            "detail": f"{m.group(1)} opened ({m.group(2)})", "severity": "CRITICAL",
            "dedup_key": f"msf_{m.group(1)}_{m.group(2)}",
        })
    return findings


def parse_subdomains(content, filename):
    findings = []
    for line in content.splitlines():
        host = line.strip()
        if not host or host.startswith("#"):
            continue
        findings.append({
            "tool": "subdomain_hunt", "type": "subdomain", "host": host,
            "source": os.path.basename(filename), "dedup_key": host,
        })
    return findings


def parse_evidence_content(category, content, filename):
    dispatch = {
        "fuzzing": parse_ffuf, "tls-analysis": parse_testssl,
        "sqli": parse_sqlmap, "lateral-movement": parse_netexec,
        "exploitation-framework": parse_msf, "subdomains": parse_subdomains,
    }
    parser = dispatch.get(category)
    return parser(content, filename) if parser else []


def collect_evidence(evidence_dir):
    items, stats = [], {
        "skipped_empty": 0, "skipped_duplicate": 0,
        "skipped_empty_files": [], "skipped_duplicate_files": [],
    }
    if not evidence_dir or not os.path.isdir(evidence_dir):
        return items, stats

    patterns = ["evidence_*", "*.hex", "banner_*", "ttl_check_*", "stealth_ping.*"]
    paths = sorted(
        set(_gather_evidence_paths(evidence_dir, patterns)),
        key=lambda x: os.path.getmtime(x) if os.path.exists(x) else 0,
    )

    dedup_keys = set()
    for path in paths:
        if os.path.isdir(path):
            continue
        bn_low = os.path.basename(path).lower()
        cat = classify_evidence(path)
        tool = infer_tool(path)

        # Large ffuf JSON: parse full file for findings; keep small raw + hash-based dedup
        if bn_low.startswith("evidence_ffuf") and bn_low.endswith(".json"):
            try:
                with open(path, "rb") as bf:
                    raw_bytes = bf.read()
                file_hash = hashlib.sha256(raw_bytes).hexdigest()
                data = json.loads(raw_bytes.decode("utf-8", errors="replace"))
            except Exception:
                pass
            else:
                status = "OK"
                nres = len(data.get("results") or [])
                parsed_findings = parse_ffuf_dict(data, max_results=FFUF_MAX_INSIGHT_ROWS)
                cmd = data.get("commandline") or ""
                raw_out = (
                    f"[ffuf JSON — {os.path.basename(path)} — {nres} results in file, "
                    f"{len(parsed_findings)} non-404 rows exported to tactical matrix (cap {FFUF_MAX_INSIGHT_ROWS})]\n\n"
                    f"commandline: {cmd}\n\n"
                    f"full path: {path}"
                )
                summary = f"ffuf JSON: {nres} results ({len(parsed_findings)} exported to matrix)"
                dk = hashlib.sha256(f"{tool}|{cat}|{file_hash}".encode("utf-8", errors="ignore")).hexdigest()
                if dk in dedup_keys:
                    stats["skipped_duplicate"] += 1
                    stats["skipped_duplicate_files"].append(path)
                    continue
                dedup_keys.add(dk)
                mtime = os.path.getmtime(path)
                items.append({
                    "file": os.path.basename(path),
                    "timestamp": datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S"),
                    "category": cat, "tool": tool, "status": status,
                    "summary": summary[:500],
                    "raw": raw_out,
                    "findings": parsed_findings,
                })
                continue

        content = safe_read_text(path)
        status = evidence_status(content, path)
        if status == "EMPTY":
            stats["skipped_empty"] += 1
            stats["skipped_empty_files"].append(path)
            continue

        parsed_findings = parse_evidence_content(cat, content, path) if status == "OK" else []
        norm = normalize_evidence_for_dedup(content)
        dk = hashlib.sha256(f"{tool}|{cat}|{norm}".encode("utf-8", errors="ignore")).hexdigest()
        if dk in dedup_keys:
            stats["skipped_duplicate"] += 1
            stats["skipped_duplicate_files"].append(path)
            continue
        dedup_keys.add(dk)

        mtime = os.path.getmtime(path)
        items.append({
            "file": os.path.basename(path),
            "timestamp": datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S"),
            "category": cat, "tool": tool, "status": status,
            "summary": summarize_text(content), "raw": content,
            "findings": parsed_findings,
        })
    return items, stats


# ---------------------------------------------------------------------------
# ASCII art loader
# ---------------------------------------------------------------------------

def load_ascii_arts(ascii_dir):
    arts = {}
    if not ascii_dir or not os.path.isdir(ascii_dir):
        return {"cyberstepper": DEFAULT_CYBERSTEPPER_ART.strip("\n")}
    for path in sorted(glob.glob(os.path.join(ascii_dir, "*.txt"))):
        if os.path.isdir(path):
            continue
        key = os.path.splitext(os.path.basename(path))[0].strip().lower()
        if not key:
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                art = f.read().strip("\n")
        except OSError:
            continue
        if art.strip():
            arts[key] = art
    if not arts:
        return {"cyberstepper": DEFAULT_CYBERSTEPPER_ART.strip("\n")}
    return arts


# ---------------------------------------------------------------------------
# Nmap XML helpers
# ---------------------------------------------------------------------------

def scan_results_by_port(tree):
    results = []
    for host in tree.getroot().findall("host"):
        addr = host.find("address")
        host_ip = addr.get("addr", "") if addr is not None else ""
        for port in host.findall("ports/port"):
            service = port.find("service")
            state = port.find("state")
            results.append({
                "host": host_ip,
                "portid": port.get("portid", ""),
                "protocol": port.get("protocol", ""),
                "state": state.get("state", "") if state is not None else "",
                "reason": state.get("reason", "") if state is not None else "",
                "service": service.get("name", "") if service is not None else "",
                "version": service.get("version", "") if service is not None else "",
                "product": service.get("product", "") if service is not None else "",
            })
    return results


def parse_nuclei_json(nuclei_json):
    summary_lines = []
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    if not nuclei_json or not os.path.exists(nuclei_json):
        return "", severity_counts
    raw = safe_read_text(nuclei_json, max_chars=10_000_000)
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            data = json.loads(line)
        except Exception:
            continue
        info = data.get("info", {})
        severity = str(info.get("severity", "unknown")).lower()
        if severity not in severity_counts:
            severity = "unknown"
        severity_counts[severity] += 1
        tid = data.get("template-id", "unknown-template")
        name = info.get("name", "Unknown")
        matched = data.get("matched-at", data.get("url", "unknown-target"))
        summary_lines.append(f"[{severity.upper()}] {tid} - {name}\n  Match: {matched}")
    return "\n\n".join(summary_lines), severity_counts


def merge_host_data(existing_host, new_host):
    existing_ports = existing_host.find("ports")
    new_ports = new_host.find("ports")
    if new_ports is not None:
        if existing_ports is None:
            existing_host.append(new_ports)
        else:
            port_map = {
                (p.get("protocol", ""), p.get("portid", "")): p
                for p in existing_ports.findall("port")
            }
            for np in new_ports.findall("port"):
                key = (np.get("protocol", ""), np.get("portid", ""))
                if key not in port_map:
                    existing_ports.append(np)
                    port_map[key] = np
                else:
                    ep = port_map[key]
                    existing_scripts = {(s.get("id"), s.get("output", "")) for s in ep.findall("script")}
                    for ns in np.findall("script"):
                        marker = (ns.get("id"), ns.get("output", ""))
                        if marker not in existing_scripts:
                            ep.append(ns)
                            existing_scripts.add(marker)
                    es = ep.find("service")
                    ns_svc = np.find("service")
                    if es is not None and ns_svc is not None:
                        if not es.get("servicefp") and ns_svc.get("servicefp"):
                            es.set("servicefp", ns_svc.get("servicefp"))

    if existing_host.find("os") is None and new_host.find("os") is not None:
        existing_host.append(new_host.find("os"))

    existing_hs = existing_host.find("hostscript")
    new_hs = new_host.find("hostscript")
    if new_hs is not None:
        if existing_hs is None:
            existing_host.append(new_hs)
        else:
            markers = {(s.get("id"), s.get("output", "")) for s in existing_hs.findall("script")}
            for ns in new_hs.findall("script"):
                m = (ns.get("id"), ns.get("output", ""))
                if m not in markers:
                    existing_hs.append(ns)
                    markers.add(m)


# ---------------------------------------------------------------------------
# XML construction and metadata
# ---------------------------------------------------------------------------

def add_metadata(base_root, stats, malformed_files, evidence_items,
                 nuclei_counts, global_severities, ascii_arts=None):
    meta = ET.SubElement(base_root, "cosmicmeta")
    summary = ET.SubElement(meta, "summary")
    for k, v in stats.items():
        summary.set(k, str(v))
    summary.set("report_generated", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    for sev, count in global_severities.items():
        summary.set(f"threat_{sev}", str(count))

    malformed = ET.SubElement(meta, "malformed_inputs")
    for item in malformed_files:
        el = ET.SubElement(malformed, "file")
        el.set("path", item["path"])
        el.set("reason", item["reason"])

    all_findings, seen = [], set()
    for item in evidence_items:
        for f in item.get("findings", []):
            k = f.get("dedup_key")
            if k and k not in seen:
                all_findings.append(f)
                seen.add(k)
            elif not k:
                all_findings.append(f)

    if all_findings:
        insights = ET.SubElement(base_root, "cosmicinsights")
        for f in all_findings:
            el = ET.SubElement(insights, "finding")
            for k, v in f.items():
                if k != "dedup_key":
                    el.set(k, str(v))

    subs = sorted(
        [f for f in all_findings if f.get("type") == "subdomain"],
        key=lambda x: x.get("host", ""),
    )
    if subs:
        subs_root = ET.SubElement(base_root, "cosmicsubdomains")
        for entry in subs:
            h = entry.get("host", "")
            if not h:
                continue
            el = ET.SubElement(subs_root, "subdomain")
            el.set("host", h)
            if entry.get("source"):
                el.set("source", entry["source"])

    if ascii_arts:
        ascii_root = ET.SubElement(base_root, "cosmicascii")
        for name, art in ascii_arts.items():
            art_el = ET.SubElement(ascii_root, "art")
            art_el.set("name", name)
            art_el.text = art

    ev_root = ET.SubElement(base_root, "cosmicevidence")
    for item in evidence_items:
        el = ET.SubElement(ev_root, "item")
        el.set("file", item["file"])
        if "timestamp" in item:
            el.set("timestamp", item["timestamp"])
        el.set("category", item["category"])
        el.set("tool", item.get("tool", "unknown"))
        el.set("status", item.get("status", "OK"))
        el.set("summary", sanitize_for_xml(item["summary"]))
        raw = ET.SubElement(el, "raw")
        raw.text = sanitize_for_xml(item["raw"])


def count_stats(base_root, total_inputs, parsed_inputs, malformed_count,
                evidence_count, skipped_empty=0, skipped_duplicate=0):
    host_count = len(base_root.findall("host"))
    port_count = script_count = 0
    for host in base_root.findall("host"):
        ports = host.findall("ports/port")
        port_count += len(ports)
        for port in ports:
            script_count += len(port.findall("script"))
        script_count += len(host.findall("hostscript/script"))
    return {
        "input_total": total_inputs, "parsed_inputs": parsed_inputs,
        "malformed_inputs": malformed_count, "hosts": host_count,
        "ports": port_count, "scripts": script_count,
        "evidence_files": evidence_count,
        "evidence_empty_skipped": skipped_empty,
        "evidence_duplicate_skipped": skipped_duplicate,
    }


# ---------------------------------------------------------------------------
# Core pipeline
# ---------------------------------------------------------------------------

def merge_nmap_xml(input_files, output_xml, stylesheet_path,
                   nuclei_json=None, evidence_dir=None, ascii_dir=None):
    if not input_files:
        print("[*] No Nmap XML files — building evidence-only report …")
        base_root = ET.Element(
            "nmaprun", scanner="cosmic-evidence-only", start="0",
            startstr="Evidence only mode", version="1.0", xmloutputversion="1.04",
        )
        parsed, malformed_files, scan_commands = [], [], []
    else:
        print(f"[*] Merging {len(input_files)} XML file(s) …")
        parsed, malformed_files = [], []
        for fp in input_files:
            try:
                parsed.append((fp, ET.parse(fp)))
            except Exception as exc:
                malformed_files.append({"path": fp, "reason": str(exc)})
                print(f"[-] Error parsing {fp}: {exc}")
        if not parsed:
            print("[-] No parseable XML files.")
            return False

        scan_commands = []
        for fp, tree in parsed:
            root = tree.getroot()
            cmd_args = root.get("args", "nmap (unknown args)")
            scan_commands.append({
                "file": os.path.basename(fp), "args": cmd_args,
                "flags": compact_flags(cmd_args),
                "startstr": root.get("startstr", ""),
                "start": root.get("start", ""), "tool": "nmap",
                "results": scan_results_by_port(tree),
            })
        base_root = parsed[0][1].getroot()
        print(f"[*] Base XML: {parsed[0][0]}")

    hosts_dict = {}
    for host in base_root.findall("host"):
        addr = host.find("address")
        if addr is not None and addr.get("addr"):
            hosts_dict[addr.get("addr")] = host

    for fp, tree in parsed[1:]:
        print(f"[*] Processing {fp} …")
        for host in tree.getroot().findall("host"):
            addr = host.find("address")
            if addr is None or not addr.get("addr"):
                continue
            ip = addr.get("addr")
            if ip not in hosts_dict:
                base_root.append(host)
                hosts_dict[ip] = host
            else:
                merge_host_data(hosts_dict[ip], host)

    nuclei_text, nuclei_counts = parse_nuclei_json(nuclei_json)
    if nuclei_text:
        print(f"[*] Injecting Nuclei results into {len(hosts_dict)} host(s) …")
        for host in hosts_dict.values():
            hs = host.find("hostscript")
            if hs is None:
                hs = ET.SubElement(host, "hostscript")
            s = ET.SubElement(hs, "script")
            s.set("id", "nuclei-scan-results")
            s.set("output", nuclei_text)

    evidence_items, ev_stats = collect_evidence(evidence_dir)
    print(
        f"[*] Evidence: included={len(evidence_items)} "
        f"skipped_empty={ev_stats.get('skipped_empty', 0)} "
        f"skipped_duplicate={ev_stats.get('skipped_duplicate', 0)}"
    )

    ascii_arts = load_ascii_arts(ascii_dir)
    if ascii_arts:
        print(f"[*] ASCII art loaded: {', '.join(ascii_arts.keys())}")

    severity_weights = {"critical": 100, "high": 50, "medium": 10, "low": 1, "info": 0}
    global_severities = nuclei_counts.copy()
    seen_keys = set()
    for item in evidence_items:
        for f in item.get("findings", []):
            k = f.get("dedup_key")
            if k and k not in seen_keys:
                seen_keys.add(k)
                sev = f.get("severity", "").lower()
                if sev in global_severities:
                    global_severities[sev] += 1
                elif sev:
                    global_severities[sev] = 1

    for host_ip, host_node in hosts_dict.items():
        score = 0
        for item in evidence_items:
            for f in item.get("findings", []):
                fh = f.get("host", "")
                if host_ip in fh or fh in host_ip:
                    score += severity_weights.get(f.get("severity", "").lower(), 0)
        if len(hosts_dict) == 1:
            for sev, count in nuclei_counts.items():
                score += severity_weights.get(sev.lower(), 0) * count
        host_node.set("risk_score", str(score))

    cmds_root = ET.SubElement(base_root, "cosmiccommands")
    for cmd in scan_commands:
        el = ET.SubElement(cmds_root, "scan")
        for attr in ("file", "args", "flags", "startstr", "start", "tool"):
            el.set(attr, cmd.get(attr, ""))
        for res in cmd.get("results", []):
            rel = ET.SubElement(el, "result")
            for attr in ("host", "portid", "protocol", "state", "reason", "service", "version", "product"):
                rel.set(attr, res.get(attr, ""))

    stats = count_stats(
        base_root, len(input_files), len(parsed), len(malformed_files),
        len(evidence_items), ev_stats.get("skipped_empty", 0),
        ev_stats.get("skipped_duplicate", 0),
    )
    add_metadata(base_root, stats, malformed_files, evidence_items,
                 nuclei_counts, global_severities, ascii_arts)

    try:
        xml_string = ET.tostring(base_root, encoding="unicode", method="xml")
        xsl_ref = os.path.basename(stylesheet_path)
        final = (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<?xml-stylesheet href="{xsl_ref}" type="text/xsl"?>\n'
            f"<!DOCTYPE nmaprun>\n{xml_string}"
        )
        with open(output_xml, "w", encoding="utf-8") as f:
            f.write(final)
        print(f"[+] Merged XML → {output_xml}")
        return True
    except Exception as exc:
        print(f"[-] Error writing XML: {exc}")
        return False


def generate_html(xml_file, xsl_file, output_html):
    print("[*] Generating HTML via xsltproc …")
    try:
        subprocess.run(["xsltproc", "-o", output_html, xsl_file, xml_file], check=True)
        print(f"[+] HTML report → {output_html}")
    except subprocess.CalledProcessError as exc:
        print(f"[-] xsltproc error: {exc}")
        sys.exit(1)
    except FileNotFoundError:
        print("[-] xsltproc not found. Install it:  sudo apt install xsltproc")
        sys.exit(1)


def _resolve_risk_eval_json_path(output_html, evidence_dir):
    """
    Find risk_evaluations.json for DIN 5008 annexes.

    Search order (first existing file wins):
      1. <report_basename>_risk_evaluations.json next to output_html
      2. risk_evaluations.json next to output_html
      3. risk_evaluations.json in evidence_dir
    """
    out_dir = os.path.dirname(os.path.abspath(output_html)) or "."
    stem = os.path.splitext(os.path.basename(output_html))[0]
    candidates = [
        os.path.join(out_dir, f"{stem}_risk_evaluations.json"),
        os.path.join(out_dir, "risk_evaluations.json"),
    ]
    if evidence_dir:
        candidates.append(os.path.join(os.path.abspath(evidence_dir), "risk_evaluations.json"))
    for p in candidates:
        if p and os.path.isfile(p):
            return os.path.abspath(p)
    return None


def _prompt_risk_eval_json(output_html, evidence_dir):
    """
    Ask whether to attach risk JSON to DIN 5008 export.
    Returns absolute path or None.
    """
    auto = _resolve_risk_eval_json_path(output_html, evidence_dir)
    if auto:
        print(f"\n[+] Found risk JSON: {auto}")
        use = input("[?] Attach to DIN 5008 PDF? (y/n, default=y): ").strip().lower()
        if use == "n":
            return None
        return auto

    print(
        "\n[*] No risk_evaluations.json next to the HTML output or in the evidence directory."
    )
    print("    In the browser: use the PDF panel → export JSON (e.g. risk_evaluations.json).")
    path = input("[?] Path to JSON manually (Enter = skip risk annexes): ").strip()
    if not path:
        return None
    path = os.path.abspath(os.path.expanduser(path))
    if not os.path.isfile(path):
        print(f"[-] File not found: {path}")
        return None
    return path


def inject_analyst_persistence_script(html_path):
    """Inject script to persist analyst comments into HTML for export."""
    persistence_script = '''
<script id="analyst-persistence">
// Persist analyst data into HTML elements for export
(function() {
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
          if (titleEl && data.title) {
            titleEl.textContent = data.title;
            titleEl.setAttribute('data-persisted-title', data.title);
          }
          // Update summary  
          var sumEl = node.querySelector('[data-evidence-summary-input="' + key + '"]');
          if (sumEl && data.summary) {
            sumEl.textContent = data.summary;
            sumEl.setAttribute('data-persisted-summary', data.summary);
          }
          // Update raw
          var rawEl = node.querySelector('[data-evidence-raw-input="' + key + '"]');
          if (rawEl && data.raw) {
            rawEl.textContent = data.raw;
            rawEl.setAttribute('data-persisted-raw', data.raw);
          }
          // Update comment
          var commentEl = node.querySelector('[data-evidence-comment-input="' + key + '"]');
          if (commentEl && data.comment) {
            commentEl.textContent = data.comment;
            commentEl.setAttribute('data-persisted-comment', data.comment);
          }
        }
      } catch (e) {}
    });

    // Hero notes (same key as cosmic_clean.xsl heroNote())
    try {
      var heroKey = 'cosmicAnal:v1:heroNote';
      var heroNote = localStorage.getItem(heroKey);
      var heroEl = document.querySelector('[data-hero-note-input]');
      if (heroEl && heroNote) {
        heroEl.textContent = heroNote;
        heroEl.setAttribute('data-persisted-hero', heroNote);
      }
    } catch (e) {}

    // Port analyst notes (stored under cosmicAnal:v1:<portKey> as JSON with .note)
    document.querySelectorAll('[data-analysis-input]').forEach(function (portEl) {
      var portKey = portEl.getAttribute('data-analysis-input');
      if (!portKey) return;
      try {
        var raw = localStorage.getItem('cosmicAnal:v1:' + portKey);
        if (!raw) return;
        var rec = JSON.parse(raw);
        if (rec && rec.note) {
          portEl.innerHTML = rec.note;
          portEl.setAttribute('data-persisted-port', rec.note);
        }
      } catch (e) {}
    });

    // Scoped editing elements
    document.querySelectorAll('[data-scope-key]').forEach(function (el) {
      var scopeKey = el.getAttribute('data-scope-key');
      if (!scopeKey) return;
      try {
        var scopeVal = localStorage.getItem('cosmicAnal:v1:scope:' + scopeKey);
        if (scopeVal) {
          el.textContent = scopeVal;
          el.setAttribute('data-persisted-scope', scopeVal);
        }
      } catch (e) {}
    });

    // DIN 5008 cover fields (inline editors)
    document.querySelectorAll('[data-din-field]').forEach(function (el) {
      var f = el.getAttribute('data-din-field');
      if (!f) return;
      try {
        var dv = localStorage.getItem('cosmicAnal:v1:din:' + f);
        if (dv) {
          el.textContent = dv;
          el.setAttribute('data-persisted-din', f);
        }
      } catch (e) {}
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', persistAnalystData);
  } else {
    persistAnalystData();
  }
})();
</script>
'''
    
    try:
        with open(html_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Only the real document closer: </body> then </html> at EOF (not </body> inside JS strings)
        doc_close = re.search(
            r"(?ms)\n(\s*</body>\s*\n\s*</html>\s*)$",
            content,
        )
        if doc_close:
            insert_at = doc_close.start(1)
            content = content[:insert_at] + persistence_script + "\n" + content[insert_at:]
        else:
            idx = content.rfind("</body>")
            if idx != -1:
                content = content[:idx] + persistence_script + "\n" + content[idx:]
            else:
                content += persistence_script
            
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print("[*] Analyst persistence script injected")
        return True
    except Exception as exc:
        print(f"[-] Failed to inject persistence script: {exc}")
        return False


# ---------------------------------------------------------------------------
# Pipeline + CLI (interactive wizard or batch args)
# ---------------------------------------------------------------------------

# NVD/MITRE sequence is typically 4+ digits (not 7+); nuclei and scanners emit shorter IDs.
_CVE_ID_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def discover_cves_in_evidence(evidence_dir: str, max_files: int = 800) -> List[str]:
    """Scan evidence trees for CVE identifiers in readable text (best-effort)."""
    found: set = set()
    n = 0
    for root in _evidence_search_roots(evidence_dir):
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                if n >= max_files:
                    return sorted(found)
                path = os.path.join(dirpath, fn)
                if not os.path.isfile(path):
                    continue
                low = fn.lower()
                if low.endswith(
                    (
                        ".pcap",
                        ".pcapng",
                        ".cap",
                        ".zip",
                        ".7z",
                        ".gz",
                        ".pdf",
                        ".png",
                        ".jpg",
                        ".jpeg",
                        ".gif",
                        ".webp",
                        ".sqlite",
                        ".db",
                    )
                ):
                    continue
                try:
                    content = safe_read_text(path, max_chars=200_000)
                except OSError:
                    continue
                for m in _CVE_ID_RE.finditer(content):
                    found.add(m.group(0).upper())
                n += 1
    return sorted(found)


def write_cve_refs_bundle(
    output_html: str,
    evidence_dir: str,
) -> Optional[str]:
    """
    For each CVE found in evidence text, call vuln_ref_lookup (NVD+EPSS+KEV).
    Writes <report_stem>_cve_refs.json next to output_html.
    """
    try:
        from vuln_ref_lookup import lookup_vuln_reference
    except ImportError:
        print("[-] vuln_ref_lookup not importable — skipping CVE reference bundle.")
        return None

    cves = discover_cves_in_evidence(evidence_dir)
    if not cves:
        print("[*] No CVE IDs found in evidence text — no *_cve_refs.json written.")
        return None

    bundle: dict = {}
    for i, cve in enumerate(cves, 1):
        print(f"    [{i}/{len(cves)}] {cve} ...")
        try:
            bundle[cve] = lookup_vuln_reference(cve, with_epss=True, with_kev=True)
        except (ValueError, RuntimeError, OSError) as exc:
            bundle[cve] = {"cve": cve, "error": str(exc)}

    out_dir = os.path.dirname(os.path.abspath(output_html)) or "."
    stem = os.path.splitext(os.path.basename(output_html))[0]
    out_path = os.path.join(out_dir, f"{stem}_cve_refs.json")
    payload = {
        "schema": "cosmic-cve-refs-bundle/1",
        "generated": datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "note": (
            "Technical reference (NVD / EPSS / CISA KEV). Organizational risk stays separate "
            "(ISO / BSI / NIST). Per-CVE JSON can be pasted into the report CVSS panel."
        ),
        "cves": bundle,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    print(f"[+] CVE references written: {out_path} ({len(cves)} CVE(s))")
    return out_path


def _discover_xml_files(evidence_dir: str) -> list:
    """Collect Nmap-style inputs. Includes merged_scan_*.xml (timestamped merges), not merged_scan.xml."""
    xml_files = []
    patterns = ("scan_*.xml", "nmap*.xml", "portscan.xml", "services.xml", "merged_scan_*.xml")
    seen = set()
    for pattern in patterns:
        found = sorted(glob.glob(os.path.join(evidence_dir, pattern)))
        for f in found:
            base = os.path.basename(f)
            if base == "merged_scan.xml":
                continue
            if f not in seen:
                seen.add(f)
                xml_files.append(f)
    return xml_files


def _pick_ascii_dir(evidence_dir: str, script_dir: str, interactive: bool) -> tuple:
    """Returns (ascii_dir or None, ascii_candidates_with_files)."""
    ascii_candidates = [
        os.path.join(evidence_dir, "ascii_arts"),
        os.path.join(evidence_dir, "ascii"),
        os.path.join(script_dir, "ascii_arts"),
    ]
    ascii_candidates = [os.path.abspath(p) for p in ascii_candidates]
    ascii_candidates_with_files = []
    for d in ascii_candidates:
        if os.path.isdir(d) and glob.glob(os.path.join(d, "*.txt")):
            ascii_candidates_with_files.append(d)

    if not ascii_candidates_with_files:
        return None, ascii_candidates_with_files
    if len(ascii_candidates_with_files) == 1:
        return ascii_candidates_with_files[0], ascii_candidates_with_files
    if not interactive:
        return ascii_candidates_with_files[0], ascii_candidates_with_files
    print("\n[?] Multiple ASCII art directories found:")
    for i, d in enumerate(ascii_candidates_with_files, start=1):
        print(f"    {i}) {d}")
    selected = input("[?] Choose number (Enter = 1): ").strip()
    try:
        idx = int(selected) - 1 if selected else 0
        return ascii_candidates_with_files[idx], ascii_candidates_with_files
    except Exception:
        return ascii_candidates_with_files[0], ascii_candidates_with_files


def run_report_pipeline(
    evidence_dir: str,
    output_html: str,
    *,
    xml_file: str = "merged_scan.xml",
    script_dir: Optional[str] = None,
    nuclei_json=None,
    ascii_dir=None,
    skip_pdf: bool = False,
    want_16x9: bool = True,
    want_din: bool = True,
    want_reader: bool = False,
    eval_json_path: Optional[str] = None,
    fetch_cve_refs: bool = False,
) -> bool:
    """Build merged XML + HTML + optional PDFs. Returns True on success."""
    if script_dir is None:
        script_dir = os.path.dirname(os.path.abspath(__file__))
    xsl_file = os.path.join(script_dir, "cosmic_clean.xsl")
    if not os.path.isfile(xsl_file):
        print(f"[-] XSL stylesheet not found: {xsl_file}")
        return False

    evidence_dir = os.path.abspath(evidence_dir)
    xml_files = _discover_xml_files(evidence_dir)

    if merge_nmap_xml(
        xml_files,
        xml_file,
        xsl_file,
        nuclei_json,
        evidence_dir=evidence_dir,
        ascii_dir=ascii_dir,
    ):
        generate_html(xml_file, xsl_file, output_html)
        inject_analyst_persistence_script(output_html)

        if fetch_cve_refs:
            print("\n[*] CVE references (NVD + EPSS + CISA KEV) ...")
            write_cve_refs_bundle(output_html, evidence_dir)

        if not skip_pdf and _PDF_AVAILABLE:
            stem = os.path.splitext(output_html)[0]
            if want_16x9:
                generate_16x9_pdf(output_html, stem + "_16x9.pdf")
            if want_din:
                eval_use = eval_json_path
                if eval_use is None:
                    eval_use = _resolve_risk_eval_json_path(output_html, evidence_dir)
                if eval_use:
                    print(f"[*] DIN 5008 with risk JSON: {eval_use}")
                else:
                    print("[*] DIN 5008 without risk JSON (add later in the browser if needed)")
                generate_din5008_pdf(xml_file, stem + "_din5008.pdf", eval_json_path=eval_use)
            if want_reader:
                generate_reader_pdf(output_html, stem + "_reader.pdf")
        elif not skip_pdf and not _PDF_AVAILABLE:
            print("[*] pdf_export not available — skipping PDF generation")

        print(f"\n[✓] Report: {os.path.abspath(output_html)}")
        print(
            "[i] Browser: Export ▾ = DIN / 16:9 / reader A4 / HTML / risk JSON; cover fields & note stay in the overview."
        )
        return True
    return False


def interactive_cli_wizard():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    _print_cli_banner(script_dir)
    xsl_file = os.path.join(script_dir, "cosmic_clean.xsl")
    if not os.path.isfile(xsl_file):
        print(f"[-] XSL stylesheet not found: {xsl_file}")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("Evidence → HTML   (interactive wizard)")
    print("=" * 60)

    print("\n--- STEP 1/8 — Evidence directory (required) ---")
    evidence_dir = input("[?] Path to evidence directory: ").strip()
    if not evidence_dir:
        print("[-] Aborted: no directory given.")
        sys.exit(1)
    evidence_dir = os.path.abspath(evidence_dir)
    if not os.path.isdir(evidence_dir):
        print(f"[-] Directory not found: {evidence_dir}")
        sys.exit(1)

    print("\n--- STEP 2/8 — HTML output file ---")
    output_html = input("[?] Output HTML filename (Enter = report.html): ").strip() or "report.html"
    xml_file = "merged_scan.xml"

    print("\n--- STEP 3/8 — Nuclei (optional) ---")
    nuclei_json = None
    nuclei_path = os.path.join(evidence_dir, "nuclei.json")
    if os.path.exists(nuclei_path):
        use_nuclei = input("[?] nuclei.json found — merge it? (y/n, Enter=y): ").strip().lower()
        if use_nuclei != "n":
            nuclei_json = nuclei_path
            print(f"[+] {nuclei_json}")
    else:
        print("[*] No nuclei.json in the evidence directory.")

    print("\n--- STEP 4/8 — Nmap XML (auto-discovered) ---")
    xml_files = _discover_xml_files(evidence_dir)
    if xml_files:
        print(f"[+] {len(xml_files)} Nmap XML file(s):")
        for f in xml_files:
            print(f"    - {os.path.basename(f)}")
    else:
        print("[*] No Nmap XML — evidence content only.")

    print("\n--- STEP 5/8 — ASCII art directory ---")
    ascii_dir, ascii_cands = _pick_ascii_dir(evidence_dir, script_dir, interactive=True)
    if ascii_dir:
        arts = sorted(glob.glob(os.path.join(ascii_dir, "*.txt")))
        print(f"[+] ASCII: {len(arts)} file(s) in {ascii_dir}")
    else:
        print("[*] No ASCII directory — built-in motif.")

    print("\n--- STEP 6/8 — PDF export (Chromium) ---")
    want_16x9 = True
    want_din = True
    want_reader = False
    skip_pdf = False
    if _PDF_AVAILABLE:
        w16 = input("[?] Generate 16:9 PDF? (y/n, Enter=y): ").strip().lower()
        want_16x9 = w16 != "n"
        wd = input("[?] Generate DIN 5008 PDF? (y/n, Enter=y): ").strip().lower()
        want_din = wd != "n"
        wr = input(
            "[?] Generate reader A4 PDF (structure-faithful, muted palette)? (y/n, Enter=n): "
        ).strip().lower()
        want_reader = wr == "y"
    else:
        skip_pdf = True
        print("[*] pdf_export not importable — HTML only.")

    eval_json = None
    if want_din and _PDF_AVAILABLE:
        print("\n--- STEP 7/8 — Risk JSON for DIN annexes ---")
        eval_json = _prompt_risk_eval_json(output_html, evidence_dir)
    else:
        print("\n--- STEP 7/8 — Risk JSON (skipped — no DIN PDF) ---")
        print("[*] You can add risk JSON later in the browser, or run again with DIN PDF enabled.")

    print("\n--- STEP 8/8 — CVE references (NVD + EPSS + CISA KEV) ---")
    print(
        "    After HTML: scan evidence text for CVE IDs, fetch over the network, "
        "and write <report_basename>_cve_refs.json next to the report."
    )
    ref_ans = input(
        "[?] Fetch CVE references now? (y/n, Enter=n): "
    ).strip().lower()
    fetch_cve_refs = ref_ans == "y"

    print("\n" + "=" * 60)
    print("Starting pipeline ...")
    print("=" * 60 + "\n")

    ok = run_report_pipeline(
        evidence_dir,
        output_html,
        xml_file=xml_file,
        script_dir=script_dir,
        nuclei_json=nuclei_json,
        ascii_dir=ascii_dir,
        skip_pdf=skip_pdf,
        want_16x9=want_16x9,
        want_din=want_din,
        want_reader=want_reader,
        eval_json_path=eval_json,
        fetch_cve_refs=fetch_cve_refs,
    )
    if not ok:
        sys.exit(1)


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(
        description="Evidence → merged XML + HTML report (+ optional PDF). "
        "With no positional argument: run the interactive wizard.",
    )
    parser.add_argument(
        "evidence_dir",
        nargs="?",
        help="Evidence directory (omit to run interactive wizard)",
    )
    parser.add_argument("-o", "--output", default="report.html", help="Output HTML path")
    parser.add_argument("--xml-out", default="merged_scan.xml", help="Merged XML filename")
    parser.add_argument("--no-pdf", action="store_true", help="Skip all PDF generation")
    parser.add_argument("--no-16x9", action="store_true", help="Skip 16:9 PDF")
    parser.add_argument("--no-din", action="store_true", help="Skip DIN 5008 PDF")
    parser.add_argument(
        "--reader-pdf",
        action="store_true",
        help="Also generate reader A4 PDF (structure-faithful, muted palette)",
    )
    parser.add_argument("--no-nuclei", action="store_true", help="Do not merge nuclei.json even if present")
    parser.add_argument("--nuclei", metavar="PATH", help="Explicit path to nuclei.json")
    parser.add_argument("--ascii-dir", metavar="PATH", help="ASCII art directory")
    parser.add_argument(
        "--eval-json",
        metavar="PATH",
        help="risk_evaluations.json for DIN annexes (browser export)",
    )
    parser.add_argument(
        "--fetch-cve-refs",
        action="store_true",
        help=(
            "After HTML: scan evidence texts for CVE-IDs, fetch NVD+EPSS+KEV, "
            "write <output_stem>_cve_refs.json next to the report"
        ),
    )
    args = parser.parse_args()

    if not args.evidence_dir:
        interactive_cli_wizard()
        return

    _print_cli_banner(script_dir)

    xsl_file = os.path.join(script_dir, "cosmic_clean.xsl")
    if not os.path.isfile(xsl_file):
        print(f"[-] XSL stylesheet not found: {xsl_file}")
        sys.exit(1)

    evidence_dir = os.path.abspath(args.evidence_dir)
    if not os.path.isdir(evidence_dir):
        print(f"[-] Directory not found: {evidence_dir}")
        sys.exit(1)

    nuclei_json = None
    if args.nuclei:
        nuclei_json = os.path.abspath(args.nuclei) if os.path.isfile(args.nuclei) else None
    elif not args.no_nuclei:
        np = os.path.join(evidence_dir, "nuclei.json")
        if os.path.isfile(np):
            nuclei_json = np

    ascii_dir = args.ascii_dir
    if ascii_dir:
        ascii_dir = os.path.abspath(ascii_dir)
    else:
        ascii_dir, _ = _pick_ascii_dir(evidence_dir, script_dir, interactive=False)

    eval_path = args.eval_json
    if eval_path:
        eval_path = os.path.abspath(os.path.expanduser(eval_path))
        if not os.path.isfile(eval_path):
            print(f"[-] --eval-json not found: {eval_path}")
            sys.exit(1)

    ok = run_report_pipeline(
        evidence_dir,
        args.output,
        xml_file=args.xml_out,
        script_dir=script_dir,
        nuclei_json=nuclei_json,
        ascii_dir=ascii_dir,
        skip_pdf=args.no_pdf,
        want_16x9=not args.no_16x9,
        want_din=not args.no_din,
        want_reader=args.reader_pdf,
        eval_json_path=eval_path,
        fetch_cve_refs=args.fetch_cve_refs,
    )
    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
