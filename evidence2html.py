#!/usr/bin/env python3
"""
evidence2html — collect pen-test evidence files, merge with optional Nmap XML,
and produce a single self-contained HTML report via xsltproc + XSL stylesheet.

Usage:
    python3 evidence2html.py path/to/evidence/
    python3 evidence2html.py path/to/evidence/ scan1.xml scan2.xml
    python3 evidence2html.py -e path/to/evidence/ -o report.html
"""

import datetime
import glob
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import xml.etree.ElementTree as ET
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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

def parse_ffuf(content, filename):
    findings = []
    try:
        data = json.loads(content)
        for res in data.get("results", []):
            status = res.get("status", 0)
            if status != 404:
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
        content = safe_read_text(path)
        cat = classify_evidence(path)
        status = evidence_status(content, path)
        if status == "EMPTY":
            stats["skipped_empty"] += 1
            stats["skipped_empty_files"].append(path)
            continue

        tool = infer_tool(path)
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
        return arts
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


# ---------------------------------------------------------------------------
# Interactive CLI
# ---------------------------------------------------------------------------

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    xsl_file = os.path.join(script_dir, "cosmic_clean.xsl")
    ascii_dir = os.path.join(script_dir, "ascii_arts")

    if not os.path.isfile(xsl_file):
        print(f"[-] XSL stylesheet not found: {xsl_file}")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("Evidence to HTML Report Generator")
    print("=" * 60)

    evidence_dir = input("\n[?] Enter evidence directory path: ").strip()
    if not evidence_dir:
        print("[-] No directory specified.")
        sys.exit(1)

    evidence_dir = os.path.abspath(evidence_dir)
    if not os.path.isdir(evidence_dir):
        print(f"[-] Directory not found: {evidence_dir}")
        sys.exit(1)

    output_html = input("\n[?] HTML output filename (default: report.html): ").strip() or "report.html"
    xml_file = "merged_scan.xml"

    nuclei_json = None
    nuclei_path = os.path.join(evidence_dir, "nuclei.json")
    if os.path.exists(nuclei_path):
        use_nuclei = input(f"\n[?] Found nuclei.json — include it? (y/n, default: y): ").strip().lower()
        if use_nuclei != "n":
            nuclei_json = nuclei_path
            print(f"[+] Using: {nuclei_json}")

    xml_files = []
    for pattern in ("scan_*.xml", "nmap*.xml", "portscan.xml", "services.xml"):
        found = sorted(glob.glob(os.path.join(evidence_dir, pattern)))
        found = [f for f in found if not os.path.basename(f).startswith("merged_scan")]
        xml_files.extend(found)

    if xml_files:
        print(f"\n[+] Found {len(xml_files)} Nmap XML file(s):")
        for f in xml_files:
            print(f"    - {os.path.basename(f)}")
    else:
        print("\n[*] No Nmap XMLs found — building evidence-only report")

    if os.path.isdir(ascii_dir):
        ascii_files = sorted(glob.glob(os.path.join(ascii_dir, "*.txt")))
        if ascii_files:
            print(f"\n[+] Found {len(ascii_files)} ASCII art file(s):")
            for f in ascii_files:
                print(f"    - {os.path.basename(f)}")
        else:
            print(f"\n[*] ASCII art directory exists but is empty: {ascii_dir}")
    else:
        print(f"\n[*] No ASCII art directory at: {ascii_dir}")

    print("\n" + "=" * 60)
    print("Starting pipeline…")
    print("=" * 60 + "\n")

    if merge_nmap_xml(xml_files, xml_file, xsl_file,
                      nuclei_json, evidence_dir=evidence_dir,
                      ascii_dir=ascii_dir if os.path.isdir(ascii_dir) else None):
        generate_html(xml_file, xsl_file, output_html)
        print("\n" + "=" * 60)
        print(f"[✓] Done! Report: {os.path.abspath(output_html)}")
        print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
