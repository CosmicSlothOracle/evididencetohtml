#!/usr/bin/env python3
"""
Industry-style technical reference for a CVE (not organizational risk).

Combines:
  - NVD API 2.0 — CVSS v3.x vector + base score (FIRST/NIST catalog)
  - EPSS (FIRST) — estimated exploitation probability
  - CISA KEV — known exploited vulnerabilities catalog (inclusion + due date)

Usage:
  python3 vuln_ref_lookup.py CVE-2024-1234
  python3 vuln_ref_lookup.py CVE-2024-1234 --json --no-epss
  python3 vuln_ref_lookup.py CVE-2024-1234 --no-kev

Environment:
  NVD_API_KEY — optional, higher NVD rate limits

Paste JSON into the HTML report **Technical reference** field (CVSS panel), or merge
into risk_evaluations.json. ISO/BSI/NIST fields stay separate (organizational risk).
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

from nvd_cve_lookup import lookup_cve as nvd_lookup_cve

SCHEMA = "cosmic-vuln-ref/1"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

_KEV_MAP: Optional[Dict[str, Dict[str, Any]]] = None


def _http_json(url: str, timeout: float = 60.0) -> Any:
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "cosmic-vuln-ref-lookup/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def fetch_epss(cve_id: str, timeout: float = 30.0) -> Dict[str, Any]:
    cve_id = cve_id.strip().upper()
    q = urllib.parse.urlencode({"cve": cve_id})
    url = f"{EPSS_URL}?{q}"
    try:
        body = _http_json(url, timeout=timeout)
    except urllib.error.HTTPError as e:
        return {"found": False, "error": f"HTTP {e.code}"}
    except urllib.error.URLError as e:
        return {"found": False, "error": str(e.reason or e)}
    except Exception as e:
        return {"found": False, "error": str(e)}

    if not isinstance(body, dict) or body.get("status") != "OK":
        return {"found": False, "error": "Unexpected EPSS response"}

    rows: List[Dict[str, Any]] = body.get("data") or []
    if not rows:
        return {"found": False, "error": "No EPSS row"}

    row = rows[0]
    try:
        score = float(row.get("epss", 0) or 0)
    except (TypeError, ValueError):
        score = None
    try:
        pct = float(row.get("percentile", 0) or 0)
    except (TypeError, ValueError):
        pct = None

    return {
        "found": True,
        "score": score,
        "percentile": pct,
        "date": row.get("date"),
    }


def load_kev_map(timeout: float = 120.0) -> Dict[str, Dict[str, Any]]:
    global _KEV_MAP
    if _KEV_MAP is not None:
        return _KEV_MAP
    try:
        data = _http_json(KEV_URL, timeout=timeout)
    except Exception:
        _KEV_MAP = {}
        return _KEV_MAP

    vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(vulns, list):
        _KEV_MAP = {}
        return _KEV_MAP

    m: Dict[str, Dict[str, Any]] = {}
    for v in vulns:
        if not isinstance(v, dict):
            continue
        cid = v.get("cveID")
        if cid:
            m[str(cid).upper()] = v
    _KEV_MAP = m
    return _KEV_MAP


def fetch_kev(cve_id: str) -> Dict[str, Any]:
    cve_id = cve_id.strip().upper()
    catalog = load_kev_map()
    if not catalog:
        return {"in_catalog": False, "error": "KEV catalog unavailable"}
    entry = catalog.get(cve_id)
    if not entry:
        return {"in_catalog": False}
    return {
        "in_catalog": True,
        "dateAdded": entry.get("dateAdded"),
        "dueDate": entry.get("dueDate"),
        "requiredAction": entry.get("requiredAction"),
        "vulnerabilityName": entry.get("vulnerabilityName"),
        "vendorProject": entry.get("vendorProject"),
        "product": entry.get("product"),
    }


def lookup_vuln_reference(
    cve_id: str,
    *,
    with_epss: bool = True,
    with_kev: bool = True,
) -> Dict[str, Any]:
    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        raise ValueError("CVE id must look like CVE-YYYY-NNNNN+")

    nvd = nvd_lookup_cve(cve_id)
    cvss_block = nvd.get("cvss") if isinstance(nvd.get("cvss"), dict) else {}

    out: Dict[str, Any] = {
        "schema": SCHEMA,
        "generated": datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "cve": cve_id,
        "note": (
            "Technical reference (NVD / EPSS / KEV). Assess organizational risk separately "
            "per ISO 27005, BSI IT-Grundschutz, and NIST SP 800-30."
        ),
        "nvd": nvd,
        "epss": None,
        "kev": None,
        "cvss": {
            "vector": cvss_block.get("vector") or "",
            "baseScore": cvss_block.get("baseScore"),
            "version": cvss_block.get("version") or "3.1",
        },
    }

    if with_epss:
        out["epss"] = fetch_epss(cve_id)
    if with_kev:
        out["kev"] = fetch_kev(cve_id)

    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        description="CVE technical reference: NVD + EPSS + CISA KEV",
    )
    ap.add_argument("cve_id", help="e.g. CVE-2024-1234")
    ap.add_argument(
        "--json",
        action="store_true",
        help="Print single JSON object (for UI paste / tooling)",
    )
    ap.add_argument("--no-epss", action="store_true", help="Skip FIRST EPSS")
    ap.add_argument("--no-kev", action="store_true", help="Skip CISA KEV check")
    args = ap.parse_args()

    try:
        result = lookup_vuln_reference(
            args.cve_id,
            with_epss=not args.no_epss,
            with_kev=not args.no_kev,
        )
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 1
    except RuntimeError as e:
        print(str(e), file=sys.stderr)
        return 1

    indent = 2 if args.json else 2
    print(json.dumps(result, indent=indent, ensure_ascii=False))
    if not args.json:
        print(
            "\n# In the report (CVSS panel): paste the JSON into **Technical reference**, then apply.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
