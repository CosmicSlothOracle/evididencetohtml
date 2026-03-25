#!/usr/bin/env python3
"""
Fetch CVE metadata from the NVD API 2.0 (CVSS v3.1 vector + base score when available).

Usage:
  python3 nvd_cve_lookup.py CVE-2024-1234
  python3 nvd_cve_lookup.py CVE-2024-1234 --json-only

Optional: set NVD_API_KEY for higher rate limits (see https://nvd.nist.gov/developers/request-an-api-key).

For NVD + EPSS + CISA KEV in one JSON (report CVSS panel „Technische Referenz“):
  python3 vuln_ref_lookup.py CVE-… --json

Paste the printed "cvss" object into the report UI, or merge into risk_evaluations.json under the evidence key.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional


NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# NVD expects CVE-YYYY-NNNN+ (digits); placeholders like "CVE-…" return HTTP 404.
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)


def _pick_cvss_v31(metrics_block: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Prefer NVD primary CVSS v3.1 entry."""
    if not metrics_block:
        return None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        lst = metrics_block.get(key)
        if not isinstance(lst, list):
            continue
        for item in lst:
            if not isinstance(item, dict):
                continue
            src = (item.get("type") or "").upper()
            if src == "PRIMARY" or key == "cvssMetricV31":
                data = item.get("cvssData")
                if isinstance(data, dict) and data.get("vectorString"):
                    return data
        for item in lst:
            if isinstance(item, dict):
                data = item.get("cvssData")
                if isinstance(data, dict) and data.get("vectorString"):
                    return data
    return None


def normalize_cve_id(cve_id: str) -> str:
    """Strip and uppercase; does not validate (use validate_cve_id_for_nvd)."""
    return (cve_id or "").strip().upper()


def validate_cve_id_for_nvd(cve_id: str) -> None:
    cid = normalize_cve_id(cve_id)
    if not cid.startswith("CVE-"):
        raise ValueError(
            "CVE id must look like CVE-YYYY-NNNN (e.g. CVE-2024-21410). "
            "Literary ellipses (…) or placeholders are not valid."
        )
    if not CVE_ID_RE.match(cid):
        raise ValueError(
            f"Invalid CVE format for NVD: {cve_id!r}. "
            "Use digits only after the year (e.g. CVE-2024-12345), not an ellipsis (…) or other placeholders."
        )


def lookup_cve(cve_id: str, timeout: float = 90.0) -> Dict[str, Any]:
    cve_id = normalize_cve_id(cve_id)
    validate_cve_id_for_nvd(cve_id)

    q = urllib.parse.urlencode({"cveId": cve_id})
    url = f"{NVD_CVE_URL}?{q}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    key = (os.environ.get("NVD_API_KEY") or "").strip()
    if key:
        req.add_header("apiKey", key)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise RuntimeError(
                f"NVD returned 404 for {cve_id!r} — usually unknown or withdrawn CVE, "
                "or a malformed id. Check spelling at https://nvd.nist.gov/."
            ) from e
        raise RuntimeError(f"NVD HTTP {e.code}: {e.reason}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"NVD request failed: {e}") from e

    data = json.loads(raw)
    vulns: List[Dict[str, Any]] = data.get("vulnerabilities") or []
    if not vulns:
        return {"cve": cve_id, "found": False, "error": "No vulnerability record returned"}

    cve = (vulns[0].get("cve") or {}) if vulns else {}
    metrics = cve.get("metrics") or {}
    cvss_data = _pick_cvss_v31(metrics)

    out: Dict[str, Any] = {
        "cve": cve_id,
        "found": True,
        "description": None,
        "cvss": {},
    }
    desc = cve.get("descriptions") or []
    for d in desc:
        if isinstance(d, dict) and d.get("lang") == "en":
            out["description"] = d.get("value")
            break
    if not out["description"] and desc and isinstance(desc[0], dict):
        out["description"] = desc[0].get("value")

    if cvss_data:
        vec = cvss_data.get("vectorString") or ""
        base = cvss_data.get("baseScore")
        out["cvss"] = {
            "vector": vec,
            "baseScore": base,
            "version": cvss_data.get("version") or "3.1",
        }
    else:
        out["cvss"] = {"vector": "", "baseScore": None, "note": "No CVSS v3.x vector in NVD metrics"}

    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Lookup CVE in NVD API 2.0")
    ap.add_argument("cve_id", help="e.g. CVE-2024-1234")
    ap.add_argument("--json-only", action="store_true", help="Print JSON only (no hints)")
    args = ap.parse_args()

    try:
        result = lookup_cve(args.cve_id)
    except (ValueError, RuntimeError) as e:
        print(str(e), file=sys.stderr)
        return 1

    if args.json_only:
        print(json.dumps(result, indent=2))
        return 0

    print(json.dumps(result, indent=2, ensure_ascii=False))
    if result.get("found") and result.get("cvss", {}).get("vector"):
        print(
            "\n# For cosmic / risk_evaluations.json under the evidence key line, e.g.:\n"
            '  "cvss": {\n'
            f'    "vector": {json.dumps(result["cvss"]["vector"])},\n'
            f'    "baseScore": {json.dumps(result["cvss"].get("baseScore"))}\n'
            "  }",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
