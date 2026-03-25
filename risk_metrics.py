#!/usr/bin/env python3
"""
risk_metrics.py — Risk vector assessment for CVSS, ISO 27005, BSI IT-Grundschutz, NIST SP 800-30.

Provides:
- CVSS v3.1/v4.0 vector parsing and score computation
- Readiness evaluation (graceful degradation when data missing)
- SVG diagram generation for DIN 5008 PDF annexes
- HTML rendering for PDF export

Official sources:
- CVSS: https://www.first.org/cvss/
- ISO/IEC 27005:2022: https://www.iso.org/standard/80585.html
- BSI IT-Grundschutz 200-2/200-3: https://www.bsi.bund.de/
- NIST SP 800-30: https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final
"""

import html
import re
import math
from typing import Optional, Dict, List, Any, Tuple

# ---------------------------------------------------------------------------
# CVSS v3.1 Metric Values and Weights (per FIRST specification)
# ---------------------------------------------------------------------------

CVSS31_METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},  # Attack Vector
    "AC": {"L": 0.77, "H": 0.44},  # Attack Complexity
    "PR": {  # Privileges Required (scope-dependent)
        "N": {"U": 0.85, "C": 0.85},
        "L": {"U": 0.62, "C": 0.68},
        "H": {"U": 0.27, "C": 0.50},
    },
    "UI": {"N": 0.85, "R": 0.62},  # User Interaction
    "S": {"U": "Unchanged", "C": "Changed"},  # Scope
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},  # Confidentiality
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},  # Integrity
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},  # Availability
}

CVSS31_SEVERITY = [
    (0.0, 0.0, "None"),
    (0.1, 3.9, "Low"),
    (4.0, 6.9, "Medium"),
    (7.0, 8.9, "High"),
    (9.0, 10.0, "Critical"),
]

# ---------------------------------------------------------------------------
# ISO 27005 - Likelihood × Impact Matrix (5×5)
# Per ISO/IEC 27005:2022 risk evaluation approach
# ---------------------------------------------------------------------------

ISO27005_LIKELIHOOD = {
    1: "Sehr selten",      # Very rare
    2: "Unwahrscheinlich", # Unlikely
    3: "Möglich",          # Possible
    4: "Wahrscheinlich",   # Likely
    5: "Fast sicher",      # Almost certain
}

ISO27005_IMPACT = {
    1: "Vernachlässigbar", # Negligible
    2: "Gering",           # Minor
    3: "Moderat",          # Moderate
    4: "Erheblich",        # Significant
    5: "Katastrophal",     # Catastrophic
}

ISO27005_RISK_MATRIX = {
    # (likelihood, impact): risk_level
    (1, 1): "Niedrig", (1, 2): "Niedrig", (1, 3): "Niedrig", (1, 4): "Mittel", (1, 5): "Mittel",
    (2, 1): "Niedrig", (2, 2): "Niedrig", (2, 3): "Mittel", (2, 4): "Mittel", (2, 5): "Hoch",
    (3, 1): "Niedrig", (3, 2): "Mittel", (3, 3): "Mittel", (3, 4): "Hoch", (3, 5): "Hoch",
    (4, 1): "Mittel", (4, 2): "Mittel", (4, 3): "Hoch", (4, 4): "Hoch", (4, 5): "Kritisch",
    (5, 1): "Mittel", (5, 2): "Hoch", (5, 3): "Hoch", (5, 4): "Kritisch", (5, 5): "Kritisch",
}

ISO27005_TREATMENT = {
    "Vermeiden": "Risiko durch Unterlassung der riskanten Aktivität eliminieren",
    "Mindern": "Maßnahmen zur Reduzierung von Eintrittswahrscheinlichkeit oder Auswirkung",
    "Übertragen": "Risiko auf Dritte übertragen (z.B. Versicherung)",
    "Akzeptieren": "Risiko bewusst tragen ohne weitere Maßnahmen",
}

# ---------------------------------------------------------------------------
# BSI IT-Grundschutz - Schutzbedarf und Maßnahmenstatus
# Per BSI-Standard 200-2 / 200-3
# ---------------------------------------------------------------------------

BSI_SCHUTZBEDARF = {
    "Normal": "Schadensauswirkungen sind begrenzt und überschaubar",
    "Hoch": "Schadensauswirkungen können beträchtlich sein",
    "Sehr hoch": "Schadensauswirkungen können existenzbedrohend oder katastrophal sein",
}

BSI_MASSNAHMEN_STATUS = {
    "Erfüllt": "Anforderung vollständig umgesetzt",
    "Teilweise": "Anforderung nur teilweise umgesetzt",
    "Nicht erfüllt": "Anforderung nicht umgesetzt",
    "Entbehrlich": "Anforderung im Kontext nicht anwendbar",
}

# ---------------------------------------------------------------------------
# NIST SP 800-30 - Likelihood and Impact Levels
# Per NIST SP 800-30 Rev. 1 Appendix G/H
# ---------------------------------------------------------------------------

NIST_LIKELIHOOD = {
    "Very Low": "Gegner ist nicht in der Lage oder hat keine Absicht; ~0-10%",
    "Low": "Gegner hat begrenzte Fähigkeiten; ~10-25%",
    "Moderate": "Gegner hat gewisse Fähigkeiten und Absicht; ~25-50%",
    "High": "Gegner ist fähig und hat Absicht; ~50-75%",
    "Very High": "Gegner ist hochmotiviert und sehr fähig; ~75-100%",
}

NIST_IMPACT = {
    "Very Low": "Vernachlässigbare nachteilige Auswirkung",
    "Low": "Begrenzte nachteilige Auswirkung",
    "Moderate": "Ernsthafte nachteilige Auswirkung",
    "High": "Schwere oder katastrophale Auswirkung",
    "Very High": "Existenzielle oder nicht wiedergutzumachende Auswirkung",
}

NIST_RISK_MATRIX = {
    # (likelihood, impact): risk_level
    ("Very Low", "Very Low"): "Very Low", ("Very Low", "Low"): "Very Low",
    ("Very Low", "Moderate"): "Low", ("Very Low", "High"): "Low", ("Very Low", "Very High"): "Moderate",
    ("Low", "Very Low"): "Very Low", ("Low", "Low"): "Low",
    ("Low", "Moderate"): "Low", ("Low", "High"): "Moderate", ("Low", "Very High"): "Moderate",
    ("Moderate", "Very Low"): "Low", ("Moderate", "Low"): "Low",
    ("Moderate", "Moderate"): "Moderate", ("Moderate", "High"): "Moderate", ("Moderate", "Very High"): "High",
    ("High", "Very Low"): "Low", ("High", "Low"): "Moderate",
    ("High", "Moderate"): "Moderate", ("High", "High"): "High", ("High", "Very High"): "Very High",
    ("Very High", "Very Low"): "Moderate", ("Very High", "Low"): "Moderate",
    ("Very High", "Moderate"): "High", ("Very High", "High"): "Very High", ("Very High", "Very High"): "Very High",
}

# NIST CSF 2.0 Functions (optional mapping)
NIST_CSF_FUNCTIONS = {
    "GV": "Govern",
    "ID": "Identify",
    "PR": "Protect",
    "DE": "Detect",
    "RS": "Respond",
    "RC": "Recover",
}


# ---------------------------------------------------------------------------
# CVSS v3.1 Parser and Calculator
# ---------------------------------------------------------------------------

def parse_cvss31_vector(vector: str) -> Optional[Dict[str, str]]:
    """Parse CVSS v3.1 vector string into metric dict."""
    if not vector:
        return None
    
    # Strip prefix if present
    vector = vector.strip()
    if vector.startswith("CVSS:3.1/"):
        vector = vector[9:]
    elif vector.startswith("CVSS:3.0/"):
        vector = vector[9:]
    
    metrics = {}
    for part in vector.split("/"):
        if ":" in part:
            key, val = part.split(":", 1)
            metrics[key.upper()] = val.upper()
    
    return metrics if metrics else None


def compute_cvss31_base(metrics: Dict[str, str]) -> Optional[float]:
    """Compute CVSS v3.1 Base Score from parsed metrics."""
    required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    if not all(m in metrics for m in required):
        return None
    
    try:
        scope = metrics["S"]
        scope_changed = (scope == "C")
        
        # Impact Sub Score
        isc_base = 1 - (
            (1 - CVSS31_METRICS["C"].get(metrics["C"], 0)) *
            (1 - CVSS31_METRICS["I"].get(metrics["I"], 0)) *
            (1 - CVSS31_METRICS["A"].get(metrics["A"], 0))
        )
        
        if scope_changed:
            isc = 7.52 * (isc_base - 0.029) - 3.25 * pow(isc_base - 0.02, 15)
        else:
            isc = 6.42 * isc_base
        
        # Exploitability Sub Score
        pr_vals = CVSS31_METRICS["PR"].get(metrics["PR"], {})
        pr_key = "C" if scope_changed else "U"
        pr_val = pr_vals.get(pr_key, 0.85)
        
        esc = (
            8.22 *
            CVSS31_METRICS["AV"].get(metrics["AV"], 0.85) *
            CVSS31_METRICS["AC"].get(metrics["AC"], 0.77) *
            pr_val *
            CVSS31_METRICS["UI"].get(metrics["UI"], 0.85)
        )
        
        # Base Score
        if isc <= 0:
            return 0.0
        
        if scope_changed:
            base = min(1.08 * (isc + esc), 10.0)
        else:
            base = min(isc + esc, 10.0)
        
        # Round up to nearest 0.1
        return math.ceil(base * 10) / 10
        
    except (KeyError, TypeError, ValueError):
        return None


def cvss_severity_label(score: float) -> str:
    """Get severity label from CVSS score."""
    if score is None:
        return "Unknown"
    for low, high, label in CVSS31_SEVERITY:
        if low <= score <= high:
            return label
    return "Unknown"


def compute_cvss_effective(cvss_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compute effective CVSS score from evaluation data.
    Supports manual score override or vector-based calculation.
    """
    result = {
        "base": None,
        "severity": None,
        "source": None,
        "version": "3.1",
    }
    
    # Priority: manual baseScore > vector computation
    if cvss_data.get("baseScore") is not None:
        try:
            result["base"] = float(cvss_data["baseScore"])
            result["severity"] = cvss_severity_label(result["base"])
            result["source"] = "manual"
            return result
        except (ValueError, TypeError):
            pass
    
    vector = cvss_data.get("vector", "")
    if vector:
        metrics = parse_cvss31_vector(vector)
        if metrics:
            result["base"] = compute_cvss31_base(metrics)
            if result["base"] is not None:
                result["severity"] = cvss_severity_label(result["base"])
                result["source"] = "vector"
                if "CVSS:4" in vector:
                    result["version"] = "4.0"
    
    return result


# ---------------------------------------------------------------------------
# Readiness Evaluation (graceful degradation)
# ---------------------------------------------------------------------------

def eval_readiness(standard: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check if minimum required fields are present for a standard.
    Returns: {"ready": bool, "missing": [field_names], "complete": percentage}
    """
    if standard == "cvss":
        cvss = data.get("cvss", {})
        has_vector = bool(cvss.get("vector", "").strip())
        bs = cvss.get("baseScore")
        has_score = bs is not None and bs != ""
        
        if has_vector or has_score:
            return {"ready": True, "missing": [], "complete": 100}
        return {"ready": False, "missing": ["vector oder baseScore"], "complete": 0}
    
    elif standard == "iso":
        iso = data.get("iso27005", {})
        missing = []
        if not iso.get("likelihood"):
            missing.append("Eintrittswahrscheinlichkeit")
        if not iso.get("impact"):
            missing.append("Auswirkung")
        
        complete = ((2 - len(missing)) / 2) * 100
        return {"ready": len(missing) == 0, "missing": missing, "complete": complete}
    
    elif standard == "bsi":
        bsi = data.get("bsi", {})
        missing = []
        if not bsi.get("protectionNeed"):
            missing.append("Schutzbedarf")
        if not bsi.get("measureStatus"):
            missing.append("Maßnahmenstatus")
        
        complete = ((2 - len(missing)) / 2) * 100
        return {"ready": len(missing) == 0, "missing": missing, "complete": complete}
    
    elif standard == "nist":
        nist = data.get("nist", {})
        missing = []
        if not nist.get("likelihood"):
            missing.append("Likelihood")
        if not nist.get("impact"):
            missing.append("Impact")
        
        complete = ((2 - len(missing)) / 2) * 100
        return {"ready": len(missing) == 0, "missing": missing, "complete": complete}
    
    return {"ready": False, "missing": ["unbekannter Standard"], "complete": 0}


def eval_all_readiness(data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Check readiness for all four standards."""
    return {
        "cvss": eval_readiness("cvss", data),
        "iso": eval_readiness("iso", data),
        "bsi": eval_readiness("bsi", data),
        "nist": eval_readiness("nist", data),
    }


# ---------------------------------------------------------------------------
# ISO 27005 Risk Computation
# ---------------------------------------------------------------------------

def compute_iso_risk(likelihood: int, impact: int) -> Dict[str, Any]:
    """Compute ISO 27005 style risk level from L×I matrix."""
    if not (1 <= likelihood <= 5) or not (1 <= impact <= 5):
        return {"level": None, "score": None}
    
    level = ISO27005_RISK_MATRIX.get((likelihood, impact), "Unbekannt")
    score = likelihood * impact  # Simple numeric for sorting
    
    return {
        "level": level,
        "score": score,
        "likelihood_label": ISO27005_LIKELIHOOD.get(likelihood, ""),
        "impact_label": ISO27005_IMPACT.get(impact, ""),
    }


# ---------------------------------------------------------------------------
# NIST Risk Computation
# ---------------------------------------------------------------------------

def compute_nist_risk(likelihood: str, impact: str) -> Dict[str, Any]:
    """Compute NIST SP 800-30 style risk level."""
    level = NIST_RISK_MATRIX.get((likelihood, impact), None)
    
    return {
        "level": level,
        "likelihood_desc": NIST_LIKELIHOOD.get(likelihood, ""),
        "impact_desc": NIST_IMPACT.get(impact, ""),
    }


# ---------------------------------------------------------------------------
# SVG Diagram Generators
# ---------------------------------------------------------------------------

def svg_cvss_bar(score: float, severity: str, width: int = 300, height: int = 40) -> str:
    """Generate SVG bar chart for CVSS score."""
    if score is None:
        return ""
    
    colors = {
        "None": "#53aa33",
        "Low": "#ffcb0d",
        "Medium": "#f9a009",
        "High": "#df3d03",
        "Critical": "#cc0500",
    }
    color = colors.get(severity, "#888")
    
    bar_width = (score / 10) * (width - 60)
    
    return f'''<svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg">
  <rect x="0" y="0" width="{width}" height="{height}" fill="#f5f5f5" rx="4"/>
  <rect x="2" y="2" width="{bar_width}" height="{height-4}" fill="{color}" rx="3"/>
  <text x="{width-55}" y="{height/2+5}" font-family="Arial" font-size="14" font-weight="bold" fill="#333">{score:.1f}</text>
  <text x="{width-55}" y="{height-2}" font-family="Arial" font-size="9" fill="#666">{severity}</text>
</svg>'''


def svg_iso_matrix(evaluations: List[Dict], width: int = 320, height: int = 280) -> str:
    """Generate 5×5 ISO 27005 risk matrix SVG with plotted evaluations."""
    cell_w = 50
    cell_h = 40
    offset_x = 50
    offset_y = 20
    
    # Risk level colors
    colors = {
        "Niedrig": "#53aa33",
        "Mittel": "#f9a009",
        "Hoch": "#df3d03",
        "Kritisch": "#cc0500",
    }
    
    svg_parts = [
        f'<svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg">',
        '<style>.cell{stroke:#333;stroke-width:1}.label{font-family:Arial;font-size:9px;fill:#333}.axis{font-family:Arial;font-size:10px;fill:#333;font-weight:bold}.marker{font-family:Arial;font-size:10px;fill:#fff;font-weight:bold}</style>',
    ]
    
    # Draw matrix cells (5×5)
    for l in range(1, 6):
        for i in range(1, 6):
            x = offset_x + (i - 1) * cell_w
            y = offset_y + (5 - l) * cell_h
            risk = ISO27005_RISK_MATRIX.get((l, i), "Niedrig")
            color = colors.get(risk, "#ccc")
            svg_parts.append(f'<rect x="{x}" y="{y}" width="{cell_w}" height="{cell_h}" fill="{color}" class="cell"/>')
    
    # Axis labels
    svg_parts.append(f'<text x="{offset_x + 2.5*cell_w}" y="{height-5}" text-anchor="middle" class="axis">Auswirkung →</text>')
    svg_parts.append(f'<text x="10" y="{offset_y + 2.5*cell_h}" text-anchor="middle" transform="rotate(-90,10,{offset_y + 2.5*cell_h})" class="axis">Wahrsch. →</text>')
    
    # Impact labels (bottom)
    for i in range(1, 6):
        x = offset_x + (i - 0.5) * cell_w
        svg_parts.append(f'<text x="{x}" y="{offset_y + 5*cell_h + 14}" text-anchor="middle" class="label">{i}</text>')
    
    # Likelihood labels (left)
    for l in range(1, 6):
        y = offset_y + (5 - l + 0.5) * cell_h
        svg_parts.append(f'<text x="{offset_x - 8}" y="{y + 3}" text-anchor="end" class="label">{l}</text>')
    
    # Plot evaluation markers
    for ev in evaluations:
        iso = ev.get("iso27005", {})
        l = iso.get("likelihood")
        i = iso.get("impact")
        if l and i and 1 <= l <= 5 and 1 <= i <= 5:
            eid = ev.get("eid", "?")
            cx = offset_x + (i - 0.5) * cell_w
            cy = offset_y + (5 - l + 0.5) * cell_h
            svg_parts.append(f'<circle cx="{cx}" cy="{cy}" r="12" fill="#000" opacity="0.7"/>')
            svg_parts.append(f'<text x="{cx}" y="{cy + 4}" text-anchor="middle" class="marker">{eid}</text>')
    
    svg_parts.append('</svg>')
    return '\n'.join(svg_parts)


def svg_bsi_traffic_light(evaluations: List[Dict], width: int = 400, height: int = 100) -> str:
    """Generate BSI protection need traffic light SVG."""
    svg_parts = [
        f'<svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg">',
        '<style>.tl{stroke:#333;stroke-width:2}.label{font-family:Arial;font-size:10px;fill:#333}</style>',
    ]
    
    # Count by protection need
    counts = {"Normal": 0, "Hoch": 0, "Sehr hoch": 0}
    for ev in evaluations:
        bsi = ev.get("bsi", {})
        pn = bsi.get("protectionNeed", "")
        if pn in counts:
            counts[pn] += 1
    
    # Traffic light circles
    lights = [
        ("Normal", "#53aa33", 60),
        ("Hoch", "#f9a009", 160),
        ("Sehr hoch", "#cc0500", 260),
    ]
    
    for label, color, cx in lights:
        count = counts.get(label, 0)
        opacity = "1" if count > 0 else "0.3"
        svg_parts.append(f'<circle cx="{cx}" cy="40" r="30" fill="{color}" opacity="{opacity}" class="tl"/>')
        svg_parts.append(f'<text x="{cx}" y="45" text-anchor="middle" font-family="Arial" font-size="16" font-weight="bold" fill="#fff">{count}</text>')
        svg_parts.append(f'<text x="{cx}" y="85" text-anchor="middle" class="label">{label}</text>')
    
    svg_parts.append('</svg>')
    return '\n'.join(svg_parts)


def svg_nist_summary(evaluations: List[Dict], width: int = 350, height: int = 200) -> str:
    """Generate NIST risk level summary bar chart."""
    # Count by risk level
    levels = ["Very Low", "Low", "Moderate", "High", "Very High"]
    counts = {l: 0 for l in levels}
    
    for ev in evaluations:
        nist = ev.get("nist", {})
        lik = nist.get("likelihood", "")
        imp = nist.get("impact", "")
        if lik and imp:
            result = compute_nist_risk(lik, imp)
            level = result.get("level")
            if level in counts:
                counts[level] += 1
    
    total = sum(counts.values())
    if total == 0:
        return ""
    
    bar_height = 25
    bar_gap = 8
    offset_x = 80
    offset_y = 20
    max_bar = width - offset_x - 40
    
    colors = {
        "Very Low": "#53aa33",
        "Low": "#a8d08d",
        "Moderate": "#f9a009",
        "High": "#df3d03",
        "Very High": "#cc0500",
    }
    
    svg_parts = [
        f'<svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg">',
        '<style>.label{font-family:Arial;font-size:10px;fill:#333}.count{font-family:Arial;font-size:11px;fill:#333;font-weight:bold}</style>',
    ]
    
    for idx, level in enumerate(levels):
        y = offset_y + idx * (bar_height + bar_gap)
        count = counts[level]
        bar_w = (count / total) * max_bar if total > 0 else 0
        color = colors.get(level, "#ccc")
        
        svg_parts.append(f'<text x="{offset_x - 5}" y="{y + 16}" text-anchor="end" class="label">{level}</text>')
        svg_parts.append(f'<rect x="{offset_x}" y="{y}" width="{max(bar_w, 2)}" height="{bar_height}" fill="{color}" rx="3"/>')
        if count > 0:
            svg_parts.append(f'<text x="{offset_x + bar_w + 5}" y="{y + 17}" class="count">{count}</text>')
    
    svg_parts.append('</svg>')
    return '\n'.join(svg_parts)


# ---------------------------------------------------------------------------
# HTML Rendering for DIN 5008 PDF Annexes
# ---------------------------------------------------------------------------

def _esc(text: Any) -> str:
    """HTML escape helper."""
    return html.escape(str(text) if text else "")


def build_din_risk_annexes_html(
    evaluations: List[Dict],
    flags: Dict[str, bool],
    include_svg: bool = True
) -> str:
    """
    Build HTML for risk annexes to inject into DIN 5008 PDF.
    
    Args:
        evaluations: List of evaluation records with eid, cvss, iso27005, bsi, nist fields
        flags: {"cvss": bool, "iso": bool, "bsi": bool, "nist": bool}
        include_svg: Whether to include SVG diagrams
    
    Returns:
        HTML string for annexes
    """
    if not evaluations:
        return ""
    
    parts = []

    def annex_export_ok(ev: Dict, std: str) -> bool:
        inc = ev.get("exportInclude") or {}
        return inc.get(std) is not False
    
    # Filter to only evaluations with data
    def has_cvss(ev):
        cvss = ev.get("cvss", {})
        v = (cvss.get("vector") or "").strip()
        bs = cvss.get("baseScore")
        if v:
            return True
        if bs is None or bs == "":
            return False
        try:
            float(bs)
        except (TypeError, ValueError):
            return False
        return True
    
    def has_iso(ev):
        iso = ev.get("iso27005", {})
        return bool(iso.get("likelihood") and iso.get("impact"))
    
    def has_bsi(ev):
        bsi = ev.get("bsi", {})
        return bool(bsi.get("protectionNeed"))
    
    def has_nist(ev):
        nist = ev.get("nist", {})
        return bool(nist.get("likelihood") and nist.get("impact"))
    
    # CVSS Annex
    if flags.get("cvss"):
        cvss_rows = [ev for ev in evaluations if has_cvss(ev) and annex_export_ok(ev, "cvss")]
        if cvss_rows:
            parts.append('<div class="annex-section" style="page-break-before:always;">')
            parts.append('<h2>Anhang: CVSS-Bewertungen</h2>')
            parts.append('<p style="font-size:9pt;color:#666;">Bewertung nach Common Vulnerability Scoring System (FIRST)</p>')
            
            parts.append('<table><tr><th style="width:60px;">Ref</th><th>Score</th><th>Schweregrad</th><th>Vektor</th></tr>')
            
            for ev in cvss_rows:
                eid = _esc(ev.get("eid", "?"))
                cvss = ev.get("cvss", {})
                eff = compute_cvss_effective(cvss)
                base = eff.get("base")
                sev = eff.get("severity", "")
                vec = _esc(cvss.get("vector", "")[:80])
                
                # Color based on severity
                sev_colors = {"Critical": "#cc0500", "High": "#df3d03", "Medium": "#f9a009", "Low": "#ffcb0d", "None": "#53aa33"}
                sev_color = sev_colors.get(sev, "#888")
                
                score_str = f"{base:.1f}" if base is not None else "-"
                
                parts.append(f'<tr>')
                parts.append(f'<td><strong>{eid}</strong></td>')
                parts.append(f'<td style="font-weight:bold;">{score_str}</td>')
                parts.append(f'<td><span style="background:{sev_color};color:#fff;padding:2px 8px;border-radius:3px;">{_esc(sev)}</span></td>')
                parts.append(f'<td style="font-family:monospace;font-size:8pt;">{vec}</td>')
                parts.append('</tr>')
                
                # SVG bar if enabled
                if include_svg and base is not None:
                    svg = svg_cvss_bar(base, sev)
                    parts.append(f'<tr><td colspan="4" style="padding:4px 8px;">{svg}</td></tr>')
            
            parts.append('</table></div>')
    
    # ISO 27005 Annex
    if flags.get("iso"):
        iso_rows = [ev for ev in evaluations if has_iso(ev) and annex_export_ok(ev, "iso")]
        if iso_rows:
            parts.append('<div class="annex-section" style="page-break-before:always;">')
            parts.append('<h2>Anhang: ISO 27005 Risikobewertung</h2>')
            parts.append('<p style="font-size:9pt;color:#666;">Risikomatrix nach ISO/IEC 27005:2022</p>')
            
            # Matrix diagram
            if include_svg:
                matrix_svg = svg_iso_matrix(iso_rows)
                parts.append(f'<div style="margin:16px 0;">{matrix_svg}</div>')
            
            parts.append('<table><tr><th style="width:60px;">Ref</th><th>Wahrsch.</th><th>Auswirkung</th><th>Risikostufe</th><th>Behandlung</th></tr>')
            
            for ev in iso_rows:
                eid = _esc(ev.get("eid", "?"))
                iso = ev.get("iso27005", {})
                lik = iso.get("likelihood", 0)
                imp = iso.get("impact", 0)
                result = compute_iso_risk(lik, imp)
                level = result.get("level", "-")
                treatment = _esc(iso.get("treatment", ""))
                
                level_colors = {"Niedrig": "#53aa33", "Mittel": "#f9a009", "Hoch": "#df3d03", "Kritisch": "#cc0500"}
                level_color = level_colors.get(level, "#888")
                
                parts.append(f'<tr>')
                parts.append(f'<td><strong>{eid}</strong></td>')
                parts.append(f'<td>{lik} ({_esc(result.get("likelihood_label", ""))})</td>')
                parts.append(f'<td>{imp} ({_esc(result.get("impact_label", ""))})</td>')
                parts.append(f'<td><span style="background:{level_color};color:#fff;padding:2px 8px;border-radius:3px;">{_esc(level)}</span></td>')
                parts.append(f'<td>{treatment}</td>')
                parts.append('</tr>')
            
            parts.append('</table></div>')
    
    # BSI Annex
    if flags.get("bsi"):
        bsi_rows = [ev for ev in evaluations if has_bsi(ev) and annex_export_ok(ev, "bsi")]
        if bsi_rows:
            parts.append('<div class="annex-section" style="page-break-before:always;">')
            parts.append('<h2>Anhang: BSI IT-Grundschutz</h2>')
            parts.append('<p style="font-size:9pt;color:#666;">Bewertung nach BSI-Standard 200-2 / 200-3</p>')
            
            # Traffic light
            if include_svg:
                tl_svg = svg_bsi_traffic_light(bsi_rows)
                parts.append(f'<div style="margin:16px 0;">{tl_svg}</div>')
            
            parts.append('<table><tr><th style="width:60px;">Ref</th><th>Baustein</th><th>Schutzbedarf</th><th>Status</th><th>Abweichung/Lücke</th></tr>')
            
            for ev in bsi_rows:
                eid = _esc(ev.get("eid", "?"))
                bsi = ev.get("bsi", {})
                module = _esc(bsi.get("module", ""))
                pn = bsi.get("protectionNeed", "")
                status = bsi.get("measureStatus", "")
                gap = _esc(bsi.get("gap", ""))[:200]
                
                pn_colors = {"Normal": "#53aa33", "Hoch": "#f9a009", "Sehr hoch": "#cc0500"}
                pn_color = pn_colors.get(pn, "#888")
                
                status_colors = {"Erfüllt": "#53aa33", "Teilweise": "#f9a009", "Nicht erfüllt": "#cc0500", "Entbehrlich": "#888"}
                status_color = status_colors.get(status, "#888")
                
                parts.append(f'<tr>')
                parts.append(f'<td><strong>{eid}</strong></td>')
                parts.append(f'<td>{module}</td>')
                parts.append(f'<td><span style="background:{pn_color};color:#fff;padding:2px 8px;border-radius:3px;">{_esc(pn)}</span></td>')
                parts.append(f'<td><span style="background:{status_color};color:#fff;padding:2px 8px;border-radius:3px;">{_esc(status)}</span></td>')
                parts.append(f'<td style="font-size:9pt;">{gap}</td>')
                parts.append('</tr>')
            
            parts.append('</table></div>')
    
    # NIST Annex
    if flags.get("nist"):
        nist_rows = [ev for ev in evaluations if has_nist(ev) and annex_export_ok(ev, "nist")]
        if nist_rows:
            parts.append('<div class="annex-section" style="page-break-before:always;">')
            parts.append('<h2>Anhang: NIST Risikobewertung</h2>')
            parts.append('<p style="font-size:9pt;color:#666;">Bewertung nach NIST SP 800-30 Rev. 1</p>')
            
            # Summary chart
            if include_svg:
                summary_svg = svg_nist_summary(nist_rows)
                if summary_svg:
                    parts.append(f'<div style="margin:16px 0;">{summary_svg}</div>')
            
            parts.append('<table><tr><th style="width:60px;">Ref</th><th>Likelihood</th><th>Impact</th><th>Risikostufe</th><th>CSF Kategorie</th></tr>')
            
            for ev in nist_rows:
                eid = _esc(ev.get("eid", "?"))
                nist = ev.get("nist", {})
                lik = nist.get("likelihood", "")
                imp = nist.get("impact", "")
                result = compute_nist_risk(lik, imp)
                level = result.get("level", "-")
                csf = _esc(nist.get("csfSubcategory", ""))
                
                level_colors = {"Very Low": "#53aa33", "Low": "#a8d08d", "Moderate": "#f9a009", "High": "#df3d03", "Very High": "#cc0500"}
                level_color = level_colors.get(level, "#888")
                
                parts.append(f'<tr>')
                parts.append(f'<td><strong>{eid}</strong></td>')
                parts.append(f'<td>{_esc(lik)}</td>')
                parts.append(f'<td>{_esc(imp)}</td>')
                parts.append(f'<td><span style="background:{level_color};color:#fff;padding:2px 8px;border-radius:3px;">{_esc(level)}</span></td>')
                parts.append(f'<td>{csf}</td>')
                parts.append('</tr>')
            
            parts.append('</table></div>')
    
    return '\n'.join(parts)


# ---------------------------------------------------------------------------
# Export JSON structure for localStorage ↔ PDF bridge
# ---------------------------------------------------------------------------

def export_evaluations_json(evaluations: List[Dict], flags: Dict[str, bool]) -> Dict:
    """
    Structure for #cosmic-eval-export hidden div in HTML.
    Used by browser JS to serialize evaluations for PDF export.
    """
    return {
        "version": "1.0",
        "generated": None,  # Set at export time
        "pdfInclude": flags,
        "evaluations": {ev.get("key", ev.get("eid", f"row_{i}")): ev for i, ev in enumerate(evaluations)},
    }


# ---------------------------------------------------------------------------
# CLI test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Quick test
    test_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    metrics = parse_cvss31_vector(test_vector)
    score = compute_cvss31_base(metrics)
    sev = cvss_severity_label(score)
    print(f"Vector: {test_vector}")
    print(f"Score: {score}, Severity: {sev}")
    
    # Test readiness
    test_data = {
        "cvss": {"vector": test_vector},
        "iso27005": {"likelihood": 4, "impact": 5},
        "bsi": {},
        "nist": {"likelihood": "High", "impact": "Moderate"},
    }
    readiness = eval_all_readiness(test_data)
    print(f"\nReadiness: {readiness}")
    
    # Test ISO risk
    iso_result = compute_iso_risk(4, 5)
    print(f"\nISO Risk (4,5): {iso_result}")
    
    # Test NIST risk
    nist_result = compute_nist_risk("High", "Moderate")
    print(f"NIST Risk (High, Moderate): {nist_result}")
