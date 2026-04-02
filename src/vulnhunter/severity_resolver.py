import logging
import re
from typing import Optional

from vulnhunter.db.store import VulnDB

logger = logging.getLogger("vulnhunter.severity_resolver")

CWE_SEVERITY_MAP: dict[str, str] = {
    "CWE-89": "HIGH",
    "CWE-78": "HIGH",
    "CWE-79": "MEDIUM",
    "CWE-94": "CRITICAL",
    "CWE-502": "CRITICAL",
    "CWE-20": "MEDIUM",
    "CWE-22": "HIGH",
    "CWE-77": "HIGH",
    "CWE-119": "HIGH",
    "CWE-120": "HIGH",
    "CWE-125": "MEDIUM",
    "CWE-190": "MEDIUM",
    "CWE-200": "MEDIUM",
    "CWE-264": "HIGH",
    "CWE-269": "HIGH",
    "CWE-276": "MEDIUM",
    "CWE-287": "HIGH",
    "CWE-295": "MEDIUM",
    "CWE-306": "HIGH",
    "CWE-310": "MEDIUM",
    "CWE-311": "MEDIUM",
    "CWE-327": "MEDIUM",
    "CWE-352": "MEDIUM",
    "CWE-362": "MEDIUM",
    "CWE-400": "MEDIUM",
    "CWE-416": "HIGH",
    "CWE-434": "HIGH",
    "CWE-476": "MEDIUM",
    "CWE-601": "MEDIUM",
    "CWE-611": "HIGH",
    "CWE-617": "MEDIUM",
    "CWE-668": "MEDIUM",
    "CWE-704": "MEDIUM",
    "CWE-732": "MEDIUM",
    "CWE-770": "MEDIUM",
    "CWE-776": "MEDIUM",
    "CWE-787": "HIGH",
    "CWE-798": "HIGH",
    "CWE-862": "HIGH",
    "CWE-863": "HIGH",
    "CWE-918": "HIGH",
}

CWE_PATTERN = re.compile(r"CWE-\d+", re.IGNORECASE)


def _resolve_from_nvd(db: VulnDB, vuln_id: str) -> Optional[str]:
    try:
        severity = db.get_severity_by_id(vuln_id)
        if severity:
            return severity

        aliases = db.get_aliases(vuln_id)
        for alias in aliases:
            severity = db.get_severity_by_id(alias)
            if severity:
                return severity
    except Exception:
        logger.debug("NVD cross-reference failed for %s", vuln_id)
    return None


def _resolve_from_cwe(summary: str) -> Optional[str]:
    matches = CWE_PATTERN.findall(summary)
    for cwe in matches:
        severity = CWE_SEVERITY_MAP.get(cwe.upper())
        if severity:
            return severity
    return None


def _resolve_from_keywords(summary: str) -> Optional[str]:
    lower = summary.lower()
    critical_keywords = [
        "remote code execution", "rce", "arbitrary code execution",
        "deserialization", "pickle", "marshal",
    ]
    high_keywords = [
        "sql injection", "command injection", "path traversal",
        "directory traversal", "authentication bypass", "privilege escalation",
        "buffer overflow", "heap overflow", "use after free",
        "ssrf", "xml external entity", "xxe",
    ]
    medium_keywords = [
        "denial of service", "dos", "cross-site scripting", "xss",
        "open redirect", "information disclosure", "information leak",
        "csrf", "cross-site request forgery", "regex",
    ]

    for kw in critical_keywords:
        if kw in lower:
            return "CRITICAL"
    for kw in high_keywords:
        if kw in lower:
            return "HIGH"
    for kw in medium_keywords:
        if kw in lower:
            return "MEDIUM"
    return None


def resolve_severity(
    db: VulnDB,
    vuln_id: str,
    current_severity: str,
    summary: str,
    original_source: str = "OSV",
) -> tuple[str, bool, str]:
    if current_severity and current_severity != "UNKNOWN":
        return current_severity, False, original_source

    nvd_severity = _resolve_from_nvd(db, vuln_id)
    if nvd_severity:
        logger.debug("Resolved %s severity via NVD: %s", vuln_id, nvd_severity)
        return nvd_severity, False, f"{original_source}+NVD"

    cwe_severity = _resolve_from_cwe(summary)
    if cwe_severity:
        logger.debug("Resolved %s severity via CWE: %s", vuln_id, cwe_severity)
        return cwe_severity, True, original_source

    keyword_severity = _resolve_from_keywords(summary)
    if keyword_severity:
        logger.debug("Resolved %s severity via keywords: %s", vuln_id, keyword_severity)
        return keyword_severity, True, original_source

    logger.debug("Fallback MEDIUM for %s", vuln_id)
    return "MEDIUM", True, original_source
