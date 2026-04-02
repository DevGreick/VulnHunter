import logging
import re
from functools import lru_cache
from pathlib import Path

from packaging.version import InvalidVersion, Version
from packaging.version import parse as parse_version

from vulnhunter.db.store import VulnDB
from vulnhunter.models import (
    OSV_ECOSYSTEM_MAP,
    Dependency,
    ScanResult,
    Severity,
    Vulnerability,
)
from vulnhunter.severity_resolver import resolve_severity

logger = logging.getLogger("vulnhunter.analyzer")


@lru_cache(maxsize=4096)
def _parse_version_safely(version_str: str) -> Version | None:
    if not version_str or not version_str.strip():
        return None
    cleaned = version_str.strip()
    try:
        return parse_version(cleaned)
    except InvalidVersion:
        pass

    normalized = re.sub(r"[:](rc|beta|b|alpha)\d*$", "", cleaned, flags=re.IGNORECASE)
    normalized = normalized.rstrip(".")
    if normalized != cleaned:
        try:
            return parse_version(normalized)
        except InvalidVersion:
            pass

    logger.debug("Could not parse version: %s", version_str)
    return None


def _is_version_in_range(
    dep_version: Version,
    version_start: str,
    version_start_inclusive: bool,
    version_end: str,
    version_end_inclusive: bool,
) -> bool:
    if version_start:
        start_obj = _parse_version_safely(version_start)
        if start_obj is not None:
            if version_start_inclusive and dep_version < start_obj:
                return False
            if not version_start_inclusive and dep_version <= start_obj:
                return False

    if version_end:
        end_obj = _parse_version_safely(version_end)
        if end_obj is not None:
            if version_end_inclusive and dep_version > end_obj:
                return False
            if not version_end_inclusive and dep_version >= end_obj:
                return False

    return True


def _load_ignore_rules(
    ignore_file: Path,
) -> tuple[set[str], dict[str, set[str]]]:
    ignored_global: set[str] = set()
    ignored_package: dict[str, set[str]] = {}

    if not ignore_file.is_file():
        return ignored_global, ignored_package

    logger.info("Loading ignore rules from %s", ignore_file)
    with open(ignore_file, encoding="utf-8") as f:
        for line in f:
            line = line.strip().split("#")[0].strip()
            if not line:
                continue
            parts = line.split()
            cve_id = parts[0].lower()
            if not re.match(r"cve-\d{4}-\d{4,}", cve_id):
                continue
            if len(parts) == 1:
                ignored_global.add(cve_id)
            elif len(parts) >= 2:
                pkg = parts[1].lower()
                if pkg not in ignored_package:
                    ignored_package[pkg] = set()
                ignored_package[pkg].add(cve_id)

    logger.info(
        "Loaded %d global rules and %d package-specific rules",
        len(ignored_global),
        len(ignored_package),
    )
    return ignored_global, ignored_package


def analyze(
    db: VulnDB,
    dependencies: list[Dependency],
    ignore_file: Path | None = None,
) -> ScanResult:
    ignored_global, ignored_package = _load_ignore_rules(ignore_file or Path(".vulnignore"))

    unique_vulns: set[Vulnerability] = set()
    ignored_count = 0

    for dep in dependencies:
        ecosystem_str = OSV_ECOSYSTEM_MAP.get(dep.ecosystem, dep.ecosystem.value)
        dep_version = _parse_version_safely(dep.version)

        rows = db.query_vulnerabilities(ecosystem_str, dep.name)

        if not rows:
            cpe_aliases = db.query_cpe_aliases(dep.name)
            for alias in cpe_aliases:
                rows.extend(db.query_vulnerabilities("", alias))

        for row in rows:
            vuln_id, source, severity_str, summary, v_start, v_start_inc, v_end, v_end_inc, fixed = row

            if dep_version is not None:
                if not _is_version_in_range(dep_version, v_start, bool(v_start_inc), v_end, bool(v_end_inc)):
                    continue

            cve_lower = vuln_id.lower()
            pkg_lower = dep.name.lower()
            if cve_lower in ignored_global:
                ignored_count += 1
                continue
            if pkg_lower in ignored_package and cve_lower in ignored_package[pkg_lower]:
                ignored_count += 1
                continue

            resolved_str, is_estimated = resolve_severity(
                db, vuln_id, severity_str, summary or "",
            )
            try:
                sev = Severity(resolved_str.upper())
            except ValueError:
                sev = Severity.MEDIUM

            display_summary = summary or "No summary provided"

            vuln = Vulnerability(
                vuln_id=vuln_id,
                source=source,
                name=dep.name,
                version=dep.version,
                ecosystem=dep.ecosystem,
                severity=sev,
                summary=display_summary,
                fixed_version=fixed if fixed else None,
            )
            unique_vulns.add(vuln)

    sorted_vulns = sorted(
        unique_vulns,
        key=lambda v: (
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"].index(v.severity.value),
            v.name,
            v.vuln_id,
        ),
    )

    return ScanResult(
        total_dependencies=len(dependencies),
        total_vulnerabilities=len(sorted_vulns),
        total_ignored=ignored_count,
        vulnerabilities=sorted_vulns,
        dependencies=dependencies,
    )
