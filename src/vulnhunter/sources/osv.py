import io
import json
import logging
import tempfile
import zipfile
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from vulnhunter.db.store import VulnDB

logger = logging.getLogger("vulnhunter.sources.osv")

OSV_BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com"
SUPPORTED_ECOSYSTEMS = ("PyPI", "npm", "Maven", "Packagist", "RubyGems", "Go")
MAX_UNCOMPRESSED_SIZE = 50 * 1024 * 1024
MAX_ZIP_TOTAL_SIZE = 500 * 1024 * 1024
MAX_ZIP_MEMBERS = 50_000
MAX_ZIP_DOWNLOAD = 200 * 1024 * 1024
REQUEST_TIMEOUT = 180


def _cvss_base_score(vector: str) -> float:
    parts = vector.split("/")
    for part in parts:
        if part.startswith("CVSS:"):
            continue
        if part.startswith("AV:"):
            continue
    try:
        score_str = vector.split("/")[0]
        if score_str.startswith("CVSS:"):
            return -1.0
    except (ValueError, IndexError):
        return -1.0
    return -1.0


def _severity_from_cvss_vector(vector: str) -> str:
    try:
        import re

        match = re.search(r"CVSS:\d+\.\d+/AV:\w/AC:\w/PR:\w/UI:\w/S:\w/C:\w/I:\w/A:\w", vector)
        if not match:
            return "UNKNOWN"
        return _severity_from_vector_components(match.group(0))
    except Exception:
        return "UNKNOWN"


def _severity_from_vector_components(vector: str) -> str:
    weights: dict[str, dict[str, float]] = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
        "AC": {"L": 0.77, "H": 0.44},
        "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
        "UI": {"N": 0.85, "R": 0.62},
        "S": {"U": 0.0, "C": 1.0},
        "C": {"H": 0.56, "L": 0.22, "N": 0.0},
        "I": {"H": 0.56, "L": 0.22, "N": 0.0},
        "A": {"H": 0.56, "L": 0.22, "N": 0.0},
    }

    parts = {}
    for component in vector.split("/"):
        if ":" in component and not component.startswith("CVSS:"):
            key, val = component.split(":", 1)
            parts[key] = val

    try:
        scope_changed = parts.get("S") == "C"

        pr_key = parts.get("PR", "N")
        if scope_changed and pr_key == "L":
            pr_val = 0.68
        elif scope_changed and pr_key == "H":
            pr_val = 0.50
        else:
            pr_val = weights["PR"].get(pr_key, 0.85)

        iss = 1.0 - (
            (1.0 - weights["C"].get(parts.get("C", "N"), 0.0))
            * (1.0 - weights["I"].get(parts.get("I", "N"), 0.0))
            * (1.0 - weights["A"].get(parts.get("A", "N"), 0.0))
        )

        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss

        if impact <= 0:
            return "UNKNOWN"

        exploitability = (
            8.22
            * weights["AV"].get(parts.get("AV", "N"), 0.85)
            * weights["AC"].get(parts.get("AC", "L"), 0.77)
            * pr_val
            * weights["UI"].get(parts.get("UI", "N"), 0.85)
        )

        if scope_changed:
            base = min(1.08 * (impact + exploitability), 10.0)
        else:
            base = min(impact + exploitability, 10.0)

        import math

        base = math.ceil(base * 10) / 10

    except (KeyError, TypeError):
        return "UNKNOWN"

    return _score_to_severity(base)


def _score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "UNKNOWN"


def _extract_severity(severity_list: list[dict[str, Any]]) -> str:
    for entry in severity_list:
        if entry.get("type") == "CVSS_V3":
            score_str = entry.get("score", "")
            if isinstance(score_str, str) and score_str.startswith("CVSS:"):
                return _severity_from_cvss_vector(score_str)
    return "UNKNOWN"


def _parse_ranges(db: VulnDB, vuln_id: str, ecosystem: str, package_name: str, ranges: list[dict[str, Any]]) -> None:
    for range_entry in ranges:
        if range_entry.get("type") != "ECOSYSTEM":
            continue
        events = range_entry.get("events", [])
        introduced: str | None = None
        for event in events:
            if "introduced" in event:
                introduced = event["introduced"]
            elif "fixed" in event and introduced is not None:
                fixed = event["fixed"]
                version_start = "" if introduced == "0" else introduced
                db.insert_affected_package(
                    vuln_id=vuln_id,
                    ecosystem=ecosystem,
                    package_name=package_name,
                    version_start=version_start,
                    version_start_inclusive=True,
                    version_end=fixed,
                    version_end_inclusive=False,
                    fixed_version=fixed,
                )
                introduced = None

        if introduced is not None:
            version_start = "" if introduced == "0" else introduced
            db.insert_affected_package(
                vuln_id=vuln_id,
                ecosystem=ecosystem,
                package_name=package_name,
                version_start=version_start,
                version_start_inclusive=True,
            )


def _process_vuln(db: VulnDB, data: dict[str, Any]) -> bool:
    vuln_id = data.get("id")
    if not vuln_id:
        return False

    summary = data.get("summary", "")
    severity_list = data.get("severity", [])
    severity = _extract_severity(severity_list) if severity_list else "UNKNOWN"
    published = data.get("published", "")
    modified = data.get("modified", "")

    db.upsert_vulnerability(
        vuln_id=vuln_id,
        source="OSV",
        severity=severity,
        summary=summary,
        published=published,
        modified=modified,
    )

    for affected in data.get("affected", []):
        pkg = affected.get("package", {})
        ecosystem = pkg.get("ecosystem", "")
        package_name = pkg.get("name", "")
        if not ecosystem or not package_name:
            continue
        _parse_ranges(db, vuln_id, ecosystem, package_name, affected.get("ranges", []))

    return True


def _download_and_process(db: VulnDB, ecosystem: str, callback: Callable | None = None) -> int:
    url = f"{OSV_BASE_URL}/{ecosystem}/all.zip"
    logger.info("Downloading OSV data for %s", ecosystem)

    response = requests.get(url, timeout=REQUEST_TIMEOUT, stream=True)
    content_type = response.headers.get("Content-Type", "")
    if response.status_code != 200:
        logger.error("Failed to download %s: HTTP %d", url, response.status_code)
        return 0

    if content_type and "zip" not in content_type and "octet-stream" not in content_type:
        logger.error("Unexpected Content-Type for %s: %s", url, content_type)
        return 0

    chunks: list[bytes] = []
    downloaded = 0
    for chunk in response.iter_content(chunk_size=8192):
        downloaded += len(chunk)
        if downloaded > MAX_ZIP_DOWNLOAD:
            logger.error("Zip download exceeds %d bytes limit for %s", MAX_ZIP_DOWNLOAD, ecosystem)
            return 0
        chunks.append(chunk)
    zip_bytes = io.BytesIO(b"".join(chunks))
    count = 0

    with tempfile.TemporaryDirectory() as tmpdir:
        extract_dir = Path(tmpdir)
        try:
            with zipfile.ZipFile(zip_bytes) as zf:
                members = zf.infolist()
                if len(members) > MAX_ZIP_MEMBERS:
                    logger.error("Zip has %d members (max %d) for %s", len(members), MAX_ZIP_MEMBERS, ecosystem)
                    return 0

                total_uncompressed = sum(m.file_size for m in members)
                if total_uncompressed > MAX_ZIP_TOTAL_SIZE:
                    logger.error(
                        "Zip total uncompressed size %d exceeds %d for %s",
                        total_uncompressed,
                        MAX_ZIP_TOTAL_SIZE,
                        ecosystem,
                    )
                    return 0

                bytes_extracted = 0
                for member_info in members:
                    if member_info.is_dir():
                        continue

                    target = extract_dir / member_info.filename
                    if not target.resolve().is_relative_to(extract_dir.resolve()):
                        logger.warning("Zip slip detected, skipping: %s", member_info.filename)
                        continue

                    if member_info.file_size > MAX_UNCOMPRESSED_SIZE:
                        logger.warning(
                            "Skipping oversized file: %s (%d bytes)",
                            member_info.filename,
                            member_info.file_size,
                        )
                        continue

                    if not member_info.filename.endswith(".json"):
                        continue

                    try:
                        raw = zf.read(member_info.filename)
                        bytes_extracted += len(raw)
                        if bytes_extracted > MAX_ZIP_TOTAL_SIZE:
                            logger.error("Real extracted size exceeds limit for %s", ecosystem)
                            return count
                        data = json.loads(raw)
                    except (json.JSONDecodeError, KeyError) as exc:
                        logger.warning("Failed to parse %s: %s", member_info.filename, exc)
                        continue

                    if _process_vuln(db, data):
                        count += 1

                    if callback and count % 500 == 0:
                        callback(ecosystem, count)

        except zipfile.BadZipFile:
            logger.error("Invalid zip file for ecosystem %s", ecosystem)
            return 0

    db.commit()
    logger.info("Processed %d vulnerabilities for %s", count, ecosystem)
    return count


def update_osv(
    db: VulnDB,
    ecosystems: list[str],
    callback: Callable | None = None,
) -> int:
    total = 0
    for ecosystem in ecosystems:
        if ecosystem not in SUPPORTED_ECOSYSTEMS:
            logger.warning("Unsupported ecosystem: %s", ecosystem)
            continue
        count = _download_and_process(db, ecosystem, callback)
        total += count

    db.set_metadata("osv_last_update", datetime.now(timezone.utc).isoformat())
    return total
