import logging
import os
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from vulnhunter.db.store import VulnDB

logger = logging.getLogger("vulnhunter.sources.nvd")

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
REQUEST_TIMEOUT = 180
PAGE_SIZE = 2000
USER_AGENT = "VulnHunter/2.0 (vulnerability-scanner)"


def _load_dotenv_key() -> str:
    for candidate in (Path.cwd() / ".env", Path.home() / ".vulnhunter" / ".env"):
        if candidate.is_file():
            try:
                for line in candidate.read_text().splitlines():
                    stripped = line.strip()
                    if stripped.startswith("NVD_API_KEY=") and not stripped.startswith("#"):
                        return stripped.split("=", 1)[1].strip().strip("\"'")
            except OSError:
                continue
    return ""


def _load_keyring_key() -> str:
    try:
        import keyring

        value: str | None = keyring.get_password("vulnhunter", "nvd_api_key")
        return value or ""
    except Exception:
        return ""


def _resolve_api_key(explicit_key: str = "") -> str:
    if explicit_key:
        return explicit_key
    from_env = os.environ.get("NVD_API_KEY", "")
    if from_env:
        return from_env
    from_keyring = _load_keyring_key()
    if from_keyring:
        return from_keyring
    return _load_dotenv_key()


def _get_session(api_key: str = "") -> tuple[requests.Session, float, bool]:
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    resolved_key: str = _resolve_api_key(api_key)
    has_key: bool = bool(resolved_key)
    if has_key:
        session.headers["apiKey"] = resolved_key
    delay: float = 0.6 if has_key else 6.0
    return session, delay, has_key


def extract_vendor_product(cpe_uri: str) -> str | None:
    parts = cpe_uri.split(":")
    if len(parts) < 5:
        return None
    vendor = parts[3]
    product = parts[4]
    if vendor == "*" or product == "*":
        return None
    return f"{vendor}:{product}"


def get_severity(metrics: dict[str, Any]) -> str:
    for key in ("cvssMetricV31", "cvssMetricV30"):
        metric_list = metrics.get(key, [])
        if metric_list:
            for m in metric_list:
                cvss = m.get("cvssData", {})
                score = cvss.get("baseScore", 0.0)
                return _score_to_severity(score)

    v2_list = metrics.get("cvssMetricV2", [])
    if v2_list:
        for m in v2_list:
            cvss = m.get("cvssData", {})
            score = cvss.get("baseScore", 0.0)
            return _score_to_severity_v2(score)

    return "UNKNOWN"


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


def _score_to_severity_v2(score: float) -> str:
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "UNKNOWN"


def get_english_description(descriptions: list[dict[str, Any]]) -> str:
    for desc in descriptions:
        if desc.get("lang", "") in ("en", "en-US"):
            return desc.get("value", "")
    if descriptions:
        return descriptions[0].get("value", "")
    return ""


def _extract_cpe_data(db: VulnDB, vuln_id: str, configurations: list[dict[str, Any]]) -> None:
    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                cpe_uri = cpe_match.get("criteria", "")
                vp = extract_vendor_product(cpe_uri)
                if not vp:
                    continue

                version_start = cpe_match.get("versionStartIncluding", "")
                version_end = cpe_match.get("versionEndExcluding", "")
                version_end_incl = cpe_match.get("versionEndIncluding", "")
                version_start_excl = cpe_match.get("versionStartExcluding", "")

                start = version_start or version_start_excl
                start_inclusive = bool(version_start)
                end = version_end or version_end_incl
                end_inclusive = bool(version_end_incl)

                db.insert_affected_package(
                    vuln_id=vuln_id,
                    ecosystem="",
                    package_name=vp,
                    version_start=start,
                    version_start_inclusive=start_inclusive,
                    version_end=end,
                    version_end_inclusive=end_inclusive,
                )

                db.upsert_cpe_alias(vp.split(":")[1], vp)


def _process_cve(db: VulnDB, cve: dict[str, Any]) -> bool:
    cve_id = cve.get("id", "")
    if not cve_id:
        return False

    descriptions = cve.get("descriptions", [])
    summary = get_english_description(descriptions)
    metrics = cve.get("metrics", {})
    severity = get_severity(metrics)
    published = cve.get("published", "")
    modified = cve.get("lastModified", "")

    db.upsert_vulnerability(
        vuln_id=cve_id,
        source="NVD",
        severity=severity,
        summary=summary,
        published=published,
        modified=modified,
    )

    configurations = cve.get("configurations", [])
    _extract_cpe_data(db, cve_id, configurations)

    return True


MAX_PAGES = 500


def _paginated_fetch(
    session: requests.Session,
    base_url: str,
    delay: float,
    results_key: str,
    callback: Callable | None = None,
) -> list[dict[str, Any]]:
    all_items: list[dict[str, Any]] = []
    start_index = 0
    page_count = 0

    while True:
        params: dict[str, Any] = {"startIndex": start_index, "resultsPerPage": PAGE_SIZE}
        logger.info("Fetching %s startIndex=%d", base_url, start_index)

        response = session.get(base_url, params=params, timeout=REQUEST_TIMEOUT)
        content_type = response.headers.get("Content-Type", "")

        if response.status_code == 403:
            logger.error("NVD API returned 403 Forbidden. Check API key.")
            break

        if response.status_code == 429:
            logger.warning("Rate limited by NVD, waiting 30s")
            time.sleep(30)
            continue

        if response.status_code != 200:
            logger.error("NVD API error: HTTP %d", response.status_code)
            break

        if "json" not in content_type and "javascript" not in content_type:
            logger.error("Unexpected Content-Type: %s", content_type)
            break

        try:
            data = response.json()
        except ValueError:
            logger.error("Invalid JSON response from NVD")
            break

        items = data.get(results_key, [])
        all_items.extend(items)

        total_results = data.get("totalResults", 0)

        if callback:
            callback(len(all_items), total_results)

        start_index += PAGE_SIZE
        page_count += 1
        if start_index >= total_results or page_count >= MAX_PAGES:
            if page_count >= MAX_PAGES:
                logger.warning("Reached max page limit (%d), stopping pagination", MAX_PAGES)
            break

        time.sleep(delay)

    return all_items


def update_nvd(
    db: VulnDB,
    api_key: str = "",
    callback: Callable | None = None,
) -> int:
    session, delay, has_key = _get_session(api_key)
    items = _paginated_fetch(session, NVD_CVE_URL, delay, "vulnerabilities", callback)

    count = 0
    for item in items:
        cve = item.get("cve", {})
        if _process_cve(db, cve):
            count += 1

        if count % 1000 == 0:
            db.commit()

    db.commit()
    db.set_metadata("nvd_last_update", datetime.now(timezone.utc).isoformat())
    logger.info("Processed %d CVEs from NVD", count)
    return count


def build_cpe_index(
    db: VulnDB,
    api_key: str = "",
    callback: Callable | None = None,
) -> int:
    session, delay, has_key = _get_session(api_key)
    items = _paginated_fetch(session, NVD_CPE_URL, delay, "products", callback)

    count = 0
    for item in items:
        cpe = item.get("cpe", {})
        cpe_name = cpe.get("cpeName", "")
        vp = extract_vendor_product(cpe_name)
        if not vp:
            continue

        titles = cpe.get("titles", [])
        for title in titles:
            title_text = title.get("title", "")
            if title_text:
                db.upsert_cpe_alias(title_text, vp)
                count += 1

        product = vp.split(":")[1] if ":" in vp else ""
        if product:
            db.upsert_cpe_alias(product, vp)
            count += 1

        if count % 1000 == 0:
            db.commit()

    db.commit()
    logger.info("Created %d CPE aliases", count)
    return count
