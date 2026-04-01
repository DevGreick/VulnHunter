import json
import logging
from pathlib import Path
from typing import Any

from vulnhunter.models import ScanResult, Severity, Vulnerability

logger = logging.getLogger(__name__)

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

SEVERITY_TO_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.UNKNOWN: "note",
}


def _build_rule(vuln: Vulnerability) -> dict[str, Any]:
    level = SEVERITY_TO_LEVEL[vuln.severity]
    return {
        "id": vuln.vuln_id,
        "shortDescription": {"text": vuln.summary},
        "defaultConfiguration": {"level": level},
    }


def _build_result(vuln: Vulnerability) -> dict[str, Any]:
    level = SEVERITY_TO_LEVEL[vuln.severity]
    message = f"{vuln.name}@{vuln.version} ({vuln.ecosystem.value})"
    if vuln.fixed_version:
        message += f" — fix available: {vuln.fixed_version}"

    return {
        "ruleId": vuln.vuln_id,
        "level": level,
        "message": {"text": message},
    }


def _validate_output_path(output_path: Path, base_dir: Path | None = None) -> Path:
    resolved = output_path.resolve()
    base = (base_dir or Path.cwd()).resolve()
    if not resolved.is_relative_to(base):
        raise ValueError(f"Output path must be inside base directory: {base}")
    return resolved


def render_sarif(result: ScanResult, output_path: Path, base_dir: Path | None = None) -> None:
    safe_path = _validate_output_path(output_path, base_dir)
    safe_path.parent.mkdir(parents=True, exist_ok=True)

    seen_rule_ids: set[str] = set()
    rules: list[dict[str, Any]] = []

    for vuln in result.vulnerabilities:
        if vuln.vuln_id not in seen_rule_ids:
            seen_rule_ids.add(vuln.vuln_id)
            rules.append(_build_rule(vuln))

    results = [_build_result(vuln) for vuln in result.vulnerabilities]

    sarif: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VulnHunter",
                        "version": "2.0.0",
                        "informationUri": "https://github.com/DevGreick/VulnHunter",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }

    safe_path.write_text(
        json.dumps(sarif, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    logger.info("SARIF report written to %s", safe_path)
