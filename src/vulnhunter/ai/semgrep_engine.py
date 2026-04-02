import json
import logging
import shutil
from pathlib import Path
from typing import Any

from vulnhunter.parsers.base import _execute_command

logger: logging.Logger = logging.getLogger(__name__)

RULE_PACKS: dict[str, list[str]] = {
    "pypi": [
        "p/python",
        "p/security-audit",
        "p/owasp-top-ten",
    ],
    "npm": [
        "p/javascript",
        "p/nodejs",
        "p/security-audit",
    ],
    "maven": [
        "p/java",
        "p/security-audit",
    ],
    "go": [
        "p/golang",
        "p/security-audit",
    ],
    "crates.io": [
        "p/rust",
        "p/security-audit",
    ],
    "packagist": [
        "p/php",
        "p/security-audit",
    ],
    "rubygems": [
        "p/ruby",
        "p/security-audit",
    ],
}


class SemgrepFinding:
    def __init__(self, data: dict[str, Any]) -> None:
        self.rule_id: str = data.get("check_id", "unknown")
        self.path: str = data.get("path", "")
        self.start_line: int = data.get("start", {}).get("line", 0)
        self.end_line: int = data.get("end", {}).get("line", 0)
        self.message: str = data.get("extra", {}).get("message", "")
        self.severity: str = data.get("extra", {}).get("severity", "WARNING")
        self.snippet: str = data.get("extra", {}).get("lines", "")
        self.metadata: dict[str, Any] = data.get("extra", {}).get("metadata", {})

    def to_context(self) -> str:
        cwe_list: list[str] = self.metadata.get("cwe", [])
        cwe_str: str = ", ".join(cwe_list) if cwe_list else "N/A"
        return (
            f"[SEMGREP FINDING] {self.rule_id}\n"
            f"  File: {self.path}:{self.start_line}-{self.end_line}\n"
            f"  Severity: {self.severity}\n"
            f"  CWE: {cwe_str}\n"
            f"  Message: {self.message}\n"
            f"  Code:\n{self.snippet}"
        )


class SemgrepEngine:
    def __init__(self) -> None:
        self._available: bool | None = None

    def is_available(self) -> bool:
        if self._available is None:
            self._available = shutil.which("semgrep") is not None
        return self._available

    def scan(
        self, project_dir: Path, ecosystem: str, package_name: str
    ) -> list[SemgrepFinding]:
        if not self.is_available():
            logger.debug("Semgrep not installed, skipping deep analysis")
            return []

        eco_key: str = ecosystem.lower()
        packs: list[str] = RULE_PACKS.get(eco_key, ["p/security-audit"])

        config_args: list[str] = []
        for pack in packs[:2]:
            config_args.extend(["--config", pack])

        cmd: list[str] = [
            "semgrep",
            "scan",
            *config_args,
            "--json",
            "--quiet",
            "--no-git-ignore",
            "--max-target-bytes", "1000000",
            "--timeout", "30",
            str(project_dir),
        ]

        output: str | None = _execute_command(cmd, project_dir, timeout=180)
        if not output:
            return []

        try:
            data: dict[str, Any] = json.loads(output)
        except (json.JSONDecodeError, ValueError):
            logger.error("Failed to parse Semgrep JSON output")
            return []

        findings: list[SemgrepFinding] = []
        pkg_lower: str = package_name.lower().replace("-", "").replace("_", "")

        for result in data.get("results", []):
            finding = SemgrepFinding(result)

            lines_lower: str = finding.snippet.lower().replace("-", "").replace("_", "")
            message_lower: str = finding.message.lower().replace("-", "").replace("_", "")
            cwe_tags: list[str] = finding.metadata.get("cwe", [])

            is_relevant: bool = (
                pkg_lower in lines_lower
                or pkg_lower in message_lower
                or pkg_lower in finding.path.lower()
                or len(cwe_tags) > 0
            )

            if is_relevant:
                findings.append(finding)

            if len(findings) >= 5:
                break

        logger.info(
            "Semgrep found %d relevant findings for %s in %s",
            len(findings), package_name, ecosystem,
        )
        return findings

    def findings_to_context(self, findings: list[SemgrepFinding]) -> str:
        if not findings:
            return ""
        sections: list[str] = [f.to_context() for f in findings]
        return "\n\n".join(sections)
