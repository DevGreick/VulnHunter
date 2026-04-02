import json
import logging
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import requests
from pydantic import BaseModel, Field, ValidationError

logger = logging.getLogger(__name__)

DISCLAIMER: str = "AI-assisted triage. Manual validation via POC required."


class TriageResponse(BaseModel):
    real_risk: str = Field(default="UNKNOWN", pattern=r"^(CRITICAL|HIGH|MEDIUM|LOW|IRRELEVANT|UNKNOWN)$")
    analysis: str = Field(default="")
    recommendation: str = Field(default="")

SKIP_DIRS: set[str] = {
    "node_modules", "vendor", ".venv", "target", "__pycache__",
    ".git", ".hg", ".svn", ".tox", ".mypy_cache", ".pytest_cache",
}

ECOSYSTEM_EXTENSIONS: dict[str, list[str]] = {
    "pypi": [".py"],
    "npm": [".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"],
    "maven": [".java", ".kt", ".scala"],
    "packagist": [".php"],
    "rubygems": [".rb"],
    "go": [".go"],
}

ECOSYSTEM_PATTERNS: dict[str, Callable[[str], re.Pattern[str]]] = {
    "pypi": lambda pkg: re.compile(
        rf"(?:^import\s+{re.escape(pkg)}|^from\s+{re.escape(pkg)}\s+import)", re.MULTILINE
    ),
    "npm": lambda pkg: re.compile(
        rf"""(?:require\s*\(\s*['\"]{re.escape(pkg)}['\"]|from\s+['\"]{re.escape(pkg)}['\"])""",
        re.MULTILINE,
    ),
    "maven": lambda pkg: re.compile(
        rf"^import\s+{re.escape(pkg)}", re.MULTILINE
    ),
    "packagist": lambda pkg: re.compile(
        rf"^use\s+{re.escape(pkg.replace('/', chr(92)))}", re.MULTILINE
    ),
    "rubygems": lambda pkg: re.compile(
        rf"""(?:require\s+['\"]{re.escape(pkg)}['\"]|gem\s+['\"]{re.escape(pkg)}['\"])""",
        re.MULTILINE,
    ),
    "go": lambda pkg: re.compile(
        rf"""['\"]{re.escape(pkg)}['\"]""", re.MULTILINE
    ),
}

SYSTEM_PROMPT: str = (
    "You are a cybersecurity analyst specialized in dependency vulnerability triage. "
    "You validate attack vectors against actual code usage. "
    "Respond strictly in JSON with keys: real_risk, analysis, recommendation."
)

PROMPT_TEMPLATE: str = (
    "VULNERABILITY:\n"
    "- ID: {vuln_id}\n"
    "- Package: {package_name} {version}\n"
    "- Severity (CVSS): {severity}\n"
    "- Description: {summary}\n"
    "\n"
    "CODE REFERENCES (where this package is used in the project):\n"
    "{code_refs_formatted}\n"
    "\n"
    "Assess based on code usage:\n"
    "1. real_risk: CRITICAL, HIGH, MEDIUM, LOW, or IRRELEVANT\n"
    "2. analysis: Brief explanation (1-2 sentences)\n"
    "3. recommendation: What the developer should do\n"
    "\n"
    "IMPORTANT: Write analysis and recommendation in {language}.\n"
    'Respond in JSON: {{"real_risk": "...", "analysis": "...", "recommendation": "..."}}'
)


def _is_hidden_or_skipped(path: Path) -> bool:
    for part in path.parts:
        if part.startswith(".") or part in SKIP_DIRS:
            return True
    return False


class CodeAnalyzer:
    def _get_file_extensions(self, ecosystem: str) -> list[str]:
        return ECOSYSTEM_EXTENSIONS.get(ecosystem.lower(), [])

    def find_imports(
        self, project_dir: Path, package_name: str, ecosystem: str
    ) -> list[dict[str, Any]]:
        extensions: list[str] = self._get_file_extensions(ecosystem)
        if not extensions:
            return []

        pattern_factory = ECOSYSTEM_PATTERNS.get(ecosystem.lower())
        if pattern_factory is None:
            return []

        pattern: re.Pattern[str] = pattern_factory(package_name)
        results: list[dict[str, Any]] = []
        files_scanned: int = 0

        for ext in extensions:
            if len(results) >= 10:
                break
            for filepath in project_dir.rglob(f"*{ext}"):
                if len(results) >= 10:
                    break
                if files_scanned >= 50:
                    break
                if not filepath.is_file():
                    continue
                if _is_hidden_or_skipped(filepath.relative_to(project_dir)):
                    continue

                files_scanned += 1
                try:
                    lines: list[str] = filepath.read_text(
                        encoding="utf-8", errors="replace"
                    ).splitlines()
                except OSError:
                    logger.error("Failed to read file: %s", filepath)
                    continue

                for idx, line in enumerate(lines):
                    if len(results) >= 10:
                        break
                    if pattern.search(line):
                        start: int = max(0, idx - 1)
                        end: int = min(len(lines), idx + 2)
                        snippet: str = "\n".join(lines[start:end])
                        results.append(
                            {
                                "file": str(filepath.relative_to(project_dir)),
                                "line": idx + 1,
                                "snippet": snippet,
                            }
                        )

        return results


LANG_NAMES: dict[str, str] = {
    "en": "English",
    "pt": "Brazilian Portuguese",
}


class TriageEngine:
    def __init__(
        self,
        model: str = "mistral",
        ollama_url: str = "http://localhost:11434",
        language: str = "en",
    ) -> None:
        self._model: str = model
        self._ollama_url: str = ollama_url.rstrip("/")
        self._analyzer: CodeAnalyzer = CodeAnalyzer()
        self._language: str = LANG_NAMES.get(language, "English")

    def is_available(self) -> bool:
        try:
            resp: requests.Response = requests.get(
                self._ollama_url, timeout=5
            )
            return resp.status_code == 200
        except requests.RequestException:
            return False

    def _build_prompt(
        self, vuln: dict[str, Any], code_refs: list[dict[str, Any]]
    ) -> str:
        if code_refs:
            refs_text: str = "\n".join(
                f"File: {ref['file']} (line {ref['line']}):\n{ref['snippet']}"
                for ref in code_refs
            )
        else:
            refs_text = (
                "No direct imports found. This package may be a transitive dependency."
            )

        return PROMPT_TEMPLATE.format(
            vuln_id=vuln.get("id", "N/A"),
            package_name=vuln.get("package", "unknown"),
            version=vuln.get("version", "unknown"),
            severity=vuln.get("severity", "unknown"),
            summary=vuln.get("summary", "No description available"),
            code_refs_formatted=refs_text,
            language=self._language,
        )

    def _call_ollama(self, prompt: str) -> dict[str, str]:
        fallback: dict[str, str] = {
            "real_risk": "UNKNOWN",
            "analysis": "Ollama unavailable or returned invalid response.",
            "recommendation": "Manual review required.",
            "disclaimer": DISCLAIMER,
        }

        try:
            resp: requests.Response = requests.post(
                f"{self._ollama_url}/api/generate",
                json={
                    "model": self._model,
                    "system": SYSTEM_PROMPT,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                },
                timeout=120,
            )
            resp.raise_for_status()
        except requests.ConnectionError:
            logger.error("Ollama connection failed at %s", self._ollama_url)
            return fallback
        except requests.Timeout:
            logger.error("Ollama request timed out after 120s")
            return fallback
        except requests.RequestException as exc:
            logger.error("Ollama request error: %s", exc)
            return fallback

        try:
            body: dict[str, Any] = resp.json()
            raw_response: str = body.get("response", "")
        except (json.JSONDecodeError, KeyError):
            logger.error("Failed to decode Ollama response body")
            return fallback

        try:
            parsed: dict[str, Any] = json.loads(raw_response)
            validated: TriageResponse = TriageResponse(
                real_risk=str(parsed.get("real_risk", "UNKNOWN")).upper(),
                analysis=str(parsed.get("analysis", "")),
                recommendation=str(parsed.get("recommendation", "")),
            )
            return {
                "real_risk": validated.real_risk,
                "analysis": validated.analysis,
                "recommendation": validated.recommendation,
                "disclaimer": DISCLAIMER,
            }
        except (json.JSONDecodeError, TypeError, ValidationError) as exc:
            logger.error("Failed to validate LLM output: %s", exc)
            return {
                "real_risk": "UNKNOWN",
                "analysis": raw_response[:500] if raw_response else "No response from LLM.",
                "recommendation": "Manual review required.",
                "disclaimer": DISCLAIMER,
            }

    def triage_vulnerability(
        self, vuln: dict[str, Any], code_refs: list[dict[str, Any]]
    ) -> dict[str, str]:
        prompt: str = self._build_prompt(vuln, code_refs)
        return self._call_ollama(prompt)

    def triage_all(
        self,
        vulnerabilities: list[dict[str, Any]],
        project_dir: Path,
        callback: Callable[[int, int], None] | None = None,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        total: int = len(vulnerabilities)

        for idx, vuln in enumerate(vulnerabilities):
            package_name: str = vuln.get("package", "")
            ecosystem: str = vuln.get("ecosystem", "")

            code_refs: list[dict[str, Any]] = self._analyzer.find_imports(
                project_dir, package_name, ecosystem
            )

            triage_result: dict[str, str] = self.triage_vulnerability(vuln, code_refs)

            results.append(
                {
                    "vuln": vuln,
                    "code_refs": code_refs,
                    "triage": triage_result,
                }
            )

            if callback is not None:
                callback(idx + 1, total)

        return results
