import json
import logging
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import requests
from pydantic import BaseModel, Field, ValidationError

from vulnhunter.validators import validate_ollama_url

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
    "crates.io": [".rs"],
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
    "crates.io": lambda pkg: re.compile(
        rf"(?:use\s+{re.escape(pkg.replace('-', '_'))}|extern\s+crate\s+{re.escape(pkg.replace('-', '_'))})",
        re.MULTILINE,
    ),
}

UNSAFE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"pickle\.loads?\s*\("),
    re.compile(r"\beval\s*\("),
    re.compile(r"\bexec\s*\("),
    re.compile(r"subprocess\.(?:call|Popen)\s*\(.*shell\s*=\s*True"),
    re.compile(r"os\.system\s*\("),
    re.compile(r"requests\.(?:get|post|put|delete)\s*\(\s*[a-zA-Z_]"),
    re.compile(r"\bopen\s*\(\s*[a-zA-Z_]"),
]


def _detect_usage_risk(snippet: str) -> str:
    for pat in UNSAFE_PATTERNS:
        if pat.search(snippet):
            return "risky"
    if snippet.strip():
        return "safe"
    return "unknown"


SYSTEM_PROMPT: str = (
    "You are a cybersecurity analyst specialized in dependency vulnerability triage. "
    "You validate attack vectors against actual code usage. "
    "Respond strictly in JSON with keys: real_risk, analysis, recommendation."
)

_SANITIZE_BACKTICKS: re.Pattern[str] = re.compile(r"`+")
_SANITIZE_JSON_LIKE: re.Pattern[str] = re.compile(r"\{[^}]*\}")
_SANITIZE_INSTRUCTIONS: re.Pattern[str] = re.compile(
    r"^(ignore|disregard|forget|override|system|assistant|user)\s*:?\s*",
    re.IGNORECASE | re.MULTILINE,
)


def _sanitize_field(value: str) -> str:
    value = _SANITIZE_BACKTICKS.sub("", value)
    value = _SANITIZE_JSON_LIKE.sub("", value)
    value = _SANITIZE_INSTRUCTIONS.sub("", value)
    return value.strip()


PROMPT_TEMPLATE: str = (
    "VULNERABILITY:\n"
    "- ID: {vuln_id}\n"
    "- Package: [BEGIN DATA]{package_name}[END DATA] [BEGIN DATA]{version}[END DATA]\n"
    "- Severity (CVSS): {severity}\n"
    "- Description: [BEGIN DATA]{summary}[END DATA]\n"
    "{fixed_info}"
    "\n"
    "CODE REFERENCES (where this package is used in the project):\n"
    "{code_refs_formatted}\n"
    "{semgrep_context}"
    "\n"
    "Assess based on ALL evidence above (code usage + static analysis findings):\n"
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
                        start: int = max(0, idx - 5)
                        end: int = min(len(lines), idx + 6)
                        snippet: str = "\n".join(lines[start:end])
                        results.append(
                            {
                                "file": str(filepath.relative_to(project_dir)),
                                "line": idx + 1,
                                "snippet": snippet,
                                "usage_risk": _detect_usage_risk(snippet),
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
        deep_triage: bool = False,
    ) -> None:
        if not validate_ollama_url(ollama_url):
            raise ValueError(f"Invalid or blocked Ollama URL: {ollama_url}")
        self._model: str = model
        self._ollama_url: str = ollama_url.rstrip("/")
        self._analyzer: CodeAnalyzer = CodeAnalyzer()
        self._language: str = LANG_NAMES.get(language, "English")
        self._deep_triage: bool = deep_triage
        self._semgrep: Any = None
        if self._deep_triage:
            from vulnhunter.ai.semgrep_engine import SemgrepEngine
            self._semgrep = SemgrepEngine()

    def is_available(self) -> bool:
        try:
            resp: requests.Response = requests.get(
                self._ollama_url, timeout=5
            )
            return resp.status_code == 200
        except requests.RequestException:
            return False

    def semgrep_available(self) -> bool:
        if self._semgrep is None:
            return False
        return self._semgrep.is_available()

    def _build_prompt(
        self,
        vuln: dict[str, Any],
        code_refs: list[dict[str, Any]],
        semgrep_context: str = "",
    ) -> str:
        if code_refs:
            dep_header: str = "DEPENDENCY TYPE: DIRECT (imported in project code)\n"
            has_risky: bool = any(
                ref.get("usage_risk") == "risky" for ref in code_refs
            )
            if has_risky:
                dep_header += "WARNING: Unsafe usage patterns detected.\n"
            refs_text: str = dep_header + "\n".join(
                f"File: {ref['file']} (line {ref['line']}):\n{ref['snippet']}"
                for ref in code_refs
            )
        else:
            refs_text = (
                "DEPENDENCY TYPE: TRANSITIVE (not imported)\n"
                "This package has NO direct imports in the project code. "
                "It exists only as a transitive dependency. "
                "Unless the vulnerability affects the package's internal API "
                "used by other dependencies, the risk is LOW. "
                "Do NOT speculate about potential risks — if there's no "
                "evidence of usage, classify as LOW or IRRELEVANT."
            )

        fixed_ver: str = vuln.get("fixed_version", "")
        fixed_info: str = f"- Fixed in: {fixed_ver}\n" if fixed_ver else ""

        semgrep_block: str = ""
        if semgrep_context:
            semgrep_block = (
                "\n\nSTATIC ANALYSIS FINDINGS (Semgrep — deterministic, high confidence):\n"
                f"{semgrep_context}\n"
            )

        return PROMPT_TEMPLATE.format(
            vuln_id=vuln.get("id", "N/A"),
            package_name=_sanitize_field(vuln.get("package", "unknown")),
            version=_sanitize_field(vuln.get("version", "unknown")),
            severity=vuln.get("severity", "unknown"),
            summary=_sanitize_field(vuln.get("summary", "No description available")),
            fixed_info=fixed_info,
            code_refs_formatted=refs_text,
            semgrep_context=semgrep_block,
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
        self,
        vuln: dict[str, Any],
        code_refs: list[dict[str, Any]],
        semgrep_context: str = "",
    ) -> dict[str, str]:
        prompt: str = self._build_prompt(vuln, code_refs, semgrep_context)
        return self._call_ollama(prompt)

    def triage_all(
        self,
        vulnerabilities: list[dict[str, Any]],
        project_dir: Path,
        callback: Callable[[int, int], None] | None = None,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        total: int = len(vulnerabilities)

        semgrep_cache: dict[str, str] = {}

        for idx, vuln in enumerate(vulnerabilities):
            package_name: str = vuln.get("package", "")
            ecosystem: str = vuln.get("ecosystem", "")

            code_refs: list[dict[str, Any]] = self._analyzer.find_imports(
                project_dir, package_name, ecosystem
            )

            semgrep_context: str = ""
            if self._deep_triage and self._semgrep is not None:
                cache_key: str = f"{ecosystem}:{package_name}"
                if cache_key not in semgrep_cache:
                    findings = self._semgrep.scan(project_dir, ecosystem, package_name)
                    semgrep_cache[cache_key] = self._semgrep.findings_to_context(findings)
                semgrep_context = semgrep_cache[cache_key]

            triage_result: dict[str, str] = self.triage_vulnerability(
                vuln, code_refs, semgrep_context
            )

            triage_result["evidence"] = "semgrep+llm" if semgrep_context else "llm"

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
