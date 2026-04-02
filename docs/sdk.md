# VulnHunter Python SDK Reference

VulnHunter can be used as a Python library for programmatic vulnerability scanning, AI-powered triage, and report generation.

## Quick Start

```python
from pathlib import Path
from vulnhunter.db.store import VulnDB
from vulnhunter.models import Dependency, Ecosystem
from vulnhunter.analyzer import analyze

db = VulnDB()
deps = [
    Dependency(name="requests", version="2.31.0", ecosystem=Ecosystem.PYPI),
    Dependency(name="flask", version="2.3.2", ecosystem=Ecosystem.PYPI),
]
result = analyze(db, deps)

for vuln in result.vulnerabilities:
    print(f"{vuln.vuln_id} | {vuln.severity.value} | {vuln.name} {vuln.version}")

db.close()
```

---

## Models

### `Severity`

```python
from vulnhunter.models import Severity
```

`Severity(str, Enum)` — Vulnerability severity levels.

| Value | Description |
|---|---|
| `CRITICAL` | Critical severity |
| `HIGH` | High severity |
| `MEDIUM` | Medium severity |
| `LOW` | Low severity |
| `UNKNOWN` | Severity not determined |

### `Ecosystem`

```python
from vulnhunter.models import Ecosystem
```

`Ecosystem(str, Enum)` — Supported package ecosystems.

| Value | Ecosystem |
|---|---|
| `PYPI` | Python (PyPI) |
| `NPM` | Node.js (npm) |
| `MAVEN` | Java (Maven) |
| `PACKAGIST` | PHP (Packagist) |
| `RUBYGEMS` | Ruby (RubyGems) |
| `GO` | Go |
| `CRATES` | Rust (crates.io) |

### `Dependency`

```python
from vulnhunter.models import Dependency
```

Pydantic model representing a project dependency.

```python
Dependency(name: str, version: str, ecosystem: Ecosystem)
```

| Field | Type | Description |
|---|---|---|
| `name` | `str` | Package name |
| `version` | `str` | Installed version (must not be empty) |
| `ecosystem` | `Ecosystem` | Package ecosystem |

### `Vulnerability`

```python
from vulnhunter.models import Vulnerability
```

Pydantic model representing a known vulnerability matched to a dependency.

```python
Vulnerability(
    vuln_id: str = "N/A",
    source: str = "unknown",
    name: str,
    version: str,
    ecosystem: Ecosystem,
    severity: Severity = Severity.UNKNOWN,
    summary: str = "No summary provided",
    fixed_version: str | None = None,
)
```

| Field | Type | Default | Description |
|---|---|---|---|
| `vuln_id` | `str` | `"N/A"` | CVE or advisory identifier |
| `source` | `str` | `"unknown"` | Data source (e.g. `"OSV"`, `"OSV+NVD"`) |
| `name` | `str` | — | Affected package name |
| `version` | `str` | — | Affected version |
| `ecosystem` | `Ecosystem` | — | Package ecosystem |
| `severity` | `Severity` | `UNKNOWN` | Resolved severity level |
| `summary` | `str` | `"No summary provided"` | Vulnerability description |
| `fixed_version` | `str \| None` | `None` | Version that fixes the issue |

### `ScanResult`

```python
from vulnhunter.models import ScanResult
```

Pydantic model returned by `analyze()`.

| Field | Type | Description |
|---|---|---|
| `total_dependencies` | `int` | Number of dependencies scanned |
| `total_vulnerabilities` | `int` | Number of vulnerabilities found |
| `total_ignored` | `int` | Number of vulnerabilities skipped via `.vulnignore` |
| `vulnerabilities` | `list[Vulnerability]` | Sorted list of matched vulnerabilities |
| `dependencies` | `list[Dependency]` | All dependencies that were scanned |

---

## Core Functions

### `analyze`

```python
from vulnhunter.analyzer import analyze

def analyze(
    db: VulnDB,
    dependencies: list[Dependency],
    ignore_file: Path | None = None,
) -> ScanResult
```

Scans a list of dependencies against the local vulnerability database.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `db` | `VulnDB` | — | Database instance |
| `dependencies` | `list[Dependency]` | — | Dependencies to scan |
| `ignore_file` | `Path \| None` | `None` | Path to `.vulnignore` file. Defaults to `.vulnignore` in CWD |

**Returns:** `ScanResult` with matched vulnerabilities sorted by severity (CRITICAL first).

**Example:**

```python
from pathlib import Path
from vulnhunter.db.store import VulnDB
from vulnhunter.models import Dependency, Ecosystem
from vulnhunter.analyzer import analyze

db = VulnDB()
deps = [Dependency(name="idna", version="3.6", ecosystem=Ecosystem.PYPI)]
result = analyze(db, deps, ignore_file=Path(".vulnignore"))

print(f"Found {result.total_vulnerabilities} vulnerabilities")
for v in result.vulnerabilities:
    print(f"  {v.vuln_id}: {v.severity.value} — {v.summary}")

db.close()
```

### `resolve_severity`

```python
from vulnhunter.severity_resolver import resolve_severity

def resolve_severity(
    db: VulnDB,
    vuln_id: str,
    current_severity: str,
    summary: str,
    original_source: str = "OSV",
) -> tuple[str, bool, str]
```

Resolves UNKNOWN severity using NVD cross-reference, CWE mapping, and keyword analysis.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `db` | `VulnDB` | — | Database instance for NVD lookups |
| `vuln_id` | `str` | — | CVE or advisory identifier |
| `current_severity` | `str` | — | Current severity string |
| `summary` | `str` | — | Vulnerability description text |
| `original_source` | `str` | `"OSV"` | Original data source name |

**Returns:** `tuple[str, bool, str]` — `(severity, is_estimated, source)`.

- `severity`: Resolved severity string (e.g. `"HIGH"`)
- `is_estimated`: `True` if severity was inferred from CWE/keywords
- `source`: Updated source string (e.g. `"OSV+NVD"`)

---

## Database

### `VulnDB`

```python
from vulnhunter.db.store import VulnDB
```

SQLite-backed local vulnerability database with thread-safe connection management.

```python
VulnDB(db_path: Path | None = None)
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `db_path` | `Path \| None` | `None` | Custom database path. Defaults to `~/.vulnhunter/vulnhunter.db` |

#### Methods

**`query_vulnerabilities(ecosystem: str, package_name: str) -> list[tuple]`**

Query vulnerabilities for a specific package. Returns tuples of `(vuln_id, source, severity, summary, version_start, version_start_inclusive, version_end, version_end_inclusive, fixed_version)`.

**`query_cpe_aliases(package_name: str) -> list[str]`**

Get CPE vendor/product aliases for a package name.

**`stats() -> dict[str, int]`**

Returns database statistics: `{"vulnerabilities": int, "packages": int, "cpe_aliases": int}`.

**`get_metadata(key: str) -> str | None`**

Retrieve a metadata value (e.g. `"osv_last_update"`).

**`get_severity_by_id(vuln_id: str) -> str | None`**

Look up the severity for a specific vulnerability ID.

**`get_aliases(vuln_id: str) -> list[str]`**

Get all known aliases for a vulnerability identifier.

**`close() -> None`**

Close the database connection.

**`commit() -> None`**

Commit pending changes.

**Example:**

```python
from vulnhunter.db.store import VulnDB

db = VulnDB()
stats = db.stats()
print(f"Database: {stats['vulnerabilities']} vulns, {stats['packages']} packages")

rows = db.query_vulnerabilities("PyPI", "requests")
for vuln_id, source, severity, summary, *_ in rows:
    print(f"{vuln_id} [{severity}] {summary[:80]}")

db.close()
```

---

## AI Triage

### `TriageEngine`

```python
from vulnhunter.ai.triage import TriageEngine
```

Orchestrates AI-powered vulnerability triage using a local Ollama LLM instance.

```python
TriageEngine(
    model: str = "mistral",
    ollama_url: str = "http://localhost:11434",
    language: str = "en",
    deep_triage: bool = False,
)
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `model` | `str` | `"mistral"` | Ollama model name |
| `ollama_url` | `str` | `"http://localhost:11434"` | Ollama server URL |
| `language` | `str` | `"en"` | Output language (`"en"` or `"pt"`) |
| `deep_triage` | `bool` | `False` | Enable Semgrep static analysis integration |

#### Methods

**`is_available() -> bool`**

Check if the Ollama server is reachable.

**`semgrep_available() -> bool`**

Check if Semgrep is installed and deep triage is enabled.

**`triage_vulnerability(vuln: dict[str, Any], code_refs: list[dict[str, Any]], semgrep_context: str = "") -> dict[str, str]`**

Triage a single vulnerability. Returns `{"real_risk": str, "analysis": str, "recommendation": str, "disclaimer": str}`.

**`triage_all(vulnerabilities: list[dict[str, Any]], project_dir: Path, callback: Callable[[int, int], None] | None = None) -> list[dict[str, Any]]`**

Triage all vulnerabilities with automatic code reference detection. Accepts an optional progress callback `callback(current, total)`. Returns a list of `{"vuln": dict, "code_refs": list, "triage": dict}`.

**Example:**

```python
from pathlib import Path
from vulnhunter.ai.triage import TriageEngine

engine = TriageEngine(model="mistral", language="en")

if not engine.is_available():
    raise RuntimeError("Ollama is not running")

vulns = [
    {
        "id": "CVE-2024-3651",
        "package": "idna",
        "version": "3.6",
        "severity": "HIGH",
        "summary": "Denial of service via resource consumption",
        "ecosystem": "PyPI",
        "fixed_version": "3.7",
    }
]

results = engine.triage_all(vulns, Path("."))
for item in results:
    triage = item["triage"]
    print(f"{item['vuln']['id']}: {triage['real_risk']} — {triage['analysis']}")
```

### `TriageResponse`

```python
from vulnhunter.ai.triage import TriageResponse
```

Pydantic model for validated LLM triage output.

| Field | Type | Pattern | Description |
|---|---|---|---|
| `real_risk` | `str` | `CRITICAL\|HIGH\|MEDIUM\|LOW\|IRRELEVANT\|UNKNOWN` | Contextual risk assessment |
| `analysis` | `str` | — | Brief explanation |
| `recommendation` | `str` | — | Remediation advice |

### `CodeAnalyzer`

```python
from vulnhunter.ai.triage import CodeAnalyzer
```

Static code analyzer that finds import references for a given package across a project.

**`find_imports(project_dir: Path, package_name: str, ecosystem: str) -> list[dict[str, Any]]`**

Scan project files for imports of a specific package. Returns up to 10 matches, each containing:

| Key | Type | Description |
|---|---|---|
| `file` | `str` | Relative file path |
| `line` | `int` | Line number of the import |
| `snippet` | `str` | Code context (5 lines before/after) |
| `usage_risk` | `str` | `"risky"`, `"safe"`, or `"unknown"` |

Supports ecosystems: PyPI, npm, Maven, Packagist, RubyGems, Go, crates.io.

---

## Semgrep Integration

### `SemgrepEngine`

```python
from vulnhunter.ai.semgrep_engine import SemgrepEngine
```

Runs Semgrep static analysis scans filtered by ecosystem and package relevance.

```python
SemgrepEngine()
```

#### Methods

**`is_available() -> bool`**

Check if the `semgrep` binary is installed.

**`scan(project_dir: Path, ecosystem: str, package_name: str) -> list[SemgrepFinding]`**

Run a Semgrep scan filtered for findings relevant to the given package. Returns up to 5 findings.

**`findings_to_context(findings: list[SemgrepFinding]) -> str`**

Convert findings to a formatted string suitable for LLM context injection.

### `SemgrepFinding`

```python
from vulnhunter.ai.semgrep_engine import SemgrepFinding
```

| Field | Type | Description |
|---|---|---|
| `rule_id` | `str` | Semgrep rule identifier |
| `path` | `str` | File path |
| `start_line` | `int` | Start line number |
| `end_line` | `int` | End line number |
| `message` | `str` | Rule description |
| `severity` | `str` | Finding severity |
| `snippet` | `str` | Matched code |
| `metadata` | `dict` | Rule metadata (CWE tags, etc.) |

**`to_context() -> str`**

Format the finding as a human-readable context block.

---

## Report Export

### `render_xlsx`

```python
from vulnhunter.output.xlsx_report import render_xlsx

def render_xlsx(
    result: ScanResult,
    output_path: Path,
    base_dir: Path | None = None,
) -> None
```

Export scan results to a styled Excel workbook with Summary, Vulnerabilities, and By Ecosystem sheets.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `result` | `ScanResult` | — | Scan results to export |
| `output_path` | `Path` | — | Output `.xlsx` file path |
| `base_dir` | `Path \| None` | `None` | Base directory for path traversal validation |

**Example:**

```python
from pathlib import Path
from vulnhunter.output.xlsx_report import render_xlsx

render_xlsx(result, Path("reports/scan.xlsx"))
```

---

## CLI Commands

VulnHunter provides a Typer-based CLI accessible via `vulnhunter`.

### `vulnhunter scan`

```
vulnhunter scan <paths> [OPTIONS]
```

| Option | Short | Default | Description |
|---|---|---|---|
| `--format` | `-f` | `table` | Output format: `table`, `json`, `sarif`, `xlsx` |
| `--output` | `-o` | auto | Save report to file |
| `--severity` | `-s` | all | Minimum severity filter: `critical`, `high`, `medium`, `low` |
| `--ignore-file` | — | `.vulnignore` | CVE ignore list file |
| `--db` | — | default | Custom database path |
| `--ai-triage` | — | `false` | Enable AI-powered triage via Ollama |
| `--model` | — | config | AI model name (e.g. `mistral`, `llama3:8b`) |
| `--deep-triage` | — | `false` | Enable Semgrep + AI evidence-based triage |
| `--verbose` | `-v` | `false` | Show detailed logs |

### `vulnhunter db update`

```
vulnhunter db update [OPTIONS]
```

| Option | Short | Default | Description |
|---|---|---|---|
| `--ecosystem` | `-e` | auto | Specific ecosystems to update |
| `--all` | — | `false` | Download all ecosystems |
| `--source` | — | `osv` | Data source: `osv`, `nvd`, or `both` |
| `--nvd-api-key` | — | env/keyring | NVD API key |

### `vulnhunter db download`

Downloads a pre-built database from GitHub Releases.

### `vulnhunter db info`

Shows database statistics and last update timestamps.

### `vulnhunter init`

Runs the interactive setup wizard.

### `vulnhunter config`

Shows current configuration. Use `vulnhunter config set-nvd-key` and `vulnhunter config remove-nvd-key` to manage the NVD API key in the system keyring.

---

## Complete Workflow Example

```python
import logging
from pathlib import Path

from vulnhunter.db.store import VulnDB
from vulnhunter.models import Dependency, Ecosystem
from vulnhunter.analyzer import analyze
from vulnhunter.ai.triage import TriageEngine
from vulnhunter.output.xlsx_report import render_xlsx

logging.basicConfig(level=logging.WARNING)

db = VulnDB()

deps = [
    Dependency(name="requests", version="2.31.0", ecosystem=Ecosystem.PYPI),
    Dependency(name="flask", version="2.3.2", ecosystem=Ecosystem.PYPI),
    Dependency(name="idna", version="3.6", ecosystem=Ecosystem.PYPI),
]

result = analyze(db, deps)

render_xlsx(result, Path("reports/scan.xlsx"))

engine = TriageEngine(model="mistral", language="en")
if engine.is_available() and result.vulnerabilities:
    vuln_dicts = [
        {
            "id": v.vuln_id,
            "package": v.name,
            "version": v.version,
            "severity": v.severity.value,
            "summary": v.summary,
            "ecosystem": v.ecosystem.value,
            "fixed_version": v.fixed_version or "",
        }
        for v in result.vulnerabilities
    ]

    triage_results = engine.triage_all(vuln_dicts, Path("."))
    for item in triage_results:
        t = item["triage"]
        print(f"{item['vuln']['id']}: {t['real_risk']} — {t['analysis']}")

db.close()
```
