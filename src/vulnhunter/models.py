from enum import Enum

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class Ecosystem(str, Enum):
    PYPI = "PyPI"
    NPM = "npm"
    MAVEN = "Maven"
    PACKAGIST = "Packagist"
    RUBYGEMS = "RubyGems"
    GO = "Go"
    CRATES = "crates.io"


ECOSYSTEM_FROM_FILE = {
    "requirements.txt": Ecosystem.PYPI,
    "package.json": Ecosystem.NPM,
    "pom.xml": Ecosystem.MAVEN,
    "composer.json": Ecosystem.PACKAGIST,
    "gemfile.lock": Ecosystem.RUBYGEMS,
    "go.mod": Ecosystem.GO,
    "cargo.toml": Ecosystem.CRATES,
    "cargo.lock": Ecosystem.CRATES,
}

OSV_ECOSYSTEM_MAP = {
    Ecosystem.PYPI: "PyPI",
    Ecosystem.NPM: "npm",
    Ecosystem.MAVEN: "Maven",
    Ecosystem.PACKAGIST: "Packagist",
    Ecosystem.RUBYGEMS: "RubyGems",
    Ecosystem.GO: "Go",
    Ecosystem.CRATES: "crates.io",
}


class Dependency(BaseModel):
    name: str
    version: str
    ecosystem: Ecosystem

    @field_validator("version")
    @classmethod
    def version_not_empty(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("version must not be empty")
        return stripped

    def __hash__(self) -> int:
        return hash((self.name.lower(), self.version, self.ecosystem))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Dependency):
            return NotImplemented
        return (
            self.name.lower() == other.name.lower()
            and self.version == other.version
            and self.ecosystem == other.ecosystem
        )


class Vulnerability(BaseModel):
    vuln_id: str = Field(default="N/A")
    source: str = Field(default="unknown")
    name: str
    version: str
    ecosystem: Ecosystem
    severity: Severity = Severity.UNKNOWN
    summary: str = Field(default="No summary provided")
    fixed_version: str | None = None

    def __hash__(self) -> int:
        return hash((self.name.lower(), self.version, self.vuln_id))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Vulnerability):
            return NotImplemented
        return (
            self.name.lower() == other.name.lower() and self.version == other.version and self.vuln_id == other.vuln_id
        )


class ScanResult(BaseModel):
    total_dependencies: int = 0
    total_vulnerabilities: int = 0
    total_ignored: int = 0
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    dependencies: list[Dependency] = Field(default_factory=list)
