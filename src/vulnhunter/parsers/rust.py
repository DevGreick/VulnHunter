import logging
import re
from pathlib import Path

from vulnhunter.models import Dependency, Ecosystem
from vulnhunter.parsers.base import _execute_command

logger: logging.Logger = logging.getLogger(__name__)

_CARGO_DEP: re.Pattern[str] = re.compile(
    r'^(?P<name>[\w-]+)\s+v(?P<version>\S+)',
)

_TOML_DEP_INLINE: re.Pattern[str] = re.compile(
    r'^(?P<name>[\w-]+)\s*=\s*"(?P<version>[^"]+)"',
)

_TOML_DEP_TABLE: re.Pattern[str] = re.compile(
    r'^(?P<name>[\w-]+)\s*=\s*\{.*?version\s*=\s*"(?P<version>[^"]+)"',
)


class RustParser:
    def parse(self, file_path: Path) -> list[Dependency]:
        deps: list[Dependency] = []
        seen: set[str] = set()

        if file_path.name.lower() == "cargo.lock":
            direct = self._parse_cargo_lock(file_path)
        else:
            direct = self._parse_cargo_toml(file_path)

        for dep in direct:
            key: str = dep.name.lower()
            if key not in seen:
                seen.add(key)
                deps.append(dep)

        transitive: list[Dependency] = self._parse_transitive(file_path.parent)
        for dep in transitive:
            key = dep.name.lower()
            if key not in seen:
                seen.add(key)
                deps.append(dep)

        logger.info("Rust parser found %d dependencies", len(deps))
        return deps

    def _parse_cargo_toml(self, file_path: Path) -> list[Dependency]:
        deps: list[Dependency] = []
        try:
            content: str = file_path.read_text(encoding="utf-8")
        except OSError as exc:
            logger.error("Failed to read %s: %s", file_path, exc)
            return deps

        in_deps: bool = False

        for line in content.splitlines():
            stripped: str = line.strip()

            if stripped in ("[dependencies]", "[dev-dependencies]", "[build-dependencies]"):
                in_deps = True
                continue

            if stripped.startswith("[") and in_deps:
                if ".dependencies]" not in stripped:
                    in_deps = False
                    continue

            if not in_deps or not stripped or stripped.startswith("#"):
                continue

            match = _TOML_DEP_TABLE.match(stripped) or _TOML_DEP_INLINE.match(stripped)
            if match:
                self._add_dep(match.group("name"), match.group("version"), deps)

        return deps

    def _parse_cargo_lock(self, file_path: Path) -> list[Dependency]:
        deps: list[Dependency] = []
        try:
            content: str = file_path.read_text(encoding="utf-8")
        except OSError as exc:
            logger.error("Failed to read %s: %s", file_path, exc)
            return deps

        current_name: str = ""
        current_version: str = ""

        for line in content.splitlines():
            stripped: str = line.strip()

            if stripped == "[[package]]":
                if current_name and current_version:
                    self._add_dep(current_name, current_version, deps)
                current_name = ""
                current_version = ""
                continue

            if stripped.startswith('name = "'):
                current_name = stripped.split('"')[1]
            elif stripped.startswith('version = "'):
                current_version = stripped.split('"')[1]

        if current_name and current_version:
            self._add_dep(current_name, current_version, deps)

        return deps

    def _add_dep(self, name: str, raw_version: str, deps: list[Dependency]) -> None:
        version: str = raw_version.lstrip("v^~>=<! ")
        if "," in version:
            version = version.split(",")[0].strip()
        if not version:
            return
        try:
            deps.append(
                Dependency(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.CRATES,
                )
            )
        except ValueError:
            logger.debug("Skipping invalid dependency: %s", name)

    def _parse_transitive(self, cwd: Path) -> list[Dependency]:
        deps: list[Dependency] = []
        lock_path: Path = cwd / "Cargo.lock"
        if lock_path.exists():
            return self._parse_cargo_lock(lock_path)

        output = _execute_command(["cargo", "metadata", "--format-version=1", "--no-deps"], cwd)
        if not output:
            return deps

        try:
            import json
            metadata = json.loads(output)
            for pkg in metadata.get("packages", []):
                name: str = pkg.get("name", "")
                version: str = pkg.get("version", "")
                if name and version:
                    self._add_dep(name, version, deps)
        except (ValueError, KeyError):
            logger.debug("Failed to parse cargo metadata output")

        return deps
