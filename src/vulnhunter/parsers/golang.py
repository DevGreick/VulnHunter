import logging
import re
from pathlib import Path

from vulnhunter.models import Dependency, Ecosystem
from vulnhunter.parsers.base import _execute_command

logger: logging.Logger = logging.getLogger(__name__)

_REQUIRE_LINE: re.Pattern[str] = re.compile(r"^\s*(\S+)\s+(v?\S+)")


class GolangParser:
    def parse(self, file_path: Path) -> list[Dependency]:
        deps: list[Dependency] = []
        seen: set[str] = set()

        direct: list[Dependency] = self._parse_go_mod(file_path)
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

        logger.info("Go parser found %d dependencies", len(deps))
        return deps

    def _parse_go_mod(self, file_path: Path) -> list[Dependency]:
        deps: list[Dependency] = []
        try:
            content: str = file_path.read_text(encoding="utf-8")
        except OSError as exc:
            logger.error("Failed to read %s: %s", file_path, exc)
            return deps

        in_require: bool = False

        for line in content.splitlines():
            stripped: str = line.strip()

            if stripped.startswith("require ("):
                in_require = True
                continue

            if in_require and stripped == ")":
                in_require = False
                continue

            if stripped.startswith("require ") and "(" not in stripped:
                parts: list[str] = stripped.split()
                if len(parts) >= 3:
                    self._add_dep(parts[1], parts[2], deps)
                continue

            if in_require:
                if stripped.startswith("//") or not stripped:
                    continue
                match: re.Match[str] | None = _REQUIRE_LINE.match(stripped)
                if match:
                    self._add_dep(match.group(1), match.group(2), deps)

        return deps

    def _add_dep(self, name: str, raw_version: str, deps: list[Dependency]) -> None:
        version: str = raw_version.lstrip("v")
        if "+incompatible" in version:
            version = version.split("+incompatible")[0]
        if "/go.mod" in version:
            version = version.split("/go.mod")[0]
        try:
            deps.append(
                Dependency(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.GO,
                )
            )
        except ValueError:
            logger.debug("Skipping invalid dependency: %s", name)

    def _parse_transitive(self, cwd: Path) -> list[Dependency]:
        deps: list[Dependency] = []
        output = _execute_command(["go", "list", "-m", "-mod=mod", "all"], cwd)
        if not output:
            return deps

        for line in output.splitlines():
            parts: list[str] = line.strip().split()
            if len(parts) >= 2:
                name: str = parts[0]
                raw_version: str = parts[1]
                self._add_dep(name, raw_version, deps)

        return deps
