import logging
import re
from pathlib import Path

from vulnhunter.models import Dependency, Ecosystem
from vulnhunter.parsers.base import _execute_command

logger: logging.Logger = logging.getLogger(__name__)

_REQ_PATTERN: re.Pattern[str] = re.compile(r"^\s*([a-zA-Z0-9\-_.]+)\s*(?:([<>=!~]{1,2})\s*([0-9a-zA-Z\-_.*+!]+))?")


class PythonParser:
    def parse(self, file_path: Path) -> list[Dependency]:
        deps: list[Dependency] = []
        seen: set[str] = set()

        direct: list[Dependency] = self._parse_requirements(file_path)
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

        logger.info("Python parser found %d dependencies", len(deps))
        return deps

    def _parse_requirements(self, file_path: Path) -> list[Dependency]:
        deps: list[Dependency] = []
        try:
            content: str = file_path.read_text(encoding="utf-8")
        except OSError as exc:
            logger.error("Failed to read %s: %s", file_path, exc)
            return deps

        for line in content.splitlines():
            stripped: str = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("-"):
                continue

            match: re.Match[str] | None = _REQ_PATTERN.match(stripped)
            if match:
                name: str = match.group(1)
                version: str = match.group(3) or "0.0.0"
                try:
                    deps.append(
                        Dependency(
                            name=name,
                            version=version,
                            ecosystem=Ecosystem.PYPI,
                        )
                    )
                except ValueError:
                    logger.debug("Skipping invalid dependency: %s", name)

        return deps

    def _parse_transitive(self, cwd: Path) -> list[Dependency]:
        deps: list[Dependency] = []
        output = _execute_command(["pipdeptree", "--freeze"], cwd)
        if not output:
            return deps

        for line in output.splitlines():
            stripped: str = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            match: re.Match[str] | None = _REQ_PATTERN.match(stripped)
            if match:
                name: str = match.group(1)
                version: str = match.group(3) or "0.0.0"
                try:
                    deps.append(
                        Dependency(
                            name=name,
                            version=version,
                            ecosystem=Ecosystem.PYPI,
                        )
                    )
                except ValueError:
                    logger.debug("Skipping invalid transitive dep: %s", name)

        return deps
