import logging
import re
from pathlib import Path

from vulnhunter.models import Dependency, Ecosystem

logger: logging.Logger = logging.getLogger(__name__)

_SPEC_PATTERN: re.Pattern[str] = re.compile(r"^\s{4}(\S+)\s+\(([^)]+)\)")


class RubyParser:
    def parse(self, file_path: Path) -> list[Dependency]:
        deps: list[Dependency] = self._parse_gemfile_lock(file_path)
        logger.info("Ruby parser found %d dependencies", len(deps))
        return deps

    def _parse_gemfile_lock(self, file_path: Path) -> list[Dependency]:
        deps: list[Dependency] = []
        try:
            content: str = file_path.read_text(encoding="utf-8")
        except OSError as exc:
            logger.error("Failed to read %s: %s", file_path, exc)
            return deps

        in_gem_section: bool = False
        in_specs: bool = False

        for line in content.splitlines():
            stripped: str = line.rstrip()

            if stripped == "GEM":
                in_gem_section = True
                in_specs = False
                continue

            if in_gem_section and stripped.strip() == "specs:":
                in_specs = True
                continue

            if in_gem_section and stripped and not stripped.startswith(" "):
                in_gem_section = False
                in_specs = False
                continue

            if not in_specs:
                continue

            match: re.Match[str] | None = _SPEC_PATTERN.match(line)
            if match:
                name: str = match.group(1)
                version: str = match.group(2)
                try:
                    deps.append(
                        Dependency(
                            name=name,
                            version=version,
                            ecosystem=Ecosystem.RUBYGEMS,
                        )
                    )
                except ValueError:
                    logger.debug("Skipping invalid dependency: %s", name)

        return deps
