import json
import logging
import re
from pathlib import Path
from typing import Any

from vulnhunter.models import Dependency, Ecosystem
from vulnhunter.parsers.base import _execute_command, _resolve_platform_command

logger: logging.Logger = logging.getLogger(__name__)

_VERSION_PREFIX: re.Pattern[str] = re.compile(r"^[\^~>=<|@]+")
_SKIP_PATTERN: re.Pattern[str] = re.compile(r"^(php|ext-)")


class PhpParser:
    def parse(self, file_path: Path) -> list[Dependency]:
        deps: list[Dependency] = []
        seen: set[str] = set()

        direct: list[Dependency] = self._parse_composer_json(file_path)
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

        logger.info("PHP parser found %d dependencies", len(deps))
        return deps

    def _parse_composer_json(self, file_path: Path) -> list[Dependency]:
        deps: list[Dependency] = []
        try:
            content: str = file_path.read_text(encoding="utf-8")
            data: dict[str, Any] = json.loads(content)
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("Failed to parse %s: %s", file_path, exc)
            return deps

        for section in ("require", "require-dev"):
            section_data: dict[str, Any] = data.get(section, {})
            if not isinstance(section_data, dict):
                continue
            for name, raw_version in section_data.items():
                if _SKIP_PATTERN.match(name):
                    continue
                if not isinstance(raw_version, str):
                    continue
                version: str = self._clean_version(raw_version)
                if not version:
                    continue
                try:
                    deps.append(
                        Dependency(
                            name=name,
                            version=version,
                            ecosystem=Ecosystem.PACKAGIST,
                        )
                    )
                except ValueError:
                    logger.debug("Skipping invalid dependency: %s", name)

        return deps

    def _clean_version(self, raw: str) -> str:
        cleaned: str = _VERSION_PREFIX.sub("", raw).strip()
        if not cleaned or cleaned == "*":
            return "0.0.0"
        if cleaned.endswith(".*"):
            cleaned = cleaned[:-2] + ".0"
        return cleaned

    def _parse_transitive(self, cwd: Path) -> list[Dependency]:
        deps: list[Dependency] = []
        composer_cmd: str = _resolve_platform_command("composer")
        output = _execute_command([composer_cmd, "show", "--format=json"], cwd)
        if not output:
            return deps

        try:
            data: dict[str, Any] = json.loads(output)
        except json.JSONDecodeError:
            return deps

        installed: list[dict[str, Any]] = data.get("installed", [])
        for pkg in installed:
            name: str = pkg.get("name", "")
            version: str = pkg.get("version", "")
            if not name or not version:
                continue
            if version.startswith("v"):
                version = version[1:]
            try:
                deps.append(
                    Dependency(
                        name=name,
                        version=version,
                        ecosystem=Ecosystem.PACKAGIST,
                    )
                )
            except ValueError:
                logger.debug("Skipping invalid transitive dep: %s", name)

        return deps
