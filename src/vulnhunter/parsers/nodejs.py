import json
import logging
import re
from pathlib import Path
from typing import Any

from vulnhunter.models import Dependency, Ecosystem
from vulnhunter.parsers.base import _execute_command, _resolve_platform_command

logger: logging.Logger = logging.getLogger(__name__)

_SEMVER_PREFIX: re.Pattern[str] = re.compile(r"^[\^~>=<]+")


class NodejsParser:
    def parse(self, file_path: Path) -> list[Dependency]:
        deps: list[Dependency] = []
        seen: set[str] = set()

        direct: list[Dependency] = self._parse_package_json(file_path)
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

        logger.info("Node.js parser found %d dependencies", len(deps))
        return deps

    def _parse_package_json(self, file_path: Path) -> list[Dependency]:
        deps: list[Dependency] = []
        try:
            content: str = file_path.read_text(encoding="utf-8")
            data: dict[str, Any] = json.loads(content)
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("Failed to parse %s: %s", file_path, exc)
            return deps

        dep_sections: list[str] = [
            "dependencies",
            "devDependencies",
            "peerDependencies",
            "optionalDependencies",
        ]

        for section in dep_sections:
            section_data: dict[str, Any] = data.get(section, {})
            if not isinstance(section_data, dict):
                continue
            for name, raw_version in section_data.items():
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
                            ecosystem=Ecosystem.NPM,
                        )
                    )
                except ValueError:
                    logger.debug("Skipping invalid dependency: %s", name)

        return deps

    def _clean_version(self, raw: str) -> str:
        cleaned: str = _SEMVER_PREFIX.sub("", raw).strip()
        if not cleaned or cleaned == "*" or cleaned == "latest":
            return "0.0.0"
        return cleaned

    def _parse_transitive(self, cwd: Path) -> list[Dependency]:
        deps: list[Dependency] = []
        npm_cmd: str = _resolve_platform_command("npm")
        output = _execute_command([npm_cmd, "ls", "--all", "--json", "--silent"], cwd)
        if not output:
            return deps

        try:
            tree: dict[str, Any] = json.loads(output)
        except json.JSONDecodeError:
            return deps

        self._walk_npm_tree(tree.get("dependencies", {}), deps)
        return deps

    def _walk_npm_tree(self, node: dict[str, Any], deps: list[Dependency]) -> None:
        for name, info in node.items():
            if not isinstance(info, dict):
                continue
            version: str = info.get("version", "")
            if version:
                try:
                    deps.append(
                        Dependency(
                            name=name,
                            version=version,
                            ecosystem=Ecosystem.NPM,
                        )
                    )
                except ValueError:
                    logger.debug("Skipping invalid transitive dep: %s", name)
            self._walk_npm_tree(info.get("dependencies", {}), deps)
