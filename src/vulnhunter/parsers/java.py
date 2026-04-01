import logging
import re
from pathlib import Path
from xml.etree.ElementTree import Element

import defusedxml.ElementTree as DET

from vulnhunter.models import Dependency, Ecosystem
from vulnhunter.parsers.base import _execute_command, _resolve_platform_command

logger: logging.Logger = logging.getLogger(__name__)

_NS: str = "{http://maven.apache.org/POM/4.0.0}"
_PROPERTY_PATTERN: re.Pattern[str] = re.compile(r"\$\{(.+?)}")


class JavaParser:
    def parse(self, file_path: Path) -> list[Dependency]:
        deps: list[Dependency] = []
        seen: set[str] = set()

        direct: list[Dependency] = self._parse_pom(file_path)
        for dep in direct:
            key: str = f"{dep.name.lower()}:{dep.version}"
            if key not in seen:
                seen.add(key)
                deps.append(dep)

        transitive: list[Dependency] = self._parse_transitive(file_path.parent)
        for dep in transitive:
            key = f"{dep.name.lower()}:{dep.version}"
            if key not in seen:
                seen.add(key)
                deps.append(dep)

        logger.info("Java parser found %d dependencies", len(deps))
        return deps

    def _parse_pom(self, file_path: Path) -> list[Dependency]:
        deps: list[Dependency] = []
        try:
            tree = DET.parse(str(file_path))
        except Exception as exc:
            logger.error("Failed to parse %s: %s", file_path, exc)
            return deps

        root = tree.getroot()
        properties: dict[str, str] = self._extract_properties(root)

        project_version: str = self._get_project_version(root, properties)

        managed_versions: dict[str, str] = {}
        dep_mgmt = root.find(f"{_NS}dependencyManagement")
        if dep_mgmt is not None:
            mgmt_deps = dep_mgmt.find(f"{_NS}dependencies")
            if mgmt_deps is not None:
                for dep_elem in mgmt_deps.findall(f"{_NS}dependency"):
                    gid: str = self._text(dep_elem, f"{_NS}groupId")
                    aid: str = self._text(dep_elem, f"{_NS}artifactId")
                    ver: str = self._text(dep_elem, f"{_NS}version")
                    if gid and aid and ver:
                        resolved: str = self._resolve_property(ver, properties, project_version)
                        managed_versions[f"{gid}:{aid}"] = resolved

        deps_elem = root.find(f"{_NS}dependencies")
        if deps_elem is not None:
            for dep_elem in deps_elem.findall(f"{_NS}dependency"):
                parsed: Dependency | None = self._parse_dependency_element(
                    dep_elem, properties, project_version, managed_versions
                )
                if parsed:
                    deps.append(parsed)

        return deps

    def _parse_dependency_element(
        self,
        elem: Element,
        properties: dict[str, str],
        project_version: str,
        managed_versions: dict[str, str],
    ) -> Dependency | None:
        group_id: str = self._text(elem, f"{_NS}groupId")
        artifact_id: str = self._text(elem, f"{_NS}artifactId")
        version_raw: str = self._text(elem, f"{_NS}version")

        if not group_id or not artifact_id:
            return None

        name: str = f"{group_id}:{artifact_id}"

        if version_raw:
            version = self._resolve_property(version_raw, properties, project_version)
        else:
            version = managed_versions.get(name, project_version)

        if not version:
            return None

        try:
            return Dependency(
                name=name,
                version=version,
                ecosystem=Ecosystem.MAVEN,
            )
        except ValueError:
            logger.debug("Skipping invalid dependency: %s", name)
            return None

    def _extract_properties(self, root: Element) -> dict[str, str]:
        props: dict[str, str] = {}
        props_elem = root.find(f"{_NS}properties")
        if props_elem is not None:
            for child in props_elem:
                tag: str = child.tag.replace(_NS, "")
                if child.text:
                    props[tag] = child.text.strip()
        return props

    def _get_project_version(self, root: Element, properties: dict[str, str]) -> str:
        version_elem = root.find(f"{_NS}version")
        if version_elem is not None and version_elem.text:
            return self._resolve_property(version_elem.text.strip(), properties, "")

        parent = root.find(f"{_NS}parent")
        if parent is not None:
            parent_version = parent.find(f"{_NS}version")
            if parent_version is not None and parent_version.text:
                return parent_version.text.strip()

        return ""

    def _resolve_property(self, value: str, properties: dict[str, str], project_version: str) -> str:
        match: re.Match[str] | None = _PROPERTY_PATTERN.fullmatch(value)
        if not match:
            return value

        prop_name: str = match.group(1)

        if prop_name == "project.version":
            return project_version

        return properties.get(prop_name, value)

    def _text(self, elem: Element, tag: str) -> str:
        child = elem.find(tag)
        if child is not None and child.text:
            return child.text.strip()
        return ""

    def _parse_transitive(self, cwd: Path) -> list[Dependency]:
        deps: list[Dependency] = []
        mvn_cmd: str = _resolve_platform_command("mvn")
        output = _execute_command([mvn_cmd, "dependency:tree", "-DoutputType=text", "-q"], cwd)
        if not output:
            return deps

        pattern: re.Pattern[str] = re.compile(r"[|+\\ -]+\s*([^:]+):([^:]+):([^:]+):([^:]+)")

        for line in output.splitlines():
            match: re.Match[str] | None = pattern.search(line)
            if match:
                group_id: str = match.group(1).strip()
                artifact_id: str = match.group(2).strip()
                version: str = match.group(4).strip()
                name: str = f"{group_id}:{artifact_id}"
                try:
                    deps.append(
                        Dependency(
                            name=name,
                            version=version,
                            ecosystem=Ecosystem.MAVEN,
                        )
                    )
                except ValueError:
                    logger.debug("Skipping invalid transitive dep: %s", name)

        return deps
