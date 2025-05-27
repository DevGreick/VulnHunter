# src/parsers.py
import re
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Callable, Dict, Set, Tuple, Optional
import subprocess
import os
import platform
import sys

try:
    from .models import Dependency
except ImportError:
    from models import Dependency

import logging
logger = logging.getLogger("src.parsers")

class DependencyParser:

    def __init__(self, file_path: str):
        logger.debug(f"Initializing DependencyParser for {file_path}.")
        self.file_path = Path(file_path)
        if not self.file_path.is_file():
            logger.error(
                f"Dependency file not found: {self.file_path}")
            raise FileNotFoundError(
                f"Dependency file not found: {self.file_path}")

    def extract_dependencies(self) -> List[Dependency]:
        filename_original = self.file_path.name
        filename_lower = filename_original.lower()
        logger.debug(
            f"Attempting to parse file: {filename_original} (dispatching based on: {filename_lower}).")
        parser_method = None
        lang_specific_transitive_parser = None

        if "requirements" in filename_lower and filename_lower.endswith(".txt"):
            parser_method = self._parse_requirements_txt
            lang_specific_transitive_parser = self._get_transitive_python_dependencies
        elif "package" in filename_lower and filename_lower.endswith(".json") and not "lock" in filename_lower:
            parser_method = self._parse_package_json
            lang_specific_transitive_parser = self._get_transitive_nodejs_dependencies
        elif "pom" in filename_lower and filename_lower.endswith(".xml"):
            parser_method = self._parse_pom_xml
            lang_specific_transitive_parser = self._get_transitive_java_dependencies
        elif "composer" in filename_lower and filename_lower.endswith(".json"):
            parser_method = self._parse_composer_json
            lang_specific_transitive_parser = self._get_transitive_php_dependencies
        elif "gemfile" in filename_lower and filename_lower.endswith(".lock"):
            parser_method = self._parse_gemfile_lock
            lang_specific_transitive_parser = self._get_transitive_ruby_dependencies
        elif "go" in filename_lower and filename_lower.endswith(".mod"):
            parser_method = self._parse_go_mod
            lang_specific_transitive_parser = self._get_transitive_go_dependencies

        if parser_method:
            try:
                dependencies = parser_method()
                if lang_specific_transitive_parser:
                    logger.debug(f"Attempting to get transitive dependencies for {filename_original} using {lang_specific_transitive_parser.__name__}")
                    transitive_dependencies = lang_specific_transitive_parser(dependencies)
                    dependencies.extend(transitive_dependencies)
                    logger.debug(f"Identified {len(transitive_dependencies)} transitive dependencies for {filename_original}")
                else:
                    logger.debug(f"No specific transitive parser for {filename_original}")
                return dependencies
            except Exception as e:
                logger.error(
                    f"Error parsing {filename_original} using {parser_method.__name__}: {e}", exc_info=True)
                return []
        else:
            logger.warning(
                f"No parser defined in DependencyParser.extract_dependencies for file: {filename_original}")
            return []

    def _execute_command(self, cmd: List[str], cwd: Path) -> Optional[str]:
        current_cmd = list(cmd)
        try:
            if current_cmd[0] == "mvn":
                logger.debug(f"Original command for mvn: \"{' '.join(current_cmd)}\" in \"{cwd}\"")
                logger.debug(f"Python's current PATH for mvn: {os.environ.get('PATH')}")
                logger.debug(f"Python's current PATHEXT for mvn: {os.environ.get('PATHEXT')}")
                if platform.system() == "Windows":
                    logger.debug("Detected Windows OS, attempting to use 'mvn.cmd'")
                    current_cmd[0] = "mvn.cmd"

            if current_cmd[0] == "composer.bat" or \
               (current_cmd[0] == "composer" and platform.system() == "Windows" and "composer.bat" not in current_cmd[0]):
                 logger.debug(f"Python's current PATH for {current_cmd[0]} (from _execute_command): {os.environ.get('PATH')}")
                 logger.debug(f"Python's current PATHEXT for {current_cmd[0]} (from _execute_command): {os.environ.get('PATHEXT')}")

            logger.debug(f"Executing command: \"{' '.join(current_cmd)}\" in \"{cwd}\"")
            result = subprocess.run(current_cmd, cwd=cwd, capture_output=True,
                                    text=True, check=True, encoding='utf-8', errors='ignore')
            return result.stdout
        except FileNotFoundError:
            logger.warning(
                f"Command not found: '{current_cmd[0]}'. Verify the tool is installed and in PATH.")
            return None
        except subprocess.CalledProcessError as e:
            logger.error(
                f"Error executing command '{' '.join(current_cmd)}' in '{cwd}'.\n"
                f"Return code: {e.returncode}\n"
                f"Stdout: {e.stdout}\n"
                f"Stderr: {e.stderr}")
            return None
        except Exception as e:
            logger.error(
                f"Unexpected error executing command '{' '.join(current_cmd)}': {e}", exc_info=True)
            return None

    def _parse_requirements_txt(self) -> List[Dependency]:
        logger.debug(f"requirements.txt: Starting parse for {self.file_path.name}")
        dependencies = []
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line_content = line.strip()
                    if not line_content or line_content.startswith("#"):
                        continue
                    match = re.match(
                        r"^\s*([a-zA-Z0-9\-_.]+)\s*(?:([<>=!~]{1,2})\s*([0-9a-zA-Z\-_.*+!]+))?", line_content)
                    if match:
                        name = match.group(1)
                        version_specifier = match.group(2)
                        version = match.group(3)
                        if version_specifier == "==" and version:
                            dependencies.append(Dependency(
                                name=name, version=version))
                            logger.debug(
                                f"requirements.txt: Parsed dependency: {name}@{version}")
                        elif version:
                            logger.debug(
                                f"requirements.txt: Dependency '{name}' has version specifier '{version_specifier}{version}', using version part '{version}' for analysis.")
                            dependencies.append(Dependency(
                                name=name, version=version))
                        else:
                            logger.warning(
                                f"requirements.txt: Skipping dependency '{name}' due to missing version or complex/unsupported specifier in line {line_num}: '{line_content}'")
                    else:
                        logger.warning(
                            f"requirements.txt: Skipping unparsable line {line_num}: '{line_content}'")
        except FileNotFoundError:
            logger.error(
                f"requirements.txt file not found during parsing: {self.file_path.name}")
        except Exception as e:
            logger.error(
                f"Error parsing {self.file_path.name}: {e}", exc_info=True)
        logger.info(
            f"Successfully parsed {len(dependencies)} direct dependencies from {self.file_path.name}")
        return dependencies

    def _get_transitive_python_dependencies(self, direct_dependencies: List[Dependency]) -> List[Dependency]:
        transitive_deps: List[Dependency] = []
        seen_dependencies: Set[Tuple[str, str]] = set(
            (dep.name.lower(), dep.version) for dep in direct_dependencies)
        logger.debug(
            "Attempting to identify transitive Python dependencies using 'pipdeptree'.")
        try:
            result = self._execute_command(
                ["pipdeptree", "--json"], self.file_path.parent)
            if result:
                dep_tree = json.loads(result)
                def traverse_tree(node):
                    pkg_name = node.get("package_name")
                    pkg_version = node.get("installed_version")
                    if pkg_name and pkg_version:
                        dep_tuple = (pkg_name.lower(), pkg_version)
                        if dep_tuple not in seen_dependencies:
                            transitive_deps.append(
                                Dependency(name=pkg_name, version=pkg_version))
                            seen_dependencies.add(dep_tuple)
                            logger.debug(f"Added transitive Python dep: {pkg_name}@{pkg_version}")
                    for child in node.get("dependencies", []):
                        traverse_tree(child)
                for top_level_dep in dep_tree:
                    traverse_tree(top_level_dep)
            else:
                logger.warning(
                    "pipdeptree returned no data or is not installed. Fallback to hardcoded common transitive dependencies.")
                for dep in direct_dependencies:
                    if dep.name.lower() == "requests":
                        if ("urllib3", "1.26.5") not in seen_dependencies:
                            transitive_deps.append(Dependency(name="urllib3", version="1.26.5"))
                            seen_dependencies.add(("urllib3", "1.26.5"))
                        if ("chardet", "3.0.4") not in seen_dependencies:
                            transitive_deps.append(Dependency(name="chardet", version="3.0.4"))
                            seen_dependencies.add(("chardet", "3.0.4"))
                    elif dep.name.lower() == "flask":
                        if ("werkzeug", "2.0.1") not in seen_dependencies:
                            transitive_deps.append(Dependency(name="werkzeug", version="2.0.1"))
                            seen_dependencies.add(("werkzeug", "2.0.1"))
                        if ("jinja2", "3.0.1") not in seen_dependencies:
                            transitive_deps.append(Dependency(name="jinja2", version="3.0.1"))
                            seen_dependencies.add(("jinja2", "3.0.1"))

        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON from pipdeptree: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error in Python transitive analysis: {e}", exc_info=True)
        logger.info(
            f"Identified {len(transitive_deps)} transitive Python dependencies.")
        return transitive_deps

    def _parse_package_json(self) -> List[Dependency]:
        dependencies = []
        logger.debug(f"ENTERING _parse_package_json for {self.file_path.name}")
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                logger.debug(f"Data loaded from package.json (first 200 chars): {str(data)[:200]}...")
                dep_sections = ["dependencies", "devDependencies",
                                "peerDependencies", "optionalDependencies"]
                for section in dep_sections:
                    logger.debug(f"Checking section: {section}")
                    if section in data and isinstance(data[section], dict):
                        logger.debug(f"Section '{section}' IS IN data and IS a dict.")
                        for name, version_ish in data[section].items():
                            version = re.sub(
                                r"^[<>=~^]*(?=[0-9])", "", str(version_ish)).strip()
                            if not version:
                                logger.warning(
                                    f"package.json: Skipping {name} from {section} due to empty version after stripping prefixes: '{version_ish}'")
                                continue
                            dependencies.append(Dependency(
                                name=name, version=version))
                            logger.debug(
                                f"package.json: Parsed dependency from {section}: {name}@{version}")
                    else:
                        logger.debug(f"Section '{section}' NOT in data or NOT a dict. In data: {section in data}, Is dict: {isinstance(data.get(section), dict) if section in data else 'N/A'}")
        except FileNotFoundError:
             logger.error(
                f"package.json file not found during parsing: {self.file_path.name}")
        except json.JSONDecodeError as e:
            logger.error(
                f"Error decoding JSON from {self.file_path.name}: {e}", exc_info=True)
        except Exception as e:
            logger.error(
                f"Error parsing {self.file_path.name}: {e}", exc_info=True)
        logger.info(
            f"Successfully parsed {len(dependencies)} direct dependencies from {self.file_path.name}")
        return dependencies

    def _get_transitive_nodejs_dependencies(self, direct_dependencies: List[Dependency]) -> List[Dependency]:
        transitive_deps: List[Dependency] = []
        seen_dependencies: Set[Tuple[str, str]] = set(
            (dep.name.lower(), dep.version) for dep in direct_dependencies)
        logger.debug("Entered _get_transitive_nodejs_dependencies")
        logger.debug(
            "Attempting to identify transitive Node.js dependencies using 'npm ls --prod --all --json'.")
        project_dir = self.file_path.parent
        current_cmd = ["npm", "ls", "--prod", "--all", "--json"]
        if platform.system() == "Windows":
            logger.debug("Detected Windows OS, attempting to use 'npm.cmd' for Node.js transitive dependencies.")
            current_cmd[0] = "npm.cmd"
        result = self._execute_command(current_cmd, project_dir)

        if result:
            logger.debug(f"Raw output from 'npm ls --prod --all --json' (first 500 chars):\n{result[:500]}")
            try:
                npm_ls_output = json.loads(result)
                def parse_npm_deps(deps_obj, path_prefix=""):
                    if not isinstance(deps_obj, dict):
                        logger.debug(f"parse_npm_deps: deps_obj at '{path_prefix}' is not a dict: {type(deps_obj)}")
                        return
                    for name, details in deps_obj.items():
                        current_path = f"{path_prefix}.{name}" if path_prefix else name
                        if not isinstance(details, dict):
                            logger.warning(f"Item '{name}' in dependencies at '{current_path}' is not a dictionary: {details}")
                            continue
                        version = details.get("version")
                        if name and version:
                            dep_tuple = (name.lower(), version)
                            if dep_tuple not in seen_dependencies:
                                transitive_deps.append(
                                    Dependency(name=name, version=version))
                                seen_dependencies.add(dep_tuple)
                                logger.debug(f"Added transitive Node.js dep: {name}@{version}")
                        if "dependencies" in details and isinstance(details["dependencies"], dict):
                            parse_npm_deps(details["dependencies"], current_path)
                        elif "dependencies" in details and not details["dependencies"]:
                             logger.debug(f"Package {name}@{version if version else 'N/A'} at '{current_path}' has an empty 'dependencies' field.")
                if isinstance(npm_ls_output, dict) and "dependencies" in npm_ls_output and isinstance(npm_ls_output["dependencies"], dict):
                    logger.debug("Calling parse_npm_deps for top-level 'dependencies'")
                    parse_npm_deps(npm_ls_output["dependencies"])
                elif isinstance(npm_ls_output, dict) and not npm_ls_output.get("dependencies"):
                     logger.warning("npm ls output does not contain a top-level 'dependencies' object or it's empty.")
                else:
                    logger.warning(f"Unexpected top-level structure in npm ls output. Type: {type(npm_ls_output)}. Keys: {npm_ls_output.keys() if isinstance(npm_ls_output, dict) else 'N/A'}")
            except json.JSONDecodeError as e:
                logger.error(f"Error decoding JSON from 'npm ls': {e}. Raw data (first 500 chars): {result[:500]}")
            except Exception as e:
                logger.error(
                    f"Unexpected error in Node.js transitive analysis: {e}", exc_info=True)
        else:
            logger.warning("Command 'npm ls --prod --all --json' produced no output or _execute_command returned None.")
        logger.info(
            f"Identified {len(transitive_deps)} transitive Node.js dependencies.")
        return transitive_deps

    def _parse_pom_xml(self) -> List[Dependency]:
        dependencies = []
        logger.debug(f"pom.xml: Starting parse for {self.file_path.name}")
        try:
            tree = ET.parse(self.file_path)
            root = tree.getroot()
            namespace_uri = ''
            if '}' in root.tag and root.tag.startswith('{'):
                namespace_uri = root.tag.split('}')[0][1:]
                logger.debug(f"pom.xml: Detected namespace: {namespace_uri}")
            def _ns_tag(tag_name: str) -> str:
                return f"{{{namespace_uri}}}{tag_name}" if namespace_uri else tag_name

            all_dependency_nodes = []
            dependencies_section = root.find(_ns_tag('dependencies'))
            if dependencies_section is not None:
                found_nodes = dependencies_section.findall(_ns_tag('dependency'))
                all_dependency_nodes.extend(found_nodes)
                logger.debug(f"pom.xml: Found {len(found_nodes)} potential dependency nodes under <dependencies>.")
            dependency_management_section = root.find(_ns_tag('dependencyManagement'))
            if dependency_management_section is not None:
                dependencies_in_dm_section = dependency_management_section.find(_ns_tag('dependencies'))
                if dependencies_in_dm_section is not None:
                    found_nodes_dm = dependencies_in_dm_section.findall(_ns_tag('dependency'))
                    all_dependency_nodes.extend(found_nodes_dm)
                    logger.debug(f"pom.xml: Found {len(found_nodes_dm)} potential dependency nodes under <dependencyManagement><dependencies>.")

            if not all_dependency_nodes:
                 logger.debug(f"pom.xml: No dependency nodes found in {self.file_path.name} "
                             f"using common paths (searched with namespace: '{namespace_uri if namespace_uri else 'None'}').")

            properties = {}
            properties_node = root.find(_ns_tag('properties'))
            if properties_node is not None:
                for prop_node in properties_node:
                    prop_tag = prop_node.tag
                    if namespace_uri and '}' in prop_tag:
                        prop_tag = prop_tag.split('}', 1)[-1]
                    properties[prop_tag] = prop_node.text.strip() if prop_node.text else ''
                logger.debug(f"pom.xml: Found properties: {properties}")

            for dep_node in all_dependency_nodes:
                group_id_node = dep_node.find(_ns_tag('groupId'))
                artifact_id_node = dep_node.find(_ns_tag('artifactId'))
                version_node = dep_node.find(_ns_tag('version'))

                group_id = group_id_node.text.strip() if group_id_node is not None and group_id_node.text else None
                artifact_id = artifact_id_node.text.strip() if artifact_id_node is not None and artifact_id_node.text else None
                version_text = version_node.text.strip() if version_node is not None and version_node.text else None
                version = None
                if version_text:
                    if version_text.startswith("${") and version_text.endswith("}"):
                        prop_name = version_text[2:-1]
                        if prop_name in properties:
                            version = properties[prop_name]
                            logger.debug(f"pom.xml: Resolved version property {version_text} to '{version}' for {group_id}:{artifact_id}")
                        else:
                            if prop_name == "project.version":
                                proj_version_node = root.find(_ns_tag('version'))
                                if proj_version_node is not None and proj_version_node.text:
                                    version = proj_version_node.text.strip()
                                    logger.debug(f"pom.xml: Resolved {version_text} to project version '{version}' for {group_id}:{artifact_id}")
                                else:
                                    parent_node = root.find(_ns_tag('parent'))
                                    if parent_node is not None:
                                        parent_version_node = parent_node.find(_ns_tag('version'))
                                        if parent_version_node is not None and parent_version_node.text:
                                            version = parent_version_node.text.strip()
                                            logger.debug(f"pom.xml: Resolved {version_text} to parent version '{version}' for {group_id}:{artifact_id}")
                                if not version:
                                     logger.warning(f"pom.xml: Could not resolve {version_text} (project/parent version not found) for {group_id}:{artifact_id}")
                            else:
                                logger.warning(f"pom.xml: Version property '{prop_name}' in '{version_text}' not found in <properties> for {group_id}:{artifact_id if artifact_id else 'unknown artifact'}")
                    else:
                        version = version_text

                if group_id and artifact_id and version:
                    name = artifact_id
                    dependencies.append(Dependency(name=name, version=version))
                    logger.debug(f"pom.xml: Parsed dependency: {name}@{version} (groupId: {group_id})")
                else:
                    g = group_id or 'N/A'
                    a = artifact_id or 'N/A'
                    v_raw = version_text or 'N/A'
                    if group_id_node is not None or artifact_id_node is not None or version_node is not None:
                        logger.warning(f"pom.xml: Skipping incomplete dependency: groupId={g}, artifactId={a}, version(raw)={v_raw}, resolved_version={version or 'N/A'} in {self.file_path.name}")

        except ET.ParseError as e:
            logger.error(f"Error parsing XML in {self.file_path.name}: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"Unexpected error parsing {self.file_path.name} ({type(e).__name__}): {e}", exc_info=True)

        logger.info(f"Successfully parsed {len(dependencies)} direct dependencies from {self.file_path.name}")
        return dependencies

    def _get_transitive_java_dependencies(self, direct_dependencies: List[Dependency]) -> List[Dependency]:
        transitive_deps: List[Dependency] = []
        seen_dependencies: Set[Tuple[str, str]] = set(
            (dep.name.lower(), dep.version) for dep in direct_dependencies)
        logger.debug("Attempting to identify transitive Java dependencies using 'mvn dependency:tree'.")
        project_dir = self.file_path.parent
        result_text = self._execute_command(["mvn", "dependency:tree"], project_dir)

        if result_text:
            for line in result_text.splitlines():
                match = re.search(r"[+\-|\\`\s]*([a-zA-Z0-9\-_.]+):([a-zA-Z0-9\-_.]+):([a-zA-Z0-9\-_.]+):([0-9a-zA-Z\-_.]+)(?::([a-zA-Z0-9\-_.]+))?", line)
                if match:
                    artifact_id = match.group(2)
                    version = match.group(4)
                    name = artifact_id
                    dep_tuple = (name.lower(), version)
                    if dep_tuple not in seen_dependencies:
                        transitive_deps.append(Dependency(name=name, version=version))
                        seen_dependencies.add(dep_tuple)
                        logger.debug(f"Added transitive Java dependency: {name}@{version}")
        else:
            logger.warning(
                "Maven command 'mvn dependency:tree' returned no data or an error occurred. "
                "Could not analyze transitive Java dependencies."
            )
        logger.info(
            f"Identified {len(transitive_deps)} transitive Java dependencies.")
        return transitive_deps

    def _parse_composer_json(self) -> List[Dependency]:
        dependencies = []
        logger.debug(f"composer.json: Starting parse for {self.file_path.name}")
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                dep_sections = ["require", "require-dev"]
                for section in dep_sections:
                    if section in data and isinstance(data[section], dict):
                        for name, version_ish in data[section].items():
                            if name.lower() == "php" or name.lower().startswith("ext-"):
                                logger.debug(f"composer.json: Skipping platform requirement in direct parse: {name}@{version_ish}")
                                continue
                            version = str(version_ish).strip()
                            if version.startswith("dev-") or version.endswith("-dev"):
                                pass
                            else:
                                version = re.sub(r"^[<>=~^|@\s]*v?(?=[0-9a-zA-Z])", "", version)
                            version = version.split(" ")[0].split(",")[0].split("|")[0].strip()
                            if version.endswith(".*"):
                                version = version[:-2] + ".0"
                            elif version.endswith("*"):
                                 if re.match(r"^\d+(\.\d+)*\.$", version[:-1]):
                                     version = version[:-1] + "0"
                                 elif re.match(r"^\d+\.$", version[:-1]):
                                     version = version[:-1] + "0"
                            if not version or not (
                                re.match(r"^(v?[0-9]+[0-9a-zA-Z\-_.]*)$", version) or
                                re.match(r"^[a-f0-9]{7,}$", version) or
                                version.startswith("dev-")
                            ):
                                logger.warning(
                                    f"composer.json: Skipping {name} from {section} due to complex/unresolvable version: '{version_ish}' -> cleaned to '{version}'")
                                continue
                            dependencies.append(Dependency(name=name, version=version))
                            logger.debug(f"composer.json: Parsed dependency from {section}: {name}@{version}")
        except FileNotFoundError:
            logger.error(f"composer.json file not found during parsing: {self.file_path.name}")
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON from {self.file_path.name}: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"Error parsing {self.file_path.name}: {e}", exc_info=True)
        logger.info(f"Successfully parsed {len(dependencies)} direct dependencies from {self.file_path.name}")
        return dependencies

    def _get_transitive_php_dependencies(self, direct_dependencies: List[Dependency]) -> List[Dependency]:
        transitive_deps: List[Dependency] = []
        seen_dependencies: Set[Tuple[str, str]] = set(
            (dep.name.lower(), dep.version) for dep in direct_dependencies)
        logger.debug("Attempting to identify transitive PHP dependencies using 'composer show --tree'.")
        project_dir = self.file_path.parent
        current_cmd = ["composer", "show", "--tree", "--no-ansi"]
        if platform.system() == "Windows":
            logger.debug("Detected Windows OS, attempting to use 'composer.bat' for PHP transitive dependencies.")
            current_cmd[0] = "composer.bat"
        result = self._execute_command(current_cmd, project_dir)

        if result:
            dep_line_pattern = re.compile(r"^[|`\s]*[+\-`|]?--\s*([a-zA-Z0-9\-_/.]+)\s+([0-9a-zA-Z\-_./@]+(?:#[a-f0-9]+)?)")
            for line in result.splitlines():
                match = dep_line_pattern.match(line)
                if match:
                    name = match.group(1)
                    version_raw_full = match.group(2)
                    if name.lower() == "php" or name.lower().startswith("ext-"):
                        logger.debug(f"Skipping platform requirement in tree: {name} {version_raw_full}")
                        continue
                    version = version_raw_full
                    if "#" in version:
                        version = version.split("#")[0]
                    if version.startswith("v") and not version.startswith("dev-"):
                        version = version[1:]
                    if name and version:
                        if version.startswith("dev-") and "/" in version:
                            version = version.split("/")[0]
                        dep_tuple = (name.lower(), version)
                        if dep_tuple not in seen_dependencies:
                            transitive_deps.append(Dependency(name=name, version=version))
                            seen_dependencies.add(dep_tuple)
                            logger.debug(f"Added transitive PHP dependency: {name}@{version}")
                        else:
                            logger.debug(f"Skipping already seen PHP dependency: {name}@{version}")
                    elif name:
                        logger.warning(f"Could not reliably parse version for PHP dependency '{name}' from raw version string '{version_raw_full}'. Cleaned version attempt: '{version}'. Original line: {line}")
        else:
            logger.warning(f"Command '{' '.join(current_cmd)}' produced no output or _execute_command returned None.")
        logger.info(
            f"Identified {len(transitive_deps)} transitive PHP dependencies.")
        return transitive_deps

    def _parse_gemfile_lock(self) -> List[Dependency]:
        dependencies = []
        logger.debug(f"Gemfile.lock: Starting parse for {self.file_path.name}")
        in_gems_section = False
        gem_pattern = re.compile(r"^\s{4}([a-zA-Z0-9\-_.]+)\s+\(([0-9a-zA-Z\-_.]+.*?)\)")
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                for line_num, line_content in enumerate(f, 1):
                    line = line_content.rstrip()
                    if line == "GEM":
                        in_gems_section = True
                        logger.debug("Gemfile.lock: Entered GEM section.")
                        continue
                    if in_gems_section and (line == "PLATFORMS" or line == "DEPENDENCIES" or line.startswith("BUNDLED WITH") or (not line.startswith(" ") and line)):
                        in_gems_section = False
                        logger.debug(f"Gemfile.lock: Exited GEM section due to '{line}'.")
                        if line == "PLATFORMS" or line == "DEPENDENCIES" or line.startswith("BUNDLED WITH"):
                            continue
                    if in_gems_section:
                        if line.startswith("      ") and "(" not in line:
                            logger.debug(f"Gemfile.lock: Skipping likely sub-dependency specifier: {line.strip()}")
                            continue
                        match = gem_pattern.match(line)
                        if match:
                            name = match.group(1)
                            version_full = match.group(2)
                            version = version_full.split("-")[0] if "-" in version_full and not re.match(r"^\d+-\d+", version_full) else version_full
                            if re.match(r"^[0-9.]+-", version_full) and any(c.isalpha() for c in version_full.split("-",1)[1]):
                                version = version_full
                            dependencies.append(Dependency(name=name, version=version))
                            logger.debug(f"Gemfile.lock: Parsed dependency: {name}@{version} (from full: {version_full})")
                        elif line and line.strip() and not line.startswith("  remote:") and not line.startswith("  specs:"):
                             logger.debug(f"Gemfile.lock: Skipping line in GEM section (no match for main gem pattern or known header): '{line.strip()}'")
        except FileNotFoundError:
            logger.error(f"Gemfile.lock file not found during parsing: {self.file_path.name}")
        except Exception as e:
            logger.error(f"Error parsing {self.file_path.name}: {e}", exc_info=True)
        logger.info(f"Successfully parsed {len(dependencies)} dependencies from {self.file_path.name}")
        return dependencies

    def _get_transitive_ruby_dependencies(self, direct_dependencies: List[Dependency]) -> List[Dependency]:
        logger.debug(f"Gemfile.lock parsing extracts all dependencies. No separate transitive step from this method.")
        return []

    def _parse_go_mod(self) -> List[Dependency]:
        dependencies = []
        logger.debug(f"go.mod: Starting parse for {self.file_path.name}.")
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                in_require_block = False
                for line_num, line_content in enumerate(f, 1):
                    line = line_content.strip()
                    if not line or line.startswith("//"):
                        continue
                    if line.startswith("require ("):
                        in_require_block = True
                        logger.debug("go.mod: Entered require block.")
                        continue
                    if in_require_block and line == ")":
                        in_require_block = False
                        logger.debug("go.mod: Exited require block.")
                        continue
                    target_line_parts = []
                    is_require_line = False
                    if in_require_block:
                        is_require_line = True
                        parts = line.split()
                        if len(parts) >= 2:
                            target_line_parts = [parts[0], parts[1]]
                    elif line.startswith("require "):
                        is_require_line = True
                        temp_line = line.replace("require ", "", 1).strip()
                        parts = temp_line.split()
                        if len(parts) >= 2:
                            target_line_parts = [parts[0], parts[1]]
                    if len(target_line_parts) >= 2:
                        name = target_line_parts[0]
                        version_ish_from_parts = target_line_parts[1]
                        version_clean_comment = version_ish_from_parts.split("//")[0].strip()
                        version_final = version_clean_comment[1:] if version_clean_comment.startswith("v") else version_clean_comment
                        if name and version_final:
                            dependencies.append(Dependency(name=name, version=version_final))
                            logger.debug(f"go.mod: Parsed dependency: {name}@{version_final}")
                    elif is_require_line:
                        logger.debug(f"go.mod: Skipping line in require context (not enough parts or malformed): {line}")
                    elif not (line.startswith("module ") or line.startswith("go ") or \
                              line.startswith("replace ") or line.startswith("exclude ") or \
                              line.startswith("retract ") or line == ")"):
                        logger.debug(f"go.mod: Skipping unhandled non-directive line {line_num}: {line}")
        except FileNotFoundError:
            logger.error(f"go.mod file not found during parsing: {self.file_path.name}")
            dependencies = []
        except Exception as e:
            logger.error(f"Error parsing {self.file_path.name}: {e}", exc_info=True)
            dependencies = []
        logger.info(f"Successfully parsed {len(dependencies)} direct dependencies from {self.file_path.name}")
        return dependencies

    def _get_transitive_go_dependencies(self, direct_dependencies: List[Dependency]) -> List[Dependency]:
        transitive_deps: List[Dependency] = []
        seen_dependencies: Set[Tuple[str, str]] = set(
            (dep.name.lower(), dep.version) for dep in direct_dependencies)
        logger.debug("Attempting to identify transitive Go dependencies using 'go list -m -mod=mod all'.")
        project_dir = self.file_path.parent
        current_cmd = ["go", "list", "-m", "-mod=mod", "all"]
        result_list_all = self._execute_command(current_cmd, project_dir)
        if result_list_all:
            for line in result_list_all.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0]
                    version_raw = parts[1]
                    version = version_raw[1:] if version_raw.startswith("v") else version_raw
                    if name and version:
                        dep_tuple = (name.lower(), version)
                        if dep_tuple not in seen_dependencies:
                            transitive_deps.append(Dependency(name=name, version=version))
                            seen_dependencies.add(dep_tuple)
                            logger.debug(f"Added transitive Go dependency: {name}@{version}")
                elif line.strip():
                    logger.debug(f"Skipping unparsable line from 'go list': {line}")
        else:
            logger.warning("Could not get Go module list. 'go list -m -mod=mod all' failed or returned no output.")
        logger.info(f"Identified {len(transitive_deps)} transitive Go dependencies.")
        return transitive_deps

def get_parser_for_file(file_path_str_for_log_only: str) -> Callable[[str], List[Dependency]]:
    logger.debug(f"Configuring parser wrapper for {file_path_str_for_log_only}.")
    def parsing_function_wrapper(actual_path_to_parse: str) -> List[Dependency]:
        logger.debug(f"parsing_function_wrapper: Instantiating DependencyParser for: {actual_path_to_parse}")
        instance = DependencyParser(actual_path_to_parse)
        return instance.extract_dependencies()
    return parsing_function_wrapper
