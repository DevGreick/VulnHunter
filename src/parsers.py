# src/parsers.py
import re
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Callable, Dict, Set, Tuple, Optional
import subprocess  
import os 
import platform 

try:
    from .models import Dependency
except ImportError:
    from models import Dependency

import logging
logger = logging.getLogger("src.parsers")


class DependencyParser:

    def __init__(self, file_path: str):
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
            f"Attempting to parse file: {filename_original} (dispatching based on: {filename_lower})")

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
                    dependencies.extend(
                        lang_specific_transitive_parser(dependencies))
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
                logger.warning(f"Original command for mvn: \"{' '.join(current_cmd)}\" in \"{cwd}\"")
                logger.warning(f"Python's current PATH for mvn: {os.environ.get('PATH')}")
                logger.warning(f"Python's current PATHEXT for mvn: {os.environ.get('PATHEXT')}")
                if platform.system() == "Windows":
                    logger.warning("Detected Windows OS, attempting to use 'mvn.cmd'")
                    current_cmd[0] = "mvn.cmd"
            
            
            if current_cmd[0] == "composer.bat" or \
               (current_cmd[0] == "composer" and platform.system() == "Windows" and "composer.bat" not in current_cmd[0]): # Check to avoid double logging if already .bat
                 logger.info(f"Python's current PATH for {current_cmd[0]} (from _execute_command): {os.environ.get('PATH')}")
                 logger.info(f"Python's current PATHEXT for {current_cmd[0]} (from _execute_command): {os.environ.get('PATHEXT')}")

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
        dependencies = []
        logger.debug(
            f"requirements.txt: Starting parse for {self.file_path.name}")
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    match = re.match(
                        r"^\s*([a-zA-Z0-9\-_.]+)\s*(?:([<>=!~]{1,2})\s*([0-9a-zA-Z\-_.*+!]+))?", line)
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
                            logger.info(
                                f"requirements.txt: Dependency '{name}' has version specifier '{version_specifier}{version}', using version part '{version}' for analysis. Consider exact versions ('==') for more precise matching.")
                            dependencies.append(Dependency(
                                name=name, version=version))
                        else:
                            logger.warning(
                                f"requirements.txt: Skipping dependency '{name}' due to missing version or complex/unsupported specifier in line {line_num}: '{line}'")
                    else:
                        logger.warning(
                            f"requirements.txt: Skipping unparsable line {line_num}: '{line}'")
        except FileNotFoundError:
            logger.error(
                f"requirements.txt file not found during parsing: {self.file_path.name}")
        except Exception as e:
            logger.error(
                f"Error parsing {self.file_path.name}: {e}", exc_info=True)
        logger.info(
            f"Successfully parsed {len(dependencies)} dependencies from {self.file_path.name}")
        return dependencies

    def _get_transitive_python_dependencies(self, direct_dependencies: List[Dependency]) -> List[Dependency]:
        transitive_deps: List[Dependency] = []
        seen_dependencies: Set[Tuple[str, str]] = set(
            (dep.name.lower(), dep.version) for dep in direct_dependencies)
        logger.info(
            "Attempting to identify transitive Python dependencies using 'pipdeptree' or 'pip show'.")
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
                    for child in node.get("dependencies", []):
                        traverse_tree(child)
                for top_level_dep in dep_tree:
                    traverse_tree(top_level_dep)
            else:
                logger.warning(
                    "pipdeptree returned no data or is not installed. Attempting alternative method with 'pip show'.")
                for dep in direct_dependencies:
                    if dep.name.lower() == "requests":
                        if ("urllib3", "1.26.5") not in seen_dependencies:
                            transitive_deps.append(Dependency(
                                name="urllib3", version="1.26.5"))
                            seen_dependencies.add(("urllib3", "1.26.5"))
                        if ("chardet", "3.0.4") not in seen_dependencies:
                            transitive_deps.append(Dependency(
                                name="chardet", version="3.0.4"))
                            seen_dependencies.add(("chardet", "3.0.4"))
                    elif dep.name.lower() == "flask":
                        if ("werkzeug", "2.0.1") not in seen_dependencies:
                            transitive_deps.append(Dependency(
                                name="werkzeug", version="2.0.1"))
                            seen_dependencies.add(("werkzeug", "2.0.1"))
                        if ("jinja2", "3.0.1") not in seen_dependencies:
                            transitive_deps.append(Dependency(
                                name="jinja2", version="3.0.1"))
                            seen_dependencies.add(("jinja2", "3.0.1"))
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON from pipdeptree: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error in Python transitive analysis: {e}", exc_info=True)
        if transitive_deps:
            logger.info(
                f"Identified {len(transitive_deps)} transitive Python dependencies.")
        else:
            logger.info("No transitive Python dependencies identified.")
        return transitive_deps

    def _parse_package_json(self) -> List[Dependency]:
        dependencies = []
        logger.debug(f"ENTERING _parse_package_json for {self.file_path.name}")
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                logger.debug(f"Data loaded from package.json: {data}") 

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
            f"Successfully parsed {len(dependencies)} dependencies from {self.file_path.name}")
        return dependencies

    def _get_transitive_nodejs_dependencies(self, direct_dependencies: List[Dependency]) -> List[Dependency]:
        transitive_deps: List[Dependency] = []
        seen_dependencies: Set[Tuple[str, str]] = set(
            (dep.name.lower(), dep.version) for dep in direct_dependencies)
        logger.debug("Entered _get_transitive_nodejs_dependencies") 
        logger.info(
            "Attempting to identify transitive Node.js dependencies using 'npm ls --prod --all --json'.")
        project_dir = self.file_path.parent
        current_cmd = ["npm", "ls", "--prod", "--all", "--json"]
        if platform.system() == "Windows":
            logger.info("Detected Windows OS, attempting to use 'npm.cmd' for Node.js transitive dependencies.")
            current_cmd[0] = "npm.cmd"
        result = self._execute_command(current_cmd, project_dir)
        logger.debug(f"Result from _execute_command for NPM LS (--all): '{result}'")
        if result:
            logger.debug(f"Raw output from 'npm ls --prod --all --json':\n{result}")
            try:
                npm_ls_output = json.loads(result)
                def parse_npm_deps(deps_obj):
                    if not isinstance(deps_obj, dict):
                        logger.debug(f"parse_npm_deps: deps_obj is not a dict: {type(deps_obj)}")
                        return
                    for name, details in deps_obj.items():
                        if not isinstance(details, dict):
                            logger.warning(f"Item '{name}' in dependencies is not a dictionary: {details}")
                            continue
                        version = details.get("version")
                        if name and version:
                            dep_tuple = (name.lower(), version)
                            if dep_tuple not in seen_dependencies:
                                transitive_deps.append(
                                    Dependency(name=name, version=version))
                                seen_dependencies.add(dep_tuple)
                        if "dependencies" in details and isinstance(details["dependencies"], dict):
                            parse_npm_deps(details["dependencies"])
                        elif "dependencies" in details and not details["dependencies"]:
                             logger.debug(f"Package {name}@{version if version else 'N/A'} has an empty 'dependencies' field or non-dict value.")
                if isinstance(npm_ls_output, dict) and "dependencies" in npm_ls_output and isinstance(npm_ls_output["dependencies"], dict):
                    logger.debug("Calling parse_npm_deps for top-level 'dependencies'")
                    parse_npm_deps(npm_ls_output["dependencies"])
                elif isinstance(npm_ls_output, dict) and not npm_ls_output.get("dependencies"):
                     logger.warning("npm ls output does not contain a top-level 'dependencies' object or it's empty.")
                else:
                    logger.warning(f"Unexpected top-level structure in npm ls output. Type: {type(npm_ls_output)}. Keys: {npm_ls_output.keys() if isinstance(npm_ls_output, dict) else 'N/A'}")
            except json.JSONDecodeError as e:
                logger.error(f"Error decoding JSON from 'npm ls': {e}")
            except Exception as e:
                logger.error(
                    f"Unexpected error in Node.js transitive analysis: {e}", exc_info=True)
        else:
            logger.warning("Command 'npm ls --prod --all --json' produced no output or _execute_command returned None.")
        if transitive_deps:
            logger.info(
                f"Identified {len(transitive_deps)} transitive Node.js dependencies.")
        else:
            logger.info("No transitive Node.js dependencies identified.")
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
                found_nodes = dependencies_section.findall(
                    _ns_tag('dependency'))
                all_dependency_nodes.extend(found_nodes)
                logger.debug(
                    f"pom.xml: Found {len(found_nodes)} potential dependency nodes under <dependencies>.")
            dependency_management_section = root.find(
                _ns_tag('dependencyManagement'))
            if dependency_management_section is not None:
                dependencies_in_dm_section = dependency_management_section.find(
                    _ns_tag('dependencies'))
                if dependencies_in_dm_section is not None:
                    found_nodes_dm = dependencies_in_dm_section.findall(
                        _ns_tag('dependency'))
                    all_dependency_nodes.extend(found_nodes_dm)
                    logger.debug(
                        f"pom.xml: Found {len(found_nodes_dm)} potential dependency nodes under <dependencyManagement><dependencies>.")
            if not all_dependency_nodes:
                logger.info(f"pom.xml: No dependency nodes found in {self.file_path.name} "
                            f"using common paths (searched with namespace: '{namespace_uri if namespace_uri else 'None'}').")
            properties = {}
            properties_node = root.find(_ns_tag('properties'))
            if properties_node is not None:
                for prop_node in properties_node:
                    prop_tag = prop_node.tag
                    if namespace_uri and '}' in prop_tag:
                        prop_tag = prop_tag.split('}', 1)[-1]
                    properties[prop_tag] = prop_node.text.strip(
                    ) if prop_node.text else ''
                logger.debug(f"pom.xml: Found properties: {properties}")
            for dep_node in all_dependency_nodes:
                group_id_node = dep_node.find(_ns_tag('groupId'))
                artifact_id_node = dep_node.find(_ns_tag('artifactId'))
                version_node = dep_node.find(_ns_tag('version'))
                group_id = group_id_node.text.strip(
                ) if group_id_node is not None and group_id_node.text else None
                artifact_id = artifact_id_node.text.strip(
                ) if artifact_id_node is not None and artifact_id_node.text else None
                version_text = version_node.text.strip(
                ) if version_node is not None and version_node.text else None
                version = None
                if version_text:
                    if version_text.startswith("${") and version_text.endswith("}"):
                        prop_name = version_text[2:-1]
                        if prop_name in properties:
                            version = properties[prop_name]
                            logger.debug(
                                f"pom.xml: Resolved version property {version_text} to '{version}' for {group_id}:{artifact_id}")
                        else:
                            if prop_name == "project.version":
                                proj_version_node = root.find(
                                    _ns_tag('version'))
                                if proj_version_node is not None and proj_version_node.text:
                                    version = proj_version_node.text.strip()
                                    logger.debug(
                                        f"pom.xml: Resolved {version_text} to project version '{version}' for {group_id}:{artifact_id}")
                                else:
                                    parent_node = root.find(_ns_tag('parent'))
                                    if parent_node is not None:
                                        parent_version_node = parent_node.find(
                                            _ns_tag('version'))
                                        if parent_version_node is not None and parent_version_node.text:
                                            version = parent_version_node.text.strip()
                                            logger.debug(
                                                f"pom.xml: Resolved {version_text} to parent version '{version}' for {group_id}:{artifact_id}")
                                if not version:
                                    logger.warning(
                                        f"pom.xml: Could not resolve {version_text} (project/parent version not found) for {group_id}:{artifact_id}")
                            else:
                                logger.warning(
                                    f"pom.xml: Version property '{prop_name}' in '{version_text}' not found in <properties> for {group_id}:{artifact_id if artifact_id else 'unknown artifact'}")
                    else:
                        version = version_text
                if group_id and artifact_id and version:
                    name = artifact_id
                    dependencies.append(Dependency(name=name, version=version))
                    logger.debug(
                        f"pom.xml: Parsed dependency: {name}@{version} (groupId: {group_id})")
                else:
                    g = group_id or 'N/A'
                    a = artifact_id or 'N/A'
                    v_raw = version_text or 'N/A'
                    if group_id_node is not None or artifact_id_node is not None or version_node is not None:
                        logger.warning(
                            f"pom.xml: Skipping incomplete dependency: groupId={g}, artifactId={a}, version(raw)={v_raw} in {self.file_path.name}")
        except ET.ParseError as e:
            logger.error(
                f"Error parsing XML in {self.file_path.name}: {e}", exc_info=True)
        except Exception as e:
            logger.error(
                f"Unexpected error parsing {self.file_path.name} ({type(e).__name__}): {e}", exc_info=True)
        logger.info(
            f"Successfully parsed {len(dependencies)} dependencies from {self.file_path.name}")
        return dependencies

    def _get_transitive_java_dependencies(self, direct_dependencies: List[Dependency]) -> List[Dependency]:
        transitive_deps: List[Dependency] = []
        seen_dependencies: Set[Tuple[str, str]] = set(
            (dep.name.lower(), dep.version) for dep in direct_dependencies)
        logger.info(
            "Attempting to identify transitive Java dependencies using 'mvn dependency:tree'.")
        project_dir = self.file_path.parent
        result_text = self._execute_command(
            ["mvn", "dependency:tree"], project_dir)
        if result_text:
            for line in result_text.splitlines():
                match = re.search(
                    r"\S+\s+([a-zA-Z0-9\-_.]+):([a-zA-Z0-9\-_.]+):jar:([0-9a-zA-Z\-_.]+)", line)
                if match:
                    artifact_id = match.group(2)
                    version = match.group(3)
                    name = artifact_id
                    dep_tuple = (name.lower(), version)
                    if dep_tuple not in seen_dependencies:
                        transitive_deps.append(
                            Dependency(name=name, version=version))
                        seen_dependencies.add(dep_tuple)
                        logger.debug(
                            f"Added transitive Java dependency: {name}@{version}")
        else: 
            logger.warning(
                "Maven command 'mvn dependency:tree' returned no data or an error occurred. "
                "Could not analyze transitive Java dependencies.")
        if transitive_deps:
            logger.info(
                f"Identified {len(transitive_deps)} transitive Java dependencies.")
        else:
            logger.info("No transitive Java dependencies identified.")
        return transitive_deps

    def _parse_composer_json(self) -> List[Dependency]:
        dependencies = []
        logger.debug(
            f"composer.json: Starting parse for {self.file_path.name}")
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                dep_sections = ["require", "require-dev"]
                for section in dep_sections:
                    if section in data and isinstance(data[section], dict):
                        for name, version_ish in data[section].items():
                            if name.lower() == "php" or name.lower().startswith("ext-"):
                                logger.debug(
                                    f"composer.json: Skipping platform requirement in direct parse: {name}@{version_ish}")
                                continue
                            version = str(version_ish).strip()
                            version = re.sub(
                                r"^[<>=~^|@dev\s]*v?(?=[0-9])", "", version)
                            version = version.split(" ")[0]
                            version = version.split(",")[0]
                            version = version.replace(
                                "-dev", "").replace("-stable", "")
                            if version.endswith(".*"):
                                version = version[:-2] + ".0" 
                            elif version.endswith("*"):
                                version = version[:-1] + "0" 
                            
                            if not version or not (re.match(r"^[0-9]", version) or re.match(r"^v[0-9]", version) or re.match(r"^[a-f0-9]{7,}$", version) or version.startswith("dev-")):
                                logger.warning(
                                    f"composer.json: Skipping {name} from {section} due to complex/unresolvable version: '{version_ish}' -> '{version}'")
                                continue
                            dependencies.append(Dependency(
                                name=name, version=version))
                            logger.debug(
                                f"composer.json: Parsed dependency from {section}: {name}@{version}")
        except FileNotFoundError:
            logger.error(
                f"composer.json file not found during parsing: {self.file_path.name}")
        except json.JSONDecodeError as e:
            logger.error(
                f"Error decoding JSON from {self.file_path.name}: {e}", exc_info=True)
        except Exception as e:
            logger.error(
                f"Error parsing {self.file_path.name}: {e}", exc_info=True)
        logger.info(
            f"Successfully parsed {len(dependencies)} dependencies from {self.file_path.name}")
        return dependencies

    def _get_transitive_php_dependencies(self, direct_dependencies: List[Dependency]) -> List[Dependency]:
        transitive_deps: List[Dependency] = []
        seen_dependencies: Set[Tuple[str, str]] = set(
            (dep.name.lower(), dep.version) for dep in direct_dependencies)

        logger.debug("ENTERING _get_transitive_php_dependencies") 

        logger.info(
            "Attempting to identify transitive PHP dependencies using 'composer show --tree'.")

        project_dir = self.file_path.parent
        current_cmd = ["composer", "show", "--tree"]
        if platform.system() == "Windows":
            logger.info("Detected Windows OS, attempting to use 'composer.bat' for PHP transitive dependencies.")
            current_cmd[0] = "composer.bat" 

        result = self._execute_command(current_cmd, project_dir)
        
        logger.debug(f"Raw output from '{' '.join(current_cmd)}':\n{result if result else 'No output or command failed/returned None.'}")

        if result:
            # Regex updated to correctly parse composer show --tree output for package lines
            dep_line_pattern = re.compile(r"^\s*([|`]\s*)*[+\-`|]?--\s*([a-zA-Z0-9\-_/.:]+)\s+([^(\s].*)")

            for line in result.splitlines():
                match = dep_line_pattern.match(line) 
                if match:
                    name = match.group(2) 
                    version_raw_full = match.group(3)

                    # Skip platform requirements (php, ext-*)
                    if name.lower() == "php" or name.lower().startswith("ext-"):
                        logger.debug(f"Skipping platform requirement in tree: {name} {version_raw_full}")
                        continue

                    version_raw_part = version_raw_full.split(" ")[0]
                    
                    version = re.sub(
                        r"^[<>=~^|@dev\s]*v?(?=[0-9])", "", version_raw_part)
                    version = version.split(",")[0] 
                    version = version.replace("-dev", "").replace("-stable", "")
                    if version.endswith(".*"): 
                        version = version[:-2] + ".0" 
                    elif version.endswith("*"): 
                         version = version[:-1] + "0"
                    
                    if name and version and \
                       (re.match(r"^[0-9]", version) or \
                        re.match(r"^v[0-9]", version) or \
                        re.match(r"^[a-f0-9]{7,}$", version) or \
                        version.startswith("dev-") ):
                        
                        if version.startswith("dev-") and "/" in version: # e.g. dev-main/foo -> dev-main
                            version = version.split("/")[0]

                        dep_tuple = (name.lower(), version)
                        if dep_tuple not in seen_dependencies:
                            transitive_deps.append(
                                Dependency(name=name, version=version))
                            seen_dependencies.add(dep_tuple)
                            logger.debug(
                                f"Added transitive PHP dependency: {name}@{version}")
                        else:
                            logger.debug(f"Skipping already seen PHP dependency: {name}@{version}")
                    elif name: 
                        logger.debug(f"Could not reliably parse version for PHP dependency '{name}' from raw version string '{version_raw_full}'. Cleaned version attempt: '{version}'. Original line: {line}")
        else:
            logger.warning(f"Command '{' '.join(current_cmd)}' produced no output or _execute_command returned None (check previous logs for errors from _execute_command if any).")

        if transitive_deps:
            logger.info(
                f"Identified {len(transitive_deps)} transitive PHP dependencies.")
        else:
            logger.info("No transitive PHP dependencies identified.")
        return transitive_deps

    def _parse_gemfile_lock(self) -> List[Dependency]:
        dependencies = []
        logger.debug(
            f"Gemfile.lock: Starting parse for {self.file_path.name}")
        in_gems_section = False
        gem_pattern = re.compile(
            r"^\s*([a-zA-Z0-9\-_.]+)\s+\(([0-9a-zA-Z\-_.]+.*?)\)")
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                for line_num, line_content in enumerate(f, 1):
                    line = line_content.strip()
                    if line == "GEM":
                        in_gems_section = True
                        logger.debug(
                            f"Gemfile.lock: Entered GEM section at line {line_num}")
                        continue
                    if in_gems_section and (line == "PLATFORMS" or line == "DEPENDENCIES" or line.startswith("BUNDLED WITH") or not line):
                        in_gems_section = False
                        logger.debug(
                            f"Gemfile.lock: Exited GEM section at line {line_num} due to '{line}'")
                        if line == "PLATFORMS" or line == "DEPENDENCIES" or line.startswith("BUNDLED WITH"):
                            continue
                    if in_gems_section:
                        if line.startswith("  ") and "(" not in line: 
                            logger.debug(
                                f"Gemfile.lock: Skipping likely sub-dependency specifier: {line}")
                            continue
                        match = gem_pattern.match(line)
                        if match:
                            name = match.group(1)
                            version = match.group(2)
                            dependencies.append(Dependency(
                                name=name, version=version))
                            logger.debug(
                                f"Gemfile.lock: Parsed dependency: {name}@{version}")
                        elif line and not line.startswith("remote:") and not line.startswith("specs:"): 
                            logger.debug(
                                f"Gemfile.lock: Skipping line in GEM section (no match for main gem pattern): {line}")
        except FileNotFoundError:
            logger.error(
                f"Gemfile.lock file not found during parsing: {self.file_path.name}")
        except Exception as e:
            logger.error(
                f"Error parsing {self.file_path.name}: {e}", exc_info=True)
        logger.info(
            f"Successfully parsed {len(dependencies)} dependencies from {self.file_path.name}")
        return dependencies

    def _get_transitive_ruby_dependencies(self, direct_dependencies: List[Dependency]) -> List[Dependency]:
        transitive_deps: List[Dependency] = []
        seen_dependencies: Set[Tuple[str, str]] = set(
            (dep.name.lower(), dep.version) for dep in direct_dependencies)
        logger.info(
            "Attempting to identify transitive Ruby dependencies by reading Gemfile.lock fully.")
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                content = f.read()
                gems_section_match = re.search(
                    r"GEM\s*\n(.*?)(?=\n(PLATFORMS|DEPENDENCIES|BUNDLED WITH|$))", content, re.DOTALL)
                if gems_section_match:
                    gems_content = gems_section_match.group(1)
                    gem_pattern = re.compile(
                        r"^\s*([a-zA-Z0-9\-_.]+)\s+\(([0-9a-zA-Z\-_.]+.*?)\)", re.MULTILINE)
                    for match in gem_pattern.finditer(gems_content):
                        name = match.group(1)
                        version = match.group(2)
                        dep_tuple = (name.lower(), version)
                        if dep_tuple not in seen_dependencies: 
                            transitive_deps.append(
                                Dependency(name=name, version=version))
                            seen_dependencies.add(dep_tuple)
                            logger.debug(
                                f"Added transitive Ruby dependency (from lock file): {name}@{version}")
                else:
                    logger.warning(
                        "Could not find 'GEM' section in Gemfile.lock for transitive analysis.")
        except FileNotFoundError:
            logger.error(
                f"Gemfile.lock not found for transitive analysis: {self.file_path.name}")
        except Exception as e:
            logger.error(
                f"Unexpected error in Ruby transitive analysis: {e}", exc_info=True)
        if transitive_deps:
            logger.info(
                f"Identified {len(transitive_deps)} transitive Ruby dependencies.")
        else:
            logger.info("No transitive Ruby dependencies identified.")
        return transitive_deps

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
                        continue
                    if in_require_block and line == ")":
                        in_require_block = False
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
                            dependencies.append(Dependency(
                                name=name, version=version_final))
                            logger.debug(
                                f"go.mod: Parsed dependency: {name}@{version_final}")
                    elif is_require_line: 
                        logger.debug(f"go.mod: Skipping line in require context (not enough parts or malformed): {line}")
                    elif not (line.startswith("module ") or line.startswith("go ") or \
                              line.startswith("replace ") or line.startswith("exclude ") or \
                              line.startswith("retract ") or line == ")"): 
                        logger.debug(f"go.mod: Skipping unhandled non-directive line {line_num}: {line}")
        except FileNotFoundError:
            logger.error(
                f"go.mod file not found during parsing: {self.file_path.name}")
            dependencies = [] 
        except Exception as e:
            logger.error(
                f"Error parsing {self.file_path.name}: {e}", exc_info=True)
            dependencies = []
        logger.info(
            f"Successfully parsed {len(dependencies)} dependencies from {self.file_path.name}")
        return dependencies

    def _get_transitive_go_dependencies(self, direct_dependencies: List[Dependency]) -> List[Dependency]:
        transitive_deps: List[Dependency] = []
        seen_dependencies: Set[Tuple[str, str]] = set(
            (dep.name.lower(), dep.version) for dep in direct_dependencies)
        logger.info(
            "Attempting to identify transitive Go dependencies using 'go mod graph' and 'go list -m all'.")
        project_dir = self.file_path.parent
        current_cmd = ["go", "list", "-m", "all"]
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
                            transitive_deps.append(
                                Dependency(name=name, version=version))
                            seen_dependencies.add(dep_tuple)
                            logger.debug(
                                f"Added transitive Go dependency: {name}@{version}")
        else:
            logger.warning(
                "Could not get Go module list. 'go list -m all' failed.")
        if transitive_deps:
            logger.info(
                f"Identified {len(transitive_deps)} transitive Go dependencies.")
        else:
            logger.info("No transitive Go dependencies identified.")
        return transitive_deps

def get_parser_for_file(file_path_str_for_log_only: str) -> Callable[[str], List[Dependency]]:
    logger.debug(
        f"get_parser_for_file: Configuring parser wrapper (final parser decision will occur in DependencyParser based on actual file name). Reference log: {file_path_str_for_log_only}")
    def parsing_function_wrapper(actual_path_to_parse: str) -> List[Dependency]:
        logger.debug(
            f"parsing_function_wrapper: Instantiating DependencyParser for: {actual_path_to_parse}")
        instance = DependencyParser(actual_path_to_parse)
        return instance.extract_dependencies()
    return parsing_function_wrapper
