# src/parsers.py
import re
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Callable, Dict

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
            logger.error(f"Arquivo de dependência não encontrado: {self.file_path}")
            raise FileNotFoundError(f"Arquivo de dependência não encontrado: {self.file_path}")

    def extract_dependencies(self) -> List[Dependency]:
        filename_original = self.file_path.name
        filename_lower = filename_original.lower()

        logger.debug(f"Tentando analisar o arquivo: {filename_original} (despachando baseado em: {filename_lower})")

        parser_method = None

        if "requirements" in filename_lower and filename_lower.endswith(".txt"):
            parser_method = self._parse_requirements_txt
        elif "package" in filename_lower and filename_lower.endswith(".json") and not "lock" in filename_lower:
            parser_method = self._parse_package_json
        elif "pom" in filename_lower and filename_lower.endswith(".xml"):
            parser_method = self._parse_pom_xml
        elif "composer" in filename_lower and filename_lower.endswith(".json"):
            parser_method = self._parse_composer_json
        elif "gemfile" in filename_lower and filename_lower.endswith(".lock"):
            parser_method = self._parse_gemfile_lock
        elif "go" in filename_lower and filename_lower.endswith(".mod"): 
            parser_method = self._parse_go_mod

        if parser_method:
            try:
                dependencies = parser_method()
                return dependencies
            except Exception as e:
                logger.error(f"Erro ao analisar {filename_original} usando {parser_method.__name__}: {e}", exc_info=True)
                return []
        else:
            logger.warning(f"Nenhum parser definido em DependencyParser.extract_dependencies para o arquivo: {filename_original}")
            return []

    def _parse_requirements_txt(self) -> List[Dependency]:
        dependencies = []
        logger.debug(f"requirements.txt: Iniciando análise para {self.file_path.name}")
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    match = re.match(r"^\s*([a-zA-Z0-9\-_.]+)\s*(?:([<>=!~]{1,2})\s*([0-9a-zA-Z\-_.*+!]+))?", line)
                    if match:
                        name = match.group(1)
                        version_specifier = match.group(2)
                        version = match.group(3)

                        if version_specifier == "==" and version:
                            dependencies.append(Dependency(name=name, version=version))
                            logger.debug(f"requirements.txt: Parsed dependency: {name}@{version}")
                        elif version:
                            logger.info(f"requirements.txt: Dependency '{name}' has version specifier '{version_specifier}{version}', using version part '{version}' for analysis. Consider exact versions ('==') for more precise matching.")
                            dependencies.append(Dependency(name=name, version=version))
                        else:
                            logger.warning(f"requirements.txt: Skipping dependency '{name}' due to missing version or complex/unsupported specifier in line {line_num}: '{line}'")
                    else:
                        logger.warning(f"requirements.txt: Skipping unparsable line {line_num}: '{line}'")
        except FileNotFoundError:
            logger.error(f"requirements.txt file not found during parsing: {self.file_path.name}")
        except Exception as e:
            logger.error(f"Error parsing {self.file_path.name}: {e}", exc_info=True)

        logger.info(f"Successfully parsed {len(dependencies)} dependencies from {self.file_path.name}")
        return dependencies

    def _parse_package_json(self) -> List[Dependency]:
        dependencies = []
        logger.debug(f"package.json: Iniciando análise para {self.file_path.name}")
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

                dep_sections = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]
                for section in dep_sections:
                    if section in data and isinstance(data[section], dict):
                        for name, version_ish in data[section].items():
                            version = re.sub(r"^[<>=~^]*(?=[0-9])", "", str(version_ish)).strip()
                            if not version:
                                logger.warning(f"package.json: Skipping {name} from {section} due to empty version after stripping prefixes: '{version_ish}'")
                                continue
                            dependencies.append(Dependency(name=name, version=version))
                            logger.debug(f"package.json: Parsed dependency from {section}: {name}@{version}")
        except FileNotFoundError:
            logger.error(f"package.json file not found during parsing: {self.file_path.name}")
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON from {self.file_path.name}: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"Error parsing {self.file_path.name}: {e}", exc_info=True)

        logger.info(f"Successfully parsed {len(dependencies)} dependencies from {self.file_path.name}")
        return dependencies

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
                logger.info(f"pom.xml: No dependency nodes found in {self.file_path.name} "
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
                        logger.warning(f"pom.xml: Skipping incomplete dependency: groupId={g}, artifactId={a}, version(raw)={v_raw} in {self.file_path.name}")

        except ET.ParseError as e:
            logger.error(f"Error parsing XML in {self.file_path.name}: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"Unexpected error parsing {self.file_path.name} ({type(e).__name__}): {e}", exc_info=True)

        logger.info(f"Successfully parsed {len(dependencies)} dependencies from {self.file_path.name}")
        return dependencies

    def _parse_composer_json(self) -> List[Dependency]:
        dependencies = []
        logger.debug(f"composer.json: Iniciando análise para {self.file_path.name}")
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

                dep_sections = ["require", "require-dev"]
                for section in dep_sections:
                    if section in data and isinstance(data[section], dict):
                        for name, version_ish in data[section].items():
                            if name.lower() == "php" or "ext-" in name.lower():
                                logger.debug(f"composer.json: Skipping PHP/extension requirement: {name}@{version_ish}")
                                continue
                            version = str(version_ish).strip()
                            version = re.sub(r"^[<>=~^|@dev\s]*v?(?=[0-9])", "", version)
                            version = version.split(" ")[0]
                            version = version.split(",")[0]
                            version = version.replace("-dev", "").replace("-stable", "")
                            if version.endswith(".*"):
                                version = version[:-2]

                            if not version or not re.match(r"^[0-9]", version):
                                logger.warning(f"composer.json: Skipping {name} from {section} due to complex/unresolvable version: '{version_ish}' -> '{version}'")
                                continue
                            dependencies.append(Dependency(name=name, version=version))
                            logger.debug(f"composer.json: Parsed dependency from {section}: {name}@{version}")
        except FileNotFoundError:
            logger.error(f"composer.json file not found during parsing: {self.file_path.name}")
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON from {self.file_path.name}: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"Error parsing {self.file_path.name}: {e}", exc_info=True)

        logger.info(f"Successfully parsed {len(dependencies)} dependencies from {self.file_path.name}")
        return dependencies

    def _parse_gemfile_lock(self) -> List[Dependency]:
        dependencies = []
        logger.debug(f"Gemfile.lock: Iniciando análise para {self.file_path.name}")
        in_gems_section = False
        gem_pattern = re.compile(r"^\s*([a-zA-Z0-9\-_.]+)\s+\(([0-9a-zA-Z\-_.]+.*?)\)")

        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                for line_num, line_content in enumerate(f, 1):
                    line = line_content.strip()

                    if line == "GEM":
                        in_gems_section = True
                        logger.debug(f"Gemfile.lock: Entered GEM section at line {line_num}")
                        continue

                    if in_gems_section and (line == "PLATFORMS" or line == "DEPENDENCIES" or line.startswith("BUNDLED WITH") or not line):
                        in_gems_section = False
                        logger.debug(f"Gemfile.lock: Exited GEM section at line {line_num} due to '{line}'")
                        if line == "PLATFORMS" or line == "DEPENDENCIES" or line.startswith("BUNDLED WITH"):
                            continue

                    if in_gems_section:
                        if line.startswith("  ") and "(" not in line:
                            logger.debug(f"Gemfile.lock: Skipping likely sub-dependency specifier: {line}")
                            continue

                        match = gem_pattern.match(line)
                        if match:
                            name = match.group(1)
                            version = match.group(2)
                            dependencies.append(Dependency(name=name, version=version))
                            logger.debug(f"Gemfile.lock: Parsed dependency: {name}@{version}")
                        elif line and not line.startswith("remote:") and not line.startswith("specs:"):
                            logger.debug(f"Gemfile.lock: Skipping line in GEM section (no match for main gem pattern): {line}")
        except FileNotFoundError:
            logger.error(f"Gemfile.lock file not found during parsing: {self.file_path.name}")
        except Exception as e:
            logger.error(f"Error parsing {self.file_path.name}: {e}", exc_info=True)

        logger.info(f"Successfully parsed {len(dependencies)} dependencies from {self.file_path.name}")
        return dependencies

    def _parse_go_mod(self) -> List[Dependency]:
        dependencies = []
        logger.debug(f"go.mod: Iniciando análise para {self.file_path.name}.") 
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

        logger.info(f"Successfully parsed {len(dependencies)} dependencies from {self.file_path.name}")
       
        return dependencies

def get_parser_for_file(file_path_str_for_log_only: str) -> Callable[[str], List[Dependency]]:
    logger.debug(f"get_parser_for_file: Configurando wrapper de parser (decisão final do parser ocorrerá em DependencyParser com base no nome do arquivo real). Log de referência: {file_path_str_for_log_only}")

    def parsing_function_wrapper(actual_path_to_parse: str) -> List[Dependency]:
        logger.debug(f"parsing_function_wrapper: Instanciando DependencyParser para: {actual_path_to_parse}")
        instance = DependencyParser(actual_path_to_parse)
        return instance.extract_dependencies()

    return parsing_function_wrapper
