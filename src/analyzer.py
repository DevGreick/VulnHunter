# src/analyzer.py
import re
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Set
from collections import defaultdict
from packaging.version import parse as parse_version, InvalidVersion, Version
from src.models import Dependency, Vulnerability
import sys

logger = logging.getLogger("analyzer")

_SAFE_VERSION_CACHE: Dict[str, Optional[Version]] = {}

def _parse_version_safely(version_str: Optional[str]) -> Optional[Version]:
    if not version_str:
        return None
    version_str = str(version_str).strip()
    if not version_str:
        return None
    if version_str in _SAFE_VERSION_CACHE:
        return _SAFE_VERSION_CACHE[version_str]
    parsed_version = None
    try:
        parsed_version = parse_version(version_str)
        _SAFE_VERSION_CACHE[version_str] = parsed_version
        return parsed_version
    except InvalidVersion:
        normalized_str = version_str
        normalized_str = re.sub(r"[:](rc|beta|b|alpha)\d*$", "", normalized_str, flags=re.IGNORECASE)
        normalized_str = normalized_str.rstrip('.')
        if normalized_str == version_str:
            logger.debug(f"Could not parse version '{version_str}' (no effective normalization applied).")
            _SAFE_VERSION_CACHE[version_str] = None
            return None
        else:
            try:
                logger.debug(f"Attempting to parse normalized version '{normalized_str}' (from '{version_str}')")
                parsed_version = parse_version(normalized_str)
                _SAFE_VERSION_CACHE[version_str] = parsed_version
                return parsed_version
            except InvalidVersion:
                logger.debug(f"Could not parse version '{version_str}' even after normalizing to '{normalized_str}'.")
                _SAFE_VERSION_CACHE[version_str] = None
                return None

class VulnerabilityAnalyzer:
    def __init__(self, nvd_data_path: str, cpe_index_path: Optional[str] = None, effective_log_level: int = logging.INFO):
        logger.setLevel(effective_log_level)
        logger.info(f"Initializing VulnerabilityAnalyzer with NVD data from: {nvd_data_path}")
        self.nvd_data = self._load_json_data(nvd_data_path)
        self.cpe_alias_index: Dict[str, Any] = {}
        self.effective_log_level = effective_log_level

        if cpe_index_path:
            cpe_index_file = Path(cpe_index_path)
            if cpe_index_file.exists() and cpe_index_file.is_file():
                logger.debug(f"Loading CPE alias index from: {cpe_index_path}")
                try:
                    self.cpe_alias_index = self._load_json_data(cpe_index_path)
                    if isinstance(self.cpe_alias_index, dict):
                         logger.debug(f"Successfully loaded CPE alias index with {len(self.cpe_alias_index)} entries.")
                    else:
                         logger.error(f"CPE alias index loaded from {cpe_index_path} is not a dictionary. Type: {type(self.cpe_alias_index)}. Disabling alias usage.")
                         self.cpe_alias_index = {}
                except Exception as e:
                    logger.error(f"Failed to load CPE alias index from {cpe_index_path}: {e}", exc_info=True)
                    self.cpe_alias_index = {}
            else:
                logger.warning(f"CPE alias index file not found or is not a file at {cpe_index_path}. Name matching might be less effective.")
        else:
            logger.warning("CPE alias index path not provided. Name matching might be less effective.")
        if not self.nvd_data or not isinstance(self.nvd_data, list):
            logger.error(f"NVD data from {nvd_data_path} failed to load or is not a list. Cannot perform analysis.")
            self.nvd_data = []

    def _load_json_data(self, path: str) -> Any:
        default_return = [] if "nvd_cve_rebuilt.json" in Path(path).name else {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data
        except FileNotFoundError:
            logger.error(f"Data file not found: {path}")
            return default_return
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON from {path}: {e}")
            return default_return
        except Exception as e:
            logger.error(f"An unexpected error occurred while loading {path}: {e}", exc_info=True)
            return default_return

    def _find_potential_nvd_names(self, dependency_name_lower: str) -> Set[str]:
        potential_names: Set[str] = {dependency_name_lower}
        if dependency_name_lower == 'spring-core':
            potential_names.add('spring-framework')
            potential_names.add('spring')
            potential_names.add('vmware:spring-framework')
            potential_names.add('pivotal_software:spring-framework')
            potential_names.add('vmware:spring-core')
            potential_names.add('pivotal:spring-core')
            potential_names.add('pivotal_software:spring-core')
        elif dependency_name_lower == 'laravel/framework':
            potential_names.add('framework')
            potential_names.add('laravel')
            potential_names.add('laravel:framework')
        elif dependency_name_lower == 'guzzlehttp/guzzle':
            potential_names.add('guzzle')
            potential_names.add('guzzlehttp:guzzle')
        elif dependency_name_lower == 'pg':
            potential_names.add('postgresql:postgresql')
            potential_names.add('postgresql')

        if not self.cpe_alias_index or not isinstance(self.cpe_alias_index, dict):
            logger.debug(f"No CPE Index or invalid format. Using basic names + heuristics for '{dependency_name_lower}'. Potential names: {potential_names}")
            return potential_names

        logger.debug(f"Finding potential NVD names for '{dependency_name_lower}'. Initial heuristic/hardcoded set: {potential_names}")
        if dependency_name_lower in self.cpe_alias_index:
            aliases = self.cpe_alias_index[dependency_name_lower]
            if isinstance(aliases, list):
                new_aliases = {alias.lower() for alias in aliases if isinstance(alias, str)}
                if new_aliases.difference(potential_names):
                     logger.debug(f"Added {len(new_aliases.difference(potential_names))} aliases because '{dependency_name_lower}' is a key. New set size: {len(potential_names.union(new_aliases))}")
                     potential_names.update(new_aliases)
            else:
                 logger.warning(f"Value for key '{dependency_name_lower}' in CPE index is not a list: {type(aliases)}")
        keys_found_in = []
        keys_to_add = set()
        aliases_to_add = set()
        for product_key, aliases_list in self.cpe_alias_index.items():
            if isinstance(aliases_list, list):
                lowercase_aliases = {alias.lower() for alias in aliases_list if isinstance(alias, str)}
                if dependency_name_lower in lowercase_aliases:
                    product_key_lower = product_key.lower()
                    keys_found_in.append(product_key_lower)
                    keys_to_add.add(product_key_lower)
                    aliases_to_add.update(lowercase_aliases)
        if keys_found_in:
            logger.debug(f"'{dependency_name_lower}' was found as an alias under primary keys: {keys_found_in}")
            if keys_to_add.difference(potential_names) or aliases_to_add.difference(potential_names):
                logger.debug(f"Adding {len(keys_to_add.difference(potential_names))} keys and {len(aliases_to_add.difference(potential_names))} aliases found via reverse lookup.")
                potential_names.update(keys_to_add)
                potential_names.update(aliases_to_add)
                logger.debug(f"Current potential name set size after reverse lookup: {len(potential_names)}")
        logger.debug(f"Final potential names for '{dependency_name_lower}': {potential_names}")
        return potential_names

    def analyze_by_cpe(self, dependencies: List[Dependency]) -> List[Vulnerability]:
        results: List[Vulnerability] = []
        if not self.nvd_data:
            logger.error("NVD data is not loaded, cannot perform analysis.")
            return results

        total_dependencies = len(dependencies)
        logger.debug(f"Starting analysis for {total_dependencies} dependencies.")

        processed_deps_count = 0
        vulnerabilities_found_count = 0

        show_progress = self.effective_log_level > logging.DEBUG

        for dep_idx, dep in enumerate(dependencies):
            processed_deps_count += 1
            dep_name_original = dep.name
            dep_name_lower = dep.name.lower()
            dep_version_str = dep.version

            if show_progress and total_dependencies > 0 :
                progress_percent = (dep_idx + 1) / total_dependencies
                bar_length = 30
                filled_length = int(bar_length * progress_percent)
                bar = '█' * filled_length + '-' * (bar_length - filled_length)
                status_line = f"Analyzing: [{bar}] {dep_idx + 1}/{total_dependencies} ({progress_percent:.0%}) - {dep_name_original[:20]:<20}..."
                sys.stdout.write(f"\r{status_line:<79}")
                sys.stdout.flush()

            logger.debug(f"--- Processing dependency {processed_deps_count}/{total_dependencies}: {dep_name_original}@{dep_version_str} ---")

            dep_version_obj: Optional[Version] = None
            if dep_version_str != '*' and dep_version_str:
                 clean_version_str = re.sub(r"^[v=\s]*", "", dep_version_str)
                 dep_version_obj = _parse_version_safely(clean_version_str)
                 if dep_version_obj is None:
                     logger.warning(f"Dependency version '{dep_version_str}' for {dep_name_original} is unparseable. Specific version ranges may not apply accurately.")
            else:
                 logger.debug(f"Version for {dep_name_original} is wildcard or empty.")

            names_to_check_in_nvd = self._find_potential_nvd_names(dep_name_lower)
            match_found_for_dep = False
            dep_vulns: List[Vulnerability] = []

            for nvd_item in self.nvd_data:
                if not isinstance(nvd_item, dict): continue
                nvd_product_name = nvd_item.get("name", "").lower()
                cve_id = nvd_item.get("cve_id")
                if not nvd_product_name or not cve_id: continue

                if logger.isEnabledFor(logging.DEBUG):
                    debug_match_list = ["spring-core", "laravel/framework", "requests", "certifi", "werkzeug", "flask"]
                    if dep_name_lower in debug_match_list or nvd_product_name in debug_match_list:
                        logger.debug(f"Comparing '{dep_name_lower}' (potentials: {names_to_check_in_nvd}) with NVD name: '{nvd_product_name}' (CVE: {cve_id})")

                if nvd_product_name not in names_to_check_in_nvd:
                    continue

                match_found_for_dep = True
                logger.debug(f"NAME MATCHED: '{dep_name_lower}' (matched via '{nvd_product_name}') for CVE {cve_id}. Checking version...")
                summary = nvd_item.get("summary", "")
                severity = nvd_item.get("severity", "UNKNOWN")
                vulnerable_version_ranges = nvd_item.get("vulnerable_versions", [])
                is_vulnerable = False

                if not vulnerable_version_ranges:
                    logger.debug(f"No version ranges in NVD for {nvd_product_name}/{cve_id}. Assuming vulnerable because name matched.")
                    is_vulnerable = True
                elif dep_version_obj is None:
                    logger.debug(f"Dependency version '{dep_version_str}' unparseable/wildcard for {dep_name_original}. NVD has ranges for {cve_id}. Assuming vulnerable.")
                    is_vulnerable = True
                else:
                    for v_range_dict in vulnerable_version_ranges:
                        if not isinstance(v_range_dict, dict):
                            logger.warning(f"Skipping malformed range item for {cve_id}: {v_range_dict}")
                            continue
                        exact_version_str = v_range_dict.get("exactVersion")
                        if exact_version_str:
                            exact_ver_obj = _parse_version_safely(exact_version_str)
                            if exact_ver_obj is None:
                                logger.debug(f"Skipping exact version check for {cve_id}: NVD version '{exact_version_str}' is unparseable.")
                                continue
                            if dep_version_obj == exact_ver_obj:
                                logger.debug(f"VERSION MATCHED (EXACT): {dep_name_original}@{dep_version_str} == {exact_version_str} for {cve_id}")
                                is_vulnerable = True
                                break
                            else:
                                continue
                        version_in_current_range = True
                        range_parts_desc = []
                        vsi_str = v_range_dict.get("versionStartIncluding")
                        vse_str = v_range_dict.get("versionStartExcluding")
                        vei_str = v_range_dict.get("versionEndIncluding")
                        vee_str = v_range_dict.get("versionEndExcluding")

                        if vsi_str:
                            vsi_obj = _parse_version_safely(vsi_str)
                            if vsi_obj:
                                if not (dep_version_obj >= vsi_obj): version_in_current_range = False
                                else: range_parts_desc.append(f">={vsi_str}")
                                logger.debug(f"Range check VSI for {cve_id}: dep_ver={dep_version_obj}, vsi_obj={vsi_obj}, in_range={version_in_current_range}")
                            else:
                                logger.debug(f"Cannot evaluate range for {cve_id}: start bound '{vsi_str}' unparseable. This range item is skipped.")
                                version_in_current_range = False
                        if version_in_current_range and vse_str:
                            vse_obj = _parse_version_safely(vse_str)
                            if vse_obj:
                                if not (dep_version_obj > vse_obj): version_in_current_range = False
                                else: range_parts_desc.append(f">{vse_str}")
                                logger.debug(f"Range check VSE for {cve_id}: dep_ver={dep_version_obj}, vse_obj={vse_obj}, in_range={version_in_current_range}")
                            else:
                                logger.debug(f"Cannot evaluate range for {cve_id}: start-ex bound '{vse_str}' unparseable. This range item is skipped.")
                                version_in_current_range = False
                        if version_in_current_range and vei_str:
                             vei_obj = _parse_version_safely(vei_str)
                             if vei_obj:
                                 if not (dep_version_obj <= vei_obj): version_in_current_range = False
                                 else: range_parts_desc.append(f"<={vei_str}")
                                 logger.debug(f"Range check VEI for {cve_id}: dep_ver={dep_version_obj}, vei_obj={vei_obj}, in_range={version_in_current_range}")
                             else:
                                  logger.debug(f"Cannot evaluate range for {cve_id}: end bound '{vei_str}' unparseable. This range item is skipped.")
                                  version_in_current_range = False
                        if version_in_current_range and vee_str:
                             vee_obj = _parse_version_safely(vee_str)
                             if vee_obj:
                                  if not (dep_version_obj < vee_obj): version_in_current_range = False
                                  else: range_parts_desc.append(f"<{vee_str}")
                                  logger.debug(f"Range check VEE for {cve_id}: dep_ver={dep_version_obj}, vee_obj={vee_obj}, in_range={version_in_current_range}")
                             else:
                                   logger.debug(f"Cannot evaluate range for {cve_id}: end-ex bound '{vee_str}' unparseable. This range item is skipped.")
                                   version_in_current_range = False

                        if version_in_current_range and range_parts_desc:
                            range_desc_str = ', '.join(range_parts_desc)
                            logger.debug(f"VERSION MATCHED (RANGE): {dep_name_original}@{dep_version_str} satisfies ({range_desc_str}) for {cve_id}")
                            is_vulnerable = True
                            break
                        elif version_in_current_range and not (vsi_str or vse_str or vei_str or vee_str):
                            logger.debug(f"Name matched {dep_name_original} for {cve_id}, and no specific version bounds were defined in NVD range entry {v_range_dict}. Assuming vulnerable.")
                            is_vulnerable = True
                            break
                if is_vulnerable:
                    found_vuln = Vulnerability(
                        name=dep_name_original,
                        version=dep_version_str,
                        cve_id=cve_id,
                        severity=severity.upper(),
                        summary=summary.strip()
                    )
                    if found_vuln not in dep_vulns:
                        dep_vulns.append(found_vuln)
                        logger.debug(f"VULNERABILITY ADDED: {dep_name_original}@{dep_version_str} - {cve_id} ({severity})")


            if not match_found_for_dep:
                 debug_names = ["spring-core", "laravel-framework", "guzzlehttp-guzzle", "flask", "django", "requests", "express", "lodash", "rails", "pg", "certifi", "werkzeug"]
                 if dep_name_lower in debug_names:
                    logger.debug(f"No matching NVD product name found for dependency: {dep_name_original}")
            elif dep_vulns:
                 logger.debug(f"Found {len(dep_vulns)} vulnerabilities for {dep_name_original}@{dep_version_str}")
                 results.extend(dep_vulns)
                 vulnerabilities_found_count += len(dep_vulns)
            elif match_found_for_dep and not dep_vulns:
                 logger.debug(f"Name matched for {dep_name_original}@{dep_version_str}, but no applicable vulnerable version range found.")

        if show_progress and total_dependencies > 0 :
             sys.stdout.write("\r" + " " * 79 + "\r")
             sys.stdout.flush()

        logger.info(f"Analysis finished. Found {vulnerabilities_found_count} raw vulnerability entries.")
        return results
