# src/nvd_parser.py
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from packaging import version as packaging_version

from .exceptions import NvdDataError
from .models import Dependency


_VERSION_CACHE: Dict[str, packaging_version.Version] = {}

def _parse_version(v_str: Optional[str]) -> Optional[packaging_version.Version]:
    """Parse version string safely, caching results."""
    if not v_str:
        return None
    if v_str in _VERSION_CACHE:
        return _VERSION_CACHE[v_str]
    try:
        parsed = packaging_version.parse(v_str)
        _VERSION_CACHE[v_str] = parsed
        return parsed
    except packaging_version.InvalidVersion:
        
        return None

def load_nvd_data(nvd_file_path: Path) -> List[Dict[str, Any]]:
    """Loads NVD JSON data."""
    try:
        with open(nvd_file_path, "r", encoding="utf-8") as f:
            nvd_data = json.load(f)
            if "CVE_Items" not in nvd_data:
                raise NvdDataError("Invalid NVD data format: 'CVE_Items' key missing.")
            return nvd_data["CVE_Items"]
    except FileNotFoundError:
        raise NvdDataError(f"NVD data file not found: {nvd_file_path}")
    except json.JSONDecodeError:
        raise NvdDataError(f"Invalid JSON format in NVD data file: {nvd_file_path}")
    except Exception as e:
        raise NvdDataError(f"Error loading NVD data from {nvd_file_path}: {e}")

def extract_cve_details(cve_item: Dict[str, Any]) -> Tuple[str, str, Optional[str]]:
    """Extracts essential details from a CVE item."""
    try:
        cve_id = cve_item["cve"]["CVE_data_meta"]["ID"]
        description = "No description available."
        if cve_item["cve"]["description"]["description_data"]:
            description = cve_item["cve"]["description"]["description_data"][0]["value"]

        severity = None
        
        if "impact" in cve_item and "baseMetricV3" in cve_item["impact"]:
            severity = cve_item["impact"]["baseMetricV3"]["cvssV3"].get("baseSeverity")
       
        elif "impact" in cve_item and "baseMetricV2" in cve_item["impact"]:
            severity = cve_item["impact"]["baseMetricV2"].get("severity")

        return cve_id, description, severity
    except KeyError as e:
        cve_id_fallback = cve_item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "UNKNOWN_ID")
        print(f"Warning: Could not fully parse details for {cve_id_fallback} due to missing key: {e}")
        return cve_id_fallback, "Error parsing description.", "UNKNOWN"


def is_dependency_vulnerable(dependency: Dependency, cve_item: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Checks if a specific dependency is vulnerable based on CPE matching within a CVE item.
    Returns (is_vulnerable, list_of_affected_version_ranges).
    NOTE: This is a simplified CPE matching logic. Real-world matching is more complex.
    """
    if not dependency.version:
        
        return False, []

    dep_version_parsed = _parse_version(dependency.version)
    if not dep_version_parsed:
<<<<<<< HEAD
         # If dependency version cannot be parsed, cannot compare
=======
         
>>>>>>> f974b67915d2818a8a5fe4d31bd2baaee323238e
        print(f"Warning: Could not parse dependency version: {dependency.name}@{dependency.version}")
        return False, []

    affected_ranges_found: List[str] = []
    is_match = False

    try:
        if "configurations" not in cve_item or "nodes" not in cve_item["configurations"]:
            return False, []

        for node in cve_item["configurations"]["nodes"]:
            
            if "children" in node: 
                 pass 

            if "cpe_match" in node:
                for cpe_match in node["cpe_match"]:
                    if not cpe_match.get("vulnerable", False):
                        continue 

                    cpe_uri = cpe_match.get("cpe23Uri")
                    if not cpe_uri:
                        continue

                  
                    cpe_parts = cpe_uri.split(':')
                    if len(cpe_parts) < 5: continue 

                    
                    
                    product = cpe_parts[4].lower() 

                  
<<<<<<< HEAD
                    if product == dependency.name.lower() or dependency.name.lower() in product: # Tentativa heurística
=======
                    if product == dependency.name.lower() or dependency.name.lower() in product: 
>>>>>>> f974b67915d2818a8a5fe4d31bd2baaee323238e

                     
                        version_start_inc = cpe_match.get("versionStartIncluding")
                        version_end_inc = cpe_match.get("versionEndIncluding")
                        version_start_exc = cpe_match.get("versionStartExcluding")
                        version_end_exc = cpe_match.get("versionEndExcluding")

                        range_str = f"Affects {product}"
                        version_matched = False

                       
                        if len(cpe_parts) > 5 and cpe_parts[5] != '*' and cpe_parts[5] != '-':
                           cpe_version_str = cpe_parts[5]
                           cpe_version_parsed = _parse_version(cpe_version_str)
                           if cpe_version_parsed and dep_version_parsed == cpe_version_parsed:
                               version_matched = True
                               range_str += f" (exact version {cpe_version_str})"

                    
                        else:
                            lower_bound_check = True
                            upper_bound_check = True
                            range_parts = []

                            if version_start_inc:
                                range_parts.append(f">= {version_start_inc}")
                                v_start_inc = _parse_version(version_start_inc)
                                if v_start_inc and not (dep_version_parsed >= v_start_inc):
                                    lower_bound_check = False
                            if version_start_exc:
                                range_parts.append(f"> {version_start_exc}")
                                v_start_exc = _parse_version(version_start_exc)
                                if v_start_exc and not (dep_version_parsed > v_start_exc):
                                     lower_bound_check = False

                            if version_end_inc:
                                range_parts.append(f"<= {version_end_inc}")
                                v_end_inc = _parse_version(version_end_inc)
                                if v_end_inc and not (dep_version_parsed <= v_end_inc):
                                    upper_bound_check = False
                            if version_end_exc:
                                range_parts.append(f"< {version_end_exc}")
                                v_end_exc = _parse_version(version_end_exc)
                                if v_end_exc and not (dep_version_parsed < v_end_exc):
                                    upper_bound_check = False

                           
                            if not range_parts: 
                               
                                
                                pass 
                            elif lower_bound_check and upper_bound_check:
                                version_matched = True
                                range_str += f" (version range: {', '.join(range_parts)})"

                        if version_matched:
                            is_match = True
                            affected_ranges_found.append(range_str)
                        

    except KeyError as e:
        print(f"Warning: Error processing CPE configurations for dependency {dependency.name}: Missing key {e}")
    except Exception as e:
         print(f"Warning: Unexpected error during CPE matching for {dependency.name}: {e}")


   
<<<<<<< HEAD
    return is_match, affected_ranges_found
=======
    return is_match, affected_ranges_found
>>>>>>> f974b67915d2818a8a5fe4d31bd2baaee323238e
