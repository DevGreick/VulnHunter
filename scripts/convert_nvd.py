# scripts/convert_nvd.py
import json
from pathlib import Path
import logging
from typing import List, Dict, Any, Tuple, Optional

logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s:%(lineno)d:%(message)s')
logger = logging.getLogger("convert_nvd")

def extract_vendor_product_name(cpe_uri: str) -> Optional[str]:
    try:
        parts = cpe_uri.split(":")
        if len(parts) >= 5:
            vendor = parts[3].lower().replace('_', '-')
            product = parts[4].lower().replace('_', '-')

            if not vendor or vendor == '*':
                 logger.debug(f"Skipping CPE with missing or placeholder vendor: {cpe_uri}")
                 return None
            if not product or product == '*':
                  logger.debug(f"Skipping CPE with missing or placeholder product: {cpe_uri}")
                  return None

            return f"{vendor}:{product}"
    except Exception as e:
        logger.error(f"Error splitting CPE URI '{cpe_uri}': {e}")

    logger.debug(f"Could not extract vendor:product name from CPE URI: {cpe_uri}")
    return None

def convert_nvd_to_minimal(input_file: str, output_file: str) -> None:
    logger.info(f"Starting conversion of {input_file} to minimal format {output_file} using vendor:product names")

    try:
        with open(input_file, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
        if "CVE_Items" not in raw_data or not isinstance(raw_data["CVE_Items"], list):
             logger.error(f"Invalid format in {input_file}: 'CVE_Items' key missing or not a list.")
             return
        cve_items = raw_data["CVE_Items"]
    except FileNotFoundError:
        logger.error(f"Input NVD file not found: {input_file}")
        return
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON from {input_file}: {e}")
        return
    except Exception as e:
        logger.error(f"Failed to load or pre-validate {input_file}: {e}", exc_info=True)
        return

    vulns_dict: Dict[Tuple[str, str], Dict[str, Any]] = {}
    processed_cve_items = 0

    for cve_item in cve_items:
        processed_cve_items += 1
        cve_id = None
        try:
            cve_meta = cve_item.get("cve", {}).get("CVE_data_meta", {})
            cve_id = cve_meta.get("ID")
            if not cve_id:
                logger.warning("Skipping CVE item with missing ID.")
                continue

            severity = "UNKNOWN"
            impact = cve_item.get("impact", {})
            if "baseMetricV3" in impact and "cvssV3" in impact["baseMetricV3"]:
                severity = impact["baseMetricV3"]["cvssV3"].get("baseSeverity", severity)
            elif "baseMetricV2" in impact and "severity" in impact["baseMetricV2"]:
                severity = impact["baseMetricV2"].get("severity", severity)

            description_data = cve_item.get("cve", {}).get("description", {}).get("description_data", [])
            summary = ""
            if description_data and isinstance(description_data, list) and description_data[0].get("lang") == "en":
                summary = description_data[0].get("value", "No description provided.")
            else:
                summary = "No English description provided."

            configurations = cve_item.get("configurations", {})
            nodes = configurations.get("nodes", [])
            if not isinstance(nodes, list): nodes = []

            cve_has_relevant_range = False

            for node in nodes:
                if not isinstance(node, dict): continue

                cpe_matches = node.get("cpe_match", [])
                if not isinstance(cpe_matches, list): cpe_matches = []

                for cpe_entry in cpe_matches:
                    if not isinstance(cpe_entry, dict): continue
                    if not cpe_entry.get("vulnerable", True): continue

                    cpe_uri = cpe_entry.get("cpe23Uri")
                    if not cpe_uri: continue

                    vendor_product_name = extract_vendor_product_name(cpe_uri)
                    if not vendor_product_name: continue

                    vsi = cpe_entry.get("versionStartIncluding")
                    vse = cpe_entry.get("versionStartExcluding")
                    vei = cpe_entry.get("versionEndIncluding")
                    vee = cpe_entry.get("versionEndExcluding")

                    range_data = {}
                    if vsi: range_data["versionStartIncluding"] = vsi
                    if vse: range_data["versionStartExcluding"] = vse
                    if vei: range_data["versionEndIncluding"] = vei
                    if vee: range_data["versionEndExcluding"] = vee

                    if not range_data:
                        cpe_parts = cpe_uri.split(':')
                        exact_ver = None
                        if len(cpe_parts) > 5 and cpe_parts[5] not in ('*', '-'):
                             exact_ver = cpe_parts[5]
                             if len(cpe_parts) > 6 and cpe_parts[6] not in ('*', '-'):
                                exact_ver += f":{cpe_parts[6]}"
                        if exact_ver:
                            range_data["exactVersion"] = exact_ver
                            logger.debug(f"Using exact version '{exact_ver}' from CPE URI {cpe_uri}")

                    if not range_data: continue

                    cve_has_relevant_range = True

                    combo_key = (vendor_product_name, cve_id)

                    if combo_key not in vulns_dict:
                        vulns_dict[combo_key] = {
                            "name": vendor_product_name, 
                            "cve_id": cve_id,
                            "severity": severity.upper(),
                            "summary": summary.strip(),
                            "vulnerable_versions": [range_data]
                        }
                        logger.debug(f"Added new entry for {combo_key} with range: {range_data}")
                    else:
                        if range_data not in vulns_dict[combo_key]["vulnerable_versions"]:
                             vulns_dict[combo_key]["vulnerable_versions"].append(range_data)
                             logger.debug(f"Appended range {range_data} to existing entry for {combo_key}")

            if nodes and not cve_has_relevant_range:
                logger.debug(f"No applicable version ranges/CPEs found for {cve_id} despite configuration nodes present.")

        except KeyError as e:
             cve_ref = cve_id if cve_id else "UNKNOWN"
             logger.warning(f"Skipping CVE item '{cve_ref}' due to missing key: {e}.")
        except Exception as e:
            cve_ref = cve_id if cve_id else "UNKNOWN"
            logger.error(f"Unexpected error processing CVE item '{cve_ref}': {e}", exc_info=True)

    logger.info(f"Finished processing {processed_cve_items} CVE items from NVD.")

    minimal_vulns = list(vulns_dict.values())
    logger.info(f"Consolidated into {len(minimal_vulns)} unique vulnerability entries (vendor:product/CVE pairs).")

    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(output_path, "w", encoding="utf-8") as out_f:
            json.dump(minimal_vulns, out_f, indent=2, ensure_ascii=False)
        logger.info(f"Successfully generated detailed NVD file: {output_path}")
    except Exception as e:
        logger.error(f"Failed to write output file {output_path}: {e}", exc_info=True)
