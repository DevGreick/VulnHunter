# src/report_generator.py
import json
import logging
from pathlib import Path
from typing import List
from collections import defaultdict


from .models import Vulnerability



def generate_json_report(vulnerabilities: List[Vulnerability], output_path: Path):
    """Generates a JSON report of found vulnerabilities (Needs attribute alignment)."""
    report_data = defaultdict(list)
    logger = logging.getLogger("report_generator") 

    

    for vuln in vulnerabilities:
        
        package_identifier = vuln.name 
        package_version_val = vuln.version 
        affected_versions_val = getattr(vuln, 'affected_versions', "N/A") 
        description_val = vuln.summary.strip() 

        report_data[package_identifier].append({
            "cve_id": vuln.cve_id,
            "severity": vuln.severity,
            "version_analyzed": package_version_val,
            "affected_ranges_matched": affected_versions_val,
            "description": description_val
        })
        

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True) 
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4, ensure_ascii=False)
        print(f"Report successfully generated at: {output_path}") 
    except IOError as e:
        print(f"Error writing report to {output_path}: {e}") 
    except Exception as e:
        print(f"An unexpected error occurred during report generation: {e}") 


def print_summary_report(vulnerabilities: List[Vulnerability]):
    """Prints a summary of vulnerabilities to the console (Needs attribute alignment)."""
    logger = logging.getLogger("report_generator") 
    if not vulnerabilities:
        print("\n--- Vulnerability Summary ---")
        print("No vulnerabilities found.")
        print("---------------------------\n")
        return

    print("\n--- Vulnerability Summary ---")
    # Group by severity
    by_severity = defaultdict(list)
    for v in vulnerabilities:
        sev = v.severity.upper() if v.severity else "UNKNOWN"
        by_severity[sev].append(v)

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"] 
    total_vulns = len(vulnerabilities) 
    print(f"Total potential vulnerabilities found (in input list): {total_vulns}\n")

    for sev in severity_order:
        if sev in by_severity:
            count = len(by_severity[sev])
            print(f"[{sev}]: {count} vulnerabilities")
            
    print("\nPackages with vulnerabilities:")
    by_package = defaultdict(list)
    
    for v in vulnerabilities:
         
         pkg_name = getattr(v, 'package_name', v.name)
         pkg_ver = getattr(v, 'package_version', v.version)
         by_package[f"{pkg_name}@{pkg_ver}"].append(v.cve_id)
         


    for pkg_ver_key, cves in sorted(by_package.items()):
        print(f"- {pkg_ver_key}: Found {len(cves)} CVEs ({', '.join(sorted(cves))})")

    print("---------------------------\n")
    
    print(f"NOTE: See report file for potentially more detailed information.")


if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.WARNING)
    logger = logging.getLogger("report_generator")
    logger.warning("This module is not designed to be run directly.")
