# scan.py
import argparse
import logging
import json
import re 
from pathlib import Path
from typing import List, Any, Dict, Tuple, Set 
from collections import defaultdict

try:
    from scripts.update_nvd import main as update_nvd_main
except ModuleNotFoundError:
    update_nvd_main = None
    logging.debug("Module 'scripts.update_nvd' not found or not a package. NVD update via --update-nvd might be unavailable.")
except ImportError:
    update_nvd_main = None
    logging.debug("Could not import 'main' from 'scripts.update_nvd'. NVD update via --update-nvd might be unavailable.")

from src.parsers import get_parser_for_file
from src.analyzer import VulnerabilityAnalyzer
from src.models import Dependency, Vulnerability
from src.report_generator import generate_json_report

logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s:%(lineno)d:%(message)s')
logger = logging.getLogger("scan")

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

def detect_language(file_path: Path) -> str:
    name_lower = file_path.name.lower()
    if name_lower == "requirements.txt":
        return "python"
    elif name_lower == "package.json":
        return "javascript"
    elif name_lower == "composer.json":
        return "php"
    elif name_lower == "gemfile.lock":
        return "ruby"
    elif name_lower == "pom.xml":
        return "java"
    elif name_lower == "go.mod":
        return "go"
    logger.debug(f"Detecting language for {file_path.name}: unknown (filename checked: {name_lower})")
    return "unknown"

def find_dependency_files(input_paths: List[Path]) -> Dict[str, List[Path]]:
    dependency_files: Dict[str, List[Path]] = defaultdict(list)
    processed_paths = set()
    paths_to_scan = list(input_paths)

    idx = 0
    while idx < len(paths_to_scan):
        current_path = paths_to_scan[idx].resolve()
        idx += 1

        if current_path in processed_paths:
            continue
        processed_paths.add(current_path)

        if not current_path.exists():
            logger.warning(f"Path does not exist during discovery: {current_path}")
            continue

        if current_path.is_file():
            lang = detect_language(current_path)
            if lang != "unknown":
                logger.debug(f"Found {lang} dependency file: {current_path}")
                dependency_files[lang].append(current_path)
            else:
                logger.debug(f"Skipping unrecognized file during discovery: {current_path}")
        elif current_path.is_dir():
            logger.debug(f"Scanning directory for dependency files: {current_path}")
            try:
                for item in current_path.iterdir():
                    if item.resolve() not in processed_paths:
                        paths_to_scan.append(item)
            except PermissionError:
                logger.warning(f"Permission denied while trying to scan directory: {current_path}")
            except Exception as e:
                logger.error(f"Error scanning directory {current_path}: {e}", exc_info=True)

    return dependency_files

def print_formatted_vulnerability_report(enriched_vulnerabilities: List[Dict[str, Any]], total_ignored: int):
    report_data: Dict[str, Dict[str, List[Dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))

    for vuln_data in enriched_vulnerabilities:
        lang = vuln_data["language"]
        lib_id = f"{vuln_data['name']}@{vuln_data['version']}"
        report_data[lang][lib_id].append({
            "cve_id": vuln_data["cve_id"],
            "severity": vuln_data["severity"].upper(),
            "summary": vuln_data["summary"]
        })

    total_vulns_reported = len(enriched_vulnerabilities)
    global_severity_counts = defaultdict(int)
    for vuln_data in enriched_vulnerabilities:
        global_severity_counts[vuln_data["severity"].upper()] += 1

    print("\n--- Vulnerability Summary (Overall) ---")
    if total_vulns_reported == 0:
        print("Total potential unique vulnerabilities found: 0")
    else:
        print(f"Total potential unique vulnerabilities found: {total_vulns_reported}")

    if total_ignored > 0:
             print(f"Additionally, {total_ignored} vulnerabilities were ignored based on '.vulnignore'.")

    print("\nBy Severity (Reported):")
    has_severities_printed = False
    for sev in SEVERITY_ORDER:
        if global_severity_counts[sev] > 0:
            print(f"  {sev}: {global_severity_counts[sev]}")
            has_severities_printed = True

    if not has_severities_printed and total_vulns_reported > 0:
        other_severities_found = False
        for sev, count in global_severity_counts.items():
            if sev not in SEVERITY_ORDER and count > 0:
                if not other_severities_found:
                    other_severities_found = True
                print(f"  {sev}: {count}")
                has_severities_printed = True

    if not has_severities_printed:
        print("  No vulnerabilities found.")


    print("\n--- Vulnerabilities Details by Language (Reported) ---")

    if not report_data:
        print("  No vulnerabilities found to detail.")

    sorted_languages = sorted(report_data.keys(), key=lambda x: x.lower())

    for lang in sorted_languages:
        print(f"\n\n## Language: {lang.upper()}")

        lang_vulns_by_lib = report_data[lang]

        sorted_libs = sorted(lang_vulns_by_lib.keys(), key=lambda x: x.lower())
        for lib_id in sorted_libs:
            print(f"\n  ### Library: {lib_id}")
            cves_for_lib = lang_vulns_by_lib[lib_id]

            cves_by_severity: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
            for cve_info in cves_for_lib:
                cves_by_severity[cve_info["severity"]].append(cve_info)

            found_any_cve_for_this_lib = False
            for sev in SEVERITY_ORDER:
                if cves_by_severity[sev]:
                    found_any_cve_for_this_lib = True
                    print(f"    Severity: {sev}")
                    for cve_detail in sorted(cves_by_severity[sev], key=lambda x: x['cve_id']):
                        print(f"      - {cve_detail['cve_id']}")

            other_severities_exist_for_lib = False
            for sev_key in cves_by_severity.keys():
                if sev_key not in SEVERITY_ORDER:
                    other_severities_exist_for_lib = True
                    break

            if other_severities_exist_for_lib:
                if found_any_cve_for_this_lib : print("    Other Severities:")
                else: print("    Severities (not in standard order):")

                for sev_key, cve_list in sorted(cves_by_severity.items()):
                    if sev_key not in SEVERITY_ORDER:
                         found_any_cve_for_this_lib = True
                         print(f"    Severity: {sev_key}")
                         for cve_detail in sorted(cve_list, key=lambda x: x['cve_id']):
                            print(f"      - {cve_detail['cve_id']}")

            if not found_any_cve_for_this_lib and cves_for_lib:
                 logger.error(f"Internal inconsistency: CVEs present for {lib_id} but not printed in detail.")

    print("\n-----------------------------------------\n")

def load_ignore_rules(ignore_file_path: Path) -> Tuple[Set[str], Dict[str, Set[str]]]:
    ignored_cves_global: Set[str] = set()
    ignored_cves_package: Dict[str, Set[str]] = defaultdict(set)
    ignored_rules_count = 0

    if ignore_file_path.is_file():
        logger.info(f"Loading ignore rules from: {ignore_file_path}")
        try:
            with open(ignore_file_path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    stripped_line = line.strip()
                    if not stripped_line or stripped_line.startswith("#"):
                        continue

                    rule_part = stripped_line.split("#", 1)[0].strip()
                    parts = rule_part.split()

                    if not parts: continue

                    cve_id_lower = parts[0].lower()

                    if not re.match(r"cve-\d{4}-\d{4,}", cve_id_lower):
                         logger.warning(f"Skipping invalid CVE format in {ignore_file_path.name} line {line_num}: '{parts[0]}'")
                         continue

                    if len(parts) == 1:
                        ignored_cves_global.add(cve_id_lower)
                        ignored_rules_count += 1
                        logger.debug(f"Ignore rule added (global): {cve_id_lower}")
                    elif len(parts) >= 2:
                        package_name_lower = parts[1].lower()
                        ignored_cves_package[package_name_lower].add(cve_id_lower)
                        ignored_rules_count += 1
                        logger.debug(f"Ignore rule added (package: {package_name_lower}): {cve_id_lower}")

            if ignored_rules_count > 0:
                logger.info(f"Loaded {ignored_rules_count} ignore rules.")
            else:
                logger.info(f"Ignore file {ignore_file_path.name} loaded but contains no valid rules.")

        except Exception as e:
            logger.error(f"Error reading or parsing {ignore_file_path.name}: {e}", exc_info=True)
    else:
        logger.info(f"No ignore file found at {ignore_file_path}. Processing all findings.")

    return ignored_cves_global, ignored_cves_package

def main():
    parser = argparse.ArgumentParser(
        description="Scans project dependency files for known vulnerabilities using local NVD data.",
        epilog=(
            "Usage Examples:\n"
            "  python3 -m scan --dir path/to/your/project         (Scan a project directory)\n"
            "  python3 -m scan --dir ./req.txt ./proj/pom.xml   (Scan specific files)\n"
            "  python3 -m scan --update-nvd                         (Only update local NVD/CPE data)\n"
            "  python3 -m scan --dir . --update-nvd               (Update data, then scan current directory)\n"
            "\n"
            "Supported dependency files:\n"
            "  requirements.txt (Python), package.json (JavaScript), pom.xml (Java),\n"
            "  composer.json (PHP), Gemfile.lock (Ruby), go.mod (Go)\n"
            "\n"
            "Ignoring Vulnerabilities:\n"
            "  Create a file named '.vulnignore' in the current directory.\n"
            "  Each line can ignore a CVE globally or for a specific package:\n"
            "    CVE-YYYY-XXXXX                # Ignores this CVE everywhere\n"
            "    CVE-YYYY-ZZZZZ package-name   # Ignores CVE only for package-name\n"
            "    # Lines starting with # are comments."
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )

    scan_options = parser.add_argument_group('Scan Options')
    scan_options.add_argument(
        "--dir",
        type=Path,
        nargs="+",
        metavar="PATH",
        help="One or more project directories or specific dependency files to scan.\n"
             "The script recursively searches for known dependency files within directories.\n"
             "(e.g., ./my_project, ./requirements.txt)"
    )
    scan_options.add_argument(
        "--update-nvd",
        action="store_true",
        help="Force an update of local NVD and CPE data from official sources before any scanning.\n"
             "Requires internet access and may take several minutes. This process also rebuilds\n"
             "the necessary local data files (e.g., data/nvd_cve_rebuilt.json, data/cpe/cpe_alias_index.json)."
    )

    data_options = parser.add_argument_group('Data Path Options')
    data_options.add_argument(
        "--nvd",
        type=Path,
        default=Path("data/nvd_cve_rebuilt.json"),
        metavar="FILE_PATH",
        help="Path to the preprocessed (rebuilt) NVD JSON data file used for the analysis.\n"
             "(Default: data/nvd_cve_rebuilt.json)"
    )
    data_options.add_argument(
        "--cpe-index",
        type=Path,
        default=Path("data/cpe/cpe_alias_index.json"),
        metavar="FILE_PATH",
        help="Path to the CPE alias index JSON file, used to improve product name matching during analysis.\n"
             "(Default: data/cpe/cpe_alias_index.json)"
    )

    general_options = parser.add_argument_group('General Options')
    general_options.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level for the scan script.\n(Default: INFO)"
    )
    general_options.add_argument(
        "--ignore-file",
        type=Path,
        default=Path(".vulnignore"),
        metavar="FILE_PATH",
        help="Path to the file containing rules to ignore specific vulnerabilities.\n(Default: ./.vulnignore)"
    )

    args = parser.parse_args()

    try:
        logger.setLevel(args.log_level.upper())
    except ValueError:
        logger.error(f"Invalid log level: {args.log_level}. Using INFO.")
        logger.setLevel("INFO")

    update_nvd_performed_and_was_sole_action = False
    if args.update_nvd:
        logger.info("NVD update requested.")
        if update_nvd_main:
            try:
                logger.info("Attempting to run NVD update script...")
                update_nvd_main()
                logger.info("NVD update process completed.")
                if not args.dir:
                    update_nvd_performed_and_was_sole_action = True
            except Exception as e:
                logger.error(f"Error during NVD update: {e}.", exc_info=True)
                if not args.dir: return
        else:
            logger.error("NVD update functionality not available (update_nvd_main not imported).")
            if not args.dir: return

    if update_nvd_performed_and_was_sole_action:
        logger.info("NVD update was the only action requested and has completed. Exiting.")
        return

    if not args.dir:
        logger.info("\nNo input directory/file provided for scanning. Please specify with --dir.")
        logger.info("Use --help for more information on command-line options.")
        return

    valid_input_paths = []
    if args.dir:
        for p_str in args.dir:
            p = Path(p_str)
            if p.exists():
                valid_input_paths.append(p)
            else:
                logger.error(f"Input path does not exist and will be skipped: {p}")

    if not valid_input_paths:
        logger.error("No valid (existing) input files or directories were provided for scanning.")
        return

    if not args.nvd.is_file():
        logger.error(f"NVD database file not found or is not a file: {args.nvd}. "
                     "Please run with --update-nvd or ensure the path is correct.")
        return

    cpe_index_to_use = None
    if args.cpe_index.is_file():
        cpe_index_to_use = str(args.cpe_index)
    else:
        logger.warning(f"CPE index file not found or is not a file at {args.cpe_index}. "
                       "Analysis will proceed, but CPE alias matching might be less effective.")

    logger.info(f"Initializing VulnerabilityAnalyzer with NVD path: {args.nvd} and CPE index: {cpe_index_to_use if cpe_index_to_use else 'Not provided/found'}")
    analyzer = VulnerabilityAnalyzer(str(args.nvd), cpe_index_to_use)

    # Load ignore rules
    ignored_cves_global, ignored_cves_package = load_ignore_rules(args.ignore_file)

    all_dependencies: List[Dependency] = []
    dependency_name_to_language: Dict[str, str] = {}

    logger.info("Finding dependency files...")
    discovered_files_by_lang = find_dependency_files(valid_input_paths)

    if not discovered_files_by_lang:
        logger.warning("No dependency files found in the provided input paths for any known language.")
        print_formatted_vulnerability_report([], 0) 
        empty_report_path = Path("reports/report.json")
        empty_report_path.parent.mkdir(parents=True, exist_ok=True)
        generate_json_report([], empty_report_path)
        logger.info(f"Empty report generated at: {empty_report_path}")
        return

    logger.info("Parsing dependency files...")
    total_parsed_dep_count = 0
    for lang, files in discovered_files_by_lang.items():
        logger.info(f"Parsing {lang} files: {[str(f) for f in files]}")
        lang_dep_count_for_log = 0
        for file_path in files:
            try:
                parser_callable = get_parser_for_file(str(file_path))
                parsed_deps: List[Dependency] = parser_callable(str(file_path))

                if parsed_deps:
                    logger.info(f"Successfully parsed {len(parsed_deps)} dependencies from {file_path.name} for language {lang}")
                    for dep in parsed_deps:
                        dependency_name_to_language[dep.name.lower()] = lang
                    all_dependencies.extend(parsed_deps)
                    lang_dep_count_for_log += len(parsed_deps)

            except Exception as e:
                logger.error(f"Failed to parse {file_path} for language {lang}: {e}", exc_info=True)

        if lang_dep_count_for_log > 0 or len(files) > 0 :
            logger.info(f"Successfully parsed {lang_dep_count_for_log} total dependencies from {len(files)} {lang} file(s)")
        total_parsed_dep_count += lang_dep_count_for_log

    if not all_dependencies:
        logger.warning("No dependencies were successfully parsed from any file.")
        print_formatted_vulnerability_report([], 0) 
        empty_report_path = Path("reports/report.json")
        empty_report_path.parent.mkdir(parents=True, exist_ok=True)
        generate_json_report([], empty_report_path)
        logger.info(f"Empty report generated at: {empty_report_path}")
        return

    logger.info(f"Analyzing {len(all_dependencies)} total dependency entries...")
    analyzer_results: List[Vulnerability] = analyzer.analyze_by_cpe(all_dependencies)
    logger.info(f"Analysis complete. Analyzer returned {len(analyzer_results)} raw vulnerability entries.")

    # Filter results based on ignore rules
    filtered_results: List[Vulnerability] = []
    ignored_count = 0
    for vuln in analyzer_results:
        vuln_cve_lower = vuln.cve_id.lower()
        vuln_name_lower = vuln.name.lower()

        is_ignored = False
        if vuln_cve_lower in ignored_cves_global:
            is_ignored = True
            logger.debug(f"Ignoring {vuln.cve_id} for {vuln.name} (global rule)")
        elif vuln_name_lower in ignored_cves_package and vuln_cve_lower in ignored_cves_package[vuln_name_lower]:
             is_ignored = True
             logger.debug(f"Ignoring {vuln.cve_id} for {vuln.name} (package rule)")

        if not is_ignored:
            filtered_results.append(vuln)
        else:
            ignored_count += 1

    if ignored_count > 0:
        logger.info(f"Ignored {ignored_count} vulnerabilities based on rules in {args.ignore_file.name}.")

    
    enriched_results_for_console_report: List[Dict[str, Any]] = []
    for vuln in filtered_results: 
        lang_for_vuln = dependency_name_to_language.get(vuln.name.lower(), "unknown")
        enriched_results_for_console_report.append({
            "name": vuln.name,
            "version": vuln.version,
            "cve_id": vuln.cve_id,
            "severity": vuln.severity,
            "summary": vuln.summary,
            "language": lang_for_vuln
        })

  
    print_formatted_vulnerability_report(enriched_results_for_console_report, ignored_count)

    
    output_report_path = Path("reports/report.json")
    output_report_path.parent.mkdir(parents=True, exist_ok=True)
    generate_json_report(filtered_results, output_report_path) 
    logger.info(f"Report successfully generated at: {output_report_path}")

if __name__ == "__main__":
    main()
