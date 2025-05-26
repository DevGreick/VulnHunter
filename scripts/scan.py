# scan.py
import argparse
import logging
import json
from pathlib import Path
from typing import List, Any, Dict
from collections import defaultdict

try:
    from scripts.update_nvd import main as update_nvd_main
except ModuleNotFoundError:
    update_nvd_main = None
except ImportError:
    update_nvd_main = None

from src.parsers import get_parser_for_file
from src.analyzer import VulnerabilityAnalyzer
from src.models import Dependency, Vulnerability
from src.report_generator import generate_json_report


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("scan")

def detect_language(file_path: Path) -> str:
    if file_path.name == "requirements.txt":
        return "python"
    elif file_path.name == "package.json":
        return "javascript"
    elif file_path.name == "composer.json":
        return "php"
    elif file_path.name == "Gemfile.lock":
        return "ruby"
    elif file_path.name == "pom.xml":
        return "java"
    elif file_path.name == "go.mod":
        return "go"
    logger.debug(f"Detecting language for {file_path.name}: unknown")
    return "unknown"

def find_dependency_files(input_paths: List[Path]) -> Dict[str, List[Path]]:
    dependency_files: Dict[str, List[Path]] = defaultdict(list)
    for path in input_paths:
        if path.is_file():
            language = detect_language(path)
            if language != "unknown":
                dependency_files[language].append(path)
            else:
                logger.debug(f"Skipping unsupported file type: {path}")
        elif path.is_dir():
            logger.debug(f"Scanning directory: {path}")
            for file_path in path.rglob("*"):
                if file_path.is_file():
                    language = detect_language(file_path)
                    if language != "unknown":
                        dependency_files[language].append(file_path)
                    else:
                         logger.debug(f"Skipping unsupported file type in directory: {file_path}")
    return dependency_files

def run_analysis(input_paths: List[Path], nvd_path: Path, cpe_index_path: Path):
    logger.info(f"Initializing VulnerabilityAnalyzer with NVD path: {nvd_path} and CPE index: {cpe_index_path}")
    analyzer = VulnerabilityAnalyzer(nvd_data_path=str(nvd_path), cpe_index_path=str(cpe_index_path))

    all_dependencies: List[Dependency] = []
    dependency_files_found = find_dependency_files(input_paths)

    if not dependency_files_found:
        logger.warning("No supported dependency files found in the specified input paths.")
        return

    logger.info("Parsing dependency files...")
    for language, file_list in dependency_files_found.items():
        logger.info(f"Parsing {language} files: {file_list}")
        for file_path in file_list:
            parser_func = get_parser_for_file(str(file_path))
            try:
                dependencies = parser_func(str(file_path))
                all_dependencies.extend(dependencies)
                logger.info(f"Successfully parsed {len(dependencies)} dependencies from {file_path} for language {language}")
            except Exception as e:
                logger.warning(f"Skipping file due to parse error: {file_path}. Error: {e}")

    if not all_dependencies:
        logger.warning("No dependencies found after parsing files.")
        return

    logger.info(f"Analyzing {len(all_dependencies)} total dependency entries...")

    vulnerabilities_found = analyzer.analyze_dependencies(all_dependencies)

    logger.info(f"Analysis complete. Analyzer returned {len(vulnerabilities_found)} raw vulnerability entries.")

    report_dir = Path("./reports")
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "report.json"

    try:
        generate_json_report(vulnerabilities_found, report_path)
        logger.info(f"Report successfully generated at: {report_path}")
    except Exception as e:
        logger.error(f"Error generating JSON report: {e}", exc_info=True)

    print("\n--- Vulnerability Summary ---")
    total_vulns = len(vulnerabilities_found)
    print(f"Total potential unique vulnerabilities found: {total_vulns}")

    by_severity = defaultdict(list)
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "NONE"]

    for v in vulnerabilities_found:
        by_severity[v.severity.upper()].append(v)

    if any(by_severity.values()):
         print("\nBy Severity:")
         for sev in severity_order:
             if sev in by_severity and by_severity[sev]:
                 print(f"  {sev}: {len(by_severity[sev])}")

    print("\n--- Vulnerabilities Details ---")
    by_package_summary = defaultdict(list)
    for v in vulnerabilities_found:
         package_identifier = f"{v.name}@{v.version}"
         by_package_summary[package_identifier].append((v.cve_id, v.severity))

    print("\nPackages with vulnerabilities:")
    for pkg_ver_key, cve_severity_pairs in sorted(by_package_summary.items()):
         cve_severity_list = [f"{cve_id} ({severity})" for cve_id, severity in cve_severity_pairs]
         print(f"- {pkg_ver_key}: Found {len(cve_severity_pairs)} CVEs ({', '.join(sorted(cve_severity_list))})")

    print("-----------------------------")

def main():
    parser = argparse.ArgumentParser(
        description="Scan dependency files for vulnerabilities using NVD data.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Examples:\n"
               "  python3 -m scan --dir /path/to/your/project\n"
               "  python3 -m scan --dir /path/to/requirements.txt /path/to/package.json\n"
               "  python3 -m scan --update-nvd\n"
               "  python3 -m scan --dir inputs/ --nvd data/nvd_cve_rebuilt.json"
    )
    parser.add_argument(
        "--dir",
        nargs='+',
        type=Path,
        help="Directory or list of files to scan."
    )
    parser.add_argument(
        "--nvd",
        type=Path,
        default=Path("./data/nvd_cve_rebuilt.json"),
        help="Path to the minimal NVD JSON data file."
    )
    parser.add_argument(
        "--cpe-index",
        type=Path,
        default=Path("./data/cpe/cpe_alias_index.json"),
        help="Path to the CPE alias index file (generated by update_nvd)."
    )
    parser.add_argument(
        "--update-nvd",
        action="store_true",
        help="Download and update the NVD and CPE data before scanning."
    )

    args = parser.parse_args()

    if args.update_nvd:
        logger.info("Running NVD update process...")
        if update_nvd_main:
            try:
                update_nvd_main()
                logger.info("NVD update process completed.")
            except Exception as e:
                 logger.error(f"NVD update process failed: {e}", exc_info=True)
                 if not args.dir:
                     logger.info("NVD update process attempted. No input directory/file provided for scanning, exiting.")
                     return
        else:
            logger.error("NVD update functionality not available. Check if update_nvd.py is in the 'scripts' directory and imports are correct.")
            if not args.dir:
                 logger.info("NVD update functionality not available. No input directory/file provided for scanning, exiting.")
                 return

    if args.dir:
        valid_input_paths = [p for p in args.dir if p.exists() and (p.is_file() or p.is_dir())]
        invalid_input_paths = [p for p in args.dir if not p.exists() or (not p.is_file() and not p.is_dir())]

        if invalid_input_paths:
             logger.error(f"\nError: Some input paths are invalid (not found or not file/directory): {invalid_input_paths}")
             return

        if not valid_input_paths:
             logger.error("\nError: No valid input files or directories were provided for scanning.")
             return

        if not args.nvd.exists():
            logger.error(f"NVD database file not found: {args.nvd}. "
                         "Please run with --update-nvd or ensure the path is correct.")
            return

        if not args.cpe_index.exists():
            logger.warning(f"CPE index file not found: {args.cpe_index}. "
                           "Analysis will proceed, but CPE alias matching might be less effective. "
                           "Consider running --update-nvd or 'python3 scripts/update_nvd.py' to generate it.")

        run_analysis(valid_input_paths, args.nvd, args.cpe_index)

if __name__ == "__main__":
    main()
