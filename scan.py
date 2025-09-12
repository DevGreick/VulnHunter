# scan.py
import argparse
import logging
import re
from pathlib import Path
from typing import List, Any, Dict, Tuple, Set
from collections import defaultdict
import sys

# Garante que os módulos em 'src' e 'scripts' possam ser importados
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from scripts.update_nvd import main as update_nvd_main
except (ModuleNotFoundError, ImportError):
    update_nvd_main = None
    # Este log só aparecerá se --update-nvd for usado e a importação falhar.
    logging.getLogger("scan").debug("Não foi possível importar a função de atualização da NVD.")

from src.parsers import get_parser_for_file
from src.analyzer import VulnerabilityAnalyzer
from src.models import Dependency, Vulnerability
from src.report_generator import generate_json_report

# Configuração do Logging
root_logger = logging.getLogger()
console_handler = logging.StreamHandler(sys.stderr)
formatter = logging.Formatter('%(levelname)s:%(name)s:%(message)s')
console_handler.setFormatter(formatter)
if not root_logger.hasHandlers():
    root_logger.addHandler(console_handler)

logger = logging.getLogger("scan")

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SUPPORTED_FILES = [
    "requirements.txt", "package.json", "pom.xml", 
    "composer.json", "gemfile.lock", "go.mod"
]

def detect_language(file_path: Path) -> str:
    """Detecta a linguagem de programação com base no nome do arquivo de dependência."""
    name_lower = file_path.name.lower()
    lang_map = {
        "requirements.txt": "python",
        "package.json": "javascript",
        "composer.json": "php",
        "gemfile.lock": "ruby",
        "pom.xml": "java",
        "go.mod": "go"
    }
    return lang_map.get(name_lower, "unknown")

def find_dependency_files(input_paths: List[Path]) -> Dict[str, List[Path]]:
    """Busca recursivamente por arquivos de dependência suportados."""
    dependency_files: Dict[str, List[Path]] = defaultdict(list)
    for path in input_paths:
        if path.is_file() and path.name.lower() in SUPPORTED_FILES:
            lang = detect_language(path)
            dependency_files[lang].append(path)
        elif path.is_dir():
            for supported_file in SUPPORTED_FILES:
                for found_file in path.rglob(supported_file):
                    lang = detect_language(found_file)
                    dependency_files[lang].append(found_file)
    return dependency_files

def print_formatted_vulnerability_report(enriched_vulns: List[Dict[str, Any]], total_ignored: int):
    """Imprime o relatório de vulnerabilidades formatado no console."""
    if not enriched_vulns:
        print("\n--- Sumário de Vulnerabilidades ---")
        print("✅ Nenhuma vulnerabilidade encontrada.")
        if total_ignored > 0:
            print(f"   ({total_ignored} vulnerabilidades foram ignoradas via .vulnignore)")
        print("-----------------------------------\n")
        return

    report_data = defaultdict(lambda: defaultdict(list))
    severity_counts = defaultdict(int)
    for vuln in enriched_vulns:
        lang = vuln["language"]
        lib_id = f"{vuln['name']}@{vuln['version']}"
        report_data[lang][lib_id].append(vuln)
        severity_counts[vuln["severity"].upper()] += 1

    print("\n--- Sumário de Vulnerabilidades ---")
    print(f"Total de vulnerabilidades encontradas: {len(enriched_vulns)}")
    if total_ignored > 0:
        print(f"Vulnerabilidades ignoradas: {total_ignored}")
    
    for sev in SEVERITY_ORDER:
        if sev in severity_counts:
            print(f"  [{sev}]: {severity_counts[sev]}")
    
    print("\n--- Detalhes por Linguagem ---")
    for lang, libs in sorted(report_data.items()):
        print(f"\n## Linguagem: {lang.upper()}")
        for lib_id, vulns in sorted(libs.items()):
            print(f"  ### Biblioteca: {lib_id}")
            for sev in SEVERITY_ORDER:
                sev_vulns = [v for v in vulns if v["severity"].upper() == sev]
                if sev_vulns:
                    print(f"    - Severidade: {sev}")
                    for v in sorted(sev_vulns, key=lambda x: x['cve_id']):
                        print(f"      - {v['cve_id']}")
    print("\n-----------------------------------\n")


def load_ignore_rules(ignore_file_path: Path) -> Tuple[Set[str], Dict[str, Set[str]]]:
    """Carrega as regras de CVEs a serem ignoradas do arquivo .vulnignore."""
    ignored_cves_global, ignored_cves_package = set(), defaultdict(set)
    if not ignore_file_path.is_file():
        logger.info(f"Arquivo .vulnignore não encontrado em {ignore_file_path}, nenhuma vulnerabilidade será ignorada.")
        return ignored_cves_global, ignored_cves_package

    logger.info(f"Carregando regras de exclusão de: {ignore_file_path}")
    with open(ignore_file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip().split("#")[0]
            if not line:
                continue
            parts = line.split()
            cve_id = parts[0].lower()
            if re.match(r"cve-\d{4}-\d{4,}", cve_id):
                if len(parts) == 1:
                    ignored_cves_global.add(cve_id)
                elif len(parts) >= 2:
                    package_name = parts[1].lower()
                    ignored_cves_package[package_name].add(cve_id)
    logger.info(f"Carregadas {len(ignored_cves_global)} regras globais e {len(ignored_cves_package)} pacotes com regras específicas.")
    return ignored_cves_global, ignored_cves_package

def main():
    parser = argparse.ArgumentParser(
        description="Scans project dependency files for known vulnerabilities using local NVD data.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--dir", type=Path, nargs="+", metavar="PATH", help="Um ou mais diretórios ou arquivos para escanear.")
    parser.add_argument("--update-nvd", action="store_true", help="Força a atualização dos dados locais da NVD e CPE.")
    parser.add_argument("--nvd", type=Path, default=Path("data/nvd_cve_rebuilt.json"), help="Caminho para o arquivo de dados NVD processado.")
    parser.add_argument("--cpe-index", type=Path, default=Path("data/cpe/cpe_alias_index.json"), help="Caminho para o índice de alias CPE.")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Define o nível do log.")
    parser.add_argument("--ignore-file", type=Path, default=Path(".vulnignore"), help="Caminho para o arquivo de exclusão de CVEs.")

    args = parser.parse_args()
    log_level_numeric = logging.getLevelName(args.log_level.upper())
    root_logger.setLevel(log_level_numeric)

    if not args.update_nvd and not args.dir:
        parser.error("Nenhuma ação especificada. Use --update-nvd ou --dir.")

    if args.update_nvd:
        if update_nvd_main:
            logger.info("Iniciando atualização da base de dados NVD...")
            update_nvd_main()
            logger.info("Processo de atualização da NVD concluído.")
        else:
            logger.error("Funcionalidade de atualização da NVD não está disponível (importação falhou).")
        if not args.dir:
            return

    if args.dir:
        if not args.nvd.is_file():
            logger.error(f"Base de dados NVD não encontrada em: {args.nvd}. Execute com --update-nvd.")
            return
        
        cpe_index_path = str(args.cpe_index) if args.cpe_index.is_file() else None

        all_deps = set()
        dep_to_lang_map = {}
        
        discovered_files = find_dependency_files(args.dir)
        if not discovered_files:
            logger.warning("Nenhum arquivo de dependência suportado encontrado.")
            return

        for lang, files in discovered_files.items():
            for file_path in files:
                logger.info(f"Analisando {file_path} ({lang})...")
                parser_func = get_parser_for_file(str(file_path))
                deps = parser_func(str(file_path))
                for dep in deps:
                    all_deps.add(dep)
                    dep_to_lang_map[dep.name.lower()] = lang
        
        analyzer = VulnerabilityAnalyzer(str(args.nvd), cpe_index_path, effective_log_level=log_level_numeric)
        raw_vulns = analyzer.analyze_by_cpe(list(all_deps))

        ignored_global, ignored_package = load_ignore_rules(args.ignore_file)
        
        final_vulns, enriched_vulns = [], []
        ignored_count = 0

        for vuln in raw_vulns:
            cve_lower = vuln.cve_id.lower()
            pkg_lower = vuln.name.lower()
            if cve_lower in ignored_global or cve_lower in ignored_package.get(pkg_lower, set()):
                ignored_count += 1
                continue
            
            final_vulns.append(vuln)
            lang = dep_to_lang_map.get(pkg_lower, "unknown")
            enriched_vulns.append({**vuln.dict(), "language": lang})

        print_formatted_vulnerability_report(enriched_vulns, ignored_count)

        report_path = Path("reports/report.json")
        report_path.parent.mkdir(parents=True, exist_ok=True)
        generate_json_report(final_vulns, report_path)
        logger.info(f"Relatório JSON gerado em: {report_path}")

if __name__ == "__main__":
    main()