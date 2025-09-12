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
    """Analisa uma string de versão de forma segura, com cache e normalização básica."""
    if not version_str:
        return None
    version_str = str(version_str).strip()
    if not version_str:
        return None
    if version_str in _SAFE_VERSION_CACHE:
        return _SAFE_VERSION_CACHE[version_str]

    try:
        parsed_version = parse_version(version_str)
        _SAFE_VERSION_CACHE[version_str] = parsed_version
        return parsed_version
    except InvalidVersion:
        # Tenta uma normalização simples para versões não padrão (ex: com sufixos)
        normalized_str = re.sub(r"[:](rc|beta|b|alpha)\d*$", "", version_str, flags=re.IGNORECASE)
        normalized_str = normalized_str.rstrip('.')
        if normalized_str == version_str:
            logger.debug(f"Não foi possível analisar a versão '{version_str}' (nenhuma normalização eficaz aplicada).")
            _SAFE_VERSION_CACHE[version_str] = None
            return None

        try:
            logger.debug(f"Tentando analisar a versão normalizada '{normalized_str}' (de '{version_str}')")
            parsed_version = parse_version(normalized_str)
            _SAFE_VERSION_CACHE[version_str] = parsed_version
            return parsed_version
        except InvalidVersion:
            logger.debug(f"Não foi possível analisar a versão '{version_str}' mesmo após normalizar para '{normalized_str}'.")
            _SAFE_VERSION_CACHE[version_str] = None
            return None

class VulnerabilityAnalyzer:
    def __init__(self, nvd_data_path: str, cpe_index_path: Optional[str] = None, effective_log_level: int = logging.INFO):
        logger.setLevel(effective_log_level)
        logger.info(f"Inicializando VulnerabilityAnalyzer com dados NVD de: {nvd_data_path}")
        self.nvd_data = self._load_json_data(nvd_data_path, is_nvd_data=True)
        self.cpe_alias_index = self._load_json_data(cpe_index_path) if cpe_index_path else {}
        self.effective_log_level = effective_log_level

        if not self.nvd_data or not isinstance(self.nvd_data, list):
            logger.error(f"Dados NVD de {nvd_data_path} falharam ao carregar ou não são uma lista. A análise não pode ser realizada.")
            self.nvd_data = []

        if cpe_index_path and (not self.cpe_alias_index or not isinstance(self.cpe_alias_index, dict)):
            logger.warning(f"Índice de alias CPE em {cpe_index_path} não foi carregado ou não é um dicionário. A correspondência de nomes pode ser menos eficaz.")


    def _load_json_data(self, path: str, is_nvd_data: bool = False) -> Any:
        default_return = [] if is_nvd_data else {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            logger.error(f"Arquivo de dados não encontrado: {path}")
        except json.JSONDecodeError as e:
            logger.error(f"Erro ao decodificar JSON de {path}: {e}")
        except Exception as e:
            logger.error(f"Ocorreu um erro inesperado ao carregar {path}: {e}", exc_info=True)
        return default_return

    def _find_potential_nvd_names(self, dependency_name_lower: str) -> Set[str]:
        """Encontra todos os nomes possíveis para uma dependência na NVD usando heurísticas e o índice CPE."""
        potential_names: Set[str] = {dependency_name_lower}

        # Heurísticas e casos comuns
        hardcoded_map = {
            'spring-core': {'spring-framework', 'spring', 'vmware:spring-framework', 'pivotal_software:spring-framework'},
            'laravel/framework': {'framework', 'laravel', 'laravel:framework'},
            'guzzlehttp/guzzle': {'guzzle', 'guzzlehttp:guzzle'},
            'pg': {'postgresql:postgresql', 'postgresql'}
        }
        if dependency_name_lower in hardcoded_map:
            potential_names.update(hardcoded_map[dependency_name_lower])

        if not self.cpe_alias_index:
            return potential_names

        # Busca direta no índice de alias (a chave é o nome da dependência)
        if dependency_name_lower in self.cpe_alias_index:
            aliases = self.cpe_alias_index[dependency_name_lower]
            if isinstance(aliases, list):
                potential_names.update(alias.lower() for alias in aliases)

        # Busca reversa (o nome da dependência pode ser um valor na lista de alias)
        for product_key, aliases_list in self.cpe_alias_index.items():
            if isinstance(aliases_list, list):
                if dependency_name_lower in {alias.lower() for alias in aliases_list}:
                    potential_names.add(product_key.lower())

        logger.debug(f"Nomes potenciais para '{dependency_name_lower}': {potential_names}")
        return potential_names

    def analyze_by_cpe(self, dependencies: List[Dependency]) -> List[Vulnerability]:
        """Analisa uma lista de dependências contra a base de dados NVD processada."""
        results: List[Vulnerability] = []
        if not self.nvd_data:
            logger.error("Dados NVD não carregados, a análise foi cancelada.")
            return results

        total_dependencies = len(dependencies)
        logger.debug(f"Iniciando análise para {total_dependencies} dependências.")
        unique_vulnerabilities: Set[Vulnerability] = set()

        for dep_idx, dep in enumerate(dependencies):
            dep_name_lower = dep.name.lower()
            dep_version_str = dep.version

            # Barra de progresso para o console
            if self.effective_log_level <= logging.INFO:
                progress = (dep_idx + 1) / total_dependencies
                bar = '█' * int(progress * 30) + '-' * (30 - int(progress * 30))
                sys.stdout.write(f"\rAnalisando: [{bar}] {dep_idx + 1}/{total_dependencies} ({progress:.0%})")
                sys.stdout.flush()

            logger.debug(f"Processando {dep.name}@{dep_version_str}")

            dep_version_obj = _parse_version_safely(dep.version)
            if not dep_version_obj:
                logger.warning(f"Versão '{dep.version}' para {dep.name} não é 'parseável'. A correspondência de versão pode ser imprecisa.")

            names_to_check = self._find_potential_nvd_names(dep_name_lower)

            for nvd_item in self.nvd_data:
                nvd_product_name = nvd_item.get("name", "").lower()
                if nvd_product_name not in names_to_check:
                    continue

                logger.debug(f"NOME CORRESPONDE: '{dep.name}' (via '{nvd_product_name}') para CVE {nvd_item.get('cve_id')}. Verificando versão...")

                is_vulnerable = False
                if not dep_version_obj:
                    # Se a versão não pôde ser analisada, assume-se como vulnerável se o nome corresponder
                    is_vulnerable = True
                else:
                    for v_range in nvd_item.get("vulnerable_versions", []):
                        if self._is_version_in_range(dep_version_obj, v_range):
                            is_vulnerable = True
                            break
                
                if is_vulnerable:
                    vuln = Vulnerability(
                        name=dep.name,
                        version=dep.version,
                        cve_id=nvd_item.get("cve_id", "N/A"),
                        severity=nvd_item.get("severity", "UNKNOWN").upper(),
                        summary=nvd_item.get("summary", "").strip()
                    )
                    unique_vulnerabilities.add(vuln)

        if self.effective_log_level <= logging.INFO:
            sys.stdout.write("\r" + " " * 80 + "\r") # Limpa a linha de progresso
            sys.stdout.flush()

        results = sorted(list(unique_vulnerabilities), key=lambda v: (v.name, v.cve_id))
        logger.info(f"Análise concluída. Encontradas {len(results)} vulnerabilidades únicas.")
        return results

    def _is_version_in_range(self, dep_version: Version, version_range: Dict[str, str]) -> bool:
        """Verifica se uma versão de dependência está dentro de uma faixa de versão vulnerável."""
        if not isinstance(version_range, dict):
            return False

        # Verifica versão exata
        exact_version_str = version_range.get("exactVersion")
        if exact_version_str:
            exact_ver_obj = _parse_version_safely(exact_version_str)
            return exact_ver_obj is not None and dep_version == exact_ver_obj

        # Verifica faixas (ranges)
        vsi_obj = _parse_version_safely(version_range.get("versionStartIncluding"))
        vse_obj = _parse_version_safely(version_range.get("versionStartExcluding"))
        vei_obj = _parse_version_safely(version_range.get("versionEndIncluding"))
        vee_obj = _parse_version_safely(version_range.get("versionEndExcluding"))

        # Checagens de limite
        lower_bound_ok = True
        upper_bound_ok = True

        if vsi_obj and not (dep_version >= vsi_obj):
            lower_bound_ok = False
        if vse_obj and not (dep_version > vse_obj):
            lower_bound_ok = False
        if vei_obj and not (dep_version <= vei_obj):
            upper_bound_ok = False
        if vee_obj and not (dep_version < vee_obj):
            upper_bound_ok = False

        return lower_bound_ok and upper_bound_ok