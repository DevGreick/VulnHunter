# scripts/convert_nvd.py
import json
from pathlib import Path
import logging
from typing import List, Dict, Any, Tuple, Optional

# --- Configuração do Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(name)s:%(lineno)d - %(message)s'
)
logger = logging.getLogger("convert_nvd")

def extract_vendor_product_name(cpe_uri: str) -> Optional[str]:
    """Extrai um nome canônico 'fornecedor:produto' de uma URI CPE 2.3."""
    try:
        parts = cpe_uri.split(":")
        if len(parts) >= 5:
            vendor = parts[3].lower().replace('_', '-')
            product = parts[4].lower().replace('_', '-')

            if not vendor or vendor == '*':
                return None
            if not product or product == '*':
                return None

            return f"{vendor}:{product}"
    except Exception as e:
        logger.warning(f"Erro ao processar a URI CPE '{cpe_uri}': {e}")
    return None


def get_severity_from_metrics(metrics: Dict[str, Any]) -> str:
    """Extrai a severidade do objeto de métricas, priorizando CVSS v3.1."""
    if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
        return metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
    if "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
        return metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
    if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        return metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN")
    return "UNKNOWN"


def get_english_description(descriptions: List[Dict[str, str]]) -> str:
    """Extrai a descrição em inglês de uma lista de descrições."""
    for desc in descriptions:
        if desc.get("lang") == "en":
            return desc.get("value", "No description provided.")
    return "No English description provided."


def convert_nvd_to_minimal(input_file: str, output_file: str) -> None:
    """
    Converte o JSON bruto da API NVD 2.0 em um formato mínimo e otimizado.

    O formato de saída agrupa as informações de vulnerabilidade por um par
    (vendor:product, cve_id), consolidando todas as faixas de versão
    vulneráveis para essa combinação.
    """
    logger.info(f"Iniciando conversão de {input_file} para o formato mínimo {output_file}")

    try:
        with open(input_file, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        if "vulnerabilities" not in raw_data or not isinstance(raw_data["vulnerabilities"], list):
            logger.error(f"Formato inválido em {input_file}: chave 'vulnerabilities' não encontrada ou não é uma lista.")
            return
        cve_wrappers = raw_data["vulnerabilities"]
    except FileNotFoundError:
        logger.error(f"Arquivo de entrada NVD não encontrado: {input_file}")
        return
    except json.JSONDecodeError as e:
        logger.error(f"Erro ao decodificar JSON de {input_file}: {e}")
        return
    except Exception as e:
        logger.error(f"Falha ao carregar ou pré-validar {input_file}: {e}", exc_info=True)
        return

    # Dicionário para consolidar vulnerabilidades: (vendor:product, cve_id) -> dados_da_vuln
    vulns_dict: Dict[Tuple[str, str], Dict[str, Any]] = {}
    processed_cves = 0

    for cve_wrapper in cve_wrappers:
        try:
            cve = cve_wrapper.get("cve")
            if not cve:
                continue

            processed_cves += 1
            cve_id = cve.get("id")
            if not cve_id:
                logger.warning("Pulando item de CVE sem ID.")
                continue

            severity = get_severity_from_metrics(cve.get("metrics", {}))
            summary = get_english_description(cve.get("descriptions", []))
            configurations = cve.get("configurations", [])

            for config in configurations:
                nodes = config.get("nodes", [])
                for node in nodes:
                    cpe_matches = node.get("cpeMatch", [])
                    for cpe_entry in cpe_matches:
                        if not cpe_entry.get("vulnerable", True):
                            continue

                        cpe_uri = cpe_entry.get("criteria")
                        if not cpe_uri:
                            continue

                        vendor_product_name = extract_vendor_product_name(cpe_uri)
                        if not vendor_product_name:
                            continue

                        # Extrai as faixas de versão da entrada CPE
                        range_data = {}
                        vsi = cpe_entry.get("versionStartIncluding")
                        vse = cpe_entry.get("versionStartExcluding")
                        vei = cpe_entry.get("versionEndIncluding")
                        vee = cpe_entry.get("versionEndExcluding")

                        if vsi: range_data["versionStartIncluding"] = vsi
                        if vse: range_data["versionStartExcluding"] = vse
                        if vei: range_data["versionEndIncluding"] = vei
                        if vee: range_data["versionEndExcluding"] = vee

                        # Se não houver faixa, pode ser uma versão exata na URI CPE
                        if not range_data:
                            cpe_parts = cpe_uri.split(':')
                            if len(cpe_parts) > 5 and cpe_parts[5] not in ('*', '-'):
                                range_data["exactVersion"] = cpe_parts[5]

                        if not range_data:
                            continue

                        # Usa (vendor:product, cve_id) como chave para agrupar as faixas
                        combo_key = (vendor_product_name, cve_id)

                        if combo_key not in vulns_dict:
                            vulns_dict[combo_key] = {
                                "name": vendor_product_name,
                                "cve_id": cve_id,
                                "severity": severity.upper(),
                                "summary": summary.strip(),
                                "vulnerable_versions": [range_data]
                            }
                        else:
                            # Adiciona uma nova faixa de versão se ela ainda não existir
                            if range_data not in vulns_dict[combo_key]["vulnerable_versions"]:
                                vulns_dict[combo_key]["vulnerable_versions"].append(range_data)

        except Exception as e:
            cve_ref = cve.get("id", "ID DESCONHECIDO")
            logger.error(f"Erro inesperado ao processar o item CVE '{cve_ref}': {e}", exc_info=True)

    logger.info(f"Processamento de {processed_cves} CVEs da API NVD concluído.")

    minimal_vulns = list(vulns_dict.values())
    logger.info(f"Dados consolidados em {len(minimal_vulns)} entradas de vulnerabilidade únicas (par vendor:product/CVE).")

    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(output_path, "w", encoding="utf-8") as out_f:
            json.dump(minimal_vulns, out_f, indent=2, ensure_ascii=False)
        logger.info(f"Arquivo NVD otimizado gerado com sucesso: {output_path}")
    except Exception as e:
        logger.error(f"Falha ao escrever o arquivo de saída {output_path}: {e}", exc_info=True)