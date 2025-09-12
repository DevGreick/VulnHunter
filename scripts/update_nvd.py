# scripts/update_nvd.py
import os
import json
import time
import zipfile
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Set, Optional
from collections import defaultdict
import requests

# --- Configuração do Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(name)s:%(lineno)d - %(message)s'
)
logger = logging.getLogger("update_nvd")

# --- Constantes e Configuração de Paths ---
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
NVD_FEEDS_DIR = DATA_DIR / "nvd_feeds"
RAW_NVD_JSON = DATA_DIR / "nvd_raw_merged.json"
REBUILT_NVD_JSON = DATA_DIR / "nvd_cve_rebuilt.json"
CPE_ALIAS_INDEX_JSON = DATA_DIR / "cpe_alias_index.json"

# --- URLs e Configurações ---
NVD_CVE_FEEDS_BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/"
NVD_CPE_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0/"
NVD_API_KEY = os.environ.get("NVD_API_KEY")
REQUEST_DELAY_SECONDS = 6 if not NVD_API_KEY else 0.6
CPE_API_RESULTS_PER_PAGE = 10000 # Máximo permitido pela API de CPEs

try:
    from .convert_nvd import convert_nvd_to_minimal
except ImportError:
    logger.critical("Falha na importação de '.convert_nvd'. A conversão dos dados da NVD falhará.")
    convert_nvd_to_minimal = None

# --- Funções Utilitárias ---
def download_file(url: str, dest_path: Path, session: requests.Session) -> bool:
    logger.info(f"Baixando: {url}")
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = session.get(url, stream=True, timeout=180, headers=headers)
        response.raise_for_status()
        with open(dest_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        logger.info(f"Download bem-sucedido: {dest_path.name}")
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Falha ao baixar {url}: {e}")
    return False

def extract_zip(zip_path: Path, output_dir: Path) -> Optional[Path]:
    logger.info(f"Extraindo {zip_path.name}...")
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            extracted_files = zip_ref.namelist()
            zip_ref.extractall(output_dir)
            if extracted_files:
                logger.info("Extração bem-sucedida.")
                return output_dir / extracted_files[0]
    except Exception as e:
        logger.error(f"Falha ao extrair {zip_path.name}: {e}")
    return None

# --- Lógica de Coleta de CVEs via Data Feeds ---
def merge_json_files(json_files: List[Path], output_file: Path):
    logger.info(f"Unificando {len(json_files)} arquivos JSON de CVEs...")
    all_vulnerabilities = []
    for json_file in json_files:
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                vulnerabilities = data.get("vulnerabilities", [])
                all_vulnerabilities.extend(vulnerabilities)
        except Exception as e:
            logger.error(f"Erro ao processar o arquivo {json_file}: {e}")
        finally:
            try: json_file.unlink()
            except OSError: pass
    
    output_data = {"vulnerabilities": all_vulnerabilities}
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output_data, f)
    logger.info(f"Unificação de CVEs concluída. Total de {len(all_vulnerabilities)} vulnerabilidades.")

def update_cves_from_data_feeds() -> bool:
    NVD_FEEDS_DIR.mkdir(parents=True, exist_ok=True)
    session = requests.Session()
    
    current_year = datetime.now().year
    files_to_download = [f"nvdcve-2.0-{year}.json.zip" for year in range(2002, current_year + 1)]
    files_to_download.append("nvdcve-2.0-modified.json.zip")
    
    extracted_json_paths = []
    for filename in files_to_download:
        url = NVD_CVE_FEEDS_BASE_URL + filename
        zip_path = NVD_FEEDS_DIR / filename
        
        if not download_file(url, zip_path, session):
            logger.warning(f"Não foi possível baixar {filename}. Continuando...")
            continue
            
        json_path = extract_zip(zip_path, NVD_FEEDS_DIR)
        if json_path:
            extracted_json_paths.append(json_path)
        
        try: zip_path.unlink()
        except OSError: pass

    if not extracted_json_paths:
        logger.error("Nenhum arquivo de feed de CVE foi baixado ou extraído.")
        return False
        
    merge_json_files(extracted_json_paths, RAW_NVD_JSON)
    return True

# --- Lógica de Coleta de CPEs via API ---
def extract_vendor_product_name(cpe_uri: str) -> Optional[str]:
    try:
        parts = cpe_uri.split(":")
        if len(parts) >= 5:
            vendor = parts[3].lower().replace('_', '-')
            product = parts[4].lower().replace('_', '-')
            if not vendor or vendor == '*': return None
            if not product or product == '*': return None
            return f"{vendor}:{product}"
    except Exception:
        return None

def build_cpe_index_from_api() -> bool:
    logger.info("Construindo índice de CPE a partir da API 2.0. Este processo é longo.")
    alias_index: Dict[str, Set[str]] = defaultdict(set)
    start_index = 0
    
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    session = requests.Session()
    session.headers.update(headers)

    while True:
        params = {"resultsPerPage": CPE_API_RESULTS_PER_PAGE, "startIndex": start_index}
        try:
            response = session.get(NVD_CPE_API_BASE_URL, params=params, timeout=180)
            response.raise_for_status()
            data = response.json()

            products = data.get("products", [])
            if not products:
                logger.info("Nenhum produto adicional retornado pela API de CPEs. Finalizando.")
                break

            for item in products:
                cpe_info = item.get("cpe", {})
                cpe_name = cpe_info.get("cpeName")
                if not cpe_name:
                    continue
                
                canonical_name = extract_vendor_product_name(cpe_name)
                if not canonical_name:
                    continue
                
                product_part = canonical_name.split(":", 1)[-1]
                alias_index[product_part].add(canonical_name)

                for title_info in cpe_info.get("titles", []):
                    if title_info.get("lang") == "en" and title_info.get("title"):
                        alias_index[title_info["title"].strip().lower()].add(canonical_name)

            total_results = data.get("totalResults", 0)
            start_index += len(products)
            progress = (start_index / total_results) * 100 if total_results > 0 else 100
            logger.info(f"Progresso CPE: {start_index}/{total_results} produtos processados ({progress:.2f}%)")

            if start_index >= total_results:
                break

            time.sleep(REQUEST_DELAY_SECONDS)

        except requests.exceptions.RequestException as e:
            logger.error(f"Erro na requisição à API de CPEs (startIndex={start_index}): {e}")
            logger.error("O processo de criação do índice de CPEs falhou.")
            return False

    final_alias_index = {key: sorted(list(value)) for key, value in alias_index.items()}
    with open(CPE_ALIAS_INDEX_JSON, "w", encoding="utf-8") as f:
        json.dump(final_alias_index, f, indent=2, ensure_ascii=False)
    
    logger.info(f"Índice de alias do CPE gerado com sucesso com {len(final_alias_index)} chaves.")
    return True

# --- Função Principal ---
def main():
    logger.info("=== Iniciando atualização da base de dados ===")
    
    # Etapa 1: Obter CVEs dos Data Feeds
    if not update_cves_from_data_feeds():
        logger.critical("Falha ao baixar os feeds de CVEs. O processo não pode continuar.")
        return
        
    if RAW_NVD_JSON.exists() and convert_nvd_to_minimal:
        logger.info("Convertendo dados brutos de CVEs para formato mínimo...")
        convert_nvd_to_minimal(input_file=str(RAW_NVD_JSON), output_file=str(REBUILT_NVD_JSON))
    
    # Etapa 2: Construir índice CPE a partir da API
    if not build_cpe_index_from_api():
        logger.error("Não foi possível construir o índice de CPE. A análise pode ser menos precisa.")
    
    logger.info("=== Processo de atualização concluído. ===")

if __name__ == "__main__":
    main()