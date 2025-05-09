# scripts/update_nvd.py
import argparse
import os
import gzip
import shutil
import json
from datetime import datetime
from pathlib import Path
import logging
import requests
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Set, Optional, Tuple
from collections import defaultdict
import zipfile 

logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s:%(lineno)d:%(message)s')
logger = logging.getLogger("update_nvd")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
NVD_FEED_DIR = DATA_DIR / "nvd_feeds"
MERGED_NVD_JSON = DATA_DIR / "nvd_cve.json"
REBUILT_NVD_JSON = DATA_DIR / "nvd_cve_rebuilt.json"

CPE_DIR = DATA_DIR / "cpe"
CPE_ZIP_NAME = "official-cpe-dictionary_v2.3.xml.zip"
CPE_XML_NAME = "official-cpe-dictionary_v2.3.xml"
CPE_ALIAS_INDEX_JSON = CPE_DIR / "cpe_alias_index.json"

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
        pass
    return None

try:
    from .convert_nvd import convert_nvd_to_minimal
except ImportError:
    logger.critical(
        f"Failed relative import of '.convert_nvd'. "
        f"Ensure 'scripts/__init__.py' exists and 'convert_nvd.py' is in 'scripts/'. "
        "NVD data conversion will fail."
    )
    convert_nvd_to_minimal = None

NVD_BASE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/"
YEARS_TO_FETCH = 5 
CPE_DICT_URL = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip"

def download_file(url: str, dest_path: Path, session: requests.Session) -> bool:
    logger.info(f"Downloading: {url} to {dest_path}")
    try:
        response = session.get(url, stream=True, timeout=60)
        response.raise_for_status()
        with open(dest_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        logger.info(f"Successfully downloaded: {dest_path.name}")
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to download {url}: {e}")
    except Exception as e:
        logger.error(f"An error occurred while downloading {url}: {e}", exc_info=True)
    return False

def extract_gz(gz_path: Path, output_path: Path) -> bool:
    logger.info(f"Extracting: {gz_path.name} to {output_path.name}")
    try:
        with gzip.open(gz_path, "rb") as f_in:
            with open(output_path, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        logger.info(f"Successfully extracted: {output_path.name}")
        return True
    except Exception as e:
        logger.error(f"Failed to extract {gz_path.name}: {e}", exc_info=True)
    return False

def extract_zip(zip_path: Path, output_dir: Path) -> bool:
    logger.info(f"Extracting {zip_path.name} to {output_dir}...")
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref: 
            zip_ref.extractall(output_dir)
        logger.info(f"Successfully extracted {zip_path.name} to {output_dir}")
        return True
    except zipfile.BadZipFile:
        logger.error(f"Failed to extract {zip_path.name}: Invalid or corrupted ZIP file.")
    except Exception as e:
        logger.error(f"Failed to extract {zip_path.name}: {e}", exc_info=True)
    return False

def get_nvd_feeds_to_download(session: requests.Session) -> List[str]:
    feeds = []
    current_year = datetime.now().year
    for i in range(YEARS_TO_FETCH):
        year = current_year - i
        feeds.append(f"nvdcve-1.1-{year}.json.gz")
    feeds.append("nvdcve-1.1-modified.json.gz")
    return feeds

def download_nvd_data():
    NVD_FEED_DIR.mkdir(parents=True, exist_ok=True)
    session = requests.Session()
    feeds_to_download = get_nvd_feeds_to_download(session)
    downloaded_json_files = []

    logger.info("Downloading NVD yearly feeds...")
    for feed_name in feeds_to_download:
        feed_url = NVD_BASE_URL + feed_name
        gz_path = NVD_FEED_DIR / feed_name
        json_path = NVD_FEED_DIR / feed_name.replace(".gz", "")

        if download_file(feed_url, gz_path, session):
            if extract_gz(gz_path, json_path):
                downloaded_json_files.append(json_path)
            else:
                logger.warning(f"Skipping {json_path.name} due to extraction error.")
        else:
            logger.warning(f"Skipping {feed_name} due to download error.")
            
    return downloaded_json_files

def merge_nvd_json_files(json_files: List[Path], output_file: Path):
    logger.info(f"Merging {len(json_files)} JSON files from {NVD_FEED_DIR}...")
    all_cve_items = []
    total_cves = 0
    
    for json_file in json_files:
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                cve_items_in_file = data.get("CVE_Items", [])
                all_cve_items.extend(cve_items_in_file)
                total_cves += len(cve_items_in_file)
                logger.debug(f"Added {len(cve_items_in_file)} CVEs from {json_file.name}")
        except Exception as e:
            logger.error(f"Error processing file {json_file}: {e}", exc_info=True)
            
    merged_data = {"CVE_data_timestamp": datetime.now().isoformat(), "CVE_Items": all_cve_items}
    
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(merged_data, f, ensure_ascii=False) 
        logger.info(f"Merge complete: {output_file} ({total_cves} CVEs)")
    except Exception as e:
        logger.error(f"Error writing merged NVD file {output_file}: {e}", exc_info=True)

def clean_temp_json_files():
    logger.info(f"Cleaning up temporary JSON files (extracted from .gz)...")
    count = 0
    for item in NVD_FEED_DIR.glob("*.json"):
        if not item.name.endswith(".gz"): 
            try:
                item.unlink()
                count += 1
            except Exception as e:
                logger.error(f"Could not delete temporary file {item}: {e}")
    if count > 0:
        logger.info(f"{count} temporary JSON files removed from {NVD_FEED_DIR}.")

def download_cpe_dictionary_if_needed():
    CPE_DIR.mkdir(parents=True, exist_ok=True)
    cpe_zip_path = CPE_DIR / CPE_ZIP_NAME
    cpe_xml_path = CPE_DIR / CPE_XML_NAME

    if not cpe_xml_path.exists(): 
        logger.info(f"Downloading CPE Dictionary from {CPE_DICT_URL} to {cpe_zip_path}...")
        session = requests.Session()
        if download_file(CPE_DICT_URL, cpe_zip_path, session):
            if extract_zip(cpe_zip_path, CPE_DIR): # extract_zip agora usa zipfile
                try:
                    cpe_zip_path.unlink() 
                    logger.info(f"Removed temporary CPE zip file: {cpe_zip_path.name}")
                except OSError as e:
                    logger.warning(f"Could not remove temporary CPE zip file {cpe_zip_path.name}: {e}")
   
    else:
        logger.info(f"CPE XML dictionary already exists at {cpe_xml_path}. Skipping download.")

def generate_cpe_alias_index():
    logger.info("Starting generation of CPE alias index...")
    cpe_xml_file = CPE_DIR / CPE_XML_NAME
    output_index_file = CPE_ALIAS_INDEX_JSON

    if not cpe_xml_file.exists():
        logger.error(f"CPE Dictionary XML file not found at {cpe_xml_file}. Cannot generate alias index. Please run --update-nvd to download and extract it.")
        return

    alias_index: Dict[str, Set[str]] = defaultdict(set)
    cpe_items_processed = 0
    unique_canonical_names_referenced = set()

    try:
        logger.info(f"Parsing CPE XML dictionary from: {cpe_xml_file}. This may take some time...")
        
        context = ET.iterparse(cpe_xml_file, events=("end",))
        context_iter = iter(context)

        for event, elem in context_iter:
            if elem.tag.endswith("cpe-item") or elem.tag.endswith("cpe23-item"):
                cpe_items_processed += 1
                if cpe_items_processed % 200000 == 0: 
                    logger.info(f"Processed {cpe_items_processed} CPE items for alias index...")

                cpe_name_attr = elem.get("name") 
                if not cpe_name_attr:
                    elem.clear()
                    continue

                canonical_vendor_product = extract_vendor_product_name(cpe_name_attr)
                if not canonical_vendor_product:
                    elem.clear()
                    continue
                
                unique_canonical_names_referenced.add(canonical_vendor_product)

                product_part_key = canonical_vendor_product.split(":", 1)[-1]
                if product_part_key:
                    alias_index[product_part_key].add(canonical_vendor_product)
                
                titles_found = []
                for child in elem: 
                    if child.tag.endswith("title") and child.text:
                        lang_attr = child.get("{http://www.w3.org/XML/1998/namespace}lang", "").lower()
                        if "en" in lang_attr or not lang_attr:
                            titles_found.append(child.text.strip().lower())
                
                for title_text in titles_found:
                    if title_text and title_text != product_part_key: 
                        alias_index[title_text].add(canonical_vendor_product)
                elem.clear()

        logger.info(f"Finished parsing XML. Total CPE items processed: {cpe_items_processed}.")
        
        final_alias_index = {key: sorted(list(value_set)) for key, value_set in alias_index.items() if value_set}

        output_index_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_index_file, "w", encoding="utf-8") as f:
            json.dump(final_alias_index, f, indent=2, ensure_ascii=False)
        logger.info(f"✔️ CPE alias index successfully generated with {len(final_alias_index)} alias keys, referencing {len(unique_canonical_names_referenced)} unique canonical 'vendor:product' names, at: {output_index_file}")

    except ET.ParseError as e:
        logger.error(f"Error parsing CPE XML file {cpe_xml_file}: {e}", exc_info=True)
    except FileNotFoundError:
        logger.error(f"CPE XML file not found at {cpe_xml_file} during parsing.")
    except Exception as e:
        logger.error(f"An unexpected error occurred during CPE alias index generation: {e}", exc_info=True)

def main():
    logger.info("=== Starting NVD database update (last 5 years + modified) ===")
    
    downloaded_json_files = download_nvd_data()
    
    if downloaded_json_files:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        merge_nvd_json_files(downloaded_json_files, MERGED_NVD_JSON)
    else:
        logger.warning("No NVD feed files were downloaded. Skipping merge and conversion.")

    if MERGED_NVD_JSON.exists() and MERGED_NVD_JSON.stat().st_size > 0 :
        logger.info(f"Converting merged NVD ({MERGED_NVD_JSON}) to minimal format ({REBUILT_NVD_JSON})...")
        if convert_nvd_to_minimal:
            try:
                 convert_nvd_to_minimal(input_file=str(MERGED_NVD_JSON), output_file=str(REBUILT_NVD_JSON))
                 logger.info(f"Converted NVD file saved as: {REBUILT_NVD_JSON}")
            except Exception as e:
                 logger.error(f"Error during NVD conversion: {e}", exc_info=True)
        else:
             logger.error("Function 'convert_nvd_to_minimal' could not be imported. Cannot convert NVD.")
    elif downloaded_json_files :
        logger.error(f"Merged NVD file {MERGED_NVD_JSON} not found or is empty after attempted merge. Cannot convert.")

    clean_temp_json_files()

    logger.info("=== Processing CPE dictionary ===")
    download_cpe_dictionary_if_needed() 
    if (CPE_DIR / CPE_XML_NAME).exists(): 
        generate_cpe_alias_index()
    else:
        logger.error(f"CPE XML file {CPE_XML_NAME} not found in {CPE_DIR}. Skipping alias index generation.")

    logger.info("=== NVD and CPE update process completed (check logs for errors). ===")

if __name__ == "__main__":
    main()