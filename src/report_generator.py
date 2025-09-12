# src/report_generator.py
import json
import logging
from pathlib import Path
from typing import List


try:
    from .models import Vulnerability
except ImportError:
    from models import Vulnerability

logger = logging.getLogger("report_generator")

def generate_json_report(vulnerabilities: List[Vulnerability], output_path: Path):
    """
    Gera um relatório JSON com as vulnerabilidades encontradas como uma lista de objetos.
    """
    report_data = []
    for vuln in vulnerabilities:
        report_data.append({
            "name": vuln.name,
            "version": vuln.version,
            "cve_id": vuln.cve_id,
            "severity": vuln.severity,
            "summary": vuln.summary.strip()
        })

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        logger.info(f"Relatório JSON gerado com sucesso em: {output_path}")
    except IOError as e:
        logger.error(f"Erro de I/O ao escrever o relatório em {output_path}: {e}")
    except Exception as e:
        logger.error(f"Um erro inesperado ocorreu durante a geração do relatório JSON: {e}", exc_info=True)


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING)
    logger = logging.getLogger("report_generator")
    logger.warning("Este módulo não foi projetado para ser executado diretamente.")