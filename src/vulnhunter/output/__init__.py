import logging
from pathlib import Path

from vulnhunter.models import ScanResult

logger = logging.getLogger(__name__)


def render_output(result: ScanResult, format: str, output_path: Path | None) -> None:
    if format == "table":
        from vulnhunter.output.table import render_table

        render_table(result)
        return

    if output_path is None:
        raise ValueError(f"output_path is required for format '{format}'")

    if format == "json":
        from vulnhunter.output.json_report import render_json

        render_json(result, output_path)
    elif format == "sarif":
        from vulnhunter.output.sarif import render_sarif

        render_sarif(result, output_path)
    else:
        raise ValueError(f"Unknown output format: {format}")

    logger.info("Report written to %s", output_path)
