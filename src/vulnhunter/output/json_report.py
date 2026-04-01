import json
import logging
from pathlib import Path

from vulnhunter.models import ScanResult

logger = logging.getLogger(__name__)


def _validate_output_path(output_path: Path, base_dir: Path | None = None) -> Path:
    resolved = output_path.resolve()
    base = (base_dir or Path.cwd()).resolve()
    if not resolved.is_relative_to(base):
        raise ValueError(f"Output path must be inside base directory: {base}")
    return resolved


def render_json(result: ScanResult, output_path: Path, base_dir: Path | None = None) -> None:
    safe_path = _validate_output_path(output_path, base_dir)
    safe_path.parent.mkdir(parents=True, exist_ok=True)

    data = result.model_dump(mode="json")

    safe_path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    logger.info("JSON report written to %s", safe_path)
