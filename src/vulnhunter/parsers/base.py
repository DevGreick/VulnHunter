import logging
import platform
import subprocess
from pathlib import Path
from typing import Protocol, runtime_checkable

from vulnhunter.models import Dependency

logger: logging.Logger = logging.getLogger(__name__)


@runtime_checkable
class Parser(Protocol):
    def parse(self, file_path: Path) -> list[Dependency]: ...


def _execute_command(cmd: list[str], cwd: Path) -> str | None:
    try:
        result: subprocess.CompletedProcess[str] = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            logger.warning(
                "Command %s exited with code %d: %s",
                cmd[0],
                result.returncode,
                result.stderr.strip()[:200],
            )
            return None
        return result.stdout
    except FileNotFoundError:
        logger.debug("Command not found: %s", cmd[0])
        return None
    except subprocess.TimeoutExpired:
        logger.warning("Command timed out: %s", cmd[0])
        return None
    except subprocess.CalledProcessError as exc:
        logger.warning("Command failed: %s — %s", cmd[0], str(exc)[:200])
        return None


def _resolve_platform_command(base: str) -> str:
    if platform.system() == "Windows":
        mapping: dict[str, str] = {
            "mvn": "mvn.cmd",
            "npm": "npm.cmd",
            "composer": "composer.bat",
        }
        return mapping.get(base, base)
    return base
