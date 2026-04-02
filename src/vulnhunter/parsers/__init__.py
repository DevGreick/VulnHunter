import logging
from pathlib import Path

from vulnhunter.models import Dependency
from vulnhunter.parsers.base import Parser
from vulnhunter.parsers.golang import GolangParser
from vulnhunter.parsers.java import JavaParser
from vulnhunter.parsers.nodejs import NodejsParser
from vulnhunter.parsers.php import PhpParser
from vulnhunter.parsers.python import PythonParser
from vulnhunter.parsers.ruby import RubyParser
from vulnhunter.parsers.rust import RustParser

logger: logging.Logger = logging.getLogger(__name__)

SUPPORTED_FILES: list[str] = [
    "requirements.txt",
    "package.json",
    "pom.xml",
    "composer.json",
    "gemfile.lock",
    "go.mod",
    "cargo.toml",
    "cargo.lock",
]

_PARSER_MAP: dict[str, Parser] = {
    "requirements.txt": PythonParser(),
    "package.json": NodejsParser(),
    "pom.xml": JavaParser(),
    "composer.json": PhpParser(),
    "gemfile.lock": RubyParser(),
    "go.mod": GolangParser(),
    "cargo.toml": RustParser(),
    "cargo.lock": RustParser(),
}


_DISPATCH_RULES: list[tuple[str, str, Parser]] = [
    ("requirements", ".txt", PythonParser()),
    ("package", ".json", NodejsParser()),
    ("pom", ".xml", JavaParser()),
    ("composer", ".json", PhpParser()),
    ("gemfile", ".lock", RubyParser()),
    ("go", ".mod", GolangParser()),
    ("cargo", ".toml", RustParser()),
    ("cargo", ".lock", RustParser()),
]


def _resolve_parser(filename: str) -> Parser | None:
    name_lower = filename.lower()
    if "lock" in name_lower and "gemfile" not in name_lower:
        return None
    for prefix, suffix, parser in _DISPATCH_RULES:
        if prefix in name_lower and name_lower.endswith(suffix):
            return parser
    return None


def parse_file(file_path: Path) -> list[Dependency]:
    filename: str = file_path.name
    parser: Parser | None = _resolve_parser(filename)

    if parser is None:
        logger.warning("No parser available for: %s", filename)
        return []

    logger.info("Parsing %s with %s", file_path, type(parser).__name__)
    return parser.parse(file_path)
