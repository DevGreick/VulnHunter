import logging
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from vulnhunter.db.store import VulnDB
from vulnhunter.models import ECOSYSTEM_FROM_FILE, OSV_ECOSYSTEM_MAP, Dependency, Ecosystem

app = typer.Typer(
    name="vulnhunter",
    help="Offline vulnerability scanner for project dependencies.",
    no_args_is_help=True,
)
db_app = typer.Typer(help="Manage the local vulnerability database.")
app.add_typer(db_app, name="db")

console = Console(stderr=True)
logger = logging.getLogger("vulnhunter.cli")

SUPPORTED_FILES = list(ECOSYSTEM_FROM_FILE.keys())


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(levelname)s:%(name)s:%(message)s",
        handlers=[logging.StreamHandler(sys.stderr)],
    )


MAX_SCAN_DEPTH = 10
SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", ".tox", "vendor"}


def _find_dependency_files(paths: list[Path]) -> dict[Ecosystem, list[Path]]:
    result: dict[Ecosystem, list[Path]] = {}
    for path in paths:
        if path.is_file():
            name_lower = path.name.lower()
            eco = ECOSYSTEM_FROM_FILE.get(name_lower)
            if eco:
                result.setdefault(eco, []).append(path)
        elif path.is_dir():
            _walk_dir(path, result, depth=0)
    return result


def _walk_dir(directory: Path, result: dict[Ecosystem, list[Path]], depth: int) -> None:
    if depth > MAX_SCAN_DEPTH:
        return
    try:
        entries = sorted(directory.iterdir())
    except PermissionError:
        return
    for entry in entries:
        if entry.is_file():
            eco = ECOSYSTEM_FROM_FILE.get(entry.name.lower())
            if eco:
                result.setdefault(eco, []).append(entry)
        elif entry.is_dir() and entry.name not in SKIP_DIRS:
            _walk_dir(entry, result, depth + 1)


def _parse_dependencies(files_by_eco: dict[Ecosystem, list[Path]]) -> list[Dependency]:
    from vulnhunter.parsers import parse_file

    all_deps: set[Dependency] = set()
    for eco, files in files_by_eco.items():
        for file_path in files:
            logger.info("Parsing %s (%s)", file_path, eco.value)
            deps = parse_file(file_path)
            for dep in deps:
                all_deps.add(dep)
    return list(all_deps)


def _detect_ecosystems(deps: list[Dependency]) -> list[str]:
    seen: set[str] = set()
    for dep in deps:
        osv_name = OSV_ECOSYSTEM_MAP.get(dep.ecosystem)
        if osv_name:
            seen.add(osv_name)
    return sorted(seen)


@app.command()
def scan(
    paths: list[Path] = typer.Argument(
        ...,
        help="Files or directories to scan for dependency files.",
        exists=True,
    ),
    format: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format: table, json, sarif",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path (required for json/sarif).",
    ),
    severity: str | None = typer.Option(
        None,
        "--severity",
        "-s",
        help="Minimum severity filter: critical, high, medium, low",
    ),
    ignore_file: Path = typer.Option(
        Path(".vulnignore"),
        "--ignore-file",
        help="Path to .vulnignore file.",
    ),
    db_path: Path | None = typer.Option(
        None,
        "--db",
        help="Path to vulnerability database.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    _setup_logging(verbose)

    db = VulnDB(db_path)
    stats = db.stats()
    if stats["vulnerabilities"] == 0:
        console.print(
            "[bold yellow]Warning:[/] Database is empty. Run 'vulnhunter db update' first.",
        )
        raise typer.Exit(1)

    files_by_eco = _find_dependency_files(paths)
    if not files_by_eco:
        console.print("[bold yellow]No supported dependency files found.[/]")
        raise typer.Exit(0)

    total_files = sum(len(f) for f in files_by_eco.values())
    console.print(f"Found [bold]{total_files}[/] dependency file(s)")

    deps = _parse_dependencies(files_by_eco)
    if not deps:
        console.print("[bold yellow]No dependencies parsed.[/]")
        raise typer.Exit(0)

    console.print(f"Parsed [bold]{len(deps)}[/] unique dependencies")

    from vulnhunter.analyzer import analyze

    result = analyze(db, deps, ignore_file)

    if severity:
        severity_order = ["critical", "high", "medium", "low", "unknown"]
        min_idx = severity_order.index(severity.lower()) if severity.lower() in severity_order else 0
        allowed = set(s.upper() for s in severity_order[: min_idx + 1])
        result.vulnerabilities = [v for v in result.vulnerabilities if v.severity.value in allowed]
        result.total_vulnerabilities = len(result.vulnerabilities)

    VALID_FORMATS = {"table", "json", "sarif"}
    if format not in VALID_FORMATS:
        console.print(f"[bold red]Invalid format '{format}'. Must be one of: {', '.join(sorted(VALID_FORMATS))}[/]")
        raise typer.Exit(1)

    from vulnhunter.output import render_output

    if format in ("json", "sarif") and output is None:
        output = Path(f"reports/report.{format}")

    render_output(result, format, output)

    db.close()

    if result.total_vulnerabilities > 0:
        raise typer.Exit(1)


@db_app.command("update")
def db_update(
    ecosystem: list[str] | None = typer.Option(
        None,
        "--ecosystem",
        "-e",
        help="Ecosystems to update (e.g., PyPI npm). Default: auto-detect or all.",
    ),
    all_ecosystems: bool = typer.Option(
        False,
        "--all",
        help="Download all ecosystems.",
    ),
    source: str | None = typer.Option(
        None,
        "--source",
        help="Data source: osv, nvd, or both (default: osv).",
    ),
    nvd_api_key: str = typer.Option(
        "",
        "--nvd-api-key",
        help="NVD API key. Also reads from NVD_API_KEY env var or .env file.",
    ),
    db_path: Path | None = typer.Option(None, "--db"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    _setup_logging(verbose)

    db = VulnDB(db_path)
    effective_source = source or "osv"

    if effective_source in ("nvd", "both"):
        from vulnhunter.sources.nvd import _resolve_api_key

        if not _resolve_api_key(nvd_api_key):
            console.print(
                "[bold yellow]No NVD API key found.[/] Requests will be rate-limited to 1 every 6s.\n"
                "Set it via: --nvd-api-key, NVD_API_KEY env var, or .env file.\n"
                "Get a free key at: [link]https://nvd.nist.gov/developers/request-an-api-key[/link]"
            )

    if effective_source in ("osv", "both"):
        from vulnhunter.sources.osv import update_osv

        if all_ecosystems:
            eco_list = list(OSV_ECOSYSTEM_MAP.values())
        elif ecosystem:
            eco_list = ecosystem
        else:
            eco_list = list(OSV_ECOSYSTEM_MAP.values())

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Updating OSV database...", total=None)
            count = update_osv(db, eco_list)
            progress.update(task, description=f"OSV: {count} vulnerabilities loaded")

        console.print(f"[bold green]OSV update complete:[/] {count} vulnerabilities")

    if effective_source in ("nvd", "both"):
        from vulnhunter.sources.nvd import update_nvd

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Updating NVD database...", total=None)
            count = update_nvd(db, api_key=nvd_api_key)
            progress.update(task, description=f"NVD: {count} vulnerabilities loaded")

        console.print(f"[bold green]NVD update complete:[/] {count} vulnerabilities")

    db.close()


@db_app.command("info")
def db_info(
    db_path: Path | None = typer.Option(None, "--db"),
) -> None:
    db = VulnDB(db_path)
    stats = db.stats()

    last_osv = db.get_metadata("osv_last_update") or "never"
    last_nvd = db.get_metadata("nvd_last_update") or "never"

    from rich.table import Table

    table = Table(title="VulnHunter Database")
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    table.add_row("Vulnerabilities", str(stats["vulnerabilities"]))
    table.add_row("Packages tracked", str(stats["packages"]))
    table.add_row("CPE aliases", str(stats["cpe_aliases"]))
    table.add_row("Last OSV update", last_osv)
    table.add_row("Last NVD update", last_nvd)
    table.add_row("Database path", str(db.db_path))

    console.print(table)
    db.close()


if __name__ == "__main__":
    app()
