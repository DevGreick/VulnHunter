import logging
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from vulnhunter.db.store import VulnDB
from vulnhunter.models import ECOSYSTEM_FROM_FILE, OSV_ECOSYSTEM_MAP, Dependency, Ecosystem, ScanResult


def _default_callback(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        from vulnhunter.onboarding import needs_setup, run_wizard, show_banner

        if needs_setup():
            run_wizard()
        else:
            show_banner()
            console.print("Run [bold cyan]vulnhunter scan <target>[/bold cyan] to start scanning.\n")
            console.print("Use [bold]--help[/bold] for available commands.\n")


app = typer.Typer(
    name="vulnhunter",
    help="Offline vulnerability scanner for project dependencies.",
    invoke_without_command=True,
    callback=_default_callback,
    add_completion=False,
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


@app.command(help="Run the setup wizard to configure VulnHunter.")
def init() -> None:
    from vulnhunter.onboarding import run_wizard

    run_wizard()


@app.command(help="Show or change current settings.")
def config() -> None:
    from vulnhunter.onboarding import load_config, run_wizard, show_banner

    cfg = load_config()
    show_banner()

    from rich.table import Table

    table = Table(title="Current Configuration")
    table.add_column("Setting", style="bold")
    table.add_column("Value")
    table.add_row("AI Triage", "enabled" if cfg.get("ai_triage_enabled") else "disabled")
    table.add_row("Model", cfg.get("model", "mistral"))
    table.add_row("Ollama URL", cfg.get("ollama_url", "http://localhost:11434"))
    table.add_row("Language", cfg.get("language", "en"))
    console.print(table)

    if typer.confirm("\nReconfigure?", default=False):
        run_wizard()


@app.command(
    help="Scan a project for known vulnerabilities.",
    epilog=(
        "Examples:\n\n"
        "  vulnhunter scan .                        Scan current directory\n"
        "  vulnhunter scan . --ai-triage             Scan + AI analysis via Ollama\n"
        "  vulnhunter scan . -s critical             Show only critical vulnerabilities\n"
        "  vulnhunter scan . -f sarif -o report.sarif Export for GitHub Code Scanning\n"
    ),
)
def scan(
    paths: list[Path] = typer.Argument(
        ...,
        help="Project folder or specific dependency file (e.g. requirements.txt, package.json).",
        exists=True,
    ),
    format: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format: table (terminal), json (report), sarif (GitHub/VS Code).",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Save report to file. Auto-set for json/sarif if omitted.",
    ),
    severity: str | None = typer.Option(
        None,
        "--severity",
        "-s",
        help="Only show vulnerabilities at this level or above: critical, high, medium, low.",
    ),
    ignore_file: Path = typer.Option(
        Path(".vulnignore"),
        "--ignore-file",
        help="File with CVE IDs to ignore (one per line).",
    ),
    db_path: Path | None = typer.Option(
        None,
        "--db",
        help="Custom path to vulnerability database.",
    ),
    ai_triage: bool = typer.Option(
        False,
        "--ai-triage",
        help="Use local AI (Ollama) to analyze each vulnerability in your code context.",
    ),
    model: str = typer.Option(
        "",
        "--model",
        help="AI model to use (e.g. llama3:8b, mistral). Uses config default if omitted.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed logs."),
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

    _run_ai_triage(result, paths, ai_triage, model)

    db.close()

    if result.total_vulnerabilities > 0:
        raise typer.Exit(1)


def _run_ai_triage(result: ScanResult, paths: list[Path], ai_triage: bool, model: str) -> None:
    from vulnhunter.onboarding import load_config

    cfg = load_config()
    should_triage = ai_triage or cfg.get("ai_triage_enabled", False)

    if not should_triage:
        return

    if not hasattr(result, "vulnerabilities") or not result.vulnerabilities:
        return

    effective_model = model or cfg.get("model", "mistral")
    ollama_url = cfg.get("ollama_url", "http://localhost:11434")
    lang = cfg.get("language", "en")

    from vulnhunter.ai.triage import TriageEngine

    engine = TriageEngine(model=effective_model, ollama_url=ollama_url, language=lang)

    if not engine.is_available():
        msg_unavail = {
            "pt": "\n[bold yellow]Triagem IA:[/] Ollama nao disponivel. "
                  "Inicie com [bold]ollama serve[/bold] ou desative no config.",
            "en": "\n[bold yellow]AI Triage:[/] Ollama is not available. "
                  "Start it with [bold]ollama serve[/bold] or disable in config.",
        }
        console.print(msg_unavail.get(lang, msg_unavail["en"]))
        return

    vuln_dicts = [
        {
            "id": v.vuln_id,
            "package": v.name,
            "version": v.version,
            "severity": v.severity.value,
            "summary": v.summary,
            "ecosystem": v.ecosystem.value if v.ecosystem else "",
        }
        for v in result.vulnerabilities
    ]

    project_dir = paths[0] if paths[0].is_dir() else paths[0].parent

    analyzing_txt = "Analisando" if lang == "pt" else "Analyzing"
    n = len(vuln_dicts)
    if lang == "pt":
        msg = f"\n[bold cyan]Triagem IA[/bold cyan] ({effective_model}) analisando {n} vulnerabilidades...\n"
    else:
        msg = f"\n[bold cyan]AI Triage[/bold cyan] ({effective_model}) analyzing {n} vulnerabilities...\n"
    console.print(msg)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(f"{analyzing_txt}...", total=len(vuln_dicts))

        def _progress_cb(current: int, total: int) -> None:
            progress.update(task, completed=current, description=f"{analyzing_txt} {current}/{total}...")

        triage_results = engine.triage_all(vuln_dicts, project_dir, callback=_progress_cb)

    from rich.table import Table

    title = "Resultados da Triagem IA" if lang == "pt" else "AI Triage Results"
    col_risk = "Risco Real" if lang == "pt" else "Real Risk"
    col_analysis = "Analise" if lang == "pt" else "Analysis"
    col_action = "Acao" if lang == "pt" else "Action"

    table = Table(title=title, show_lines=True)
    table.add_column("CVE", style="bold", width=18)
    table.add_column("Package", width=15)
    table.add_column("CVSS", width=10)
    table.add_column(col_risk, width=12)
    table.add_column(col_analysis, width=40)
    table.add_column(col_action, width=30)

    risk_colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
        "IRRELEVANT": "dim",
        "UNKNOWN": "dim",
    }

    for tr in triage_results:
        vuln = tr["vuln"]
        triage = tr["triage"]
        risk = triage.get("real_risk", "UNKNOWN")
        color = risk_colors.get(risk, "dim")
        table.add_row(
            vuln.get("id", ""),
            vuln.get("package", ""),
            vuln.get("severity", ""),
            f"[{color}]{risk}[/{color}]",
            triage.get("analysis", ""),
            triage.get("recommendation", ""),
        )

    console.print(table)


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


@db_app.command("download")
def db_download(
    db_path: Path | None = typer.Option(None, "--db"),
    repo: str = typer.Option(
        "DevGreick/VulnHunter",
        "--repo",
        help="GitHub repo to download from.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    _setup_logging(verbose)

    import gzip
    import tempfile

    import requests

    target = db_path or (Path.home() / ".vulnhunter" / "vulnhunter.db")
    target.parent.mkdir(parents=True, exist_ok=True)

    release_url = f"https://api.github.com/repos/{repo}/releases/tags/db-latest"

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Fetching release info...", total=None)

        try:
            resp = requests.get(release_url, timeout=30)
            if resp.status_code != 200:
                console.print(f"[bold red]Failed to fetch release:[/] HTTP {resp.status_code}")
                raise typer.Exit(1)

            assets = resp.json().get("assets", [])
            db_asset = None
            for asset in assets:
                if asset["name"].endswith(".db.gz"):
                    db_asset = asset
                    break

            if not db_asset:
                console.print("[bold red]No database asset found in release.[/]")
                raise typer.Exit(1)

            download_url = db_asset["browser_download_url"]
            size_mb = db_asset.get("size", 0) / (1024 * 1024)
            progress.update(task, description=f"Downloading database ({size_mb:.1f} MB)...")

            dl_resp = requests.get(download_url, timeout=300, stream=True)
            if dl_resp.status_code != 200:
                console.print(f"[bold red]Download failed:[/] HTTP {dl_resp.status_code}")
                raise typer.Exit(1)

            with tempfile.NamedTemporaryFile(delete=False, suffix=".db.gz") as tmp:
                for chunk in dl_resp.iter_content(chunk_size=8192):
                    tmp.write(chunk)
                tmp_path = Path(tmp.name)

            progress.update(task, description="Extracting database...")

            with gzip.open(tmp_path, "rb") as gz_in:
                target.write_bytes(gz_in.read())

            tmp_path.unlink(missing_ok=True)

        except requests.RequestException as exc:
            console.print(f"[bold red]Network error:[/] {exc}")
            raise typer.Exit(1) from None

    db = VulnDB(target)
    stats = db.stats()
    db.close()

    console.print(
        f"[bold green]Database ready:[/] {stats['vulnerabilities']} vulnerabilities, "
        f"{stats['packages']} packages"
    )
    console.print(f"Saved to: {target}")


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
