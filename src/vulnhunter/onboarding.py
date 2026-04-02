from __future__ import annotations

import json
import pathlib
from typing import Any

import requests
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

BANNER = r"""
[cyan]██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
██║   ██║██║   ██║██║     ████╗  ██║██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██║   ██║██║   ██║██║     ██╔██╗ ██║███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝

                        Offline Vulnerability Scanner | v2.0[/cyan]
"""

CONFIG_DIR: pathlib.Path = pathlib.Path.home() / ".vulnhunter"
CONFIG_FILE: pathlib.Path = CONFIG_DIR / "config.json"

DEFAULT_CONFIG: dict[str, Any] = {
    "ai_triage_enabled": False,
    "model": "mistral",
    "ollama_url": "http://localhost:11434",
    "nvd_api_key": "",
    "language": "en",
}

MODEL_TIERS: list[dict[str, str]] = [
    {"name": "phi3", "params": "3.8B", "tier": "Light", "desc": "Basic triage"},
    {"name": "mistral", "params": "7B", "tier": "Medium", "desc": "Code analysis (RECOMMENDED)"},
    {"name": "llama3", "params": "8B", "tier": "Full", "desc": "Deep analysis"},
]

console = Console()


def load_config() -> dict[str, Any]:
    if not CONFIG_FILE.exists():
        return dict(DEFAULT_CONFIG)
    try:
        raw: str = CONFIG_FILE.read_text(encoding="utf-8")
        stored: dict[str, Any] = json.loads(raw)
        merged: dict[str, Any] = dict(DEFAULT_CONFIG)
        merged.update(stored)
        return merged
    except (json.JSONDecodeError, OSError):
        return dict(DEFAULT_CONFIG)


def save_config(config: dict[str, Any]) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(
        json.dumps(config, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def show_banner() -> None:
    console.print(BANNER)


def detect_ollama(ollama_url: str = "http://localhost:11434") -> tuple[bool, list[str]]:
    try:
        resp: requests.Response = requests.get(
            f"{ollama_url}/api/tags",
            timeout=5,
        )
        resp.raise_for_status()
        data: dict[str, Any] = resp.json()
        models: list[str] = [
            m.get("name", "") for m in data.get("models", []) if m.get("name")
        ]
        return True, models
    except (requests.RequestException, ValueError, KeyError):
        return False, []


def needs_setup() -> bool:
    return not CONFIG_FILE.exists()


def _show_model_table(installed_models: list[str]) -> None:
    table = Table(title="Recommended Models")
    table.add_column("Tier", style="bold")
    table.add_column("Model", style="cyan")
    table.add_column("Parameters")
    table.add_column("Description")
    table.add_column("Status")

    for tier_info in MODEL_TIERS:
        installed: bool = any(
            tier_info["name"] in m for m in installed_models
        )
        status: str = "[green]installed[/green]" if installed else "[yellow]not installed[/yellow]"
        table.add_row(
            tier_info["tier"],
            tier_info["name"],
            tier_info["params"],
            tier_info["desc"],
            status,
        )

    console.print(table)


def _show_installed_models(models: list[str]) -> None:
    if not models:
        return
    console.print("\n[bold]Installed models:[/bold]")
    for model in models:
        console.print(f"  - {model}")


def run_wizard() -> dict[str, Any]:
    show_banner()

    config: dict[str, Any] = load_config()

    console.print(
        Panel(
            "Welcome to VulnHunter setup wizard.\n"
            "This will configure your local environment for vulnerability scanning.",
            title="Setup",
            border_style="cyan",
        )
    )

    ollama_url: str = typer.prompt(
        "Ollama server URL",
        default=config["ollama_url"],
        type=str,
    )
    config["ollama_url"] = ollama_url

    console.print("\n[bold]Detecting Ollama...[/bold]")
    available, models = detect_ollama(ollama_url)

    if not available:
        console.print(
            Panel(
                "[yellow]Ollama was not detected.[/yellow]\n\n"
                "VulnHunter uses Ollama for local AI-powered vulnerability triage.\n"
                "Install it from: [bold cyan]https://ollama.com/download[/bold cyan]\n\n"
                "After installing, start it with: [bold]ollama serve[/bold]\n"
                "Then re-run this wizard.",
                title="Ollama Not Found",
                border_style="yellow",
            )
        )
        enable_ai: bool = False
        selected_model: str = config["model"]
    else:
        console.print("[green]Ollama detected successfully.[/green]\n")
        _show_installed_models(models)
        console.print()
        _show_model_table(models)
        console.print()

        enable_ai = typer.confirm(
            "Enable AI-powered vulnerability triage?",
            default=True,
        )

        default_model: str = "mistral"
        for tier_info in MODEL_TIERS:
            match: list[str] = [m for m in models if tier_info["name"] in m]
            if match:
                default_model = match[0]
                break

        selected_model = typer.prompt(
            "Select model",
            default=default_model,
            type=str,
        )

        model_choices: list[str] = [t["name"] for t in MODEL_TIERS]
        if selected_model not in model_choices and not any(selected_model in m for m in models):
            console.print(
                f"[yellow]'{selected_model}' is not in the recommended list, "
                f"but will be used if available in Ollama.[/yellow]"
            )

        if enable_ai and not any(selected_model in m for m in models):
            console.print(
                f"\n[yellow]Model '{selected_model}' is not installed in Ollama.[/yellow]"
            )
            console.print(
                f"Pull it with: [bold]ollama pull {selected_model}[/bold]\n"
            )

    config["ai_triage_enabled"] = enable_ai
    config["model"] = selected_model

    nvd_key: str = typer.prompt(
        "NVD API key (optional, press Enter to skip)",
        default=config.get("nvd_api_key", ""),
        type=str,
    )
    config["nvd_api_key"] = nvd_key

    language: str = typer.prompt(
        "Preferred language",
        default=config["language"],
        type=str,
    )
    config["language"] = language

    db_path: pathlib.Path = pathlib.Path.home() / ".vulnhunter" / "vulndb"
    if not db_path.exists():
        console.print(
            "\n[yellow]Vulnerability database not found.[/yellow]"
        )
        download_db: bool = typer.confirm(
            "Download vulnerability database now?",
            default=True,
        )
        if download_db:
            console.print(
                "[bold]Run [cyan]vulnhunter db update[/cyan] after setup to download the database.[/bold]"
            )

    save_config(config)

    console.print(
        Panel(
            f"[green]Configuration saved to {CONFIG_FILE}[/green]\n\n"
            f"  AI Triage:  {'enabled' if config['ai_triage_enabled'] else 'disabled'}\n"
            f"  Model:      {config['model']}\n"
            f"  Ollama URL: {config['ollama_url']}\n"
            f"  Language:   {config['language']}\n\n"
            "Run [bold cyan]vulnhunter scan <target>[/bold cyan] to start scanning.",
            title="Setup Complete",
            border_style="green",
        )
    )

    return config
