from __future__ import annotations

import json
import locale
import pathlib
from typing import Any

import requests
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from vulnhunter.validators import validate_ollama_url

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
DB_FILE: pathlib.Path = CONFIG_DIR / "vulnhunter.db"

DEFAULT_CONFIG: dict[str, Any] = {
    "ai_triage_enabled": False,
    "model": "mistral",
    "ollama_url": "http://localhost:11434",
    "language": "en",
}

MODEL_TIERS: list[dict[str, str]] = [
    {
        "name": "phi3", "params": "3.8B", "tier": "Light",
        "desc_en": "Basic triage", "desc_pt": "Triagem basica",
    },
    {
        "name": "mistral", "params": "7B", "tier": "Medium",
        "desc_en": "Code analysis (RECOMMENDED)", "desc_pt": "Analise de codigo (RECOMENDADO)",
    },
    {
        "name": "llama3", "params": "8B", "tier": "Full",
        "desc_en": "Deep analysis", "desc_pt": "Analise profunda",
    },
]

_STRINGS: dict[str, dict[str, str]] = {
    "welcome_title": {"en": "Setup", "pt": "Configuracao"},
    "welcome_body": {
        "en": (
            "Welcome to VulnHunter!\n\n"
            "This wizard will set up your environment for offline vulnerability scanning.\n"
            "VulnHunter can use a local AI (Ollama) to analyze vulnerabilities in your code.\n\n"
            "Let's check if everything is ready."
        ),
        "pt": (
            "Bem-vindo ao VulnHunter!\n\n"
            "Este assistente vai configurar seu ambiente para scan offline de vulnerabilidades.\n"
            "O VulnHunter pode usar uma IA local (Ollama) para analisar vulnerabilidades no seu codigo.\n\n"
            "Vamos verificar se esta tudo pronto."
        ),
    },
    "checking_ollama": {
        "en": "Checking for Ollama (local AI engine)...",
        "pt": "Verificando Ollama (engine de IA local)...",
    },
    "ollama_detected": {
        "en": "Ollama detected successfully.",
        "pt": "Ollama detectado com sucesso.",
    },
    "ollama_not_found_title": {
        "en": "Ollama Not Found",
        "pt": "Ollama Nao Encontrado",
    },
    "ollama_not_found_body": {
        "en": (
            "VulnHunter uses Ollama for local AI-powered vulnerability triage.\n"
            "Install it from: [bold cyan]https://ollama.com/download[/bold cyan]\n\n"
            "After installing, start it with: [bold]ollama serve[/bold]\n"
            "Then run [bold]vulnhunter init[/bold] again."
        ),
        "pt": (
            "O VulnHunter usa o Ollama para triagem de vulnerabilidades com IA local.\n"
            "Instale em: [bold cyan]https://ollama.com/download[/bold cyan]\n\n"
            "Apos instalar, inicie com: [bold]ollama serve[/bold]\n"
            "Depois rode [bold]vulnhunter init[/bold] novamente."
        ),
    },
    "ollama_custom_url": {
        "en": "Is Ollama running on a different address?",
        "pt": "O Ollama esta rodando em outro endereco?",
    },
    "ollama_url_prompt": {
        "en": "Ollama URL",
        "pt": "URL do Ollama",
    },
    "ollama_found": {
        "en": "Ollama detected!",
        "pt": "Ollama detectado!",
    },
    "ollama_still_unreachable": {
        "en": "Still not reachable. Continuing without AI.",
        "pt": "Ainda nao acessivel. Continuando sem IA.",
    },
    "recommended_models": {
        "en": "Recommended Models",
        "pt": "Modelos Recomendados",
    },
    "enable_ai": {
        "en": "Enable AI-powered vulnerability triage?",
        "pt": "Ativar triagem de vulnerabilidades com IA?",
    },
    "select_model": {
        "en": "Select model (number)",
        "pt": "Escolha o modelo (numero)",
    },
    "invalid_choice": {
        "en": "Invalid choice. Pick a number from the list.",
        "pt": "Opcao invalida. Escolha um numero da lista.",
    },
    "custom_model": {
        "en": "Custom model",
        "pt": "Modelo customizado",
    },
    "model_not_installed_pull": {
        "en": "not installed — pull with: [bold]ollama pull {model}[/bold]",
        "pt": "nao instalado — baixe com: [bold]ollama pull {model}[/bold]",
    },
    "db_not_found": {
        "en": "Vulnerability database not found.",
        "pt": "Banco de vulnerabilidades nao encontrado.",
    },
    "db_download_ask": {
        "en": "Download pre-built database from GitHub? (recommended)",
        "pt": "Baixar banco pre-construido do GitHub? (recomendado)",
    },
    "db_downloading": {
        "en": "Downloading database...",
        "pt": "Baixando banco de dados...",
    },
    "db_download_hint": {
        "en": "Run [cyan]vulnhunter db download[/cyan] later to get the database.",
        "pt": "Rode [cyan]vulnhunter db download[/cyan] depois para obter o banco.",
    },
    "setup_complete_title": {
        "en": "Setup Complete",
        "pt": "Configuracao Concluida",
    },
    "setup_complete_scan": {
        "en": "Run [bold cyan]vulnhunter scan <target>[/bold cyan] to start scanning.",
        "pt": "Rode [bold cyan]vulnhunter scan <target>[/bold cyan] para iniciar o scan.",
    },
    "ai_triage_label": {"en": "AI Triage", "pt": "Triagem IA"},
    "enabled": {"en": "enabled", "pt": "ativado"},
    "disabled": {"en": "disabled", "pt": "desativado"},
    "nvd_ask": {
        "en": "Do you have an NVD API key? (speeds up database updates)",
        "pt": "Voce tem uma API key do NVD? (acelera atualizacoes do banco)",
    },
    "nvd_key_prompt": {
        "en": "NVD API key",
        "pt": "API key do NVD",
    },
    "nvd_saved": {
        "en": "NVD API key saved securely in system keyring.",
        "pt": "API key do NVD salva com seguranca no keyring do sistema.",
    },
    "nvd_save_failed": {
        "en": "Could not save to keyring. Set NVD_API_KEY as environment variable instead.",
        "pt": "Nao foi possivel salvar no keyring. Defina NVD_API_KEY como variavel de ambiente.",
    },
    "nvd_get_key": {
        "en": "Get a free key at: [bold cyan]https://nvd.nist.gov/developers/request-an-api-key[/bold cyan]",
        "pt": "Obtenha uma key gratuita em: [bold cyan]https://nvd.nist.gov/developers/request-an-api-key[/bold cyan]",
    },
    "nvd_skip": {
        "en": "No problem. VulnHunter works without it, just slower on NVD updates.",
        "pt": "Sem problema. O VulnHunter funciona sem ela, so fica mais lento nas atualizacoes do NVD.",
    },
    "dep_tools_title": {
        "en": "Transitive Dependency Tools",
        "pt": "Ferramentas de Dependencias Transitivas",
    },
    "dep_tools_desc": {
        "en": (
            "VulnHunter can detect transitive dependencies (deps of your deps) "
            "using ecosystem-specific tools.\n"
            "[yellow]Without these tools, only direct dependencies will be scanned. "
            "Hidden vulnerabilities in sub-dependencies will NOT be detected.[/yellow]"
        ),
        "pt": (
            "O VulnHunter detecta dependencias transitivas (deps das suas deps) "
            "usando ferramentas de cada ecossistema.\n"
            "[yellow]Sem essas ferramentas, apenas dependencias diretas serao escaneadas. "
            "Vulnerabilidades ocultas em sub-dependencias NAO serao detectadas.[/yellow]"
        ),
    },
    "dep_tools_install_ask": {
        "en": "Install missing Python tools? (pipdeptree)",
        "pt": "Instalar ferramentas Python faltando? (pipdeptree)",
    },
    "dep_tools_installing": {
        "en": "Installing",
        "pt": "Instalando",
    },
    "dep_tools_installed": {
        "en": "installed",
        "pt": "instalado",
    },
    "dep_tools_install_failed": {
        "en": "Failed to install",
        "pt": "Falha ao instalar",
    },
}

console = Console()


def _detect_language() -> str:
    try:
        loc: str = locale.getdefaultlocale()[0] or ""
    except ValueError:
        loc = ""
    if loc.startswith("pt"):
        return "pt"
    return "en"


def _t(key: str, lang: str) -> str:
    entry = _STRINGS.get(key, {})
    return entry.get(lang, entry.get("en", key))


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


def detect_ollama(
    ollama_url: str = "http://localhost:11434",
) -> tuple[bool, list[dict[str, str]]]:
    try:
        resp: requests.Response = requests.get(
            f"{ollama_url}/api/tags",
            timeout=5,
        )
        resp.raise_for_status()
        data: dict[str, Any] = resp.json()
        models: list[dict[str, str]] = []
        for m in data.get("models", []):
            name: str = m.get("name", "")
            if not name:
                continue
            details: dict[str, Any] = m.get("details", {})
            param_size: str = details.get("parameter_size", "")
            models.append({"name": name, "params": param_size})
        return True, models
    except (requests.RequestException, ValueError, KeyError):
        return False, []


def needs_setup() -> bool:
    return not CONFIG_FILE.exists()


DEP_TOOLS: list[dict[str, str]] = [
    {"name": "pipdeptree", "ecosystem": "Python", "install": "pip install pipdeptree", "check": "pipdeptree"},
    {"name": "npm", "ecosystem": "Node.js", "install": "https://nodejs.org", "check": "npm"},
    {"name": "mvn", "ecosystem": "Java", "install": "https://maven.apache.org", "check": "mvn"},
    {"name": "composer", "ecosystem": "PHP", "install": "https://getcomposer.org", "check": "composer"},
    {"name": "go", "ecosystem": "Go", "install": "https://go.dev/dl", "check": "go"},
]


def _check_tool(cmd: str) -> bool:
    import shutil

    return shutil.which(cmd) is not None


def _show_dep_tools(lang: str) -> None:
    import subprocess

    console.print(f"\n[bold]{_t('dep_tools_desc', lang)}[/bold]\n")

    table = Table(title=_t("dep_tools_title", lang))
    table.add_column("Ecosystem", style="bold")
    table.add_column("Tool", style="cyan")
    table.add_column("Status")
    table.add_column("Install")

    missing_pip: list[str] = []

    for tool in DEP_TOOLS:
        found: bool = _check_tool(tool["check"])
        if found:
            status = "[green]OK[/green]"
        else:
            status = "[yellow]missing[/yellow]"
            if tool["install"].startswith("pip"):
                missing_pip.append(tool["name"])
        table.add_row(
            tool["ecosystem"],
            tool["name"],
            status,
            "" if found else tool["install"],
        )

    console.print(table)

    if missing_pip:
        install = typer.confirm(
            _t("dep_tools_install_ask", lang),
            default=True,
        )
        if install:
            for pkg in missing_pip:
                console.print(f"  {_t('dep_tools_installing', lang)} {pkg}...")
                try:
                    import sys

                    subprocess.run(
                        [sys.executable, "-m", "pip", "install", pkg],
                        capture_output=True,
                        check=True,
                        timeout=60,
                    )
                    console.print(f"  [green]{pkg} {_t('dep_tools_installed', lang)}[/green]")
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                    console.print(f"  [red]{_t('dep_tools_install_failed', lang)} {pkg}[/red]")


def _build_model_menu(
    installed_models: list[dict[str, str]], lang: str,
) -> list[dict[str, Any]]:
    menu: list[dict[str, Any]] = []
    added_names: set[str] = set()

    for m in installed_models:
        base_name: str = m["name"].split(":")[0]
        params: str = m["params"] or "?"
        tier_match: list[dict[str, str]] = [
            t for t in MODEL_TIERS if t["name"] == base_name
        ]
        if tier_match:
            t = tier_match[0]
            desc_key = f"desc_{lang}" if f"desc_{lang}" in t else "desc_en"
            menu.append({
                "name": m["name"], "params": params,
                "desc": t[desc_key], "installed": True,
            })
        else:
            menu.append({
                "name": m["name"], "params": params,
                "desc": _t("custom_model", lang), "installed": True,
            })
        added_names.add(base_name)

    for t in MODEL_TIERS:
        if t["name"] not in added_names:
            desc_key = f"desc_{lang}" if f"desc_{lang}" in t else "desc_en"
            menu.append({
                "name": t["name"], "params": t["params"],
                "desc": t[desc_key], "installed": False,
            })

    return menu


def _show_model_menu(
    installed_models: list[dict[str, str]], lang: str,
) -> str:
    menu: list[dict[str, Any]] = _build_model_menu(installed_models, lang)

    table = Table(title=_t("recommended_models", lang))
    table.add_column("#", style="bold", justify="right")
    table.add_column("Model", style="cyan")
    table.add_column("Params")
    table.add_column("Description")
    table.add_column("Status")

    for idx, item in enumerate(menu, 1):
        status = "[green]✓ installed[/green]" if item["installed"] else "[yellow]not installed[/yellow]"
        table.add_row(
            str(idx), item["name"], item["params"], item["desc"], status,
        )

    console.print(table)

    default_idx: int = 1
    for idx, item in enumerate(menu, 1):
        if item["installed"]:
            default_idx = idx
            break

    while True:
        raw: str = typer.prompt(
            _t("select_model", lang),
            default=str(default_idx),
            type=str,
        )
        try:
            choice: int = int(raw)
            if 1 <= choice <= len(menu):
                selected = menu[choice - 1]
                if not selected["installed"]:
                    msg = _t("model_not_installed_pull", lang).format(model=selected["name"])
                    console.print(f"\n[yellow]{msg}[/yellow]\n")
                return selected["name"]
        except ValueError:
            pass
        console.print(f"[red]{_t('invalid_choice', lang)}[/red]")




def run_wizard() -> dict[str, Any]:
    show_banner()

    config: dict[str, Any] = load_config()
    lang: str = _detect_language()
    config["language"] = lang

    console.print(
        Panel(
            _t("welcome_body", lang),
            title=_t("welcome_title", lang),
            border_style="cyan",
        )
    )

    console.print(f"\n[bold]{_t('checking_ollama', lang)}[/bold]")
    ollama_url: str = config["ollama_url"]
    available, models = detect_ollama(ollama_url)

    if not available:
        console.print(
            Panel(
                f"[yellow]Ollama not found at {ollama_url}[/yellow]\n\n"
                + _t("ollama_not_found_body", lang),
                title=_t("ollama_not_found_title", lang),
                border_style="yellow",
            )
        )
        custom_url: bool = typer.confirm(
            _t("ollama_custom_url", lang),
            default=False,
        )
        if custom_url:
            ollama_url = typer.prompt(_t("ollama_url_prompt", lang), type=str)
            if not validate_ollama_url(ollama_url):
                console.print("[red]Blocked: URL targets a private/invalid network range.[/red]")
                ollama_url = config["ollama_url"]
            config["ollama_url"] = ollama_url
            available, models = detect_ollama(ollama_url)
            if available:
                console.print(f"[green]{_t('ollama_found', lang)}[/green]")
            else:
                console.print(f"[red]{_t('ollama_still_unreachable', lang)}[/red]")

        enable_ai: bool = available if custom_url else False
        selected_model: str = config["model"]
    else:
        console.print(f"[green]{_t('ollama_detected', lang)}[/green]\n")

        enable_ai = typer.confirm(
            _t("enable_ai", lang),
            default=True,
        )

        if enable_ai:
            console.print()
            selected_model = _show_model_menu(models, lang)
        else:
            selected_model = config["model"]

    config["ai_triage_enabled"] = enable_ai
    config["model"] = selected_model

    has_nvd = typer.confirm(_t("nvd_ask", lang), default=False)
    if has_nvd:
        console.print(_t("nvd_get_key", lang))
        nvd_key: str = typer.prompt(_t("nvd_key_prompt", lang), type=str, hide_input=True)
        if nvd_key.strip():
            try:
                import keyring

                keyring.set_password("vulnhunter", "nvd_api_key", nvd_key.strip())
                console.print(f"[green]{_t('nvd_saved', lang)}[/green]")
            except Exception:
                console.print(f"[yellow]{_t('nvd_save_failed', lang)}[/yellow]")
    else:
        console.print(_t("nvd_skip", lang))

    _show_dep_tools(lang)

    if not DB_FILE.exists():
        console.print(f"\n[yellow]{_t('db_not_found', lang)}[/yellow]")
        download_db: bool = typer.confirm(
            _t("db_download_ask", lang),
            default=True,
        )
        if download_db:
            console.print(f"[bold]{_t('db_downloading', lang)}[/bold]")
            try:
                from vulnhunter.cli import db_download

                db_download(db_path=None, repo="DevGreick/VulnHunter", verbose=False)
            except (SystemExit, Exception):
                console.print(f"[bold]{_t('db_download_hint', lang)}[/bold]")
        else:
            console.print(f"[bold]{_t('db_download_hint', lang)}[/bold]")

    save_config(config)

    ai_status = _t("enabled", lang) if config["ai_triage_enabled"] else _t("disabled", lang)
    console.print(
        Panel(
            f"[green]Config saved: {CONFIG_FILE}[/green]\n\n"
            f"  {_t('ai_triage_label', lang)}:  {ai_status}\n"
            f"  Model:      {config['model']}\n"
            f"  Ollama URL: {config['ollama_url']}\n\n"
            + _t("setup_complete_scan", lang),
            title=_t("setup_complete_title", lang),
            border_style="green",
        )
    )

    return config
