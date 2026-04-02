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
    "installed_models": {
        "en": "Installed models:",
        "pt": "Modelos instalados:",
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
        "en": "Select model",
        "pt": "Escolha o modelo",
    },
    "model_not_recommended": {
        "en": "is not in the recommended list, but will be used if available in Ollama.",
        "pt": "nao esta na lista recomendada, mas sera usado se disponivel no Ollama.",
    },
    "model_not_installed": {
        "en": "is not installed in Ollama.",
        "pt": "nao esta instalado no Ollama.",
    },
    "model_pull": {
        "en": "Pull it with:",
        "pt": "Baixe com:",
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


def _show_model_table(installed_models: list[str], lang: str) -> None:
    table = Table(title=_t("recommended_models", lang))
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
        desc_key: str = f"desc_{lang}" if f"desc_{lang}" in tier_info else "desc_en"
        table.add_row(
            tier_info["tier"],
            tier_info["name"],
            tier_info["params"],
            tier_info[desc_key],
            status,
        )

    console.print(table)


def _show_installed_models(models: list[str], lang: str) -> None:
    if not models:
        return
    console.print(f"\n[bold]{_t('installed_models', lang)}[/bold]")
    for model in models:
        console.print(f"  - {model}")


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
        _show_installed_models(models, lang)
        console.print()
        _show_model_table(models, lang)
        console.print()

        enable_ai = typer.confirm(
            _t("enable_ai", lang),
            default=True,
        )

        default_model: str = "mistral"
        for tier_info in MODEL_TIERS:
            match: list[str] = [m for m in models if tier_info["name"] in m]
            if match:
                default_model = match[0]
                break

        selected_model = typer.prompt(
            _t("select_model", lang),
            default=default_model,
            type=str,
        )

        if not any(selected_model == m or selected_model in m for m in models):
            exact_matches: list[str] = [m for m in models if selected_model in m]
            if exact_matches:
                selected_model = exact_matches[0]
                console.print(f"[cyan]Using: {selected_model}[/cyan]")
            else:
                console.print(
                    f"\n[yellow]'{selected_model}' {_t('model_not_installed', lang)}[/yellow]"
                )
                console.print(
                    f"{_t('model_pull', lang)} [bold]ollama pull {selected_model}[/bold]\n"
                )

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
