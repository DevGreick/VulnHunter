from collections import defaultdict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from vulnhunter.models import ScanResult, Severity, Vulnerability

SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.UNKNOWN: "dim",
}

console = Console()


def _build_summary(result: ScanResult) -> str:
    severity_counts: dict[Severity, int] = defaultdict(int)
    for vuln in result.vulnerabilities:
        severity_counts[vuln.severity] += 1

    lines: list[str] = [
        f"[bold]Dependencies scanned:[/bold] {result.total_dependencies}",
        f"[bold]Vulnerabilities found:[/bold] {result.total_vulnerabilities}",
        f"[bold]Ignored:[/bold] {result.total_ignored}",
    ]

    sev_lines: list[str] = []

    for sev in Severity:
        count = severity_counts.get(sev, 0)
        if count > 0:
            style = SEVERITY_STYLE[sev]
            sev_lines.append(f"  [{style}]{sev.value}[/{style}]: {count}")

    if sev_lines:
        lines.append("")
        lines.extend(sev_lines)

    return "\n".join(lines)


def _group_vulnerabilities(
    vulns: list[Vulnerability],
) -> dict[str, dict[str, list[Vulnerability]]]:
    grouped: dict[str, dict[str, list[Vulnerability]]] = defaultdict(lambda: defaultdict(list))
    for vuln in vulns:
        grouped[vuln.ecosystem.value][vuln.name].append(vuln)
    return grouped


def render_table(result: ScanResult) -> None:
    summary = _build_summary(result)
    console.print(Panel(summary, title="VulnHunter Scan Summary", border_style="cyan"))
    console.print()

    if not result.vulnerabilities:
        console.print(
            Panel(
                "[bold green]No vulnerabilities found![/bold green]",
                border_style="green",
            )
        )
        return

    grouped = _group_vulnerabilities(result.vulnerabilities)

    for ecosystem, packages in sorted(grouped.items()):
        table = Table(
            title=f"Ecosystem: {ecosystem}",
            show_header=True,
            header_style="bold magenta",
            show_lines=True,
        )
        table.add_column("CVE ID", style="cyan", no_wrap=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Package", style="white")
        table.add_column("Version", style="white")
        table.add_column("Fixed", style="green")
        table.add_column("Source", style="dim")

        for pkg_name in sorted(packages.keys(), key=str.lower):
            for vuln in sorted(packages[pkg_name], key=lambda v: v.vuln_id):
                style = SEVERITY_STYLE.get(vuln.severity, "dim")
                table.add_row(
                    vuln.vuln_id,
                    f"[{style}]{vuln.severity.value}[/{style}]",
                    pkg_name,
                    vuln.version,
                    vuln.fixed_version or "N/A",
                    vuln.source,
                )

        console.print(table)
        console.print()
