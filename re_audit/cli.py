"""re-audit: static reverse-engineering-assisted vulnerability triage CLI.

Only run this against files you own or are explicitly authorized to test
(your own builds, CTF binaries, or an in-scope bug-bounty asset). This tool
performs static file analysis only -- it never sends network requests and
never executes the target.
"""
from __future__ import annotations

import sys

import click
from rich.console import Console
from rich.table import Table

from . import report as report_mod

console = Console()


@click.group()
def main() -> None:
    """re-audit: static RE-assisted vulnerability triage for files you're authorized to test."""


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True, help="Print the full report as JSON.")
@click.option("--out", type=click.Path(), help="Write the JSON report to this file.")
@click.option("--html", "html_out", type=click.Path(), help="Write a self-contained HTML report to this file.")
def scan(path: str, as_json: bool, out: str | None, html_out: str | None) -> None:
    """Run the full static audit against PATH (ELF/PE/Mach-O binary or APK)."""
    try:
        data = report_mod.audit_file(path)
    except Exception as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        sys.exit(1)

    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write(report_mod.to_json(data))
        console.print(f"[green]Report written to {out}[/]")

    if html_out:
        from . import html_report

        with open(html_out, "w", encoding="utf-8") as f:
            f.write(html_report.render(data))
        console.print(f"[green]HTML report written to {html_out}[/]")

    if as_json:
        print(report_mod.to_json(data))
        return

    console.print(f"[bold]{data['path']}[/] -- detected type: [cyan]{data['detected_type']}[/] -- {data['size_bytes']} bytes")
    console.print(f"[dim]{data['scope_disclaimer']}[/]\n")

    if data["summary_findings"]:
        table = Table(title="Findings")
        table.add_column("Finding")
        for finding in data["summary_findings"]:
            table.add_row(finding)
        console.print(table)
    else:
        console.print("[green]No heuristic findings flagged.[/]")

    console.print("\n[dim]Run with --json for the full detailed report (strings, imports, permissions, etc).[/]")


@main.command()
@click.argument("path", type=click.Path(exists=True))
def strings(path: str) -> None:
    """Extract and classify printable strings from PATH."""
    from .analyzers import strings_scan

    with open(path, "rb") as f:
        data = f.read()
    rep = strings_scan.analyze(data)
    console.print(f"Total strings: {rep.total_strings}")
    if rep.urls:
        console.print(f"\n[bold]URLs ({len(rep.urls)}):[/]")
        for u in rep.urls[:50]:
            console.print(f"  {u}")
    if rep.ips:
        console.print(f"\n[bold]IPs ({len(rep.ips)}):[/]")
        for ip in rep.ips[:50]:
            console.print(f"  {ip}")
    if rep.risky_symbols:
        console.print(f"\n[bold red]Risky symbols:[/] {', '.join(rep.risky_symbols)}")


@main.command()
@click.argument("path", type=click.Path(exists=True))
def secrets(path: str) -> None:
    """Scan PATH for hardcoded secret-like patterns."""
    from .analyzers import secrets as secrets_analyzer
    from .analyzers import strings_scan

    with open(path, "rb") as f:
        data = f.read()
    text = "\n".join(strings_scan.extract_strings(data))
    findings = secrets_analyzer.scan_text(text)
    high_entropy = secrets_analyzer.scan_high_entropy_tokens(text)

    if not findings and not high_entropy:
        console.print("[green]No secret-like patterns found.[/]")
        return

    table = Table(title="Potential secrets (redacted)")
    table.add_column("Type")
    table.add_column("Match")
    table.add_column("Context")
    for f in findings + high_entropy:
        table.add_row(f.label, f.match, f.context)
    console.print(table)


@main.command()
@click.argument("path", type=click.Path(exists=True))
def binary(path: str) -> None:
    """Check exploit mitigations and risky imports for an ELF/PE/Mach-O binary."""
    from .analyzers import binary as binary_analyzer

    try:
        rep = binary_analyzer.analyze(path)
    except Exception as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        sys.exit(1)

    console.print(f"Format: [cyan]{rep.format}[/]  Arch: {rep.arch}")
    m = rep.mitigations
    table = Table(title="Mitigations")
    table.add_column("Check")
    table.add_column("Status")
    for name, val in [
        ("NX/DEP", m.nx),
        ("PIE/ASLR", m.pie_or_aslr),
        ("RELRO", m.relro),
        ("Stack canary", m.stack_canary),
        ("CFG (PE)", m.cfg),
        ("SafeSEH (PE)", m.safe_seh),
        ("Signed", m.signed),
        ("Stripped", m.stripped),
    ]:
        if val is None:
            continue
        style = "green" if val in (True, "full") else "red" if val in (False, "none") else "yellow"
        table.add_row(name, f"[{style}]{val}[/]")
    console.print(table)

    if rep.risky_imports:
        console.print(f"\n[bold red]Risky imports:[/] {', '.join(rep.risky_imports)}")


@main.command()
@click.argument("path", type=click.Path(exists=True))
def apk(path: str) -> None:
    """Static security audit of an Android APK."""
    from .analyzers import apk as apk_analyzer

    try:
        rep = apk_analyzer.analyze(path)
    except Exception as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        sys.exit(1)

    console.print(f"Package: [cyan]{rep.package}[/]  version={rep.version_name}  minSdk={rep.min_sdk} targetSdk={rep.target_sdk}")
    for finding in rep.findings:
        console.print(f"  - {finding}")
    if rep.exported_providers:
        console.print(f"\nExported providers: {rep.exported_providers}")
    if rep.exported_services:
        console.print(f"Exported services: {rep.exported_services}")
    if rep.exported_receivers:
        console.print(f"Exported receivers: {rep.exported_receivers}")


if __name__ == "__main__":
    main()
