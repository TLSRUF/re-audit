from click.testing import CliRunner

from re_audit import report as report_mod
from re_audit.cli import main

NOTEPAD = r"C:\Windows\System32\notepad.exe"


def test_audit_file_produces_full_report():
    data = report_mod.audit_file(NOTEPAD)
    assert data["detected_type"] == "pe"
    assert "strings" in data["sections"]
    assert "secrets" in data["sections"]
    assert "binary" in data["sections"]
    assert isinstance(data["summary_findings"], list)


def test_audit_file_missing_path_raises():
    try:
        report_mod.audit_file("does_not_exist.bin")
        assert False, "expected FileNotFoundError"
    except FileNotFoundError:
        pass


def test_cli_scan_json_runs_end_to_end():
    runner = CliRunner()
    result = runner.invoke(main, ["scan", NOTEPAD, "--json"])
    assert result.exit_code == 0
    assert "detected_type" in result.output


def test_cli_scan_human_readable_runs():
    runner = CliRunner()
    result = runner.invoke(main, ["scan", NOTEPAD])
    assert result.exit_code == 0
    assert "detected type" in result.output
