from re_audit import html_report, report as report_mod

NOTEPAD = r"C:\Windows\System32\notepad.exe"


def test_renders_valid_looking_html():
    data = report_mod.audit_file(NOTEPAD)
    page = html_report.render(data)
    assert page.startswith("<!doctype html>")
    assert "</html>" in page
    assert "re-audit report" in page
    assert NOTEPAD in page


def test_escapes_html_in_findings(tmp_path):
    # A finding string containing HTML-special characters must not break
    # out of its container -- guards against XSS if a scanned file's
    # strings ever end up echoed into a finding.
    data = {
        "path": "<script>alert(1)</script>",
        "detected_type": "elf",
        "size_bytes": 10,
        "scope_disclaimer": "test",
        "summary_findings": ["HIGH: <img src=x onerror=alert(1)>"],
        "sections": {},
    }
    page = html_report.render(data)
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page
