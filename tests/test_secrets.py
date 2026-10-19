from re_audit.analyzers import secrets


def test_detects_aws_key():
    text = 'aws_secret = "AKIAIOSFODNN7EXAMPLE"'
    findings = secrets.scan_text(text)
    assert any(f.label == "AWS Access Key ID" for f in findings)


def test_detects_private_key_block():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK...\n-----END RSA PRIVATE KEY-----"
    findings = secrets.scan_text(text)
    assert any(f.label == "Private Key Block" for f in findings)


def test_no_false_positive_on_plain_text():
    text = "just a normal line of text with nothing interesting in it at all"
    findings = secrets.scan_text(text)
    assert findings == []


def test_redacts_matches():
    text = 'aws_secret = "AKIAIOSFODNN7EXAMPLE"'
    findings = secrets.scan_text(text)
    for f in findings:
        assert "AKIAIOSFODNN7EXAMPLE" not in f.match


def test_high_entropy_ignores_camel_case_api_names():
    text = "call WaitForSingleObjectEx then K32GetModuleFileNameExW before exit"
    findings = secrets.scan_high_entropy_tokens(text)
    assert findings == []


def test_high_entropy_detects_base64_like_secret():
    # A real base64 encoding (of an obviously-fake string), not a vendor key
    # format -- avoids both GitHub push-protection false-triggers and our
    # own CamelCase-identifier exclusion, while still being high-entropy.
    text = 'token = "dGhpcy1pcy1hLWZha2UtdGVzdC1zZWNyZXQta2V5LW5vdC1yZWFsLTAwMDE="'
    findings = secrets.scan_high_entropy_tokens(text)
    assert len(findings) >= 1
