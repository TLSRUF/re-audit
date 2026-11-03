import time

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


# --- ReDoS regressions -------------------------------------------------
# Found by a security-audit-skill review: re-audit's whole purpose is
# scanning attacker-controlled file content, so a crafted string that hangs
# a regex for minutes is a real, practical DoS against this tool's primary
# use case, not a theoretical one. Both were confirmed with real timing
# (the old CamelCase regex took 7s+ at ~29 bytes and climbed exponentially;
# the old DB-connection-string regex took 9.5s at 64,000 bytes) before being
# fixed. These tests assert the fix holds with a generous bound -- failing
# because it's slow, not failing because of an exact number, is the signal
# that the backtracking regressed.

def test_camel_case_check_is_fast_on_adversarial_input():
    # Shape that broke the old regex: one uppercase letter, a long digit
    # run, then a character outside either alternative's alphabet -- forces
    # the match to fail only after exploring every way to split the digits.
    token = "A" + "1" * 200 + "+"
    t0 = time.perf_counter()
    result = secrets._looks_like_camel_case_identifier(token)
    elapsed = time.perf_counter() - t0
    assert elapsed < 1.0, f"took {elapsed:.3f}s -- possible backtracking regression"
    assert result is False  # doesn't match the CamelCase shape (trailing '+')


def test_db_connection_pattern_is_fast_on_adversarial_input():
    # Shape that broke the old regex: scheme + a long run of ':' with no
    # '@', forcing O(n^2) backtracking between the two adjacent unbounded
    # classes that used to both accept ':'.
    text = "mysql://" + ":" * 20_000
    t0 = time.perf_counter()
    findings = secrets.scan_text(text)
    elapsed = time.perf_counter() - t0
    assert elapsed < 2.0, f"took {elapsed:.3f}s -- possible backtracking regression"
    assert findings == []  # no '@' -- not a match, just shouldn't hang getting there


def test_camel_case_check_still_matches_real_api_names():
    for name in ["WaitForSingleObjectEx", "K32GetModuleFileNameExW", "GetSaveFileNameW"]:
        assert secrets._looks_like_camel_case_identifier(name) is True
