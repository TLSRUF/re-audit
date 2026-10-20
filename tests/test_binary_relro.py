"""Regression test for the RELRO misclassification reported in
https://github.com/morluto/awesome-reverse-engineering/pull/16:
`_analyze_elf` treated the mere presence of a DT_FLAGS_1 entry as BIND_NOW,
so a PIE binary with GNU_RELRO but *without* eager binding (partial RELRO,
e.g. `gcc -fPIE -pie -Wl,-z,relro,-z,lazy`) was misreported as "full".

Builds minimal ELF64 fixtures by hand (tests/fixtures/elf_builder.py)
instead of shelling out to a C compiler, since this project's CI and dev
environment is Windows.
"""
from re_audit.analyzers import binary
from tests.fixtures.elf_builder import build_elf, build_elf_no_relro


def test_relro_segment_without_now_bit_is_partial(tmp_path):
    # Mirrors `gcc -fPIE -pie -Wl,-z,relro,-z,lazy`: GNU_RELRO segment
    # present, DT_FLAGS_1 present (e.g. for DF_1_PIE) but DF_1_NOW unset.
    path = tmp_path / "p.elf"
    path.write_bytes(build_elf(bind_now_tag=False, flags_1_now_bit=False))
    report = binary.analyze(str(path))
    assert report.mitigations.relro == "partial"


def test_flags_1_now_bit_is_full(tmp_path):
    # Mirrors `gcc -fPIE -pie -Wl,-z,relro,-z,now`: DF_1_NOW set.
    path = tmp_path / "f.elf"
    path.write_bytes(build_elf(bind_now_tag=False, flags_1_now_bit=True))
    report = binary.analyze(str(path))
    assert report.mitigations.relro == "full"


def test_legacy_bind_now_tag_is_full(tmp_path):
    # The older boolean DT_BIND_NOW tag (pre-dates DT_FLAGS_1) must also
    # count as eager binding on its own.
    path = tmp_path / "b.elf"
    path.write_bytes(build_elf(bind_now_tag=True, flags_1_now_bit=False))
    report = binary.analyze(str(path))
    assert report.mitigations.relro == "full"


def test_no_relro_segment_is_none(tmp_path):
    path = tmp_path / "n.elf"
    path.write_bytes(build_elf_no_relro())
    report = binary.analyze(str(path))
    assert report.mitigations.relro == "none"
