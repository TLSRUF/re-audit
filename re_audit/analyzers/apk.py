"""Android APK static security analysis via androguard.

Flags common mobile-app misconfigurations: debuggable builds, backup
allowed, cleartext traffic permitted, exported components without
permission guards, dangerous permission requests, and weak/no signature.
Static only -- does not install, launch, or instrument the app.
"""
from __future__ import annotations

import logging
import zipfile
from dataclasses import dataclass, field

from androguard.core.apk import APK

from re_audit.limits import check_file_size

# androguard/apkInspector decompress zip entries (e.g. AndroidManifest.xml)
# with no size cap of their own, trusting the attacker-controlled
# "uncompressed size" header field. A sub-2MB crafted APK can claim a
# single huge entry and force that much memory to be allocated before
# parsing even starts -- a classic zip-bomb, confirmed by a
# security-audit-skill review (~1000x amplification, bounded by DEFLATE's
# own ~1032:1 single-pass ceiling since androguard doesn't recurse into
# nested archives). zipfile.ZipFile() here only reads the central
# directory -- no decompression -- so this check is cheap even against a
# hostile file.
MAX_APK_ENTRY_UNCOMPRESSED_BYTES = 500 * 1024 * 1024  # 500 MB, generous for real APKs


def _reject_zip_bomb(path: str) -> None:
    try:
        with zipfile.ZipFile(path) as zf:
            total = 0
            for info in zf.infolist():
                if info.file_size > MAX_APK_ENTRY_UNCOMPRESSED_BYTES:
                    raise ValueError(
                        f"APK entry '{info.filename}' claims "
                        f"{info.file_size:,} uncompressed bytes, over the "
                        f"{MAX_APK_ENTRY_UNCOMPRESSED_BYTES:,}-byte per-entry "
                        "limit -- refusing to decompress (possible zip bomb)."
                    )
                total += info.file_size
                if total > MAX_APK_ENTRY_UNCOMPRESSED_BYTES:
                    raise ValueError(
                        f"This APK's entries sum to over "
                        f"{MAX_APK_ENTRY_UNCOMPRESSED_BYTES:,} uncompressed "
                        "bytes -- refusing to decompress (possible zip bomb)."
                    )
    except zipfile.BadZipFile as exc:
        raise ValueError(f"'{path}' is not a valid zip/APK: {exc}") from exc

# androguard uses loguru and defaults to very verbose DEBUG/INFO logging
# (every AXML parser event). Silence it so CLI/MCP output stays readable;
# callers who want androguard's own diagnostics can re-enable it.
try:
    import sys as _sys

    from loguru import logger as _loguru_logger

    _loguru_logger.remove()
    _loguru_logger.add(_sys.stderr, level="ERROR")
except Exception:
    pass
logging.getLogger("androguard").setLevel(logging.ERROR)

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
}


@dataclass
class ApkReport:
    package: str
    version_name: str | None
    min_sdk: str | None
    target_sdk: str | None
    debuggable: bool
    allow_backup: bool
    uses_cleartext_traffic: bool | None
    permissions: list[str]
    dangerous_permissions: list[str]
    exported_activities: list[str]
    exported_services: list[str]
    exported_receivers: list[str]
    exported_providers: list[str]
    is_signed: bool
    signature_names: list[str]
    findings: list[str] = field(default_factory=list)


def analyze(path: str) -> ApkReport:
    check_file_size(path)
    _reject_zip_bomb(path)
    apk = APK(path)

    debuggable = bool(apk.get_attribute_value("application", "debuggable"))
    allow_backup_raw = apk.get_attribute_value("application", "allowBackup")
    # androguard returns None if absent; AOSP default is "true" when unspecified.
    allow_backup = True if allow_backup_raw is None else allow_backup_raw == "true"

    cleartext_raw = apk.get_attribute_value("application", "usesCleartextTraffic")
    uses_cleartext = None if cleartext_raw is None else cleartext_raw == "true"

    permissions = sorted(apk.get_permissions())
    dangerous = sorted(p for p in permissions if p in DANGEROUS_PERMISSIONS)

    def exported(components, tag):
        out = []
        for name in components:
            try:
                exported_attr = apk.get_attribute_value(tag, "exported", name=name)
                has_intent_filter = bool(apk.get_intent_filters(tag, name))
                # Android: a component with an intent-filter and no explicit
                # exported="false" is exported by default on API < 31.
                is_exported = exported_attr == "true" or (exported_attr is None and has_intent_filter)
                if is_exported:
                    out.append(name)
            except Exception:
                continue
        return out

    exported_activities = exported(apk.get_activities(), "activity")
    exported_services = exported(apk.get_services(), "service")
    exported_receivers = exported(apk.get_receivers(), "receiver")
    exported_providers = exported(apk.get_providers(), "provider")

    try:
        is_signed = apk.is_signed()
        sig_names = list(apk.get_signature_names())
    except Exception:
        is_signed = False
        sig_names = []

    findings: list[str] = []
    if debuggable:
        findings.append("CRITICAL: android:debuggable=true in a release build allows attaching a debugger / JDWP exploitation.")
    if allow_backup:
        findings.append("MEDIUM: android:allowBackup not disabled -- app data can be extracted via 'adb backup' on debug-enabled devices.")
    if uses_cleartext:
        findings.append("MEDIUM: usesCleartextTraffic=true -- app may send data over unencrypted HTTP.")
    if exported_providers:
        findings.append(f"HIGH: {len(exported_providers)} exported ContentProvider(s) -- check for SQL injection / path traversal via exposed URIs.")
    if exported_services:
        findings.append(f"MEDIUM: {len(exported_services)} exported Service(s) -- check for unauthenticated IPC.")
    if exported_receivers:
        findings.append(f"MEDIUM: {len(exported_receivers)} exported BroadcastReceiver(s) -- check for spoofable broadcasts.")
    if not is_signed:
        findings.append("HIGH: APK does not appear to be signed.")
    if dangerous:
        findings.append(f"INFO: requests {len(dangerous)} sensitive permission(s): {', '.join(dangerous)}")

    return ApkReport(
        package=apk.get_package(),
        version_name=apk.get_androidversion_name(),
        min_sdk=apk.get_min_sdk_version(),
        target_sdk=apk.get_target_sdk_version(),
        debuggable=debuggable,
        allow_backup=allow_backup,
        uses_cleartext_traffic=uses_cleartext,
        permissions=permissions,
        dangerous_permissions=dangerous,
        exported_activities=exported_activities,
        exported_services=exported_services,
        exported_receivers=exported_receivers,
        exported_providers=exported_providers,
        is_signed=is_signed,
        signature_names=sig_names,
        findings=findings,
    )
