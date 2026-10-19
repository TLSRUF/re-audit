"""Generate examples/demo.gif -- an animated terminal-style walkthrough of
re-audit for the README. Hand-rendered with Pillow (not a captured terminal
session) so colors/typography stay crisp and font-independent across
machines; the text and findings shown are taken verbatim from real `re-audit`
runs against notepad.exe and the synthetic secrets fixture used in tests/.
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "examples" / "demo.gif"

W, H = 980, 620
TITLEBAR_H = 40
PAD = 28
FONT_SIZE = 18
LINE_H = 28

FONT_DIR = Path(r"C:\Windows\Fonts")
FONT_REGULAR = ImageFont.truetype(str(FONT_DIR / "CascadiaMono.ttf"), FONT_SIZE)
FONT_BOLD = ImageFont.truetype(str(FONT_DIR / "consolab.ttf"), FONT_SIZE)

COL = {
    "bg": (13, 15, 20),
    "titlebar": (24, 26, 33),
    "border": (42, 46, 56),
    "text": (224, 226, 230),
    "muted": (139, 146, 160),
    "green": (82, 196, 26),
    "red": (255, 77, 79),
    "yellow": (255, 197, 61),
    "cyan": (64, 169, 255),
    "accent": (124, 92, 255),
    "dot_red": (255, 95, 86),
    "dot_yellow": (255, 189, 46),
    "dot_green": (39, 201, 63),
}


class Frame:
    def __init__(self):
        self.img = Image.new("RGB", (W, H), COL["bg"])
        self.d = ImageDraw.Draw(self.img)
        self._chrome()

    def _chrome(self):
        d = self.d
        d.rectangle([0, 0, W, TITLEBAR_H], fill=COL["titlebar"])
        d.rectangle([0, 0, W - 1, H - 1], outline=COL["border"], width=1)
        for i, c in enumerate(["dot_red", "dot_yellow", "dot_green"]):
            cx = 20 + i * 22
            d.ellipse([cx, TITLEBAR_H // 2 - 6, cx + 12, TITLEBAR_H // 2 + 6], fill=COL[c])
        title = "re-audit -- PowerShell"
        tw = d.textlength(title, font=FONT_REGULAR)
        d.text(((W - tw) / 2, TITLEBAR_H // 2 - FONT_SIZE / 2 - 1), title, fill=COL["muted"], font=FONT_REGULAR)

    def text(self, x, y, s, color="text", bold=False, font=None):
        f = font or (FONT_BOLD if bold else FONT_REGULAR)
        self.d.text((x, y), s, fill=COL[color] if isinstance(color, str) else color, font=f)
        return self.d.textlength(s, font=f)

    def badge(self, x, y, label, color):
        f = FONT_BOLD
        w = self.d.textlength(label, font=f) + 16
        h = LINE_H - 8
        self.d.rounded_rectangle([x, y, x + w, y + h], radius=4, fill=COL[color])
        self.d.text((x + 8, y + 3), label, fill=(10, 10, 12), font=f)
        return w


def cursor_frame(lines, prompt, typed, show_cursor, extra_blank=0):
    f = Frame()
    y = TITLEBAR_H + PAD
    for kind, *content in lines:
        if kind == "prompt":
            text = content[0]
            f.text(PAD, y, "PS> ", color="accent", bold=True)
            f.text(PAD + f.d.textlength("PS> ", font=FONT_BOLD), y, text, color="text", bold=True)
        elif kind == "plain":
            f.text(PAD, y, content[0], color=content[1] if len(content) > 1 else "text")
        elif kind == "muted":
            f.text(PAD, y, content[0], color="muted")
        elif kind == "finding":
            sev, text = content
            sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "INFO": "cyan"}[sev]
            bw = f.badge(PAD, y, sev, sev_color)
            f.text(PAD + bw + 12, y, text, color="text")
        elif kind == "secret":
            label, match, ctx = content
            bw = f.badge(PAD, y, "HIGH", "red")
            x2 = PAD + bw + 12
            w2 = f.text(x2, y, label, color="text")
            x3 = x2 + w2 + 14
            w3 = f.text(x3, y, match, color="yellow", bold=True)
        y += LINE_H

    if prompt is not None:
        f.text(PAD, y, "PS> ", color="accent", bold=True)
        tw = f.text(PAD + f.d.textlength("PS> ", font=FONT_BOLD), y, typed, color="text", bold=True)
        if show_cursor:
            cx = PAD + f.d.textlength("PS> ", font=FONT_BOLD) + tw + 2
            f.d.rectangle([cx, y, cx + 10, y + FONT_SIZE + 2], fill=COL["text"])
    return f.img


def typing_frames(lines_before, command, hold_ms=120):
    frames, durations = [], []
    for i in range(1, len(command) + 1):
        frames.append(cursor_frame(lines_before, True, command[:i], i % 2 == 0))
        durations.append(35)
    # a couple of blinking-cursor holds before "running"
    for show in (False, True, False, True):
        frames.append(cursor_frame(lines_before, True, command, show))
        durations.append(220)
    return frames, durations


def build():
    frames, durations = [], []

    scan_cmd = "re-audit scan notepad.exe"
    f1, d1 = typing_frames([], scan_cmd)
    frames += f1
    durations += d1

    scan_lines = [
        ("prompt", scan_cmd),
        ("plain", "C:\\Windows\\System32\\notepad.exe -- detected type: pe -- 360,448 bytes"),
        ("muted", "Static analysis only -- no network requests, no execution of the target."),
        ("plain", ""),
        ("plain", "Findings", "text"),
    ]
    findings = [
        ("MEDIUM", "references to risky functions/APIs: CreateProcess, ShellExecute, memcpy"),
        ("MEDIUM", "no stack canary detected"),
        ("MEDIUM", "imports known memory-unsafe functions: CreateProcessW, ShellExecuteW"),
    ]
    # progressively reveal the scan result lines
    for n in range(1, len(scan_lines) + 1):
        img = cursor_frame(scan_lines[:n], None, "", False)
        frames.append(img)
        durations.append(160)
    for n in range(1, len(findings) + 1):
        rows = scan_lines + [("finding", sev, txt) for sev, txt in findings[:n]]
        frames.append(cursor_frame(rows, None, "", False))
        durations.append(260)

    base_after_scan = scan_lines + [("finding", sev, txt) for sev, txt in findings]
    final_scan_rows = base_after_scan + [("plain", ""), ("muted", "HTML report written to report.html")]
    frames.append(cursor_frame(final_scan_rows, None, "", False))
    durations.append(1400)

    secrets_cmd = "re-audit secrets sample.txt"
    f2, d2 = typing_frames(final_scan_rows, secrets_cmd)
    frames += f2
    durations += d2

    secrets_lines = final_scan_rows + [
        ("prompt", secrets_cmd),
        ("plain", "Potential secrets (redacted)", "text"),
    ]
    secret_rows = [
        ("AWS Access Key ID", "AKIA...MPLE", ""),
        ("Generic password assignment", "pass...23!\"", ""),
        ("Private Key Block", "----...----", ""),
    ]
    for n in range(1, len(secret_rows) + 1):
        rows = secrets_lines + [("secret", *s) for s in secret_rows[:n]]
        frames.append(cursor_frame(rows, None, "", False))
        durations.append(280)

    final_rows = secrets_lines + [("secret", *s) for s in secret_rows]
    frames.append(cursor_frame(final_rows, None, "", False))
    durations.append(2200)

    # optimize=True makes Pillow store per-frame diffs; without explicit
    # disposal=2 on every frame that corrupts playback in most viewers
    # (later frames bleed into earlier ones). Full RGB frames avoid that,
    # but are large -- quantize to a shared adaptive palette instead, which
    # shrinks the file a lot without touching frame diffing.
    base_palette = frames[len(frames) // 2].convert("RGB").quantize(colors=64, method=Image.MEDIANCUT)
    quantized = [f.convert("RGB").quantize(palette=base_palette, dither=Image.NONE) for f in frames]
    quantized[0].save(
        OUT,
        save_all=True,
        append_images=quantized[1:],
        duration=durations,
        loop=0,
        optimize=False,
        disposal=2,
    )
    print(f"wrote {OUT} ({len(frames)} frames, {sum(durations)/1000:.1f}s)")


if __name__ == "__main__":
    build()
