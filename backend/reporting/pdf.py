"""
Minimal, dependency-free PDF writer used for ForenSys reports.

Why hand-rolled: no third-party PDF library has to be installed or shipped, the output is deterministic, and the
report only needs a handful of primitives - wrapped text, tables that repeat their header across pages, key/value
blocks, a bar chart, a banner and page numbers. It emits standard PDF 1.4 with the built-in Helvetica/Courier fonts
(WinAnsi encoding, so text is limited to Latin-1/Windows-1252; anything else is replaced with '?').
"""

import time
import zlib
from typing import List, Optional, Sequence, Tuple

Color = Tuple[float, float, float]

A4_W, A4_H = 595.28, 841.89

INK: Color = (0.10, 0.12, 0.16)
MUTED: Color = (0.40, 0.44, 0.50)
FAINT: Color = (0.62, 0.66, 0.72)
WHITE: Color = (1.0, 1.0, 1.0)
NAVY: Color = (0.05, 0.09, 0.16)
ACCENT: Color = (0.0, 0.62, 0.78)
ZEBRA: Color = (0.955, 0.965, 0.975)
LABEL_BG: Color = (0.92, 0.94, 0.96)
RULE: Color = (0.82, 0.85, 0.89)
SEVERITY_COLORS = {
    "critical": (0.78, 0.10, 0.12), "high": (0.90, 0.40, 0.05),
    "medium": (0.80, 0.62, 0.02), "low": (0.20, 0.45, 0.80), "info": (0.40, 0.44, 0.50),
}
STATUS_COLORS = {
    "contained": (0.10, 0.55, 0.30), "investigating": (0.80, 0.62, 0.02), "open": (0.78, 0.10, 0.12),
    "resolved": (0.10, 0.55, 0.30),
}

# Helvetica / Helvetica-Bold advance widths (1/1000 em) for ASCII 32..126 (from the standard AFM metrics).
_HELV = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
         556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015,
         667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722,
         667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333,
         556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556,
         500, 722, 500, 500, 500, 334, 260, 334, 584]
_HELV_B = [278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278,
           556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611, 975,
           722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778, 667, 778, 722, 667, 611, 722,
           667, 944, 667, 667, 611, 333, 278, 333, 584, 556, 333,
           556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611, 611, 611, 389, 556, 333, 611,
           556, 778, 556, 556, 500, 389, 280, 389, 584]
assert len(_HELV) == 95 and len(_HELV_B) == 95

FONTS = {"F1": "Helvetica", "F2": "Helvetica-Bold", "F3": "Courier", "F4": "Courier-Bold"}


def text_width(s: str, font: str, size: float) -> float:
    if font in ("F3", "F4"):
        return len(s) * 0.6 * size
    table = _HELV if font == "F1" else _HELV_B
    total = 0
    for ch in s:
        o = ord(ch)
        total += table[o - 32] if 32 <= o <= 126 else 556
    return total * size / 1000.0


def clean(value: object) -> str:
    """Printable single-string form: control characters become spaces, text is forced into Windows-1252."""
    s = "" if value is None else str(value)
    s = "".join(ch if (ch == "\n" or ch >= " ") and ch != "\x7f" else " " for ch in s)
    return s.encode("cp1252", "replace").decode("cp1252")


def _pdf_string(s: str) -> bytes:
    raw = clean(s).encode("cp1252", "replace")
    return b"(" + raw.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)") + b")"


def _num(v: float) -> str:
    return f"{v:.2f}".rstrip("0").rstrip(".") or "0"


def _rg(c: Color) -> str:
    return f"{c[0]:.3f} {c[1]:.3f} {c[2]:.3f}"


class PdfReport:
    def __init__(self, title: str, running_head: str, footer_note: str, margin: float = 42.0) -> None:
        self.title = title
        self.running_head = running_head
        self.footer_note = footer_note
        self.margin = margin
        self.width = A4_W - 2 * margin
        self.pages: List[List[bytes]] = []
        self.y = 0.0
        self.new_page(first=True)

    # ── page / low-level drawing ────────────────────────────────────────────

    @property
    def bottom(self) -> float:
        return self.margin + 14

    def new_page(self, first: bool = False) -> None:
        self.pages.append([])
        self.y = A4_H - self.margin
        if not first:
            self._text(self.margin, A4_H - self.margin + 8, self.running_head, "F1", 7.5, FAINT)
            self._line(self.margin, A4_H - self.margin + 3, A4_W - self.margin, A4_H - self.margin + 3, RULE, 0.5)
            self.y -= 12

    def _emit(self, op: bytes) -> None:
        self.pages[-1].append(op)

    def _text(self, x: float, y: float, s: str, font: str = "F1", size: float = 9, color: Color = INK) -> None:
        self._emit(f"BT {_rg(color)} rg /{font} {_num(size)} Tf {_num(x)} {_num(y)} Td ".encode() + _pdf_string(s) + b" Tj ET")

    def _rect(self, x: float, y: float, w: float, h: float, fill: Optional[Color] = None,
              stroke: Optional[Color] = None, lw: float = 0.5) -> None:
        if fill is not None:
            self._emit(f"{_rg(fill)} rg {_num(x)} {_num(y)} {_num(w)} {_num(h)} re f".encode())
        if stroke is not None:
            self._emit(f"{_rg(stroke)} RG {_num(lw)} w {_num(x)} {_num(y)} {_num(w)} {_num(h)} re S".encode())

    def _line(self, x1: float, y1: float, x2: float, y2: float, color: Color = RULE, lw: float = 0.5) -> None:
        self._emit(f"{_rg(color)} RG {_num(lw)} w {_num(x1)} {_num(y1)} m {_num(x2)} {_num(y2)} l S".encode())

    # ── text layout ─────────────────────────────────────────────────────────

    @staticmethod
    def wrap(text: object, font: str, size: float, max_w: float) -> List[str]:
        """Word-wraps to max_w points, hard-breaking tokens (IPs, hashes, paths) that are wider than the line."""
        lines: List[str] = []
        for para in clean(text).split("\n"):
            words = para.split(" ")
            cur = ""
            for word in words:
                trial = word if not cur else cur + " " + word
                if text_width(trial, font, size) <= max_w:
                    cur = trial
                    continue
                if cur:
                    lines.append(cur)
                    cur = ""
                while text_width(word, font, size) > max_w and len(word) > 1:
                    cut = len(word)
                    while cut > 1 and text_width(word[:cut], font, size) > max_w:
                        cut -= 1
                    lines.append(word[:cut])
                    word = word[cut:]
                cur = word
            lines.append(cur)
        return lines or [""]

    def ensure(self, h: float) -> None:
        if self.y - h < self.bottom:
            self.new_page()

    def space(self, h: float = 8) -> None:
        self.y -= h

    # ── blocks ──────────────────────────────────────────────────────────────

    def banner(self, product: str, title: str, subtitle: str, chips: Sequence[Tuple[str, Color]] = ()) -> None:
        h = 92
        self._rect(self.margin, self.y - h, self.width, h, fill=NAVY)
        self._rect(self.margin, self.y - h, 5, h, fill=ACCENT)
        self._text(self.margin + 18, self.y - 20, product, "F2", 8.5, (0.30, 0.82, 0.95))
        title_lines = self.wrap(title, "F2", 17, self.width - 36)[:2]
        ty = self.y - 42
        for ln in title_lines:
            self._text(self.margin + 18, ty, ln, "F2", 17, WHITE)
            ty -= 20
        sub = self.wrap(subtitle, "F1", 8.5, self.width - 36)[0]
        self._text(self.margin + 18, self.y - h + 11, sub, "F1", 8.5, (0.72, 0.78, 0.86))
        cx = self.margin + self.width - 14
        for label, color in reversed(list(chips)):
            w = text_width(label, "F2", 8) + 16
            cx -= w
            self._rect(cx, self.y - 26, w, 15, fill=color)
            self._text(cx + 8, self.y - 21.5, label, "F2", 8, WHITE)
            cx -= 6
        self.y -= h + 14

    def heading(self, text: str, level: int = 1) -> None:
        size = 12.5 if level == 1 else 10
        self.ensure(90 if level == 1 else 60)   # keep the heading together with the start of what follows
        self.space(6 if level == 1 else 3)
        self._text(self.margin, self.y - size, text, "F2", size, NAVY if level == 1 else INK)
        self.y -= size + 4
        if level == 1:
            self._rect(self.margin, self.y - 1.2, 38, 2.2, fill=ACCENT)
            self._line(self.margin + 38, self.y - 0.1, self.margin + self.width, self.y - 0.1, RULE, 0.6)
            self.y -= 9
        else:
            self.y -= 3

    def paragraph(self, text: str, size: float = 9, font: str = "F1", color: Color = INK,
                  indent: float = 0.0, leading: float = 1.38, space_after: float = 5) -> None:
        for ln in self.wrap(text, font, size, self.width - indent):
            self.ensure(size * leading)
            self._text(self.margin + indent, self.y - size, ln, font, size, color)
            self.y -= size * leading
        self.y -= space_after

    def bullets(self, items: Sequence[str], size: float = 9) -> None:
        for item in items:
            lines = self.wrap(item, "F1", size, self.width - 14)
            self.ensure(size * 1.38 * len(lines))
            self._text(self.margin + 2, self.y - size, "-", "F2", size, ACCENT)
            for ln in lines:
                self._text(self.margin + 12, self.y - size, ln, "F1", size, INK)
                self.y -= size * 1.38
        self.y -= 4

    def kv_table(self, rows: Sequence[Tuple[str, object]], key_w: float = 132, size: float = 8.5,
                 value_font: str = "F1", max_lines: int = 12) -> None:
        pad, lead = 4.0, size * 1.32
        val_w = self.width - key_w - 2 * pad
        for i, (key, value) in enumerate(rows):
            vlines = self.wrap(value if value not in (None, "") else "-", value_font, size, val_w)
            if len(vlines) > max_lines:
                vlines = vlines[:max_lines - 1] + [vlines[max_lines - 1].rstrip() + " ..."]
            klines = self.wrap(key, "F2", size, key_w - 2 * pad)
            h = max(len(vlines), len(klines)) * lead + 2 * pad
            self.ensure(h)
            top = self.y
            self._rect(self.margin, top - h, key_w, h, fill=LABEL_BG)
            if i % 2:
                self._rect(self.margin + key_w, top - h, self.width - key_w, h, fill=ZEBRA)
            for j, ln in enumerate(klines):
                self._text(self.margin + pad, top - pad - size - j * lead + 1.5, ln, "F2", size, MUTED)
            for j, ln in enumerate(vlines):
                self._text(self.margin + key_w + pad, top - pad - size - j * lead + 1.5, ln, value_font, size, INK)
            self.y -= h
        self._line(self.margin, self.y, self.margin + self.width, self.y, RULE, 0.6)
        self.y -= 8

    def table(self, headers: Sequence[str], rows: Sequence[Sequence[object]], widths: Sequence[float],
              size: float = 7.4, font: str = "F1", max_lines: int = 4, mono_cols: Sequence[int] = (),
              empty_text: str = "No records.") -> None:
        total = float(sum(widths))
        widths = [w * self.width / total for w in widths]
        pad, lead = 3.2, size * 1.3
        xs = [self.margin]
        for w in widths:
            xs.append(xs[-1] + w)

        def draw_header() -> None:
            h = size + 2 * pad + 1
            self.ensure(h + 24)
            self._rect(self.margin, self.y - h, self.width, h, fill=NAVY)
            for i, head in enumerate(headers):
                self._text(xs[i] + pad, self.y - pad - size + 1, self.wrap(head, "F2", size, widths[i] - 2 * pad)[0], "F2", size, WHITE)
            self.y -= h

        if not rows:
            self.ensure(20)
            self._text(self.margin + pad, self.y - 11, empty_text, "F1", 8.5, MUTED)
            self.y -= 22
            return
        draw_header()
        for r, row in enumerate(rows):
            cells: List[List[str]] = []
            for i, cell in enumerate(row):
                cf = "F3" if i in mono_cols else font
                lines = self.wrap(cell if cell not in (None, "") else "-", cf, size, widths[i] - 2 * pad)
                if len(lines) > max_lines:
                    lines = lines[:max_lines - 1] + [lines[max_lines - 1].rstrip()[:-3] + "..."]
                cells.append(lines)
            h = max(len(c) for c in cells) * lead + 2 * pad
            if self.y - h < self.bottom:
                self.new_page()
                draw_header()
            if r % 2:
                self._rect(self.margin, self.y - h, self.width, h, fill=ZEBRA)
            for i, lines in enumerate(cells):
                cf = "F3" if i in mono_cols else font
                for j, ln in enumerate(lines):
                    self._text(xs[i] + pad, self.y - pad - size - j * lead + 1.2, ln, cf, size, INK)
            self.y -= h
        self._line(self.margin, self.y, self.margin + self.width, self.y, RULE, 0.6)
        self.y -= 10

    def bar_chart(self, labels: Sequence[str], values: Sequence[float], height: float = 90,
                  color: Color = ACCENT, title: str = "") -> None:
        n = len(values)
        if n == 0:
            return
        label_h, top_pad = 14.0, 16.0
        self.ensure(height + label_h + top_pad + 6)
        if title:
            self._text(self.margin, self.y - 9, title, "F2", 8.5, MUTED)
        base_y = self.y - top_pad - height
        peak = max(max(values), 1)
        slot = self.width / n
        bw = max(2.0, min(34.0, slot * 0.62))
        self._line(self.margin, base_y, self.margin + self.width, base_y, RULE, 0.8)
        every = max(1, int(round(n / 14)))
        for i, v in enumerate(values):
            bh = (v / peak) * height
            x = self.margin + i * slot + (slot - bw) / 2
            if bh > 0:
                self._rect(x, base_y, bw, bh, fill=color)
                if n <= 31:
                    lab = f"{v:g}"
                    self._text(x + bw / 2 - text_width(lab, "F2", 6.5) / 2, base_y + bh + 2, lab, "F2", 6.5, MUTED)
            if i % every == 0:
                lab = clean(labels[i])[:8]
                self._text(x + bw / 2 - text_width(lab, "F1", 6.5) / 2, base_y - 9, lab, "F1", 6.5, MUTED)
        self.y = base_y - label_h - 4

    # ── serialisation ───────────────────────────────────────────────────────

    def to_bytes(self) -> bytes:
        total = len(self.pages)
        stamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        pages_with_footer: List[List[bytes]] = []
        for i, ops in enumerate(self.pages, start=1):
            footer: List[bytes] = []
            real, self.pages = self.pages, [footer]   # draw the footer into its own list (keeps to_bytes repeatable)
            self._line(self.margin, self.margin + 8, A4_W - self.margin, self.margin + 8, RULE, 0.5)
            self._text(self.margin, self.margin - 2, self.footer_note, "F1", 7, FAINT)
            label = f"Page {i} of {total}  |  {stamp}"
            self._text(A4_W - self.margin - text_width(label, "F1", 7), self.margin - 2, label, "F1", 7, FAINT)
            self.pages = real
            pages_with_footer.append(ops + footer)

        objs: List[bytes] = []

        def add(body: bytes) -> int:
            objs.append(body)
            return len(objs)

        add(b"<< /Type /Catalog /Pages 2 0 R >>")  # 1
        add(b"")                                      # 2 (Pages, patched below)
        font_ids = {k: add(f"<< /Type /Font /Subtype /Type1 /BaseFont /{v} /Encoding /WinAnsiEncoding >>".encode())
                    for k, v in FONTS.items()}        # 3..6
        font_res = " ".join(f"/{k} {i} 0 R" for k, i in font_ids.items()).encode()
        kids = []
        for ops in pages_with_footer:
            stream = zlib.compress(b"\n".join(ops), 6)
            content_id = add(b"<< /Length " + str(len(stream)).encode() + b" /Filter /FlateDecode >>\nstream\n" + stream + b"\nendstream")
            page_id = add(
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {A4_W} {A4_H}] /Contents {content_id} 0 R "
                f"/Resources << /Font << ".encode() + font_res + b" >> >> >>")
            kids.append(page_id)
        objs[1] = f"<< /Type /Pages /Count {len(kids)} /Kids [{' '.join(f'{k} 0 R' for k in kids)}] >>".encode()
        info_id = add(b"<< /Title " + _pdf_string(self.title) + b" /Producer (ForenSys) /Creator (ForenSys SOC) /CreationDate "
                      + time.strftime("(D:%Y%m%d%H%M%SZ)", time.gmtime()).encode() + b" >>")

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for n, body in enumerate(objs, start=1):
            offsets.append(len(out))
            out += f"{n} 0 obj\n".encode() + body + b"\nendobj\n"
        xref = len(out)
        out += f"xref\n0 {len(objs) + 1}\n".encode() + b"0000000000 65535 f \n"
        for off in offsets:
            out += f"{off:010d} 00000 n \n".encode()
        out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R /Info {info_id} 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
        return bytes(out)
