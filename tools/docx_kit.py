"""Shared python-docx helpers for the agentbridge documents.

Content lives in `whitepaper_content.py` / `manual_content.py` as simple blocks; this module
turns them into a styled document. CJK text needs an explicit w:eastAsia font, otherwise
LibreOffice/Docs may substitute a Latin font for Chinese glyphs.
"""
from __future__ import annotations

import datetime

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

BODY_FONT = "PingFang SC"
MONO_FONT = "Menlo"
ACCENT = RGBColor(0x1F, 0x3A, 0x5F)
MUTED = RGBColor(0x55, 0x5F, 0x6B)


def _set_style_font(style, name: str, size: int | None = None, bold: bool | None = None,
                    color: RGBColor | None = None):
    style.font.name = name
    if size is not None:
        style.font.size = Pt(size)
    if bold is not None:
        style.font.bold = bold
    if color is not None:
        style.font.color.rgb = color
    rpr = style.element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = OxmlElement("w:rFonts")
        rpr.append(rfonts)
    for attr in ("w:ascii", "w:hAnsi", "w:eastAsia", "w:cs"):
        rfonts.set(qn(attr), name)


def _run_font(run, name=BODY_FONT):
    run.font.name = name
    rpr = run._element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = OxmlElement("w:rFonts")
        rpr.append(rfonts)
    rfonts.set(qn("w:eastAsia"), name)


def _shade(paragraph, fill="F4F5F7"):
    ppr = paragraph._p.get_or_add_pPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:fill"), fill)
    ppr.append(shd)


def _page_number_footer(section, label: str):
    footer = section.footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = footer.add_run(label + "  ·  ")
    _run_font(run)
    run.font.size = Pt(8)
    run.font.color.rgb = MUTED

    run = footer.add_run()
    begin = OxmlElement("w:fldChar")
    begin.set(qn("w:fldCharType"), "begin")
    instr = OxmlElement("w:instrText")
    instr.set(qn("xml:space"), "preserve")
    instr.text = "PAGE"
    end = OxmlElement("w:fldChar")
    end.set(qn("w:fldCharType"), "end")
    run._r.append(begin)
    run._r.append(instr)
    run._r.append(end)
    run.font.size = Pt(8)
    run.font.color.rgb = MUTED


def new_document(title: str, subtitle: str, version: str, author: str = "agentbridge authors") -> Document:
    doc = Document()
    for section in doc.sections:
        section.top_margin = Cm(2.4)
        section.bottom_margin = Cm(2.2)
        section.left_margin = Cm(2.6)
        section.right_margin = Cm(2.6)

    normal = doc.styles["Normal"]
    _set_style_font(normal, BODY_FONT, 10.5)
    normal.paragraph_format.space_after = Pt(6)
    normal.paragraph_format.line_spacing = 1.28

    h1 = doc.styles["Heading 1"]
    _set_style_font(h1, BODY_FONT, 18, True, ACCENT)
    h1.paragraph_format.space_before = Pt(18)
    h1.paragraph_format.space_after = Pt(8)

    h2 = doc.styles["Heading 2"]
    _set_style_font(h2, BODY_FONT, 13.5, True, ACCENT)
    h2.paragraph_format.space_before = Pt(12)
    h2.paragraph_format.space_after = Pt(6)

    for name in ("List Bullet", "List Number"):
        _set_style_font(doc.styles[name], BODY_FONT, 10.5)

    _page_number_footer(doc.sections[0], f"{title} · v{version}")

    # cover
    for _ in range(5):
        doc.add_paragraph()
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run(title)
    _run_font(run)
    run.font.size = Pt(30)
    run.font.bold = True
    run.font.color.rgb = ACCENT

    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run(subtitle)
    _run_font(run)
    run.font.size = Pt(13)
    run.font.color.rgb = MUTED

    for _ in range(9):
        doc.add_paragraph()

    today = datetime.date.today().isoformat()
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run(f"版本 {version}　|　{today}　|　{author}")
    _run_font(run)
    run.font.size = Pt(10)
    run.font.color.rgb = MUTED

    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run("MIT License")
    _run_font(run)
    run.font.size = Pt(9)
    run.font.color.rgb = MUTED

    doc.add_page_break()
    doc.core_properties.title = title
    doc.core_properties.author = author
    doc.core_properties.subject = subtitle
    return doc


def _add_runs(paragraph, text: str, name=BODY_FONT, size=None, color=None, italic=False):
    parts = text.split("**")
    for i, part in enumerate(parts):
        if not part:
            continue
        run = paragraph.add_run(part)
        _run_font(run, name)
        if i % 2 == 1:
            run.font.bold = True
        if size is not None:
            run.font.size = Pt(size)
        if color is not None:
            run.font.color.rgb = color
        if italic:
            run.font.italic = True


def render(doc: Document, blocks) -> None:
    for block in blocks:
        kind = block[0]
        if kind == "h1":
            doc.add_heading(block[1], level=1)
        elif kind == "h2":
            doc.add_heading(block[1], level=2)
        elif kind == "h3":
            p = doc.add_paragraph()
            run = p.add_run(block[1])
            _run_font(run)
            run.font.bold = True
            run.font.size = Pt(11.5)
            run.font.color.rgb = ACCENT
        elif kind == "p":
            p = doc.add_paragraph()
            _add_runs(p, block[1])
        elif kind == "muted":
            p = doc.add_paragraph()
            run = p.add_run(block[1])
            _run_font(run)
            run.font.size = Pt(9)
            run.font.color.rgb = MUTED
        elif kind == "bullet":
            p = doc.add_paragraph(style="List Bullet")
            _add_runs(p, block[1])
        elif kind == "num":
            p = doc.add_paragraph(style="List Number")
            _add_runs(p, block[1])
        elif kind == "code":
            for line in block[1].split("\n"):
                p = doc.add_paragraph()
                p.paragraph_format.left_indent = Cm(0.4)
                p.paragraph_format.space_after = Pt(0)
                p.paragraph_format.line_spacing = 1.0
                run = p.add_run(line if line else " ")
                _run_font(run, MONO_FONT)
                run.font.size = Pt(8.5)
                _shade(p)
            doc.add_paragraph().paragraph_format.space_after = Pt(2)
        elif kind == "quote":
            p = doc.add_paragraph()
            p.paragraph_format.left_indent = Cm(0.6)
            _add_runs(p, block[1], italic=True, color=MUTED)
        elif kind == "table":
            headers, rows = block[1], block[2]
            table = doc.add_table(rows=1, cols=len(headers))
            table.style = "Table Grid"
            table.alignment = WD_TABLE_ALIGNMENT.CENTER
            hdr = table.rows[0].cells
            for i, text in enumerate(headers):
                hdr[i].text = ""
                run = hdr[i].paragraphs[0].add_run(str(text).replace("**", ""))
                _run_font(run)
                run.font.bold = True
                run.font.size = Pt(9.5)
            # No tblHeader repeat: LibreOffice renders the repeated header as an empty row
            # when a table breaks across pages. Rows are kept splittable for the same reason.
            for row in rows:
                cells = table.add_row().cells
                for i, text in enumerate(row):
                    cells[i].text = ""
                    _add_runs(cells[i].paragraphs[0], str(text), size=9.5)
            # NOTE: do not add w:cantSplit to every row: LibreOffice can drop body rows
            # when a table starts near the page bottom. Header repeat alone is safe.
            doc.add_paragraph().paragraph_format.space_after = Pt(2)
        elif kind == "pagebreak":
            doc.add_page_break()
        elif kind == "toc":
            p = doc.add_paragraph()
            run = p.add_run("目录")
            _run_font(run)
            run.font.size = Pt(16)
            run.font.bold = True
            run.font.color.rgb = ACCENT
            for title in block[1]:
                p = doc.add_paragraph()
                p.paragraph_format.space_after = Pt(3)
                run = p.add_run("　" + title)
                _run_font(run)
                run.font.size = Pt(10.5)
            doc.add_page_break()
        else:
            raise ValueError(f"unknown block kind: {kind}")


def save(doc: Document, path: str) -> None:
    doc.save(path)
