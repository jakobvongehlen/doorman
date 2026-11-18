"""Plain text out of documents: mail attachments, files in the archive, uploads.

PDFs are read page by page with pypdfium2 (PDFium, the PDF engine in Chrome). A page with a text layer
gives its text directly. A page without one (a scan, a photographed letter) is rendered at `dpi` and read
with RapidOCR and the PP-OCRv6 small models, which are multilingual and cover Latin-script languages
(German, Dutch, English among them). Images go to OCR directly. Word, OpenDocument, HTML and text files
are read as they are.

What a reader of the document doesn't see is left out (sanitize.py): hidden HTML, hidden Word runs,
deleted changes, comments. Text in a PDF nobody can see can't be cut out, so it is reported as `hidden_text`
and the guard holds the PDF back. Two checks look for it: pdf_hidden.py, from each page itself in
milliseconds (invisible, white on white, tiny, off the page, covered), which says `clean`, `hidden` or
`undecided` (`hidden_check`); and, as the backstop, OCR of up to 2 pages at 100 dpi, when the text layer holds
clearly more than OCR reads off the rendered page (seconds a page).

Bombs (a few KB that unpack or decode into gigabytes) are caught before anything is decoded: a Word or
OpenDocument file by what its zip directory claims, an image by the size in its header, and a PDF page is
rendered no larger than MAX_RENDER_PIXELS. They come back as "couldn't extract text: too large (...)".

This runs in the extractor's own process (extract_worker.py), locked down with no network and no files
beyond Python itself, so parsing a stranger's PDF never happens next to the vault or a plugin's password.
`extract()` is also usable in-process for tests and as a fallback.
"""

from __future__ import annotations

import hashlib
import html
import io
import mimetypes
import re
import zipfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from . import pdf_hidden, sanitize

TEXT_TYPES = {".txt", ".md", ".csv", ".json", ".xml", ".yaml", ".yml", ".log", ".ics", ".vcf", ".eml", ".html",
              ".htm"}
IMAGE_TYPES = {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp", ".webp"}
LIMIT = 2_000_000
MIN_LAYER_CHARS = 20   # a page whose text layer has fewer non-blank characters counts as a scan
MAX_PAGES = 500        # pages read from one PDF
CHECK_PAGES, CHECK_DPI, CHECK_MIN_WORDS = 2, 100, 50  # the hidden-text check: pages, resolution, minimum text

# Bombs: a small file that unpacks or renders into gigabytes. Each is checked before anything is decoded.
MAX_RENDER_PIXELS = 25_000_000   # a rendered PDF page (A4 at 200 dpi is 3.9 M); larger pages render coarser
MAX_IMAGE_PIXELS = 50_000_000    # an image decoded for OCR (a 48 MP photo; JPEGs are scaled down while decoding)
OCR_MAX_SIDE = 6000              # an image larger than this is scaled down before OCR
MAX_XML_BYTES = 40_000_000       # the text part of a Word or OpenDocument file, unpacked
MAX_ZIP_BYTES = 500_000_000      # all parts of one, unpacked, as its directory claims
MAX_ZIP_RATIO = 200              # unpacked : packed for a part over 1 MB (text XML packs about 5 to 30 : 1)


class TooLarge(Exception):
    """A document that would unpack or decode into far more than it looks: not read."""

# RapidOCR 3.10.0 ships these in its wheel; checked before use, so another version can't slip in
OCR_MODELS = {
    "det": ("PP-OCRv6_det_small.onnx", "090f04abcd9d9a7498bc4ebf677e4cb9bdce1fe4197ddb7e529f1ef44e1ff94f"),
    "rec": ("PP-OCRv6_rec_small.onnx", "6f327246b50388f3c176ae304bd95767ea6dc0c9ae92153ef8cbe210b3c14884"),
}


def suffix_for(name: str, content_type: str | None = None) -> str:
    suffix = Path(name or "").suffix.lower()
    if not suffix and content_type:
        suffix = (mimetypes.guess_extension(content_type.split(";")[0].strip()) or "").lower()
    return suffix


class OCR:
    """RapidOCR with the bundled PP-OCRv6 small models, loaded on first use."""

    def __init__(self):
        self._engine = None
        self.error: str | None = None

    @staticmethod
    def model_paths() -> dict[str, Path]:
        import rapidocr

        models = Path(rapidocr.__file__).resolve().parent / "models"
        return {key: models / name for key, (name, _) in OCR_MODELS.items()}

    def engine(self):
        if self._engine is None and self.error is None:
            try:
                import onnxruntime

                onnxruntime.set_default_logger_severity(3)  # errors only: no telemetry or GPU warnings
                from rapidocr import OCRVersion, RapidOCR

                paths = self.model_paths()
                for key, (name, sha) in OCR_MODELS.items():
                    if hashlib.sha256(paths[key].read_bytes()).hexdigest() != sha:
                        raise RuntimeError(f"{name} isn't the pinned PP-OCRv6 model (install rapidocr==3.10.0)")
                self._engine = RapidOCR(params={
                    "Global.use_cls": False, "Global.log_level": "error",
                    "Det.model_path": str(paths["det"]), "Det.ocr_version": OCRVersion.PPOCRV6,
                    "Rec.model_path": str(paths["rec"]), "Rec.ocr_version": OCRVersion.PPOCRV6,
                    "EngineConfig.onnxruntime.intra_op_num_threads": 1,
                    "EngineConfig.onnxruntime.inter_op_num_threads": 1,
                })
            except Exception as exc:  # noqa: BLE001 - not installed, wrong models: say so, read the rest
                self.error = f"{type(exc).__name__}: {exc}"
        return self._engine

    def read(self, image) -> str:
        """Text lines of a PIL image, top to bottom."""
        import numpy as np

        engine = self.engine()
        if engine is None:
            raise RuntimeError(self.error or "OCR isn't available")
        result = engine(np.array(image.convert("RGB")))
        return "\n".join(result.txts or ())


def check_mode(value) -> bool | str:
    """check_pdf as a caller may pass it: True (both checks), "fast" (pdf_hidden's only) or False."""
    return "fast" if value == "fast" else bool(value)


def _pdf(content: bytes, ocr: OCR | None, read_scans: bool, check_pdf: bool | str, dpi: int, max_ocr_pages: int,
         limit: int) -> dict:
    import pypdfium2 as pdfium

    # page text only: annotations, form fields, document info and XMP metadata are never read
    document = pdfium.PdfDocument(content)
    fast = pdf_hidden.Check() if check_pdf else None
    try:
        total = len(document)
        texts, ocr_pages, skipped, checked = [], [], [], 0
        report: dict = {}
        size = 0
        for index in range(min(total, MAX_PAGES)):
            page = document[index]
            try:
                textpage = page.get_textpage()
                text = textpage.get_text_bounded()
                if fast is not None:
                    fast.page(index, page, textpage, text)
                textpage.close()
                if len(re.sub(r"\s", "", text)) < MIN_LAYER_CHARS:
                    read = None
                    if read_scans and ocr is not None and ocr.error is None and len(ocr_pages) < max_ocr_pages:
                        try:
                            read = ocr.read(_render(page, dpi))
                            ocr_pages.append(index + 1)
                        except RuntimeError:
                            read = None  # OCR can't load: ocr.error says why
                    if read is not None:
                        text = read
                    elif not text.strip():
                        skipped.append(index + 1)
                elif check_pdf is True and ocr is not None and checked < CHECK_PAGES and "hidden_text" not in report \
                        and not fast.hiding() and len(re.findall(r"\w", text)) >= CHECK_MIN_WORDS:
                    # text nobody sees (white, tiny, covered, off the page): the layer holds much more than
                    # the rendered page shows
                    checked += 1
                    try:
                        # a page too large for CHECK_DPI would render coarser and OCR would see less: no check
                        image = _render(page, CHECK_DPI, exact=True)
                        seen = ocr.read(image) if image is not None else None
                    except RuntimeError:
                        seen = None  # a check that can't run says nothing
                    if seen is not None and sanitize.pdf_mismatch(text, seen):
                        count = lambda s: len(re.findall(r"\w", s))  # noqa: E731
                        report["hidden_text"] = {"reason": "a PDF with text that isn't visible on the page",
                                                 "page": index + 1, "extracted": count(text), "visible": count(seen)}
            finally:
                page.close()
            texts.append(text.strip())
            size += len(text)
            if size > limit:
                break
    finally:
        document.close()
    out: dict[str, Any] = {"text": "\n\n".join(t for t in texts if t)[:limit], "pages": total,
                           "ocr_pages": ocr_pages, "report": report}
    if fast is not None:
        outcome, found = fast.outcome()
        if found and "hidden_text" not in report:
            report["hidden_text"] = found
        out["hidden_check"] = "hidden" if "hidden_text" in report else outcome
    notes = []
    if skipped:
        why = ("OCR is off" if ocr is None or not read_scans else f"OCR isn't available: {ocr.error}" if ocr.error
               else f"only the first {max_ocr_pages} scanned pages are read")
        notes.append(f"pages without text that weren't read ({why}): {_ranges(skipped)}")
    if total > MAX_PAGES:
        notes.append(f"only the first {MAX_PAGES} of {total} pages were read")
    if notes:
        out["note"] = "; ".join(notes)
    return out


def render_scale(width_pt: float, height_pt: float, dpi: float) -> float:
    """pdfium's scale for a page of this size at `dpi`, lowered so the bitmap stays under MAX_RENDER_PIXELS
    (a page can claim to be metres wide; at 200 dpi that would be gigabytes)."""
    scale = dpi / 72
    area = max(width_pt, 1.0) * max(height_pt, 1.0)
    return min(scale, (MAX_RENDER_PIXELS / area) ** 0.5)


def _render(page, dpi: float, exact: bool = False):
    """The page as a PIL image at `dpi`, or coarser if it's huge. `exact`: None instead of coarser."""
    width, height = page.get_size()
    scale = render_scale(width, height, dpi)
    if exact and scale < dpi / 72:
        return None
    return page.render(scale=scale).to_pil()


def _ranges(pages: list[int]) -> str:
    parts, start = [], None
    for i, n in enumerate(pages):
        if start is None:
            start = n
        if i + 1 == len(pages) or pages[i + 1] != n + 1:
            parts.append(str(start) if start == n else f"{start}-{n}")
            start = None
    return ", ".join(parts)


# Word: deleted tracked changes, field codes, comments' anchors; runs that are hidden (w:vanish, w:specVanish),
# white, or 1 pt and smaller (w:sz is in half-points). Comments live in word/comments.xml, which isn't read.
_DOCX_DROP = re.compile(r"(?s)<w:del\b[^>]*>.*?</w:del>|<w:delText\b[^>]*>.*?</w:delText>|"
                        r"<w:instrText\b[^>]*>.*?</w:instrText>|<w:moveFrom\b[^>]*>.*?</w:moveFrom>")
_DOCX_RUN = re.compile(r"(?s)<w:r\b[^>]*>.*?</w:r>")
_DOCX_HIDDEN = re.compile(r'<w:(?:spec)?[vV]anish\b(?![^>]*w:val="(?:0|false)")[^>]*/>|'
                          r'<w:color\b[^>]*w:val="(?:FFFFFF|ffffff)"|<w:sz\b[^>]*w:val="[0-2]"')
# OpenDocument: comments sit inline (office:annotation), deleted changes in text:tracked-changes
_ODT_DROP = re.compile(r"(?s)<office:annotation\b.*?</office:annotation>|<text:tracked-changes\b.*?"
                       r"</text:tracked-changes>|<text:hidden-text\b[^>]*/>|<text:hidden-text\b.*?</text:hidden-text>|"
                       r"<text:hidden-paragraph\b.*?</text:hidden-paragraph>")


def office_text(xml: str, kind: str, limit: int = LIMIT) -> tuple[str, dict]:
    report: dict = {}
    if kind == "docx":
        xml, dropped = _DOCX_DROP.subn("", xml)

        def run(match: re.Match) -> str:
            properties = re.search(r"(?s)<w:rPr\b.*?</w:rPr>", match.group(0))
            if properties and _DOCX_HIDDEN.search(properties.group(0)):
                report["hidden runs"] = report.get("hidden runs", 0) + 1
                return ""
            return match.group(0)
        xml = _DOCX_RUN.sub(run, xml)
        xml = re.sub(r"</w:p>", "\n", xml)
        xml = re.sub(r"<w:tab/>", "\t", xml)
    else:
        xml, dropped = _ODT_DROP.subn("", xml)
        xml = re.sub(r"</text:p>|<text:p[^>]*/>|</text:h>|<text:line-break/>", "\n", xml)
    if dropped:
        report["comments or deleted changes"] = dropped
    return html.unescape(re.sub(r"<[^>]+>", "", xml))[:limit], report


MAX_ZIP_ENTRIES = 10_000


def zip_member(content: bytes, inner: str) -> bytes:
    """One part of a zip (a Word or OpenDocument file), after checking what its directory claims: the number
    of parts, their unpacked size, the part's size and how far it unpacks. The read itself stops at the cap
    too, so a directory that lies doesn't help."""
    stream = io.BytesIO(content)
    try:  # the entry count before ZipFile builds an object per entry
        end = zipfile._EndRecData(stream)  # noqa: SLF001 - no public way to read it first
    except Exception:  # noqa: BLE001 - ZipFile below says what's wrong
        end = None
    if end and end[zipfile._ECD_ENTRIES_TOTAL] > MAX_ZIP_ENTRIES:  # noqa: SLF001
        raise TooLarge(f"{end[zipfile._ECD_ENTRIES_TOTAL]} parts")  # noqa: SLF001
    with zipfile.ZipFile(stream) as archive:
        total = sum(info.file_size for info in archive.infolist())
        if total > MAX_ZIP_BYTES:
            raise TooLarge(f"unpacks to {total // 1_000_000} MB")
        info = archive.getinfo(inner)
        if info.file_size > MAX_XML_BYTES:
            raise TooLarge(f"its text unpacks to {info.file_size // 1_000_000} MB")
        if info.file_size > 1_000_000 and info.file_size > MAX_ZIP_RATIO * max(info.compress_size, 1):
            raise TooLarge(f"its text unpacks {info.file_size // max(info.compress_size, 1)} times larger")
        with archive.open(info) as fh:
            data = fh.read(MAX_XML_BYTES + 1)
    if len(data) > MAX_XML_BYTES:
        raise TooLarge(f"its text unpacks to more than {MAX_XML_BYTES // 1_000_000} MB")
    return data


@contextmanager
def open_image(content: bytes):
    """A PIL image ready for OCR, at most OCR_MAX_SIDE on its longer side. Its size comes from the header
    (Image.open doesn't decode); one over MAX_IMAGE_PIXELS is refused before any pixel is decoded, except
    a JPEG, which decodes at 1/2, 1/4 or 1/8 of its size when that brings it under."""
    import warnings

    from PIL import Image

    # Pillow refuses at twice its limit, from the header in Image.open: here what a JPEG decoded at 1/8 can
    # bring under ours. Everything else is held to ours below.
    Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS * 32
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", Image.DecompressionBombWarning)  # checked here instead
        try:
            image = Image.open(io.BytesIO(content))
        except Image.DecompressionBombError as exc:
            raise TooLarge(str(exc).split(",")[0]) from None
    with image:
        width, height = image.size
        if width * height > MAX_IMAGE_PIXELS and image.format == "JPEG":
            step = next((s for s in (2, 4, 8) if width * height / (s * s) <= MAX_IMAGE_PIXELS), 8)
            image.draft(image.mode, (max(width // step, 1), max(height // step, 1)))
        if image.size[0] * image.size[1] > MAX_IMAGE_PIXELS:
            raise TooLarge(f"an image of {width} × {height} pixels")
        image.load()
        if max(image.size) > OCR_MAX_SIDE:
            image.thumbnail((OCR_MAX_SIDE, OCR_MAX_SIDE))
        yield image


def extract(name: str, content: bytes, content_type: str | None = None, ocr: OCR | None = None,
            dpi: int = 200, max_ocr_pages: int = 20, limit: int = LIMIT, read_scans: bool = True,
            check_pdf: bool | str = True) -> dict:
    """{text, report, pages?, ocr_pages?, note?, hidden_check?}. `report` says what was left out
    (sanitize.describe makes a line of it) and holds `hidden_text` for a PDF with invisible text.
    `check_pdf`: True runs both checks for hidden text in a PDF, the structural one (pdf_hidden.py; its outcome
    is `hidden_check`: "clean", "hidden" or "undecided") and the OCR comparison; "fast" only the structural
    one; False neither. `ocr` None: no OCR at all (scans come back empty, with a note; no OCR comparison);
    `read_scans` False: OCR only for the comparison."""
    check_pdf = check_mode(check_pdf)
    suffix = suffix_for(name, content_type)
    ctype = (content_type or "").split(";")[0].strip().lower()
    try:
        if suffix == ".pdf" or ctype == "application/pdf":
            return _pdf(content, ocr, read_scans, check_pdf, dpi, max_ocr_pages, limit)
        if suffix in (".html", ".htm") or ctype in ("text/html", "application/xhtml+xml"):
            text, report = sanitize.html_to_text(content[:limit].decode("utf-8", "replace"))
            return {"text": text, "report": report}
        if suffix in TEXT_TYPES or ctype.startswith("text/"):
            return {"text": content[:limit].decode("utf-8", "replace"), "report": {}}
        if suffix in (".docx", ".odt"):
            inner = "word/document.xml" if suffix == ".docx" else "content.xml"
            xml = zip_member(content, inner).decode("utf-8", "replace")
            text, report = office_text(xml, suffix[1:], limit)
            return {"text": text, "report": report}
        if suffix in IMAGE_TYPES or ctype.startswith("image/"):
            if ocr is None or not read_scans:
                return {"text": "", "report": {}, "note": "an image; OCR is off"}
            with open_image(content) as image:
                return {"text": ocr.read(image)[:limit], "report": {}, "ocr_pages": [1]}
    except TooLarge as exc:
        return {"text": "", "report": {}, "note": f"couldn't extract text: too large ({exc})"[:300]}
    except MemoryError:  # the extractor's memory cap (extract.memory_mb)
        return {"text": "", "report": {}, "note": "couldn't extract text: too large (it needs more memory than "
                                                  "the extractor may use)"}
    except Exception as exc:  # noqa: BLE001 - one unreadable document must not stop the caller
        return {"text": "", "report": {}, "note": f"could not extract text: {type(exc).__name__}: {exc}"[:300]}
    return {"text": "", "report": {}}


_LOCAL_OCR: OCR | None = None


def _local_ocr() -> OCR:
    global _LOCAL_OCR
    if _LOCAL_OCR is None:
        _LOCAL_OCR = OCR()
    return _LOCAL_OCR


def extract_checked(name: str, content: bytes, ocr: bool = False, limit: int = LIMIT,
                    content_type: str | None = None, check_pdf: bool | str = True) -> tuple[str, dict]:
    """(text, report) in this process: scans read only with `ocr`, the hidden-text checks with `check_pdf`."""
    engine = _local_ocr() if (ocr or check_pdf is True) else None
    out = extract(name, content, content_type, engine, limit=limit, read_scans=ocr, check_pdf=check_pdf)
    return out["text"], out.get("report") or {}


def extract_bytes(name: str, content: bytes, ocr: bool = False, limit: int = LIMIT,
                  content_type: str | None = None) -> str:
    """Just the text, in this process."""
    return extract_checked(name, content, ocr=ocr, limit=limit, content_type=content_type, check_pdf=False)[0]


def extract_text(path: Path, ocr: bool = False, limit: int = LIMIT) -> str:
    try:
        content = path.read_bytes()
    except OSError as exc:
        return f"[could not extract text: {type(exc).__name__}]"
    return extract_bytes(path.name, content, ocr=ocr, limit=limit)
