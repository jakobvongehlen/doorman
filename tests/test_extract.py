"""Text out of documents: pypdfium2 for pages with a text layer, RapidOCR (PP-OCRv6) for scanned pages,
in the extractor's own process. OCR tests need rapidocr and take a few seconds a page."""

import io
from pathlib import Path

import pytest
from PIL import Image, ImageDraw, ImageFont

from doorman.extract import OCR, extract
from doorman.extractor import Extractor
from conftest import make_engine
from test_attachments import tiny_docx, tiny_pdf

try:
    import rapidocr  # noqa: F401 - is it installed?
    HAVE_OCR = True
except ImportError:
    HAVE_OCR = False


def needs_ocr(test):
    """Needs RapidOCR, and is slow: a few seconds a page. `pytest -m "not slow"` leaves these out."""
    return pytest.mark.slow(pytest.mark.skipif(not HAVE_OCR, reason="rapidocr isn't installed")(test))

LINES = ["Rechnung Nr. 2026-1184", "bitte überweisen Sie 84,20 EUR", "het rooster voor blok 2"]


def font(size=34):
    for candidate in ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
                      "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf"):
        if Path(candidate).exists():
            return ImageFont.truetype(candidate, size)
    return ImageFont.load_default(size=size)


def scan_image(lines=LINES) -> Image.Image:
    image = Image.new("RGB", (1240, 120 + 70 * len(lines)), "white")
    draw = ImageDraw.Draw(image)
    for i, line in enumerate(lines):
        draw.text((80, 60 + i * 70), line, fill="black", font=font())
    return image


def scan_pdf(pages: int = 1) -> bytes:
    """Image-only pages, like a scanner makes: no text layer."""
    out = io.BytesIO()
    images = [scan_image() for _ in range(pages)]
    images[0].save(out, format="PDF", resolution=150, save_all=True, append_images=images[1:])
    return out.getvalue()


def merge(*pdfs: bytes) -> bytes:
    import pypdfium2 as pdfium

    merged = pdfium.PdfDocument.new()
    for blob in pdfs:
        source = pdfium.PdfDocument(blob)
        merged.import_pages(source)
    out = io.BytesIO()
    merged.save(out)
    return out.getvalue()


def test_text_layer_pages_come_from_pdfium_without_ocr():
    out = extract("invoice.pdf", tiny_pdf("Total 84.20 EUR due 2026-11-15"), ocr=None)
    assert "Total 84.20 EUR" in out["text"] and out["pages"] == 1 and out["ocr_pages"] == []


def test_without_ocr_a_scan_says_which_pages_were_left_out():
    out = extract("scan.pdf", merge(tiny_pdf("Cover letter text here"), scan_pdf(2)), ocr=None)
    assert "Cover letter" in out["text"]
    assert out["pages"] == 3 and "2-3" in out["note"] and "OCR is off" in out["note"]


def test_office_and_text_formats():
    assert "room 4.12" in extract("s.docx", tiny_docx("Lecture in room 4.12"))["text"]
    assert extract("a.html", b"<p>Hi <b>there</b></p><script>x()</script>")["text"].split() == ["Hi", "there"]
    assert extract("broken.pdf", b"%PDF-1.4 nonsense")["note"].startswith("could not extract text")


@needs_ocr
def test_scanned_pages_are_read_with_ocr():
    out = extract("letter.pdf", merge(tiny_pdf("Page one has a text layer"), scan_pdf(1)), ocr=OCR())
    assert out["ocr_pages"] == [2]
    assert "Page one has a text layer" in out["text"]
    assert "2026-1184" in out["text"] and "84,20" in out["text"] and "überweisen" in out["text"]


@needs_ocr
def test_only_so_many_scanned_pages_are_read():
    out = extract("long.pdf", scan_pdf(2), ocr=OCR(), max_ocr_pages=1)
    assert out["ocr_pages"] == [1] and "only the first 1 scanned pages" in out["note"]


@needs_ocr
def test_images_are_read_with_ocr():
    buf = io.BytesIO()
    scan_image(["Termin am 12.11. um 10:00"]).save(buf, format="PNG")
    out = extract("photo.png", buf.getvalue(), ocr=OCR())
    assert "12.11" in out["text"] and out["ocr_pages"] == [1]


@needs_ocr
def test_the_extractor_process_in_its_sandbox(tmp_path):
    extractor = Extractor({"plugin_sandbox": True, "extract": {"ocr": True, "dpi": 150, "ocr_max_pages": 5}})
    try:
        out = extractor.extract("scan.pdf", scan_pdf(1), "application/pdf")
        assert out["ocr_pages"] == [1] and "2026-1184" in out["text"], out
        assert extractor.worker.alive()
    finally:
        extractor.stop()


def test_a_broken_extractor_gives_empty_text_and_a_note(monkeypatch):
    from doorman import extractor as module

    class Broken:
        def __init__(self, *args, **kwargs):
            pass

        def start(self, timeout):
            raise module.WorkerUnavailable("The text extractor stopped (exit code -9).")

    monkeypatch.setattr(module, "Worker", Broken)
    out = Extractor({"plugin_sandbox": False}).extract("a.pdf", tiny_pdf("x"))
    assert out == {"text": "", "report": {}, "note": "couldn't extract text: The text extractor stopped (exit code -9)."}


@needs_ocr
def test_files_read_uses_ocr_for_a_scan(tmp_path):
    from conftest import Agent

    archive = tmp_path / "archive"
    archive.mkdir()
    (archive / "brief.pdf").write_bytes(scan_pdf(1))
    engine = make_engine(tmp_path, plugins={"files": {"enabled": True, "config": {"root": str(archive)}}})
    out = Agent(engine).read("files.read", {"path": "brief.pdf"})
    assert out["ocr_pages"] == [1] and "2026-1184" in out["text"]


# ------------------------------------------------------------------ bombs: small files that unpack into gigabytes

class SizeOCR:
    """Stands in for RapidOCR: records the size of each image it gets."""
    error = None

    def __init__(self):
        self.sizes = []

    def read(self, image):
        self.sizes.append(image.size)
        return "seen"


def blank_pdf(width_pt: int, height_pt: int) -> bytes:
    """One page with nothing on it (so it counts as a scan), of any size a PDF can claim."""
    objects = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
               b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] >>" % (width_pt, height_pt)]
    out, offsets = io.BytesIO(), []
    out.write(b"%PDF-1.4\n")
    for n, body in enumerate(objects, 1):
        offsets.append(out.tell())
        out.write(b"%d 0 obj\n" % n + body + b"\nendobj\n")
    xref = out.tell()
    out.write(b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1))
    for offset in offsets:
        out.write(b"%010d 00000 n \n" % offset)
    out.write(b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref))
    return out.getvalue()


def png_claiming(width: int, height: int) -> bytes:
    """A real 1×1 PNG whose header says width × height: tiny on disk, gigabytes once decoded."""
    import struct
    import zlib

    buf = io.BytesIO()
    Image.new("L", (1, 1)).save(buf, format="PNG")
    data = bytearray(buf.getvalue())
    at = data.index(b"IHDR")
    data[at + 4:at + 12] = struct.pack(">II", width, height)
    data[at + 17:at + 21] = struct.pack(">I", zlib.crc32(bytes(data[at:at + 17])))
    return bytes(data)


def docx_with(xml: bytes, extra: int = 0) -> bytes:
    import zipfile

    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("word/document.xml", xml)
        for n in range(extra):
            archive.writestr(f"word/media/{n}.bin", b"")
    return out.getvalue()


def test_a_zip_bomb_in_a_word_file_is_refused_before_it_unpacks(monkeypatch):
    from doorman import extract as module

    bomb = docx_with(b"<w:document>" + b" " * 5_000_000 + b"</w:document>")  # 5 MB of spaces in ~5 KB
    assert len(bomb) < 20_000
    out = extract("cv.docx", bomb)
    assert out["text"] == "" and out["note"].startswith("couldn't extract text: too large")
    assert "times larger" in out["note"]

    ordinary = docx_with(b'<w:document xmlns:w="w"><w:p><w:r><w:t>Lecture in room 4.12</w:t></w:r></w:p></w:document>',
                         extra=20)
    assert "room 4.12" in extract("s.docx", ordinary)["text"]
    monkeypatch.setattr(module, "MAX_ZIP_ENTRIES", 10)  # a directory of a million empty entries
    assert "21 parts" in extract("s.docx", ordinary)["note"]
    monkeypatch.setattr(module, "MAX_ZIP_ENTRIES", 10_000)
    monkeypatch.setattr(module, "MAX_XML_BYTES", 50)  # larger than the cap, however well it packs
    assert "too large" in extract("s.docx", ordinary)["note"]
    monkeypatch.setattr(module, "MAX_XML_BYTES", 40_000_000)
    monkeypatch.setattr(module, "MAX_ZIP_BYTES", 50)  # all parts together
    assert "unpacks to" in extract("s.docx", ordinary)["note"]


def test_an_image_whose_header_claims_huge_dimensions_is_refused_before_decoding():
    ocr = SizeOCR()
    for width, height in ((100_000, 100_000), (8_000, 8_000)):  # Pillow's own limit, and ours below it
        out = extract("scan.png", png_claiming(width, height), ocr=ocr)
        assert out["text"] == "" and out["note"].startswith("couldn't extract text: too large"), out
    assert ocr.sizes == []  # nothing reached OCR, nothing was decoded


def test_a_large_jpeg_is_decoded_smaller_and_a_large_image_scaled_for_ocr(monkeypatch):
    from doorman import extract as module

    buf = io.BytesIO()
    Image.new("RGB", (800, 600), "white").save(buf, format="JPEG")
    monkeypatch.setattr(module, "MAX_IMAGE_PIXELS", 200_000)
    ocr = SizeOCR()
    assert extract("photo.jpg", buf.getvalue(), ocr=ocr)["text"] == "seen"
    assert ocr.sizes == [(400, 300)]  # decoded at half size: 120,000 pixels
    monkeypatch.setattr(module, "MAX_IMAGE_PIXELS", 50_000_000)
    monkeypatch.setattr(module, "OCR_MAX_SIDE", 200)
    extract("photo.jpg", buf.getvalue(), ocr=ocr)
    assert ocr.sizes[-1] == (200, 150)


def test_a_huge_pdf_page_renders_under_the_pixel_cap(monkeypatch):
    from doorman import extract as module

    assert module.render_scale(595, 842, 200) == 200 / 72  # A4 renders at the dpi asked for
    scale = module.render_scale(14_400, 14_400, 200)  # 5 m × 5 m: 1.6 billion pixels at 200 dpi
    assert (14_400 * scale) ** 2 <= module.MAX_RENDER_PIXELS * 1.0001
    monkeypatch.setattr(module, "MAX_RENDER_PIXELS", 1_000_000)
    ocr = SizeOCR()
    out = extract("poster.pdf", blank_pdf(14_400, 14_400), ocr=ocr)
    assert out["ocr_pages"] == [1] and len(ocr.sizes) == 1
    width, height = ocr.sizes[0]
    assert width * height <= 1_000_000 and width >= 990


def test_a_bomb_through_the_extractor_process_comes_back_as_a_note():
    extractor = Extractor({"plugin_sandbox": False, "extract": {"ocr": True}})
    try:
        out = extractor.extract("scan.png", png_claiming(100_000, 100_000), "image/png")
        assert out["text"] == "" and "too large" in out["note"]
        assert extractor.worker.alive()  # it answered; nothing crashed
        limits = Path(f"/proc/{extractor.worker.pid}/limits").read_text()
        assert f"Max address space         {2048 * 1024 * 1024}" in limits  # extract.memory_mb
        bomb = docx_with(b"<w:document>" + b" " * 5_000_000 + b"</w:document>")
        assert "too large" in extractor.extract("cv.docx", bomb)["note"]
    finally:
        extractor.stop()
