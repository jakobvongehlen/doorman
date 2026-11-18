"""Text in a PDF that nobody sees, found from the page itself in milliseconds, without OCR (extract._pdf).

Each page with a text layer is rendered twice at 72 dpi: as it is, and with its text switched off. A character
a reader can see changes the pixels under it toward its own colour; one that doesn't is hidden: drawn in
invisible mode, fully transparent, in the colour of what's behind it (white on white), covered by something
drawn over it, cut away by a clip or an optional layer that's off. Two rules need no pixels: a character
outside the page's visible area (its crop box) and one too small to read (under TINY_PT) are hidden too.

What this can't tell is `undecided`, left to the OCR comparison (sanitize.pdf_mismatch):
- a character that doesn't show where the page has an image, under it or over it. A scanner's searchable PDF
  puts an invisible text layer over the picture of the page; that's normal, and only OCR can say whether the
  two say the same. So can a text with a picture (a stamp, a signature) drawn over it;
- a character that doesn't show over other drawing (lettering drawn as outlines, with a text layer for search);
- pages it doesn't look at: past MAX_PAGES, a page with more than MAX_PAGE_CHARS characters, one too large
  to render at MIN_DPI, one pdfium can't take apart.

A page hides text from PAGE_MIN hidden letters and digits on it, a document from DOC_MIN over all its pages,
so a few stray characters, a pale footer or a tiny page number don't count. Undecided characters count the
same way: a few under a logo leave a PDF clean, a scanned page of them makes it undecided."""

from __future__ import annotations

import ctypes
import re
import struct
from collections import Counter
from dataclasses import dataclass, field

DPI = 72                 # the two renders: a pixel per point, enough for 3 pt text in pale grey to show
MIN_DPI = 36             # a page so large that its renders would be coarser than this isn't looked at
MAX_PIXELS = 2_000_000   # per render (A4 at 72 dpi is 0.5 M); a larger page renders coarser
TINY_PT = 1.5            # an em under this is unreadable at any normal zoom (fine print is 5 to 6 pt)
CONTRAST = 60            # |colour - background| summed over R, G, B (0-765) under which text can't be told apart
COVER = 0.2              # a pixel shows a character when it moved this far from the background toward its colour
INK = 12                 # standard deviation of the brightness (0-255) under a character with the text off,
                         # from which something is drawn there (outlines, a pattern) and the pixels can't decide
PAGE_MIN = 40            # hidden letters and digits that make a page hide text
DOC_MIN = 200            # and the whole document
MAX_PAGES = 100          # pages looked at; text on a page after them leaves the PDF undecided
MAX_PAGE_CHARS = 25_000  # characters on one page
MAX_IMAGES = 500         # images on one page
MAX_LOOK_BEHIND = 1000   # characters out of sight on a page whose background is looked at; the rest undecided

TRICKS = {
    "off_page": "text outside the visible page",
    "tiny": "text too small to read",
    "invisible": "text drawn invisible",
    "transparent": "fully transparent text",
    "white": "white text on a white page",
    "background": "text in the colour of its background",
    "covered": "text that is covered or cut off",
}

_EDGE_TRICKS = ("covered", "white", "background")  # what changes along a line: where it is, what's behind
_INVISIBLE_MODES = (3, 7)   # FPDF_TEXTRENDERMODE_INVISIBLE, _CLIP
_STROKE_MODES = (1, 5)      # stroke only (and clip)
_BOTH_MODES = (2, 6)        # fill and stroke


@dataclass
class Page:
    """What the check found on one page: hidden letters and digits by trick, undecided ones, all of them;
    `whole` says why the page as a whole is undecided."""
    hidden: Counter = field(default_factory=Counter)
    undecided: int = 0
    words: int = 0
    whole: str | None = None


def _void_binding(name: str):
    """A pdfium function that returns a pointer as a plain int (the same object, comparable), not a ctypes
    pointer object: casting one per character would be a third of the check's time."""
    import pypdfium2.raw as pdfium_c
    import pypdfium2_raw.bindings as bindings

    func = bindings._libs["pdfium"][name]  # noqa: SLF001 - a fresh function object; pypdfium2's stays as it is
    func.argtypes = getattr(pdfium_c, name).argtypes
    func.restype = ctypes.c_void_p
    return func


_TEXT_OBJECT = None


def _text_object(textpage, index: int) -> int | None:
    """The text object a character belongs to, as an int (None for one pdfium made up, a space)."""
    global _TEXT_OBJECT
    if _TEXT_OBJECT is None:
        try:
            _TEXT_OBJECT = _void_binding("FPDFText_GetTextObject")
        except Exception:  # noqa: BLE001 - another build of the bindings: the slow way
            import pypdfium2.raw as pdfium_c

            _TEXT_OBJECT = lambda tp, i: ctypes.cast(pdfium_c.FPDFText_GetTextObject(tp, i),  # noqa: E731
                                                     ctypes.c_void_p).value
    return _TEXT_OBJECT(textpage, index)


def _objects(page_raw):
    """(text objects, image boxes in page space) of a page, inside form XObjects too."""
    import pypdfium2.raw as pdfium_c

    texts, images = [], []

    def walk(count, get, container, matrix):
        for k in range(count(container)):
            obj = get(container, k)
            kind = pdfium_c.FPDFPageObj_GetType(obj)
            if kind == pdfium_c.FPDF_PAGEOBJ_TEXT:
                texts.append(obj)
            elif kind == pdfium_c.FPDF_PAGEOBJ_IMAGE:
                left, bottom, right, top = (ctypes.c_float() for _ in range(4))
                if pdfium_c.FPDFPageObj_GetBounds(obj, left, bottom, right, top):
                    corners = [_apply(matrix, x, y) for x in (left.value, right.value)
                               for y in (bottom.value, top.value)]
                    xs, ys = [c[0] for c in corners], [c[1] for c in corners]
                    images.append((min(xs), min(ys), max(xs), max(ys)))
            elif kind == pdfium_c.FPDF_PAGEOBJ_FORM:
                inner = pdfium_c.FS_MATRIX()
                pdfium_c.FPDFPageObj_GetMatrix(obj, inner)
                walk(pdfium_c.FPDFFormObj_CountObjects, pdfium_c.FPDFFormObj_GetObject, obj,
                     _compose((inner.a, inner.b, inner.c, inner.d, inner.e, inner.f), matrix))

    walk(pdfium_c.FPDFPage_CountObjects, pdfium_c.FPDFPage_GetObject, page_raw, (1.0, 0.0, 0.0, 1.0, 0.0, 0.0))
    return texts, images


def _apply(m, x, y):
    return m[0] * x + m[2] * y + m[4], m[1] * x + m[3] * y + m[5]


def _compose(first, then):
    """The matrix that applies `first`, then `then` (PDF's row-vector convention)."""
    a, b, c, d, e, f = first
    A, B, C, D, E, F = then
    return (a * A + b * C, a * B + b * D, c * A + d * C, c * B + d * D, e * A + f * C + E, e * B + f * D + F)


def _to_device(page_raw, width: int, height: int):
    """The affine map from page space to the bitmap's pixels, as pdfium renders it (crop box, /Rotate)."""
    import pypdfium2.raw as pdfium_c

    k = 1000  # FPDF_PageToDevice answers in whole pixels: ask for a bitmap k times larger and divide
    x, y = ctypes.c_int(), ctypes.c_int()
    points = []
    for px, py in ((0.0, 0.0), (1000.0, 0.0), (0.0, 1000.0)):
        pdfium_c.FPDF_PageToDevice(page_raw, 0, 0, width * k, height * k, 0, px, py, x, y)
        points.append((x.value / k, y.value / k))
    (x0, y0), (x1, y1), (x2, y2) = points
    return ((x1 - x0) / 1000, (y1 - y0) / 1000, (x2 - x0) / 1000, (y2 - y0) / 1000, x0, y0)


def check_page(page, textpage) -> Page:
    """The check of one page (a pypdfium2 PdfPage and its PdfTextPage). Raises on what pdfium can't do; the
    caller counts that page undecided."""
    import numpy as np
    import pypdfium2.raw as pdfium_c

    tp = textpage.raw
    count = pdfium_c.FPDFText_CountChars(tp)
    found = Page()
    if count <= 0:
        return found
    if count > MAX_PAGE_CHARS:
        found.whole = f"more than {MAX_PAGE_CHARS} characters"
        return found
    width_pt, height_pt = page.get_size()
    scale = min(DPI / 72, (MAX_PIXELS / max(width_pt * height_pt, 1.0)) ** 0.5)
    if scale < MIN_DPI / 72:
        found.whole = "too large a page"
        return found

    # the characters: each one's box, letter or digit or not, and its text object's look
    chars = _chars(tp, count)
    rect = pdfium_c.FS_RECTF()
    raw_rect = memoryview(rect).cast("B")
    loose_box, unpack = pdfium_c.FPDFText_GetLooseCharBox, _RECT.unpack_from
    boxes, kept, kind = [], [], []
    numbers: dict[int, int] = {}  # text object -> its number in `looks`
    looks: list[tuple] = []
    for i, char in enumerate(chars):
        if char <= " " or char.isspace() or not loose_box(tp, i, rect):
            continue
        obj = _text_object(tp, i)
        k = numbers.get(obj)
        if k is None:
            k = numbers[obj] = len(looks)
            looks.append(_look(tp, i, obj))
        boxes.append(unpack(raw_rect))  # left, top, right, bottom
        kept.append(i)
        kind.append(k)
    if not boxes:
        return found
    box = np.array(boxes, dtype=np.float64)
    box = np.stack([np.minimum(box[:, 0], box[:, 2]), np.minimum(box[:, 1], box[:, 3]),
                    np.maximum(box[:, 0], box[:, 2]), np.maximum(box[:, 1], box[:, 3])], axis=1)
    word = np.array([c.isalnum() for c in chars], dtype=bool)[kept]
    found.words = int(word.sum())
    kind = np.array(kind)
    size = np.array([lk[3] for lk in looks])[kind]

    # the two renders: as it is, and with every text object switched off
    texts, images = _objects(page.raw)
    if len(images) > MAX_IMAGES:
        found.whole = f"more than {MAX_IMAGES} images"
        return found
    first = _render(page, scale)  # the bitmaps stay referenced while their pixels are used
    shown = first.to_numpy()
    for obj in texts:
        pdfium_c.FPDFPageObj_SetIsActive(obj, 0)
    try:
        second = _render(page, scale)
        bare = second.to_numpy()
    finally:
        for obj in texts:
            pdfium_c.FPDFPageObj_SetIsActive(obj, 1)
    height, width = shown.shape[:2]

    # each character's box in pixels
    m = _to_device(page.raw, width, height)
    xs = np.stack([m[0] * box[:, x] + m[2] * box[:, y] + m[4] for x in (0, 2) for y in (1, 3)], axis=1)
    ys = np.stack([m[1] * box[:, x] + m[3] * box[:, y] + m[5] for x in (0, 2) for y in (1, 3)], axis=1)
    cx, cy = xs.mean(axis=1), ys.mean(axis=1)
    off_page = (cx < 0) | (cx >= width) | (cy < 0) | (cy >= height)
    x0 = np.clip(np.floor(xs.min(axis=1)), 0, width - 1).astype(np.int64)
    y0 = np.clip(np.floor(ys.min(axis=1)), 0, height - 1).astype(np.int64)
    x1 = np.maximum(np.clip(np.ceil(xs.max(axis=1)), 0, width).astype(np.int64), x0 + 1)
    y1 = np.maximum(np.clip(np.ceil(ys.max(axis=1)), 0, height).astype(np.int64), y0 + 1)

    def rows_of(members):
        """The span of rows and columns these characters' boxes cover, and which changed pixels lie in its rows
        (a slice of `where`, which runs row by row)."""
        top, left = int(y0[members].min()), int(x0[members].min())
        bottom, right = int(y1[members].max()), int(x1[members].max())
        return (top, left, bottom, right), slice(*np.searchsorted(where, (top * width, bottom * width)))

    def any_in_box(pixels, members, span):
        """Whether each of these characters has one of these pixels (flat indexes) in its box: a summed-area
        table over just the span their boxes cover."""
        top, left, bottom, right = span
        rows, cols = np.divmod(pixels, width)
        inside = (cols >= left) & (cols < right)
        mask = np.zeros((bottom - top, right - left), dtype=np.int32)
        mask[rows[inside] - top, cols[inside] - left] = 1
        table = np.zeros((bottom - top + 1, right - left + 1), dtype=np.int32)
        table[1:, 1:] = mask.cumsum(axis=0, dtype=np.int32).cumsum(axis=1, dtype=np.int32)
        a, b, c, d = y0[members] - top, y1[members] - top, x0[members] - left, x1[members] - left
        return (table[b, d] - table[a, d] - table[b, c] + table[a, c]) > 0

    # a character shows when some pixel in its box moved toward its colour, clearly apart from what's behind
    visible = np.zeros(len(box), dtype=bool)
    where = np.flatnonzero(shown.view(np.uint32)[:, :, 0] != bare.view(np.uint32)[:, :, 0])
    if len(where):
        colours: dict[tuple, list[int]] = {}
        blind = []  # text objects whose colour pdfium can't say (a pattern): any change in a box shows it
        for k, lk in enumerate(looks):
            if lk[0] in _INVISIBLE_MODES:
                continue
            if not lk[1]:
                blind.append(k)
            for colour in lk[1]:
                colours.setdefault(colour, []).append(k)
        if blind:
            members = np.nonzero(np.isin(kind, blind))[0]
            span, rows = rows_of(members)
            visible[members] |= any_in_box(where[rows], members, span)
        # the changed pixels' channels, each in a row of its own (as int16: differences go below 0)
        now = shown.reshape(-1, 4)[where, :3].T.astype(np.int16)
        before = bare.reshape(-1, 4)[where, :3].T.astype(np.int16)
        for colour, ks in colours.items():
            members = np.nonzero(np.isin(kind, ks) & ~visible)[0]
            if not len(members):
                continue
            span, rows = rows_of(members)
            far = sum(np.abs(before[ch, rows] - colour[ch]) for ch in range(3))
            near = sum(np.abs(now[ch, rows] - colour[ch]) for ch in range(3))
            shows = (far >= CONTRAST) & ((far - near) >= COVER * far)
            visible[members] |= any_in_box(where[rows][shows], members, span)

    # what doesn't show (or is too small), sorted out
    tiny = size < TINY_PT
    suspect = np.nonzero(off_page | tiny | ~visible)[0]
    if not len(suspect):
        return found
    over_image = np.zeros(len(box), dtype=bool)
    if images:
        pictures = np.array(images)
        part = box[suspect]
        over_image[suspect] = ((part[:, None, 0] < pictures[None, :, 2]) & (part[:, None, 2] > pictures[None, :, 0]) &
                               (part[:, None, 1] < pictures[None, :, 3]) &
                               (part[:, None, 3] > pictures[None, :, 1])).any(axis=1)
    suspect = suspect[word[suspect]]  # letters and digits count; a stray dot or dash doesn't
    # a text object partly in sight: what of it doesn't show is cut off at an edge (a long line past the page's
    # edge, a spreadsheet cell's overflow clipped), which is ordinary, or a trick; OCR can tell
    in_sight = np.zeros(len(looks), dtype=bool)
    in_sight[kind[visible & ~off_page & ~tiny]] = True
    tricks: list[str | None] = []
    for n in suspect[off_page[suspect]]:
        tricks.append(None if in_sight[kind[n]] else "off_page")
    tricks += [None] * int((~off_page[suspect] & over_image[suspect]).sum())  # a picture there: only OCR can say
    tricks += ["tiny"] * int((~off_page[suspect] & ~over_image[suspect] & tiny[suspect]).sum())
    look_behind = suspect[~off_page[suspect] & ~over_image[suspect] & ~tiny[suspect]]
    if len(look_behind):
        # what's behind each, with the text off: its colour, and whether anything is drawn there
        rgb = bare[:, :, :3]
        bright = rgb @ np.array([0.299, 0.587, 0.114], dtype=np.float32)
        for n in look_behind[:MAX_LOOK_BEHIND]:
            a, b, c, d = y0[n], y1[n], x0[n], x1[n]
            trick = _why(looks[kind[n]], tuple(rgb[a:b, c:d].mean(axis=(0, 1))), float(bright[a:b, c:d].std()) > INK)
            tricks.append(None if trick in _EDGE_TRICKS and in_sight[kind[n]] else trick)
        tricks += [None] * max(len(look_behind) - MAX_LOOK_BEHIND, 0)
    for trick in tricks:
        if trick is None:
            found.undecided += 1
        else:
            found.hidden[trick] += 1
    return found


_RECT = struct.Struct("4f")  # FS_RECTF: left, top, right, bottom
_SURROGATE = re.compile("[\ud800-\udfff]")


def _chars(tp, count: int) -> str:
    """The page's characters, one per index (pdfium's text in one call; character by character when it holds
    a pair of surrogates, which would shift the indexes)."""
    import pypdfium2.raw as pdfium_c

    buffer = (ctypes.c_ushort * (count + 1))()
    pdfium_c.FPDFText_GetText(tp, 0, count, buffer)
    text = bytes(buffer)[:2 * count].decode("utf-16-le", "surrogatepass")
    if not _SURROGATE.search(text):
        return text
    out = []
    for i in range(count):
        try:
            out.append(chr(pdfium_c.FPDFText_GetUnicode(tp, i)))
        except (ValueError, OverflowError):
            out.append(" ")
    return "".join(out)


def _render(page, scale: float):
    """The page as an RGBx bitmap (annotations drawn, as a reader sees them)."""
    return page.render(scale=scale, rev_byteorder=True, prefer_bgrx=True, may_draw_forms=False)


def _why(look, background: tuple, ink: bool) -> str | None:
    """The trick that keeps a character on the page out of sight; None when other drawing is there."""
    mode, colours, alpha = look[0], look[1], look[2]
    if mode in _INVISIBLE_MODES:
        return None if ink else "invisible"
    if alpha == 0:
        return "transparent"
    if colours and not ink and min(sum(abs(c - b) for c, b in zip(colour, background)) for colour in colours) < CONTRAST:
        return "white" if min(background) >= 235 and min(colours[0]) >= 235 else "background"
    return None if ink else "covered"


def _look(tp, index: int, obj: int) -> tuple:
    """(render mode, colours it's drawn in, fill alpha, size in points) of a character's text object."""
    import pypdfium2.raw as pdfium_c

    handle = ctypes.cast(ctypes.c_void_p(obj), pdfium_c.FPDF_PAGEOBJECT) if obj else None
    mode = pdfium_c.FPDFTextObj_GetTextRenderMode(handle) if handle else 0
    r, g, b, a = (ctypes.c_uint() for _ in range(4))
    fill = stroke = None
    alpha = 255
    if pdfium_c.FPDFText_GetFillColor(tp, index, r, g, b, a):
        fill, alpha = (r.value, g.value, b.value), a.value
    if mode in _STROKE_MODES + _BOTH_MODES and pdfium_c.FPDFText_GetStrokeColor(tp, index, r, g, b, a):
        stroke = (r.value, g.value, b.value)
        if mode in _STROKE_MODES:
            alpha = a.value
    colours = [c for c in ((stroke,) if mode in _STROKE_MODES else (fill, stroke)) if c is not None]
    matrix = pdfium_c.FS_MATRIX()
    scale = 1.0
    if pdfium_c.FPDFText_GetMatrix(tp, index, matrix):
        # the em along each axis: text squeezed flat (horizontal scaling near 0) is as unreadable as tiny text
        scale = min((matrix.a ** 2 + matrix.b ** 2) ** 0.5, (matrix.c ** 2 + matrix.d ** 2) ** 0.5)
    return mode, colours, alpha, abs(pdfium_c.FPDFText_GetFontSize(tp, index)) * scale


class Check:
    """The check over a document: `page()` for each page as it's read, then `outcome()`."""

    def __init__(self):
        self.pages: dict[int, Page] = {}
        self.looked = 0

    def page(self, index: int, page, textpage, text: str) -> None:
        if not text.strip():
            return
        if self.looked >= MAX_PAGES:
            self.pages[index] = Page(words=sum(ch.isalnum() for ch in text), whole="past the pages looked at")
            return
        self.looked += 1
        try:
            self.pages[index] = check_page(page, textpage)
        except Exception as exc:  # noqa: BLE001 - pdfium couldn't: the OCR check decides
            self.pages[index] = Page(words=sum(ch.isalnum() for ch in text), whole=f"{type(exc).__name__}")

    def hiding(self) -> bool:
        """Whether the pages so far already make the document one that hides text."""
        counts = [sum(p.hidden.values()) for p in self.pages.values()]
        return sum(counts) >= DOC_MIN or any(c >= PAGE_MIN for c in counts)

    def outcome(self) -> tuple[str, dict | None]:
        """("hidden", hidden_text) | ("undecided", None) | ("clean", None)."""
        hidden = sum(sum(p.hidden.values()) for p in self.pages.values())
        if self.hiding():
            index, worst = max(self.pages.items(), key=lambda kv: sum(kv[1].hidden.values()))
            trick = worst.hidden.most_common(1)[0][0]
            count = sum(worst.hidden.values())
            return "hidden", {"reason": f"a PDF with {TRICKS[trick]}", "page": index + 1, "extracted": worst.words,
                              "visible": max(worst.words - count, 0), "hidden": hidden}
        unsure = hidden + sum(p.undecided for p in self.pages.values())
        if unsure >= DOC_MIN or any(p.whole for p in self.pages.values()) or \
                any(sum(p.hidden.values()) + p.undecided >= PAGE_MIN for p in self.pages.values()):
            return "undecided", None
        return "clean", None
