"""Shared fixtures. One OPA server per test session keeps policy-backed tests fast."""

import base64
import re
import sys
import zlib
from collections.abc import Callable, Iterator

import pytest

from soclab.policy import OpaHttpPolicyEngine, find_opa_binary
from soclab.policy.server import ManagedOpaServer


@pytest.fixture(scope="session")
def opa_engine() -> Iterator[OpaHttpPolicyEngine]:
    if find_opa_binary() is None:
        pytest.skip("opa binary not installed")
    with ManagedOpaServer() as engine:
        yield engine


_STREAM = re.compile(rb"stream\r?\n(.*?)\r?\n?endstream", re.S)
_TEXT_OBJECT = re.compile(rb"BT(.*?)ET", re.S)
_LITERAL = re.compile(rb"\((?:\\.|[^\\)])*\)", re.S)
_ESCAPE = re.compile(rb"\\([0-7]{1,3}|.)", re.S)


def _unescape(literal: bytes) -> str:
    body = literal[1:-1]

    def one(match: re.Match[bytes]) -> bytes:
        code = match.group(1)
        if code.isdigit():
            return bytes([int(code, 8)])
        return {b"n": b"\n", b"r": b"\r", b"t": b"\t"}.get(code, code)

    return _ESCAPE.sub(one, body).decode("latin-1")


def extract_pdf_text(data: bytes) -> str:
    """Pull the literal strings out of every text object.

    Enough for PDFs the lab writes itself: standard fonts, ASCII85 and Flate streams, no
    hex strings. Fragments inside one text object join with a space, text
    objects join with a newline, so callers should normalize whitespace.
    """
    lines: list[str] = []
    for stream in _STREAM.finditer(data):
        raw = stream.group(1)
        if raw.rstrip().endswith(b"~>"):
            raw = base64.a85decode(raw.strip(), adobe=True)
        try:
            content = zlib.decompress(raw)
        except zlib.error:
            content = raw
        for text_object in _TEXT_OBJECT.finditer(content):
            parts = [_unescape(m.group(0)) for m in _LITERAL.finditer(text_object.group(1))]
            if parts:
                lines.append(" ".join(parts))
    return "\n".join(lines)


@pytest.fixture
def pdf_text() -> Callable[[bytes], str]:
    """The extractor as a fixture, so any test can read a PDF back without a parser dependency."""
    return extract_pdf_text


@pytest.fixture
def hide_reportlab(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every reportlab import fail, as it does when the pdf extra is not installed."""
    for name in [m for m in sys.modules if m == "reportlab" or m.startswith("reportlab.")]:
        monkeypatch.delitem(sys.modules, name)
    monkeypatch.setitem(sys.modules, "reportlab", None)
