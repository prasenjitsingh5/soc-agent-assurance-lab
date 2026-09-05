"""Generate the social preview image and the site logo.

Outputs:
  docs/assets/social-preview.png   1280 x 640, for the GitHub repository social preview
  docs/assets/logo.png             512 x 512, for the MkDocs header and favicon

Run from the repository root:

    uv run python scripts/make_social_preview.py

The script uses a font that ships with the operating system. No font file is
committed. On Windows it prefers Segoe UI, then Arial; on Linux it falls back
to DejaVu Sans. Pillow's built-in bitmap font is the last resort.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

REPO = Path(__file__).resolve().parents[1]
ASSETS = REPO / "docs" / "assets"

BACKGROUND = (15, 27, 45)
PANEL = (23, 40, 66)
TEXT = (240, 244, 248)
MUTED = (160, 174, 192)
ACCENT = (45, 212, 191)
ARROW = (120, 140, 165)

TITLE = "SOC Agent Assurance Lab"
TAGLINE = "Has your AI SOC agent earned operational authority?"
STAGES = ("proposal", "policy", "grant", "executor", "evidence")

REGULAR_FONTS = (
    "C:/Windows/Fonts/segoeui.ttf",
    "C:/Windows/Fonts/arial.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
)
BOLD_FONTS = (
    "C:/Windows/Fonts/segoeuib.ttf",
    "C:/Windows/Fonts/arialbd.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
)

Font = ImageFont.FreeTypeFont | ImageFont.ImageFont


@dataclass(frozen=True)
class Box:
    """Axis-aligned rectangle in pixel coordinates."""

    left: int
    top: int
    right: int
    bottom: int

    @property
    def center_x(self) -> int:
        return (self.left + self.right) // 2

    @property
    def center_y(self) -> int:
        return (self.top + self.bottom) // 2


def load_font(candidates: tuple[str, ...], size: int) -> Font:
    """Return the first available system font at the requested size."""
    for candidate in candidates:
        if Path(candidate).exists():
            return ImageFont.truetype(candidate, size)
    return ImageFont.load_default(size=size)


def text_size(draw: ImageDraw.ImageDraw, text: str, font: Font) -> tuple[int, int]:
    left, top, right, bottom = draw.textbbox((0, 0), text, font=font)
    return int(right - left), int(bottom - top)


def draw_centered_text(
    draw: ImageDraw.ImageDraw, center: tuple[int, int], text: str, font: Font, fill: tuple[int, int, int]
) -> None:
    """Draw text centered on the given point.

    Horizontal centering uses the text's own width. Vertical centering uses the
    font's full ascender-to-descender box so that words with different
    descenders share one baseline when drawn side by side.
    """
    left, _, right, _ = (int(value) for value in draw.textbbox((0, 0), text, font=font))
    _, top, _, bottom = (int(value) for value in draw.textbbox((0, 0), "Ag", font=font))
    x = center[0] - (right - left) // 2 - left
    y = center[1] - (bottom - top) // 2 - top
    draw.text((x, y), text, font=font, fill=fill)


def draw_arrow(draw: ImageDraw.ImageDraw, start: tuple[int, int], end: tuple[int, int], width: int) -> None:
    """Horizontal arrow from start to end with a filled head."""
    head = max(6, width * 3)
    draw.line([start, (end[0] - head, end[1])], fill=ARROW, width=width)
    draw.polygon(
        [(end[0], end[1]), (end[0] - head, end[1] - head // 2 - 1), (end[0] - head, end[1] + head // 2 + 1)],
        fill=ARROW,
    )


def draw_chain(
    draw: ImageDraw.ImageDraw,
    area: Box,
    labels: tuple[str, ...],
    font: Font | None,
    *,
    gap: int,
    radius: int,
    outline: int,
    highlight: str | None = "grant",
) -> list[Box]:
    """Draw labeled boxes joined by arrows across the given area. Returns the boxes."""
    count = len(labels)
    box_width = (area.right - area.left - gap * (count - 1)) // count
    boxes: list[Box] = []
    for index, label in enumerate(labels):
        left = area.left + index * (box_width + gap)
        box = Box(left, area.top, left + box_width, area.bottom)
        boxes.append(box)
        filled = label == highlight
        draw.rounded_rectangle(
            (box.left, box.top, box.right, box.bottom),
            radius=radius,
            fill=ACCENT if filled else PANEL,
            outline=ACCENT,
            width=outline,
        )
        if font is not None:
            draw_centered_text(
                draw, (box.center_x, box.center_y), label, font, BACKGROUND if filled else TEXT
            )
        if index < count - 1:
            draw_arrow(
                draw, (box.right + 2, box.center_y), (box.right + gap - 2, box.center_y), max(2, outline)
            )
    return boxes


def make_social_preview(path: Path) -> None:
    width, height = 1280, 640
    image = Image.new("RGB", (width, height), BACKGROUND)
    draw = ImageDraw.Draw(image)

    title_font = load_font(BOLD_FONTS, 66)
    tagline_font = load_font(REGULAR_FONTS, 34)
    label_font = load_font(REGULAR_FONTS, 26)
    caption_font = load_font(REGULAR_FONTS, 22)
    margin = 80

    # Accent rule at the top left, then the title and the one-line question.
    draw.rectangle((margin, 88, margin + 72, 94), fill=ACCENT)
    draw.text((margin, 118), TITLE, font=title_font, fill=TEXT)
    draw.text((margin, 212), TAGLINE, font=tagline_font, fill=MUTED)

    # The invariant as five boxes with arrows.
    chain_area = Box(margin, 340, width - margin, 430)
    draw_chain(draw, chain_area, STAGES, label_font, gap=54, radius=12, outline=3)

    caption = (
        "The model proposes. Policy decides. A signed grant authorizes execution. Everything is hash-chained."
    )
    draw.text((margin, 478), caption, font=caption_font, fill=MUTED)

    footer = "github.com/prasenjitsingh5/soc-agent-assurance-lab"
    footer_width, _ = text_size(draw, footer, caption_font)
    draw.text((width - margin - footer_width, height - 70), footer, font=caption_font, fill=ACCENT)
    draw.text((margin, height - 70), "Apache-2.0", font=caption_font, fill=MUTED)

    image.save(path, format="PNG", optimize=True)


def make_logo(path: Path) -> None:
    size = 512
    image = Image.new("RGB", (size, size), BACKGROUND)
    draw = ImageDraw.Draw(image)

    top_font = load_font(BOLD_FONTS, 78)
    bottom_font = load_font(BOLD_FONTS, 54)

    draw.rounded_rectangle((0, 0, size - 1, size - 1), radius=64, fill=BACKGROUND, outline=ACCENT, width=10)
    draw_centered_text(draw, (size // 2, 140), "SOC", top_font, TEXT)

    # Unlabeled chain in the middle, the grant box filled, mirroring the preview.
    chain_area = Box(64, 222, size - 64, 290)
    draw_chain(draw, chain_area, STAGES, None, gap=22, radius=8, outline=4)

    draw_centered_text(draw, (size // 2, 372), "ASSURANCE", bottom_font, ACCENT)
    draw_centered_text(draw, (size // 2, 432), "LAB", bottom_font, TEXT)

    image.save(path, format="PNG", optimize=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--out", type=Path, default=ASSETS, help="output directory (default: docs/assets)")
    args = parser.parse_args()
    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)
    make_social_preview(out / "social-preview.png")
    make_logo(out / "logo.png")
    print(f"wrote {out / 'social-preview.png'} and {out / 'logo.png'}")


if __name__ == "__main__":
    main()
