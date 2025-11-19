"""Shared UI helpers for the Web Security Assessment Tool."""
from pathlib import Path
from typing import Optional, Tuple
from PIL import Image

DEFAULT_FALLBACK_SIZE: Tuple[int, int] = (100, 100)
DEFAULT_FALLBACK_COLOR = "#0B1320"


def open_image(path: str, fallback_size: Optional[Tuple[int, int]] = None,
               fallback_color: str = DEFAULT_FALLBACK_COLOR) -> Image.Image:
    """Return an :class:`Image.Image` for ``path``.

    The original project expected several image assets to be present next to the
    source files.  In a clean checkout those assets might not exist which used to
    crash the GUI immediately.  This helper provides a small, solid-color image
    whenever the requested file is missing so that the UI can still be rendered.
    The returned object can safely be resized by the caller.
    """
    target = Path(path)
    if target.exists():
        try:
            return Image.open(target)
        except OSError:
            # File exists but Pillow failed to decode it.  Fall back to a
            # generated image so the GUI keeps working.
            pass

    size = fallback_size or DEFAULT_FALLBACK_SIZE
    image = Image.new("RGB", size, fallback_color)
    return image
