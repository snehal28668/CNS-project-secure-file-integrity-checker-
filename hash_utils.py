"""SHA-256 helpers for the Secure File Integrity Checker."""

from pathlib import Path
from typing import BinaryIO


CHUNK_SIZE = 1024 * 1024


def calculate_sha256(file_path: str | Path) -> str:
    """Return the SHA-256 digest for a file, read in safe-sized chunks."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as file_handle:
        _update_digest(digest, file_handle)
    return digest.hexdigest()


def _update_digest(digest: object, file_handle: BinaryIO) -> None:
    """Read the file incrementally so large files do not fill memory."""
    while chunk := file_handle.read(CHUNK_SIZE):
        digest.update(chunk)  # type: ignore[attr-defined]


def get_file_metadata(file_path: str | Path) -> dict[str, str | int]:
    """Return display-friendly metadata without reading file contents."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    return {
        "name": path.name,
        "path": str(path.resolve()),
        "size": path.stat().st_size,
        "type": path.suffix.lower() or "No extension",
    }


def format_file_size(size_bytes: int) -> str:
    """Format a byte count for the interface."""
    size = float(size_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{size_bytes} B"
