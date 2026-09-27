from pathlib import Path

from PIL import Image
from PIL.ExifTags import TAGS
from PyPDF2 import PdfReader


def run(file_paths: list[str]) -> dict:
    """Extracts embedded metadata (EXIF for images, document info for PDFs).

    Takes explicit local file paths supplied by the user (e.g. documents/images
    downloaded from a target's public website) rather than crawling on its own,
    to keep scope intentional and auditable.
    """
    results = {}
    for path_str in file_paths:
        path = Path(path_str)
        if not path.exists():
            results[path_str] = {"error": "file not found"}
            continue

        suffix = path.suffix.lower()
        try:
            if suffix in {".jpg", ".jpeg", ".png", ".tiff"}:
                results[path_str] = _extract_image_metadata(path)
            elif suffix == ".pdf":
                results[path_str] = _extract_pdf_metadata(path)
            else:
                results[path_str] = {"error": f"unsupported file type: {suffix}"}
        except Exception as exc:
            results[path_str] = {"error": str(exc)}

    return results


def _extract_image_metadata(path: Path) -> dict:
    image = Image.open(path)
    exif_data = image.getexif()
    if not exif_data:
        return {"exif": {}}

    metadata = {}
    for tag_id, value in exif_data.items():
        tag = TAGS.get(tag_id, tag_id)
        metadata[str(tag)] = str(value)
    return {"exif": metadata}


def _extract_pdf_metadata(path: Path) -> dict:
    reader = PdfReader(str(path))
    info = reader.metadata or {}
    return {"pdf_info": {str(k): str(v) for k, v in info.items()}}
