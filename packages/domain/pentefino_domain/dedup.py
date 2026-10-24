import hashlib
import posixpath
import re
import urllib.parse
import uuid


def compute_finding_dedup_key(
    program_id: uuid.UUID | str,
    canonical_asset: str,
    port: int | str,
    normalized_path: str,
    detector_id: str,
) -> str:
    """Computes deterministic SHA-256 deduplication key for vulnerability findings.

    Formula:
        sha256(program_id | canonical_asset | port | normalized_path | detector_id)
    Returns:
        64-character lowercase hexadecimal string.
    """
    # 1. Normalize program_id
    if isinstance(program_id, uuid.UUID):
        norm_program_id = str(program_id).lower()
    else:
        norm_program_id = str(uuid.UUID(str(program_id).strip())).lower()

    # 2. Normalize canonical_asset
    raw_asset = str(canonical_asset).strip()
    if "://" in raw_asset:
        parsed = urllib.parse.urlsplit(raw_asset)
        raw_asset = parsed.hostname or parsed.netloc or raw_asset
    else:
        # Strip potential port or path if raw string contains them
        if "/" in raw_asset:
            raw_asset = raw_asset.split("/", 1)[0]
        if ":" in raw_asset:
            raw_asset = raw_asset.split(":", 1)[0]

    norm_asset = raw_asset.rstrip(".").lower()

    # 3. Normalize port
    norm_port = str(int(port))

    # 4. Normalize path
    raw_path = str(normalized_path).strip()
    if not raw_path:
        norm_path = "/"
    else:
        # Strip query strings and URL fragments
        if "://" in raw_path:
            parsed_path = urllib.parse.urlsplit(raw_path).path
        else:
            parsed_path = urllib.parse.urlsplit(raw_path).path if ("?" in raw_path or "#" in raw_path) else raw_path

        if not parsed_path.startswith("/"):
            parsed_path = "/" + parsed_path

        # Resolve relative segments . and ..
        cleaned = posixpath.normpath(parsed_path)
        # Collapse multiple slashes
        norm_path = re.sub(r"/+", "/", cleaned)
        if not norm_path.startswith("/"):
            norm_path = "/" + norm_path
        if len(norm_path) > 1 and norm_path.endswith("/"):
            norm_path = norm_path.rstrip("/")

    # 5. Normalize detector_id
    norm_detector_id = str(detector_id).strip().lower()

    # 6. Compose preimage with explicit pipe delimiters
    preimage = f"{norm_program_id}|{norm_asset}|{norm_port}|{norm_path}|{norm_detector_id}"
    return hashlib.sha256(preimage.encode("utf-8")).hexdigest()
