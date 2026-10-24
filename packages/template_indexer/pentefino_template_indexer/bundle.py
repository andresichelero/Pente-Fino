import hashlib
from pathlib import Path
from typing import Any
import yaml


def _find_referenced_files(obj: Any, base_dir: Path) -> dict[str, bytes]:
    """Recursively search parsed YAML AST for payload/helper file references."""
    referenced: dict[str, bytes] = {}

    def _inspect_val(val: Any) -> None:
        if isinstance(val, str):
            val_clean = val.strip()
            # Check if this string corresponds to an existing relative file
            if val_clean and not val_clean.startswith(("http://", "https://", "{{", "/")):
                candidate = (base_dir / val_clean).resolve()
                try:
                    # Guard against directory traversal escaping base_dir if desired,
                    # but if candidate exists and is a file, read it.
                    if candidate.is_file():
                        rel = candidate.relative_to(base_dir.resolve()).as_posix()
                        referenced[rel] = candidate.read_bytes()
                except (ValueError, OSError):
                    pass
        elif isinstance(val, list):
            for item in val:
                _inspect_val(item)
        elif isinstance(val, dict):
            for k, v in val.items():
                if k in ("payloads", "payload", "attack-data", "helpers", "words", "paths"):
                    _inspect_val(v)
                else:
                    _inspect_val(v)

    _inspect_val(obj)
    return referenced


def compute_bundle_hash(
    raw_yaml: str,
    base_dir: Path | None = None,
    parsed_data: dict[str, Any] | None = None,
) -> str:
    """
    Compute a deterministic SHA-256 bundle digest for a Nuclei template.

    If the template is self-contained, the digest is SHA-256(raw_yaml_bytes).
    If the template references external payload/wordlist files and base_dir is provided,
    the digest deterministically binds the template content and all referenced
    external files in lexicographical order of relative path.
    """
    yaml_bytes = raw_yaml.encode("utf-8")

    referenced_files: dict[str, bytes] = {}
    if base_dir and Path(base_dir).is_dir():
        try:
            parsed = parsed_data if parsed_data is not None else yaml.safe_load(raw_yaml)
            if isinstance(parsed, dict):
                referenced_files = _find_referenced_files(parsed, Path(base_dir))
        except Exception:
            # If yaml parsing fails, fallback to pure yaml hashing
            referenced_files = {}

    if not referenced_files:
        return hashlib.sha256(yaml_bytes).hexdigest()

    hasher = hashlib.sha256()
    hasher.update(b"BUNDLE_V1\n")
    hasher.update(yaml_bytes)
    for rel_path in sorted(referenced_files.keys()):
        hasher.update(b"\x00")
        hasher.update(rel_path.encode("utf-8"))
        hasher.update(b"\x00")
        hasher.update(referenced_files[rel_path])

    return hasher.hexdigest()
