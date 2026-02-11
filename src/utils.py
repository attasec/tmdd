"""TMDD shared utilities - YAML loading, path helpers, and exceptions."""
import logging
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required. Install it with: pip install pyyaml")

logger = logging.getLogger("tmdd")

# Default directory for threat model files
DEFAULT_MODEL_DIR = ".tmdd"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class TMDDError(Exception):
    """Base exception for all TMDD errors."""


class ModelNotFoundError(TMDDError):
    """Raised when a threat-model directory does not exist."""


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def resolve_model_dir(path):
    """Resolve and validate a model directory path.

    Returns a Path object if the directory exists, raises ModelNotFoundError otherwise.
    """
    model_dir = Path(path)
    if not model_dir.is_dir():
        raise ModelNotFoundError(f"Not a directory: {model_dir}")
    return model_dir


def get_project_root():
    """Get the TMDD project root (directory containing templates/)."""
    src_dir = Path(__file__).parent
    if (src_dir / "templates").is_dir():
        return src_dir
    if (src_dir.parent / "templates").is_dir():
        return src_dir.parent
    return src_dir


def get_output_dir():
    """Get the output directory (.tmdd/out)."""
    output_dir = Path.cwd() / DEFAULT_MODEL_DIR / "out"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def safe_name(text):
    """Convert string to a safe filename.

    Strips unsafe characters, collapses underscores, and falls back to
    'unnamed' for empty/None input.
    """
    if not text:
        return "unnamed"
    name = text.lower().strip()
    name = re.sub(r"[^a-z0-9_\-]", "_", name)
    name = re.sub(r"_+", "_", name)
    return name.strip("_") or "unnamed"


# ---------------------------------------------------------------------------
# YAML loading
# ---------------------------------------------------------------------------

def get_mitigation_desc(entry, fallback=""):
    """Return the description string from a mitigation entry.

    Supports both simple string format and rich object format:
        "description text"
        {"description": "text", "references": [...]}
    """
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        return entry.get("description", fallback)
    return fallback


def get_mitigation_refs(entry):
    """Return the references list from a rich mitigation entry, or []."""
    if isinstance(entry, dict):
        return entry.get("references", [])
    return []


def load_yaml(path, strict=False):
    """Load a YAML file and return its contents as a dict.

    Args:
        path: Path to the YAML file.
        strict: If True, return None on failure (useful for linting).
                If False (default), return {} on failure.
    """
    try:
        return yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except FileNotFoundError:
        logger.warning("File not found: %s", path)
    except yaml.YAMLError as e:
        logger.error("YAML parse error in %s: %s", path, e)
    except (OSError, UnicodeDecodeError) as e:
        logger.error("Cannot read %s: %s", path, e)
    return None if strict else {}


def load_threat_model(model_dir):
    """Load all threat model files into a single dict.

    Raises ModelNotFoundError if model_dir does not exist.
    """
    model_path = resolve_model_dir(model_dir)
    threats_path = model_path / "threats"
    return {
        "system": load_yaml(model_path / "system.yaml").get("system", {}),
        "actors": load_yaml(model_path / "actors.yaml").get("actors", []),
        "components": load_yaml(model_path / "components.yaml").get("components", []),
        "features": load_yaml(model_path / "features.yaml").get("features", []),
        "data_flows": load_yaml(model_path / "data_flows.yaml").get("data_flows", []),
        "threats": load_yaml(threats_path / "catalog.yaml").get("threats", {}),
        "mitigations": load_yaml(threats_path / "mitigations.yaml").get("mitigations", {}),
        "threat_actors": load_yaml(threats_path / "threat_actors.yaml").get("threat_actors", {}),
    }
