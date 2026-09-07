"""TMDD shared utilities - YAML loading, path helpers, and exceptions."""

import logging
import re
import sys
from collections import namedtuple
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
# Glob matching (component source_paths <-> changed files)
# ---------------------------------------------------------------------------


def _normalize_path(path):
    """Normalize a path for matching: use forward slashes, strip './' and leading '/'."""
    p = str(path).replace("\\", "/").strip()
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def glob_to_regex(pattern):
    """Translate a git-style glob into an anchored regex string.

    Matching rules (POSIX/gitignore-flavored):
        **/   matches zero or more directory segments
        **    matches any characters, including '/'
        *     matches any characters except '/'
        ?     matches a single character except '/'

    Everything else is matched literally. Paths are compared with '/'
    separators regardless of platform.
    """
    pattern = _normalize_path(pattern)
    out = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            if i + 1 < n and pattern[i + 1] == "*":
                # '**' — consume it, and an immediately following '/' if present
                if i + 2 < n and pattern[i + 2] == "/":
                    out.append("(?:.*/)?")
                    i += 3
                else:
                    out.append(".*")
                    i += 2
            else:
                out.append("[^/]*")
                i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    return "^" + "".join(out) + "$"


def path_matches_glob(path, pattern):
    """Return True if *path* matches the git-style glob *pattern*."""
    return re.match(glob_to_regex(pattern), _normalize_path(path)) is not None


def path_matches_any(path, patterns):
    """Return True if *path* matches any glob in *patterns*."""
    return any(path_matches_glob(path, p) for p in (patterns or []))


# ---------------------------------------------------------------------------
# YAML loading
# ---------------------------------------------------------------------------


#: A threat mapping normalized into its three independent dimensions. Kept as
#: a NamedTuple so call sites read by attribute and new dimensions can be added
#: without breaking the ones that only care about mitigations.
FeatureThreat = namedtuple("FeatureThreat", "mitigations flows status")

#: Lifecycle of a control, distinct from *which* mitigations apply.
STATUS_REQUIRED = "required"  # not done, or nothing recorded (the default)
STATUS_IMPLEMENTED = "implemented"  # shipped; changes on its flows need re-checking
STATUS_ACCEPTED = "accepted"  # deliberately not fixed
FEATURE_THREAT_STATUSES = {STATUS_REQUIRED, STATUS_IMPLEMENTED, STATUS_ACCEPTED}


def normalize_feature_threat(value):
    """Normalize a features.yaml threat mapping value into a FeatureThreat.

    A feature maps threat IDs to how they are handled. Supported forms:

        threat_id: default                  # inherit suggested_mitigations
        threat_id: accepted                 # risk accepted
        threat_id: [mit_a, mit_b]           # explicit mitigation IDs
        threat_id:                          # object form
          mitigations: default
          flows: [df_cdn_to_browser]        # data flows the threat lives on
          status: implemented               # control is shipped

    The object form carries two things the scalar form cannot express. *flows*
    binds a threat to the data flows it actually lives on, so `tmdd review`
    stops surfacing it whenever any unrelated flow of the same feature moves.
    *status* records whether the control is shipped, which is what separates
    "you still owe this" from "you changed code a shipped control depends on".

    Returns FeatureThreat(mitigations, flows, status):
      - *flows* is None when unbound, meaning "applies to the whole feature".
      - *status* is always one of FEATURE_THREAT_STATUSES; an unrecognised
        value normalizes to STATUS_REQUIRED so a typo fails safe (loud in
        lint, and shown as outstanding work rather than silently dropped).
    """
    if not isinstance(value, dict):
        status = STATUS_ACCEPTED if value == "accepted" else STATUS_REQUIRED
        return FeatureThreat(value, None, status)

    flows = value.get("flows")
    if not isinstance(flows, list):
        flows = None

    mitigations = value.get("mitigations")
    raw_status = value.get("status")
    # 'accepted' predates this field and was expressible two ways, as the
    # mitigations value or as a bare status. Both still mean the same thing.
    if raw_status == STATUS_ACCEPTED or mitigations == "accepted":
        return FeatureThreat("accepted", flows, STATUS_ACCEPTED)
    status = raw_status if raw_status in FEATURE_THREAT_STATUSES else STATUS_REQUIRED
    return FeatureThreat(mitigations, flows, status)


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
        "threats": load_yaml(threats_path / "threats.yaml").get("threats", {}),
        "mitigations": load_yaml(threats_path / "mitigations.yaml").get(
            "mitigations", {}
        ),
        "threat_actors": load_yaml(threats_path / "threat_actors.yaml").get(
            "threat_actors", []
        ),
    }
