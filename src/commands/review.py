"""TMDD review command - Map a code diff to the threats it may affect.

Closes the loop between the threat model and the code it describes:

    changed files --(component.source_paths globs)--> components
                  --(data_flows source/destination)--> data flows
                  --(features.data_flows)------------> features
                  --(features.threats)---------------> threats + mitigations

The result is a deterministic, review-ready checklist of the threats a pull
request touches, plus coverage gaps (changed files that map to no modeled
component, and components with no source_paths at all).
"""

import json
import subprocess

from ..utils import (
    load_threat_model,
    resolve_model_dir,
    path_matches_any,
    get_mitigation_desc,
    normalize_feature_threat,
    TMDDError,
)

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# ---------------------------------------------------------------------------
# Discovering the changed files
# ---------------------------------------------------------------------------


def _run_git(repo_root, git_args):
    """Run a git command in *repo_root*, returning stdout. Raises TMDDError on failure."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_root), *git_args],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        raise TMDDError(
            "git is not installed or not on PATH. Pass changed files with --files instead."
        )
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "unknown error"
        raise TMDDError(
            f"git {' '.join(git_args)} failed: {detail}. Pass changed files with --files instead."
        )
    return proc.stdout


def changed_files_from_git(repo_root, base=None, staged=False):
    """Return the list of changed file paths (relative to *repo_root*) from git."""
    if base:
        git_args = ["diff", "--name-only", f"{base}...HEAD"]
    elif staged:
        git_args = ["diff", "--name-only", "--cached"]
    else:
        git_args = ["diff", "--name-only", "HEAD"]
    out = _run_git(repo_root, git_args)
    return [line.strip() for line in out.splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# The mapping (pure function - easy to test)
# ---------------------------------------------------------------------------


def _resolve_feature_threats(feature, threats_catalog, mitigations, affected_flows):
    """Resolve a feature's threat->mitigation mapping into display-ready entries.

    A threat that names its own *flows* is only surfaced when the diff actually
    touched one of them. Threats with no flow binding apply to the whole
    feature and are always surfaced, which is the pre-existing behaviour.
    """
    resolved = []
    feature_threats = feature.get("threats", {})
    if isinstance(feature_threats, dict):
        items = list(feature_threats.items())
    elif isinstance(feature_threats, list):
        items = [(tid, None) for tid in feature_threats]
    else:
        items = []

    for tid, raw in items:
        mapping = normalize_feature_threat(raw)
        mits, threat_flows = mapping.mitigations, mapping.flows
        if threat_flows is not None and not (set(threat_flows) & affected_flows):
            continue
        info = threats_catalog.get(tid, {})
        info = info if isinstance(info, dict) else {}
        entry = {
            "id": tid,
            "name": info.get("name", tid),
            "severity": info.get("severity"),
            "stride": info.get("stride"),
            "cwe": info.get("cwe"),
            # 'implemented' survives to the output on purpose: the threat only
            # got this far because the diff touched a flow it lives on, so a
            # shipped control here is a re-verify prompt, not a silent pass.
            "status": mapping.status,
            "mitigations": [],
        }
        if mits == "accepted":
            entry["status"] = "accepted"
        elif mits == "default":
            suggested = info.get("suggested_mitigations", []) or []
            entry["mitigations"] = [
                get_mitigation_desc(mitigations.get(m, m), m) for m in suggested
            ]
        elif isinstance(mits, list):
            entry["mitigations"] = [
                get_mitigation_desc(mitigations.get(m, m), m) for m in mits
            ]
        else:
            entry["status"] = "unmapped"
        resolved.append(entry)
    return resolved


def map_changed_files(tm, changed_files):
    """Map changed files to affected components, data flows, features and threats.

    Returns a structured dict describing the mapping and any coverage gaps.
    """
    components = [c for c in tm.get("components", []) if isinstance(c, dict)]
    data_flows = [f for f in tm.get("data_flows", []) if isinstance(f, dict)]
    features = [f for f in tm.get("features", []) if isinstance(f, dict)]
    threats_catalog = tm.get("threats", {}) or {}
    mitigations = tm.get("mitigations", {}) or {}

    # 1. changed files -> components (via source_paths globs)
    file_component_map = []
    matched_ids = set()
    unmapped_files = []
    for path in changed_files:
        hits = [
            c.get("id")
            for c in components
            if path_matches_any(path, c.get("source_paths"))
        ]
        if hits:
            file_component_map.append({"file": path, "components": hits})
            matched_ids.update(hits)
        else:
            unmapped_files.append(path)

    affected_components = [
        {
            "id": c.get("id"),
            "description": c.get("description", ""),
            "type": c.get("type", ""),
        }
        for c in components
        if c.get("id") in matched_ids
    ]

    # 2. components -> data flows they participate in
    affected_flow_ids = []
    for df in data_flows:
        if df.get("source") in matched_ids or df.get("destination") in matched_ids:
            affected_flow_ids.append(df.get("id"))
    affected_flow_set = set(affected_flow_ids)

    # 3. data flows -> features
    affected_features = []
    for feat in features:
        feat_flows = set(feat.get("data_flows", []) or [])
        if feat_flows & affected_flow_set:
            affected_features.append(
                {
                    "name": feat.get("name", "?"),
                    "goal": feat.get("goal", ""),
                    "reviewed_by": feat.get("reviewed_by"),
                    "reviewed_at": feat.get("reviewed_at"),
                    "last_updated": feat.get("last_updated"),
                    "threats": _resolve_feature_threats(
                        feat, threats_catalog, mitigations, affected_flow_set
                    ),
                }
            )

    # De-duplicated, severity-sorted summary of every affected threat.
    seen = {}
    for feat in affected_features:
        for t in feat["threats"]:
            existing = seen.get(t["id"])
            if existing is None:
                copy = dict(t)
                copy["features"] = [feat["name"]]
                seen[t["id"]] = copy
            else:
                existing["features"].append(feat["name"])
    affected_threats = sorted(
        seen.values(),
        key=lambda t: (
            _SEVERITY_ORDER.get((t.get("severity") or "").lower(), 99),
            t["id"],
        ),
    )

    # --- coverage gaps ---
    components_without_source_paths = [
        c.get("id") for c in components if not c.get("source_paths")
    ]
    matched_without_features = sorted(
        matched_ids
        - {df.get("source") for df in data_flows if df.get("id") in affected_flow_set}
        - {
            df.get("destination")
            for df in data_flows
            if df.get("id") in affected_flow_set
        }
    )

    return {
        "changed_files": list(changed_files),
        "file_component_map": file_component_map,
        "unmapped_files": unmapped_files,
        "affected_components": affected_components,
        "affected_data_flows": affected_flow_ids,
        "affected_features": affected_features,
        "affected_threats": affected_threats,
        "components_without_source_paths": components_without_source_paths,
        "matched_components_without_features": matched_without_features,
    }


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------


def _sev(t):
    s = (t.get("severity") or "?").upper()
    st = t.get("stride")
    return f"[{s}{'/' + st if st else ''}]"


def _status_tag(t):
    """Suffix marking a threat's control lifecycle, empty for ordinary open work."""
    if t["status"] == "accepted":
        return " ACCEPTED"
    if t["status"] == "implemented":
        return " IMPLEMENTED - re-verify"
    return ""


def _file_component_pairs(result):
    """Yield (file, components) in diff order; components is [] when unmapped."""
    mapping = {m["file"]: m["components"] for m in result["file_component_map"]}
    for path in result["changed_files"]:
        yield path, mapping.get(path, [])


def format_text(result):
    lines = []
    n_files = len(result["changed_files"])
    lines.append(f"Threat review: {n_files} changed file(s)\n" + "=" * 60)

    if result["changed_files"]:
        lines.append("\nChanged files  (what you touched):")
        width = min(max(len(f) for f in result["changed_files"]), 56)
        for path, hits in _file_component_pairs(result):
            marker = "  " if hits else "? "
            target = ", ".join(hits) if hits else "no component matched"
            lines.append(f"  {marker}{path.ljust(width)}  -> {target}")

    if result["affected_components"]:
        lines.append("\nAffected components  (what those files map to):")
        for c in result["affected_components"]:
            lines.append(f"  - {c['id']} ({c['type']})")
    else:
        lines.append("\nNo modeled components touched by these changes.")

    if result["affected_features"]:
        lines.append("\nAffected features  (what that reaches):")
        for f in result["affected_features"]:
            lines.append(f"  - {f['name']}")

    if result["affected_threats"]:
        lines.append("\nThreats to review  (what to check):")
        for t in result["affected_threats"]:
            lines.append(f"\n  {_sev(t)} {t['name']} ({t['id']}){_status_tag(t)}")
            lines.append(f"      via feature(s): {', '.join(t['features'])}")
            if t["status"] == "accepted":
                lines.append("      - risk accepted")
            elif t["mitigations"]:
                box = "[x]" if t["status"] == "implemented" else "[ ]"
                for m in t["mitigations"]:
                    lines.append(f"      - {box} {m}")
            else:
                lines.append("      - no mitigations mapped")
    else:
        lines.append("\nNo modeled threats affected.")

    # coverage gaps - the files themselves are already listed and marked '?'
    # above, so only summarise here rather than repeating every path.
    gaps = []
    if result["unmapped_files"]:
        n = len(result["unmapped_files"])
        gaps.append(f"  {n} changed file(s) matched no component (marked ? above)")
    if result["components_without_source_paths"]:
        gaps.append(
            "  components with no source_paths (invisible to diff mapping): "
            + ", ".join(result["components_without_source_paths"])
        )
    if gaps:
        lines.append("\nCoverage gaps  (what the model cannot see):")
        lines.extend(gaps)
    return "\n".join(lines)


def format_markdown(result):
    lines = [
        "## Threat review",
        "",
        f"**{len(result['changed_files'])}** changed file(s) analyzed.",
        "",
    ]

    if result["affected_threats"]:
        lines.append("### Threats to review — what to check")
        lines.append("")
        lines.append(
            "| Severity | STRIDE | Threat | Status | Feature(s) | Required controls |"
        )
        lines.append("|---|---|---|---|---|---|")
        for t in result["affected_threats"]:
            sev = (t.get("severity") or "?").upper()
            stride = t.get("stride") or ""
            feats = ", ".join(t["features"])
            if t["status"] == "accepted":
                status, controls = "risk accepted", "_risk accepted_"
            elif t["mitigations"]:
                implemented = t["status"] == "implemented"
                status = "**re-verify**" if implemented else "open"
                box = "[x]" if implemented else "[ ]"
                controls = "<br>".join(f"- {box} {m}" for m in t["mitigations"])
            else:
                status, controls = "open", "_no mitigations mapped_"
            lines.append(
                f"| {sev} | {stride} | {t['name']} (`{t['id']}`) "
                f"| {status} | {feats} | {controls} |"
            )
        lines.append("")
    else:
        lines.append("_No modeled threats affected by these changes._\n")

    if result["affected_components"]:
        ids = ", ".join(f"`{c['id']}`" for c in result["affected_components"])
        lines.append(f"**Affected components** (what those files map to): {ids}")
        lines.append("")

    if result["changed_files"]:
        lines.append("### Changed files — what you touched")
        lines.append("")
        for path, hits in _file_component_pairs(result):
            target = (
                ", ".join(f"`{h}`" for h in hits) if hits else "_no component matched_"
            )
            lines.append(f"- `{path}` -> {target}")
        lines.append("")

    gaps = []
    if result["unmapped_files"]:
        n = len(result["unmapped_files"])
        gaps.append(f"- {n} changed file(s) matched no component `source_paths`")
    if result["components_without_source_paths"]:
        ids = ", ".join(f"`{c}`" for c in result["components_without_source_paths"])
        gaps.append(
            f"- components with no `source_paths` (invisible to diff mapping): {ids}"
        )
    if gaps:
        lines.append("### Coverage gaps — what the model cannot see")
        lines.append("")
        lines.extend(gaps)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Command entry point
# ---------------------------------------------------------------------------


def cmd_review(args):
    """Map a diff to the threats it may affect."""
    model_dir = resolve_model_dir(args.path)
    tm = load_threat_model(model_dir)

    repo_root = getattr(args, "repo_root", None) or model_dir.parent

    explicit = getattr(args, "files", None)
    if explicit:
        changed_files = list(explicit)
    else:
        changed_files = changed_files_from_git(
            repo_root,
            base=getattr(args, "base", None),
            staged=getattr(args, "staged", False),
        )

    if not changed_files:
        print("No changed files to review.")
        return 0

    result = map_changed_files(tm, changed_files)

    fmt = getattr(args, "format", "text")
    if fmt == "json":
        print(json.dumps(result, indent=2))
    elif fmt == "md":
        print(format_markdown(result))
    else:
        print(format_text(result))
    return 0
