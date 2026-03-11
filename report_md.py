#!/usr/bin/env python3
"""TMDD Markdown Report Generator - GitHub-native threat model reports.

Generates a GitHub-Flavored Markdown report with Mermaid architecture diagrams,
GFM tables, and full threat-to-mitigation mappings. The output renders natively
on GitHub/GitLab, in VS Code preview, and in any Markdown viewer — no HTML
download, no JavaScript, no trust concerns.
"""
import re
from src import load_threat_model
from src.utils import get_output_dir, resolve_model_dir

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

STRIDE_NAMES = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Info Disclosure",
    "D": "Denial of Service",
    "E": "Elevation of Privilege",
}

_MERMAID_SHAPES = {
    "frontend": ('(["{label}"])', "rounded"),
    "api":      ('["{label}"]', "rect"),
    "service":  ('(["{label}"])', "rounded"),
    "database": ('[("{label}")]', "cylinder"),
    "cache":    ('[("{label}")]', "cylinder"),
    "queue":    ('>"{label}"]', "asymmetric"),
    "external": ('{{"{label}"}}', "diamond"),
    "external_service": ('{{"{label}"}}', "diamond"),
    "other":    ('["{label}"]', "rect"),
}

_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _esc_mermaid(text):
    """Escape text for use inside Mermaid labels (quoted strings)."""
    if not text:
        return ""
    return str(text).replace('"', "#quot;").replace("<", "&lt;").replace(">", "&gt;")


def _esc_md_table(text):
    """Escape text for use inside a GFM table cell."""
    if not text:
        return ""
    return str(text).replace("|", "\\|").replace("\n", " ")


def _join(value):
    """Join a list with commas, or return string as-is."""
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value) if value else ""


def _mitigation_desc(value):
    """Extract description from a mitigation entry (string or rich dict)."""
    if isinstance(value, dict):
        return value.get("description", "Unknown mitigation")
    return str(value) if value else "Unknown mitigation"


def _mitigation_refs(value):
    """Build a markdown reference string for a mitigation, if it has code refs."""
    if not isinstance(value, dict):
        return ""
    refs = value.get("references", [])
    if not refs:
        return ""
    parts = []
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        fpath = ref.get("file", "")
        lines = ref.get("lines", "")
        loc = f"`{fpath}`"
        if lines:
            loc += f":{lines}"
        parts.append(loc)
    return " (" + ", ".join(parts) + ")" if parts else ""


# ---------------------------------------------------------------------------
# Mermaid diagram builder
# ---------------------------------------------------------------------------

def _build_mermaid_diagram(threat_model):
    """Build a Mermaid flowchart from the threat model architecture."""
    lines = ["```mermaid", "flowchart TD"]

    actors = threat_model.get("actors", [])
    components = threat_model.get("components", [])
    data_flows = threat_model.get("data_flows", [])

    if not components and not actors:
        return ""

    # Actors subgraph
    if actors:
        lines.append('    subgraph Actors')
        for actor in actors:
            aid = actor.get("id", "unknown")
            label = _esc_mermaid(aid.replace("_", " ").title())
            lines.append(f'        {aid}(("{label}"))')
        lines.append("    end")

    # Components grouped by trust boundary
    boundaries = {}
    for comp in components:
        b = comp.get("trust_boundary", "internal")
        boundaries.setdefault(b, []).append(comp)

    for boundary, comps in boundaries.items():
        bid = re.sub(r"[^a-zA-Z0-9_]", "_", boundary)
        lines.append(f'    subgraph {bid}["{_esc_mermaid("Trust: " + boundary)}"]')
        for comp in comps:
            cid = comp.get("id", "unknown")
            ctype = comp.get("type", "other")
            name = comp.get("name", cid.replace("_", " ").title())
            tech = comp.get("technology", "")
            label = _esc_mermaid(name)
            if tech:
                label += f"<br/><small>{_esc_mermaid(tech)}</small>"

            shape_tmpl, _ = _MERMAID_SHAPES.get(ctype, _MERMAID_SHAPES["other"])
            node_def = shape_tmpl.format(label=label)
            lines.append(f"        {cid}{node_def}")
        lines.append("    end")

    # Edges (data flows)
    for flow in data_flows:
        src = flow.get("source", "?")
        dst = flow.get("destination", "?")
        proto = flow.get("protocol", "")
        edge_label = _esc_mermaid(proto)
        if edge_label:
            lines.append(f'    {src} -->|"{edge_label}"| {dst}')
        else:
            lines.append(f"    {src} --> {dst}")

    lines.append("```")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _build_stats_section(threat_model, total_threats_used, total_mitigations_used, reviewed_features):
    """Build the quick-stats summary."""
    components = threat_model.get("components", [])
    data_flows = threat_model.get("data_flows", [])
    features = threat_model.get("features", [])
    threats = threat_model.get("threats", {})
    mitigations = threat_model.get("mitigations", {})

    return (
        f"| Components | Data Flows | Features | Threats | Mitigations | Active Threats | Reviewed |\n"
        f"|:---:|:---:|:---:|:---:|:---:|:---:|:---:|\n"
        f"| {len(components)} | {len(data_flows)} | {len(features)} "
        f"| {len(threats)} | {len(mitigations)} "
        f"| {len(total_threats_used)} | {reviewed_features}/{len(features)} |"
    )


def _build_components_table(components):
    rows = [
        "| ID | Description | Type | Technology | Trust Boundary | Source Paths |",
        "|:---|:---|:---:|:---|:---:|:---|",
    ]
    for comp in components:
        cid = f"`{_esc_md_table(comp.get('id', ''))}`"
        desc = _esc_md_table(comp.get("description", ""))
        ctype = f"**{_esc_md_table(comp.get('type', 'unknown'))}**"
        tech = f"`{_esc_md_table(comp.get('technology', 'N/A'))}`"
        boundary = comp.get("trust_boundary", "internal")
        boundary_md = f"**{_esc_md_table(boundary)}**"
        paths = comp.get("source_paths", [])
        paths_md = " ".join(f"`{_esc_md_table(p)}`" for p in paths) if paths else "—"
        rows.append(f"| {cid} | {desc} | {ctype} | {tech} | {boundary_md} | {paths_md} |")
    return "\n".join(rows)


def _build_flows_table(data_flows):
    rows = [
        "| ID | Path | Description | Protocol | Auth |",
        "|:---|:---|:---|:---:|:---|",
    ]
    for flow in data_flows:
        fid = f"`{_esc_md_table(flow.get('id', ''))}`"
        src = _esc_md_table(flow.get("source", ""))
        dst = _esc_md_table(flow.get("destination", ""))
        path = f"`{src}` → `{dst}`"
        desc = _esc_md_table(flow.get("data_description", ""))
        proto = f"**{_esc_md_table(flow.get('protocol', 'N/A'))}**"
        auth = _esc_md_table(flow.get("authentication", "N/A"))
        rows.append(f"| {fid} | {path} | {desc} | {proto} | {auth} |")
    return "\n".join(rows)


def _build_threats_table(threats, total_threats_used):
    rows = [
        "| ID | Name | Severity | STRIDE | CWE | Suggested Mitigations | Mapped? |",
        "|:---|:---|:---:|:---:|:---:|:---|:---:|",
    ]
    for tid, threat in threats.items():
        if not isinstance(threat, dict):
            continue
        severity = threat.get("severity", "medium")
        stride = threat.get("stride", "?")
        emoji = _SEVERITY_EMOJI.get(severity, "⚪")
        stride_name = STRIDE_NAMES.get(stride, stride)
        suggested = _join(threat.get("suggested_mitigations", []))
        mapped = "✅" if tid in total_threats_used else "—"
        rows.append(
            f"| `{_esc_md_table(tid)}` "
            f"| **{_esc_md_table(threat.get('name', 'Unknown'))}** "
            f"| {emoji} {_esc_md_table(severity).upper()} "
            f"| **{_esc_md_table(stride)}** {_esc_md_table(stride_name)} "
            f"| `{_esc_md_table(threat.get('cwe', 'N/A'))}` "
            f"| `{_esc_md_table(suggested) or 'N/A'}` "
            f"| {mapped} |"
        )
    return "\n".join(rows)


def _build_mitigations_table(mitigations, total_mitigations_used):
    rows = [
        "| ID | Description | Applied? |",
        "|:---|:---|:---:|",
    ]
    for mid, value in mitigations.items():
        desc = _esc_md_table(_mitigation_desc(value))
        refs = _mitigation_refs(value)
        if refs:
            desc += _esc_md_table(refs)
        applied = "✅" if mid in total_mitigations_used else "—"
        rows.append(f"| `{_esc_md_table(mid)}` | {desc} | {applied} |")
    return "\n".join(rows)


def _resolve_mitigations_cell(mids, tinfo, mitigations_catalog):
    """Resolve mitigation IDs into a compact table cell string."""
    if mids == "accepted" or (isinstance(mids, dict) and mids.get("status") == "accepted"):
        return "**Risk accepted**"
    if mids == "default":
        resolved = tinfo.get("suggested_mitigations", [])
        if not isinstance(resolved, list):
            resolved = []
        if not resolved:
            return "*none in catalog*"
        return ", ".join(f"`{mid}`" for mid in resolved) + " *(default)*"
    if isinstance(mids, list):
        if not mids:
            return "—"
        return ", ".join(f"`{mid}`" for mid in mids)
    return "—"


def _build_feature_section(feature, threats_catalog, mitigations_catalog):
    """Build a markdown section for a single feature."""
    fname = feature.get("name", "Unknown")
    fgoal = feature.get("goal", "")
    fupdated = feature.get("last_updated", "")
    reviewed_by = feature.get("reviewed_by", "")
    reviewed_at = feature.get("reviewed_at", "")

    feature_threats = feature.get("threats", {})
    has_accepted = isinstance(feature_threats, dict) and any(
        v == "accepted" or (isinstance(v, dict) and v.get("status") == "accepted")
        for v in feature_threats.values()
    )
    stale = fupdated and reviewed_at and fupdated > reviewed_at

    # Review badge
    if reviewed_by:
        if stale:
            review = f"⚠️ Reviewed by {reviewed_by} ({reviewed_at}) — **needs re-review**"
        else:
            review = f"✅ Reviewed by {reviewed_by} ({reviewed_at})"
    elif has_accepted:
        review = "❌ Has accepted risks — **not reviewed**"
    else:
        review = "🔲 Not reviewed"

    parts = [f"### {fname}", ""]
    if fgoal:
        parts.append(f"> {fgoal}")
        parts.append("")

    # Meta line
    meta_items = []
    if fupdated:
        meta_items.append(f"Updated: {fupdated}")
    meta_items.append(review)
    parts.append(" · ".join(meta_items))
    parts.append("")

    # Data flows, actors as compact inline
    fflows = feature.get("data_flows", [])
    factors = feature.get("threat_actors", [])
    if fflows:
        parts.append(f"**Data Flows:** {', '.join(f'`{f}`' for f in fflows)}  ")
    if factors:
        parts.append(f"**Threat Actors:** {', '.join(f'`{a}`' for a in factors)}")
    if fflows or factors:
        parts.append("")

    # Threat → mitigation table
    if isinstance(feature_threats, list) and feature_threats:
        parts.append("| | Threat | STRIDE | Mitigations |")
        parts.append("|:---:|:---|:---:|:---|")
        for tid in feature_threats:
            tinfo = threats_catalog.get(tid, {})
            if not isinstance(tinfo, dict):
                tinfo = {}
            severity = tinfo.get("severity", "medium")
            stride = tinfo.get("stride", "?")
            emoji = _SEVERITY_EMOJI.get(severity, "⚪")
            tname = _esc_md_table(tinfo.get("name", tid))
            parts.append(f"| {emoji} | `{tid}` {tname} | **{stride}** | *not yet mapped* |")
        parts.append("")

    elif isinstance(feature_threats, dict) and feature_threats:
        parts.append("| | Threat | STRIDE | Mitigations |")
        parts.append("|:---:|:---|:---:|:---|")
        for tid, mids in feature_threats.items():
            tinfo = threats_catalog.get(tid, {})
            if not isinstance(tinfo, dict):
                tinfo = {}
            severity = tinfo.get("severity", "medium")
            stride = tinfo.get("stride", "?")
            emoji = _SEVERITY_EMOJI.get(severity, "⚪")
            tname = _esc_md_table(tinfo.get("name", tid))
            mit_cell = _esc_md_table(_resolve_mitigations_cell(mids, tinfo, mitigations_catalog))
            parts.append(f"| {emoji} | `{tid}` {tname} | **{stride}** | {mit_cell} |")
        parts.append("")

    else:
        parts.append("*No threat mappings defined for this feature.*")
        parts.append("")

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------

def generate_markdown_report(threat_model, system_name):
    """Generate the full Markdown report string."""
    system = threat_model.get("system", {})
    actors = threat_model.get("actors", [])
    components = threat_model.get("components", [])
    features = threat_model.get("features", [])
    data_flows = threat_model.get("data_flows", [])
    threats = threat_model.get("threats", {})
    mitigations = threat_model.get("mitigations", {})
    threat_actors = threat_model.get("threat_actors", {})

    # Compute usage stats
    total_threats_used = set()
    total_mitigations_used = set()
    for feature in features:
        ft = feature.get("threats", {})
        if isinstance(ft, list):
            total_threats_used.update(ft)
        elif isinstance(ft, dict):
            for tid, mids in ft.items():
                total_threats_used.add(tid)
                if mids == "default":
                    tdef = threats.get(tid, {})
                    suggested = tdef.get("suggested_mitigations", []) if isinstance(tdef, dict) else []
                    total_mitigations_used.update(suggested)
                elif isinstance(mids, list):
                    total_mitigations_used.update(mids)

    reviewed_features = sum(1 for f in features if isinstance(f, dict) and f.get("reviewed_by"))

    description = system.get("description", "Security Assessment")

    # --- Assemble document ---
    doc = []
    doc.append(f"# {system_name}")
    doc.append("")
    doc.append(f"**Threat Model Report** · {description}")
    doc.append("")

    # Stats
    doc.append(_build_stats_section(threat_model, total_threats_used, total_mitigations_used, reviewed_features))
    doc.append("")
    doc.append("---")
    doc.append("")

    # Architecture diagram
    diagram = _build_mermaid_diagram(threat_model)
    if diagram:
        doc.append("## System Diagram")
        doc.append("")
        doc.append(diagram)
        doc.append("")

    # Features
    doc.append("## Features")
    doc.append("")
    if features:
        for feature in features:
            doc.append(_build_feature_section(feature, threats, mitigations))
    else:
        doc.append("*No features defined yet.*")
        doc.append("")

    doc.append("---")
    doc.append("")

    # Components
    doc.append("## Components")
    doc.append("")
    if components:
        doc.append(_build_components_table(components))
    else:
        doc.append("*No components defined.*")
    doc.append("")

    # Data Flows
    doc.append("## Data Flows")
    doc.append("")
    if data_flows:
        doc.append(_build_flows_table(data_flows))
    else:
        doc.append("*No data flows defined.*")
    doc.append("")

    # Threat Catalog
    doc.append("## Threat Catalog")
    doc.append("")
    doc.append("*Threats without ✅ in the Mapped column are defined but not currently assigned to any feature.*")
    doc.append("")
    if threats:
        doc.append(_build_threats_table(threats, total_threats_used))
    else:
        doc.append("*No threats defined.*")
    doc.append("")

    # Mitigations Catalog
    doc.append("## Mitigations Catalog")
    doc.append("")
    doc.append("*Mitigations without ✅ in the Applied column are defined but not currently used by any feature.*")
    doc.append("")
    if mitigations:
        doc.append(_build_mitigations_table(mitigations, total_mitigations_used))
    else:
        doc.append("*No mitigations defined.*")
    doc.append("")

    # Actors (two-column: system actors + threat actors)
    doc.append("## Actors")
    doc.append("")
    if actors:
        doc.append("### System Actors")
        doc.append("")
        for actor in actors:
            if isinstance(actor, dict):
                doc.append(f"- **`{actor.get('id', '')}`** — {actor.get('description', '')}")
        doc.append("")

    if threat_actors:
        doc.append("### Threat Actors")
        doc.append("")
        for ta_id, ta_desc in threat_actors.items():
            doc.append(f"- **`{ta_id}`** — {ta_desc}")
        doc.append("")

    # Footer
    doc.append("---")
    doc.append("")
    doc.append(f"*Generated by TMDD (Threat Modeling Driven Development) · {system_name}*")
    doc.append("")

    return "\n".join(doc)
