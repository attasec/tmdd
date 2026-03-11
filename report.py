#!/usr/bin/env python3
"""TMDD Report Generator - Generate HTML threat model reports from YAML files."""
import argparse
import json
import sys
from html import escape
from pathlib import Path

from src import load_threat_model, safe_name
from src.utils import get_output_dir, resolve_model_dir, TMDDError

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#65a30d",
}

STRIDE_COLORS = {
    "S": "#8b5cf6",
    "T": "#ef4444",
    "R": "#f97316",
    "I": "#3b82f6",
    "D": "#6b7280",
    "E": "#ec4899",
}

STRIDE_NAMES = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Information Disclosure",
    "D": "Denial of Service",
    "E": "Elevation of Privilege",
}

FEATURE_COLORS = [
    "#e74c3c", "#3498db", "#2ecc71", "#9b59b6", "#f39c12",
    "#1abc9c", "#e67e22", "#34495e", "#16a085", "#c0392b",
]

_COMPONENT_BG = {
    "frontend": "#3498db", "api": "#2ecc71", "service": "#27ae60",
    "database": "#e67e22", "cache": "#f39c12", "queue": "#1abc9c",
    "external": "#95a5a6", "external_service": "#9b59b6", "other": "#bdc3c7",
}

_CYTOSCAPE_SHAPES = {
    "frontend": "round-rectangle", "api": "rectangle", "service": "round-rectangle",
    "database": "barrel", "cache": "barrel", "queue": "tag",
    "external": "diamond", "external_service": "diamond", "other": "rectangle",
}

BOUNDARY_COLORS = {
    "public": "#e74c3c", "internal": "#3498db",
    "external": "#9b59b6", "dmz": "#f39c12",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _esc(value):
    """HTML-escape a value, returning '' for None."""
    return escape(str(value)) if value else ""


def _join_list_or_string(value):
    """Safely join a list, or return string as-is."""
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value) if value else ""


def _mitigation_desc(value):
    """Extract a display description from a mitigation value (string or rich dict)."""
    if isinstance(value, dict):
        return value.get("description", "Unknown mitigation")
    return str(value) if value else "Unknown mitigation"


def _mitigation_refs_html(value):
    """Build HTML for mitigation code references, if any."""
    if not isinstance(value, dict):
        return ""
    refs = value.get("references", [])
    if not refs:
        return ""
    parts = []
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        fpath = _esc(ref.get("file", ""))
        lines = ref.get("lines", "")
        loc = f"<code>{fpath}</code>"
        if lines:
            loc += f"<span style=\"color:#888;\">:{_esc(str(lines))}</span>"
        parts.append(loc)
    if not parts:
        return ""
    return (
        '<span class="mit-refs" style="font-size:0.8em;color:#666;margin-left:0.25rem;">'
        "(" + ", ".join(parts) + ")</span>"
    )


def _safe_json(data):
    """Serialize *data* to JSON safe for embedding inside HTML <script> tags."""
    return json.dumps(data, ensure_ascii=True).replace("</", "<\\/")


def _build_cytoscape_elements(threat_model):
    """Convert a loaded threat-model dict into Cytoscape.js *elements* (nodes + edges)."""
    import hashlib
    nodes = []
    edges = []
    features = threat_model.get("features", [])
    threats_catalog = threat_model.get("threats", {})
    mitigations_catalog = threat_model.get("mitigations", {})

    # flow -> feature colour mapping
    flow_features = {}
    legend = []
    for idx, feat in enumerate(features):
        name = feat.get("name", f"Feature {idx}")
        color = FEATURE_COLORS[idx % len(FEATURE_COLORS)]
        goal = feat.get("goal", "")
        flow_ids = feat.get("data_flows", [])

        # Resolve threat -> mitigation details for this feature
        feat_threats_raw = feat.get("threats", {})
        resolved_threats = []
        if isinstance(feat_threats_raw, dict):
            for tid, mids in feat_threats_raw.items():
                tinfo = threats_catalog.get(tid, {})
                if not isinstance(tinfo, dict):
                    tinfo = {}
                severity = tinfo.get("severity", "medium")

                # Resolve mitigation IDs
                if mids == "default":
                    mid_list = tinfo.get("suggested_mitigations", [])
                    if not isinstance(mid_list, list):
                        mid_list = []
                    mode = "default"
                elif mids == "accepted":
                    mid_list = []
                    mode = "accepted"
                elif isinstance(mids, list):
                    mid_list = mids
                    mode = "explicit"
                else:
                    mid_list = []
                    mode = "unknown"

                mit_details = []
                for mid in mid_list:
                    mval = mitigations_catalog.get(mid, mid)
                    mdesc = mval.get("description", str(mval)) if isinstance(mval, dict) else str(mval)
                    mit_details.append({"id": mid, "description": mdesc})

                resolved_threats.append({
                    "id": tid,
                    "name": tinfo.get("name", tid),
                    "severity": severity,
                    "stride": tinfo.get("stride", "?"),
                    "mode": mode,
                    "mitigations": mit_details,
                })
        elif isinstance(feat_threats_raw, list):
            for tid in feat_threats_raw:
                tinfo = threats_catalog.get(tid, {})
                if not isinstance(tinfo, dict):
                    tinfo = {}
                resolved_threats.append({
                    "id": tid,
                    "name": tinfo.get("name", tid),
                    "severity": tinfo.get("severity", "medium"),
                    "stride": tinfo.get("stride", "?"),
                    "mode": "unmapped",
                    "mitigations": [],
                })

        legend.append({
            "name": name, "color": color, "goal": goal,
            "flows": flow_ids, "threats": resolved_threats,
        })
        for fid in flow_ids:
            flow_features.setdefault(fid, []).append({"name": name, "color": color})

    # --- actors boundary ---
    actors = threat_model.get("actors", [])
    if actors:
        nodes.append({"data": {"id": "_grp_actors", "label": "Actors",
                                "nodeType": "boundary", "borderColor": "#95a5a6"}})
        for actor in actors:
            aid = actor.get("id", "unknown")
            nodes.append({"data": {
                "id": aid,
                "label": aid.replace("_", " ").title(),
                "nodeType": "actor",
                "parent": "_grp_actors",
                "description": actor.get("description", ""),
            }})

    # --- components grouped by trust boundary ---
    boundaries = {}
    for comp in threat_model.get("components", []):
        b = comp.get("trust_boundary", "internal")
        boundaries.setdefault(b, []).append(comp)

    for boundary, comps in boundaries.items():
        bid = f"_grp_{boundary}"
        bc = BOUNDARY_COLORS.get(boundary.lower())
        if not bc:
            h = hashlib.md5(boundary.encode()).hexdigest()
            bc = "#%02x%02x%02x" % tuple(int(h[i:i+2], 16) % 200 + 55 for i in (0, 2, 4))
        nodes.append({"data": {"id": bid, "label": f"Trust: {boundary}",
                                "nodeType": "boundary", "borderColor": bc}})
        for comp in comps:
            cid = comp.get("id", "unknown")
            ctype = comp.get("type", "other")
            nodes.append({"data": {
                "id": cid,
                "label": comp.get("name", cid),
                "nodeType": ctype,
                "parent": bid,
                "bgColor": _COMPONENT_BG.get(ctype, "#bdc3c7"),
                "shape": _CYTOSCAPE_SHAPES.get(ctype, "rectangle"),
                "description": comp.get("description", ""),
                "technology": comp.get("technology", ""),
                "sourcePaths": comp.get("source_paths", []),
            }})

    # --- edges (data flows) ---
    for flow in threat_model.get("data_flows", []):
        fid = flow.get("id", "")
        fi = flow_features.get(fid, [])
        color = fi[0]["color"] if fi else "#34495e"
        fnames = [f["name"] for f in fi]
        edges.append({"data": {
            "id": f"e_{fid}", "source": flow.get("source", "?"),
            "target": flow.get("destination", "?"),
            "label": flow.get("protocol", ""),
            "edgeColor": color, "flowId": fid,
            "features": fnames,
            "description": flow.get("data_description", ""),
        }})

    return nodes, edges, legend



# ---------------------------------------------------------------------------
# CSS (extracted for readability)
# ---------------------------------------------------------------------------

_CSS = """\
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: Arial, sans-serif; background: #fff; color: #000; line-height: 1.5; }
.container { max-width: 1200px; margin: 0 auto; padding: 1.5rem; }
header { padding: 2rem 0; border-bottom: 2px solid #000; margin-bottom: 2rem; }
header h1 { font-size: 2rem; margin-bottom: 0.25rem; }
header .subtitle { color: #444; }
.stats-grid { display: flex; flex-wrap: wrap; gap: 1.5rem; margin-bottom: 2rem; padding-bottom: 1.5rem; border-bottom: 1px solid #ccc; }
.stat-card { text-align: center; }
.stat-card .number { font-size: 1.75rem; font-weight: bold; }
.stat-card .label { color: #444; font-size: 0.85rem; }
section { margin-bottom: 2.5rem; }
section h2 { font-size: 1.25rem; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid #000; }
#cy { width: 100%; height: 70vh; min-height: 500px; border: 1px solid #ddd; border-top: none; background: #fafbfc; }
.diagram-toolbar { display: flex; align-items: center; gap: 0.5rem; padding: 0.4rem 0.75rem; background: #f0f0f0; border: 1px solid #ddd; border-radius: 4px 4px 0 0; }
.diagram-toolbar button { padding: 0.25rem 0.7rem; border: 1px solid #ccc; background: #fff; cursor: pointer; font-size: 0.85rem; border-radius: 3px; transition: background 0.15s; }
.diagram-toolbar button:hover { background: #e0e0e0; }
.diagram-hint { margin-left: auto; font-size: 0.75rem; color: #999; }
#cy-wrapper { position: relative; }
#diagram-legend { position: absolute; bottom: 10px; left: 10px; background: rgba(255,255,255,0.93); border: 1px solid #ddd; border-radius: 4px; padding: 0.5rem 0.75rem; font-size: 0.8rem; max-height: 220px; overflow-y: auto; z-index: 5; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }
.legend-title { font-weight: bold; margin-bottom: 0.3rem; font-size: 0.7rem; color: #555; text-transform: uppercase; letter-spacing: 0.5px; }
.legend-item { display: flex; align-items: center; gap: 0.4rem; padding: 0.12rem 0; }
.legend-dot { width: 10px; height: 10px; border-radius: 2px; flex-shrink: 0; }
#node-info { position: absolute; top: 10px; right: 10px; background: rgba(255,255,255,0.95); border: 1px solid #ddd; border-radius: 4px; padding: 0.6rem 0.8rem; font-size: 0.85rem; max-width: 300px; z-index: 5; box-shadow: 0 1px 6px rgba(0,0,0,0.12); display: none; line-height: 1.45; }
#node-info strong { display: block; margin-bottom: 0.2rem; }
#node-info .info-label { color: #888; font-size: 0.8em; }
.legend-item { cursor: pointer; padding: 0.2rem 0.35rem; border-radius: 3px; transition: background 0.15s; }
.legend-item:hover { background: rgba(0,0,0,0.06); }
.legend-item.active { background: rgba(0,0,0,0.1); font-weight: bold; }
#feature-panel { position: absolute; top: 10px; right: 10px; width: 340px; max-height: calc(100% - 20px); overflow-y: auto; background: rgba(255,255,255,0.97); border: 1px solid #ddd; border-radius: 5px; padding: 0; z-index: 10; box-shadow: 0 2px 12px rgba(0,0,0,0.15); display: none; font-size: 0.83rem; line-height: 1.45; }
#feature-panel .fp-header { display: flex; align-items: center; gap: 0.5rem; padding: 0.6rem 0.75rem; border-bottom: 1px solid #eee; background: #f8f9fa; border-radius: 5px 5px 0 0; }
#feature-panel .fp-header .fp-dot { width: 12px; height: 12px; border-radius: 3px; flex-shrink: 0; }
#feature-panel .fp-header strong { flex: 1; font-size: 0.9rem; }
#feature-panel .fp-close { border: none; background: none; cursor: pointer; font-size: 1.1rem; color: #999; padding: 0 0.2rem; }
#feature-panel .fp-close:hover { color: #333; }
#feature-panel .fp-body { padding: 0.6rem 0.75rem; }
#feature-panel .fp-goal { color: #555; margin-bottom: 0.5rem; font-style: italic; }
#feature-panel .fp-section { margin-bottom: 0.5rem; }
#feature-panel .fp-section-title { font-weight: bold; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.4px; color: #888; margin-bottom: 0.25rem; }
.fp-threat { padding: 0.4rem 0.5rem; margin-bottom: 0.35rem; background: #f8f9fa; border-left: 3px solid #ccc; border-radius: 0 3px 3px 0; }
.fp-threat-head { display: flex; align-items: center; gap: 0.4rem; margin-bottom: 0.2rem; }
.fp-threat-head code { font-weight: bold; }
.fp-threat-head .sev { display: inline-block; padding: 0.05rem 0.35rem; font-size: 0.7rem; font-weight: bold; color: #fff; border-radius: 2px; }
.fp-threat-head .stride-tag { display: inline-block; padding: 0.05rem 0.3rem; font-size: 0.7rem; font-weight: bold; color: #fff; border-radius: 2px; }
.fp-threat .fp-mit { padding-left: 0.75rem; color: #555; font-size: 0.8rem; }
.fp-threat .fp-mit code { font-size: 0.78rem; color: #333; margin-right: 0.2rem; }
.fp-threat .fp-mode { font-size: 0.75rem; color: #999; font-style: italic; }
.fp-flows { display: flex; flex-wrap: wrap; gap: 0.3rem; }
.fp-flows code { font-size: 0.78rem; background: #eef; padding: 0.1rem 0.3rem; border-radius: 2px; }
.no-diagram { color: #666; font-style: italic; padding: 2rem; }
table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
th, td { padding: 0.6rem 0.75rem; text-align: left; border: 1px solid #ccc; }
th { background: #f5f5f5; font-weight: bold; }
tr.unused { color: #888; }
tr.critical { background: #fff0f0; }
code { font-family: Consolas, monospace; background: #f5f5f5; padding: 0.1rem 0.3rem; font-size: 0.85em; }
.badge { display: inline-block; padding: 0.15rem 0.5rem; font-size: 0.75rem; font-weight: bold; color: #fff; }
.badge.type { background: #666; }
.badge.protocol { background: #444; }
.badge.boundary { background: #888; }
.badge.boundary.public { background: #c00; }
.badge.boundary.internal { background: #060; }
.badge.boundary.external { background: #555; }
.badge.stride { min-width: 1.25rem; text-align: center; }
.feature-card { border: 1px solid #ccc; padding: 1rem; margin-bottom: 1rem; }
.feature-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; }
.feature-header h3 { font-size: 1.1rem; }
.last-updated { font-size: 0.8rem; color: #666; }
.review-badge { font-size: 0.75rem; padding: 0.15rem 0.5rem; border-radius: 3px; font-weight: bold; white-space: nowrap; }
.review-ok { background: #d1fae5; color: #065f46; }
.review-stale { background: #fef3c7; color: #92400e; }
.review-warn { background: #fee2e2; color: #991b1b; }
.review-none { background: #f3f4f6; color: #6b7280; }
.feature-goal { color: #444; margin-bottom: 0.75rem; }
.feature-meta { display: flex; flex-wrap: wrap; gap: 1rem; margin-bottom: 1rem; font-size: 0.9rem; }
.meta-item { background: #f5f5f5; padding: 0.4rem 0.6rem; }
.threat-mappings h4 { font-size: 0.9rem; margin-bottom: 0.5rem; color: #444; }
.threat-mapping { display: flex; flex-wrap: wrap; align-items: flex-start; gap: 0.75rem; padding: 0.75rem; background: #f9f9f9; margin-bottom: 0.5rem; border-left: 3px solid #ccc; }
.threat-id { font-weight: bold; min-width: 180px; }
.mapping-arrow { color: #666; line-height: 1.6; }
.mitigations-list { display: flex; flex-direction: column; gap: 0.4rem; flex: 1; }
.mitigation-item { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.5rem; font-size: 0.9rem; padding: 0.25rem 0.4rem; background: #fff; border-radius: 3px; }
.mitigation-item code { white-space: nowrap; font-weight: 600; }
.mit-desc { color: #333; }
.mit-refs { display: block; width: 100%; margin-top: 0.15rem; padding-left: 3.5rem; }
.actor-item { padding: 0.5rem; background: #f5f5f5; margin-bottom: 0.4rem; font-size: 0.9rem; }
.two-col { display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 1.5rem; }
footer { text-align: center; padding: 1.5rem; color: #666; font-size: 0.85rem; border-top: 1px solid #ccc; margin-top: 2rem; }
@media (max-width: 768px) {
  .container { padding: 1rem; }
  header h1 { font-size: 1.5rem; }
  .two-col { grid-template-columns: 1fr; }
  table { font-size: 0.8rem; }
  th, td { padding: 0.4rem; }
}
@media print {
  body { font-size: 11pt; }
  .container { max-width: none; padding: 0; }
  section { page-break-inside: avoid; }
  .diagram-toolbar { display: none; }
  #cy { height: auto; min-height: 0; border: none; }
  #diagram-legend { position: static; box-shadow: none; }
  #node-info { display: none !important; }
}
"""


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------


def _build_threats_rows(threats, total_threats_used):
    rows = []
    for tid, threat in threats.items():
        if not isinstance(threat, dict):
            continue
        severity = threat.get("severity", "medium")
        stride = threat.get("stride", "?")
        color = SEVERITY_COLORS.get(severity, "#6b7280")
        stride_color = STRIDE_COLORS.get(stride, "#6b7280")
        stride_name = STRIDE_NAMES.get(stride, stride)
        suggested = _esc(_join_list_or_string(threat.get("suggested_mitigations", [])))
        used_class = "used" if tid in total_threats_used else "unused"
        rows.append(
            f'<tr class="{used_class}">'
            f"<td><code>{_esc(tid)}</code></td>"
            f"<td><strong>{_esc(threat.get('name', 'Unknown'))}</strong></td>"
            f"<td>{_esc(threat.get('description', ''))}</td>"
            f'<td><span class="badge" style="background:{color}">{_esc(severity).upper()}</span></td>'
            f'<td><span class="badge stride" style="background:{stride_color}" title="{_esc(stride_name)}">{_esc(stride)}</span></td>'
            f"<td><code>{_esc(threat.get('cwe', 'N/A'))}</code></td>"
            f"<td><code>{suggested or 'N/A'}</code></td>"
            f"</tr>"
        )
    return "\n".join(rows)


def _build_mitigations_rows(mitigations, total_mitigations_used):
    rows = []
    for mid, value in mitigations.items():
        used_class = "used" if mid in total_mitigations_used else "unused"
        desc = _esc(_mitigation_desc(value))
        refs = _mitigation_refs_html(value)
        rows.append(
            f'<tr class="{used_class}">'
            f"<td><code>{_esc(mid)}</code></td>"
            f"<td>{desc}{refs}</td>"
            f"</tr>"
        )
    return "\n".join(rows)


def _build_components_rows(components):
    rows = []
    for comp in components:
        boundary = comp.get("trust_boundary", "internal")
        boundary_class = _esc(boundary).lower().replace(" ", "-")
        source_paths = comp.get("source_paths", [])
        if source_paths:
            paths_html = " ".join(
                f'<code style="font-size:0.85em;background:#eef;padding:0.1rem 0.3rem;border-radius:2px;">{_esc(p)}</code>'
                for p in source_paths
            )
        else:
            paths_html = '<span style="color:#999;">—</span>'
        rows.append(
            f"<tr>"
            f"<td><code>{_esc(comp.get('id', ''))}</code></td>"
            f"<td>{_esc(comp.get('description', ''))}</td>"
            f'<td><span class="badge type">{_esc(comp.get("type", "unknown"))}</span></td>'
            f"<td><code>{_esc(comp.get('technology', 'N/A'))}</code></td>"
            f'<td><span class="badge boundary {boundary_class}">{_esc(boundary)}</span></td>'
            f"<td>{paths_html}</td>"
            f"</tr>"
        )
    return "\n".join(rows)


def _build_flows_rows(data_flows):
    rows = []
    for flow in data_flows:
        sensitivity = flow.get("sensitivity", "normal")
        sens_class = "critical" if sensitivity == "critical" else ""
        rows.append(
            f'<tr class="{sens_class}">'
            f"<td><code>{_esc(flow.get('id', ''))}</code></td>"
            f"<td><code>{_esc(flow.get('source', ''))}</code> &rarr; <code>{_esc(flow.get('destination', ''))}</code></td>"
            f"<td>{_esc(flow.get('data_description', ''))}</td>"
            f'<td><span class="badge protocol">{_esc(flow.get("protocol", "N/A"))}</span></td>'
            f"<td>{_esc(flow.get('authentication', 'N/A'))}</td>"
            f"</tr>"
        )
    return "\n".join(rows)


def _build_features_html(features, threats, mitigations):
    sections = []
    for feature in features:
        fname = _esc(feature.get("name", "Unknown"))
        fgoal = _esc(feature.get("goal", ""))
        finputs = _esc(_join_list_or_string(feature.get("input_data", [])))
        foutputs = _esc(_join_list_or_string(feature.get("output_data", [])))
        fflows = _esc(_join_list_or_string(feature.get("data_flows", [])))
        factors = _esc(_join_list_or_string(feature.get("threat_actors", [])))
        fupdated = _esc(feature.get("last_updated", ""))

        # --- meta items (only render rows that have content) ---
        meta_items = []
        if finputs:
            meta_items.append(f'<div class="meta-item"><strong>Input Data:</strong> <code>{finputs}</code></div>')
        if foutputs:
            meta_items.append(f'<div class="meta-item"><strong>Output Data:</strong> <code>{foutputs}</code></div>')
        if fflows:
            meta_items.append(f'<div class="meta-item"><strong>Data Flows:</strong> <code>{fflows}</code></div>')
        if factors:
            meta_items.append(f'<div class="meta-item"><strong>Threat Actors:</strong> <code>{factors}</code></div>')
        meta_html = "\n".join(meta_items)

        # --- threat -> mitigation mappings ---
        mapping_parts = []
        feature_threats = feature.get("threats", {})

        # Flat list of threat IDs (mitigations not yet mapped)
        if isinstance(feature_threats, list):
            for tid in feature_threats:
                threat_info = threats.get(tid, {})
                if not isinstance(threat_info, dict):
                    threat_info = {}
                threat_name = _esc(threat_info.get("name", tid))
                severity = threat_info.get("severity", "medium")
                color = SEVERITY_COLORS.get(severity, "#6b7280")
                mapping_parts.append(
                    f'<div class="threat-mapping">'
                    f'<div class="threat-id" style="border-color:{color}"><code>{_esc(tid)}</code> {threat_name}</div>'
                    f'<div class="mitigations-list">'
                    f'<span class="mit-desc" style="color:#999;font-style:italic;">Mitigations not yet defined</span>'
                    f'</div></div>'
                )

        # Dict mapping threat IDs -> mitigations (full mapping)
        elif isinstance(feature_threats, dict):
            for tid, mids in feature_threats.items():
                threat_info = threats.get(tid, {})
                if not isinstance(threat_info, dict):
                    threat_info = {}
                threat_name = _esc(threat_info.get("name", tid))
                severity = threat_info.get("severity", "medium")
                color = SEVERITY_COLORS.get(severity, "#6b7280")

                # Resolve "default" to catalog suggested_mitigations
                if mids == "default":
                    resolved = threat_info.get("suggested_mitigations", [])
                    mit_items_list = []
                    for mid in (resolved if isinstance(resolved, list) else []):
                        mit_raw = mitigations.get(mid, "Unknown mitigation")
                        mit_desc = _esc(_mitigation_desc(mit_raw))
                        mit_refs = _mitigation_refs_html(mit_raw)
                        mit_items_list.append(
                            f'<div class="mitigation-item"><code>{_esc(mid)}</code>'
                            f'<span class="mit-desc">{mit_desc}</span>{mit_refs}'
                            f'<span style="color:#999;font-size:0.8em;"> (default)</span></div>'
                        )
                    mit_items = "\n".join(mit_items_list) or '<span class="mit-desc" style="color:#999;">No suggested mitigations in catalog</span>'
                elif mids == "accepted" or (isinstance(mids, dict) and mids.get("status") == "accepted"):
                    mit_items = (
                        f'<div class="mitigation-item"><code>accepted</code>'
                        f'<span class="mit-desc">Risk accepted</span></div>'
                    )
                else:
                    mit_items_list = []
                    for mid in (mids if isinstance(mids, list) else []):
                        mit_raw = mitigations.get(mid, "Unknown mitigation")
                        mit_desc = _esc(_mitigation_desc(mit_raw))
                        mit_refs = _mitigation_refs_html(mit_raw)
                        mit_items_list.append(
                            f'<div class="mitigation-item"><code>{_esc(mid)}</code>'
                            f'<span class="mit-desc">{mit_desc}</span>{mit_refs}</div>'
                        )
                    mit_items = "\n".join(mit_items_list)

                mapping_parts.append(
                    f'<div class="threat-mapping">'
                    f'<div class="threat-id" style="border-color:{color}"><code>{_esc(tid)}</code> {threat_name}</div>'
                    f'<div class="mapping-arrow">&rarr;</div>'
                    f'<div class="mitigations-list">{mit_items}</div>'
                    f"</div>"
                )

        threat_mappings = "\n".join(mapping_parts)
        if not threat_mappings:
            threat_mappings = '<p style="color:#999;font-size:0.9rem;">No threat mappings defined for this feature.</p>'

        # --- updated / review badges ---
        updated_html = f'<span class="last-updated">Updated: {fupdated}</span>' if fupdated else ""

        reviewed_by = _esc(feature.get("reviewed_by", ""))
        reviewed_at = _esc(feature.get("reviewed_at", ""))
        has_accepted = isinstance(feature_threats, dict) and any(
            v == "accepted" or (isinstance(v, dict) and v.get("status") == "accepted")
            for v in feature_threats.values()
        )
        stale = (fupdated and reviewed_at and fupdated > reviewed_at)

        if reviewed_by:
            if stale:
                review_badge = (
                    f'<span class="review-badge review-stale" title="Updated after last review">'
                    f'Reviewed: {reviewed_by} ({reviewed_at}) &mdash; needs re-review</span>'
                )
            else:
                review_badge = (
                    f'<span class="review-badge review-ok">'
                    f'Reviewed: {reviewed_by} ({reviewed_at})</span>'
                )
        elif has_accepted:
            review_badge = (
                '<span class="review-badge review-warn">'
                'Has accepted risks &mdash; not reviewed</span>'
            )
        else:
            review_badge = '<span class="review-badge review-none">Not reviewed</span>'

        sections.append(
            f'<div class="feature-card">'
            f'<div class="feature-header"><h3>{fname}</h3>'
            f'<div>{review_badge} {updated_html}</div></div>'
            f'<p class="feature-goal">{fgoal}</p>'
            f'<div class="feature-meta">{meta_html}</div>'
            f'<div class="threat-mappings"><h4>Threat &rarr; Mitigation Mappings</h4>'
            f"{threat_mappings}</div></div>"
        )
    return "\n".join(sections)


def _build_actor_items(items, id_key="id", desc_key="description"):
    """Render a list of actor-items (used for both system actors and threat actors)."""
    parts = []
    for item in items:
        if isinstance(item, dict):
            parts.append(f'<div class="actor-item"><code>{_esc(item.get(id_key, ""))}</code>: {_esc(item.get(desc_key, ""))}</div>')
        elif isinstance(item, tuple) and len(item) == 2:
            parts.append(f'<div class="actor-item"><code>{_esc(item[0])}</code>: {_esc(item[1])}</div>')
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Interactive diagram (Cytoscape.js)
# ---------------------------------------------------------------------------

_DIAGRAM_JS = r"""
(function () {
  var dataEl = document.getElementById('diagram-data');
  if (!dataEl) return;
  var data = JSON.parse(dataEl.textContent);

  /* --- HTML-escape helper (prevent XSS from YAML data) ------------------ */
  var _e = document.createElement('div');
  function esc(s) { if (s == null) return ''; _e.textContent = String(s); return _e.innerHTML; }

  /* --- wait for CDN libs ------------------------------------------------ */
  if (typeof cytoscape === 'undefined') {
    document.getElementById('cy').innerHTML =
      '<p style="padding:2rem;color:#666;">Interactive diagram requires an internet connection.</p>';
    return;
  }

  /* Register dagre layout extension */
  if (typeof cytoscapeDagre === 'function') cytoscapeDagre(cytoscape);

  var layoutOpts = {
    name: 'dagre',
    rankDir: 'TB',
    nodeSep: 50,
    rankSep: 70,
    edgeSep: 10,
    padding: 30,
    animate: false
  };

  var cy = window._cy = cytoscape({
    container: document.getElementById('cy'),
    elements: data.nodes.concat(data.edges),
    minZoom: 0.15,
    maxZoom: 4,
    wheelSensitivity: 0.25,
    boxSelectionEnabled: false,

    style: [
      /* ----- compound / boundary nodes --------------------------------- */
      {
        selector: 'node[nodeType="boundary"]',
        style: {
          'shape': 'round-rectangle',
          'background-color': '#f4f5f7',
          'background-opacity': 0.35,
          'border-width': 2,
          'border-style': 'dashed',
          'border-color': 'data(borderColor)',
          'label': 'data(label)',
          'text-valign': 'top',
          'text-halign': 'center',
          'font-size': '13px',
          'font-weight': 'bold',
          'color': '#555',
          'padding': '24px',
          'text-margin-y': -5
        }
      },
      /* ----- actor nodes ----------------------------------------------- */
      {
        selector: 'node[nodeType="actor"]',
        style: {
          'shape': 'ellipse',
          'background-color': '#ecf0f1',
          'border-width': 1.5,
          'border-color': '#bdc3c7',
          'label': 'data(label)',
          'text-valign': 'center',
          'text-halign': 'center',
          'font-size': '11px',
          'color': '#2c3e50',
          'width': 'label',
          'height': 'label',
          'padding': '14px',
          'text-wrap': 'wrap',
          'text-max-width': '90px'
        }
      },
      /* ----- component nodes (generic) --------------------------------- */
      {
        selector: 'node[nodeType!="boundary"][nodeType!="actor"]',
        style: {
          'shape': 'data(shape)',
          'background-color': 'data(bgColor)',
          'label': 'data(label)',
          'text-valign': 'center',
          'text-halign': 'center',
          'font-size': '11px',
          'color': '#fff',
          'text-outline-width': 1,
          'text-outline-color': 'data(bgColor)',
          'width': 'label',
          'height': 'label',
          'padding': '14px',
          'text-wrap': 'wrap',
          'text-max-width': '110px',
          'border-width': 0
        }
      },
      /* ----- edges ----------------------------------------------------- */
      {
        selector: 'edge',
        style: {
          'width': 2,
          'line-color': 'data(edgeColor)',
          'target-arrow-color': 'data(edgeColor)',
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier',
          'label': 'data(label)',
          'font-size': '9px',
          'color': '#555',
          'text-background-color': '#fff',
          'text-background-opacity': 0.85,
          'text-background-padding': '2px',
          'arrow-scale': 1.2
        }
      },
      /* ----- hover / selected states ----------------------------------- */
      {
        selector: 'node:active, node:selected',
        style: {
          'overlay-color': '#2980b9',
          'overlay-opacity': 0.12,
          'border-width': 3,
          'border-color': '#2980b9'
        }
      },
      {
        selector: 'edge:selected',
        style: { 'width': 4, 'overlay-opacity': 0.08 }
      }
    ],

    layout: layoutOpts
  });

  /* ----- Severity / STRIDE colour maps --------------------------------- */
  var sevColors = { critical: '#dc2626', high: '#ea580c', medium: '#ca8a04', low: '#65a30d' };
  var strideColors = { S: '#8b5cf6', T: '#ef4444', R: '#f97316', I: '#3b82f6', D: '#6b7280', E: '#ec4899' };

  /* ----- Info panel on tap --------------------------------------------- */
  var info = document.getElementById('node-info');
  var fpanel = document.getElementById('feature-panel');

  cy.on('tap', 'node[nodeType!="boundary"]', function (evt) {
    if (fpanel.style.display === 'block') return;
    var d = evt.target.data();
    var h = '<strong>' + esc(d.label) + '</strong>';
    if (d.description) h += '<div>' + esc(d.description) + '</div>';
    if (d.technology) h += '<div><span class="info-label">Tech:</span> ' + esc(d.technology) + '</div>';
    if (d.nodeType && d.nodeType !== 'actor')
      h += '<div><span class="info-label">Type:</span> ' + esc(d.nodeType) + '</div>';
    if (d.sourcePaths && d.sourcePaths.length)
      h += '<div><span class="info-label">Sources:</span> ' + d.sourcePaths.map(function(p){ return '<code>' + esc(p) + '</code>'; }).join(' ') + '</div>';
    info.innerHTML = h;
    info.style.display = 'block';
  });

  cy.on('tap', 'edge', function (evt) {
    if (fpanel.style.display === 'block') return;
    var d = evt.target.data();
    var h = '<strong>' + esc(d.flowId) + '</strong>';
    if (d.label) h += ' <code>' + esc(d.label) + '</code>';
    if (d.description) h += '<div>' + esc(d.description) + '</div>';
    if (d.features && d.features.length)
      h += '<div><span class="info-label">Features:</span> ' + esc(d.features.join(', ')) + '</div>';
    info.innerHTML = h;
    info.style.display = 'block';
  });

  cy.on('tap', function (evt) {
    if (evt.target === cy) {
      info.style.display = 'none';
      clearFeatureHighlight();
    }
  });

  /* ----- Feature highlight + threat panel ------------------------------ */
  var activeFeature = null;

  function clearFeatureHighlight() {
    activeFeature = null;
    fpanel.style.display = 'none';
    info.style.display = 'none';
    cy.elements().removeClass('dimmed');
    cy.edges().style({ 'opacity': 1, 'width': 2 });
    cy.nodes().style({ 'opacity': 1 });
    document.querySelectorAll('.legend-item').forEach(function (el) { el.classList.remove('active'); });
  }

  function showFeature(feat, idx) {
    if (activeFeature === feat.name) { clearFeatureHighlight(); return; }
    activeFeature = feat.name;
    info.style.display = 'none';

    /* Dim all edges, then highlight matching ones */
    cy.edges().style({ 'opacity': 0.1, 'width': 1 });
    cy.nodes('[nodeType!="boundary"]').style({ 'opacity': 0.35 });
    var flowSet = {};
    (feat.flows || []).forEach(function (f) { flowSet[f] = true; });
    var touchedNodes = {};
    cy.edges().forEach(function (edge) {
      if (flowSet[edge.data('flowId')]) {
        edge.style({ 'opacity': 1, 'width': 3 });
        touchedNodes[edge.data('source')] = true;
        touchedNodes[edge.data('target')] = true;
      }
    });
    cy.nodes().forEach(function (n) {
      if (touchedNodes[n.data('id')] || n.data('nodeType') === 'boundary') {
        n.style({ 'opacity': 1 });
      }
    });

    /* Mark active legend item */
    document.querySelectorAll('.legend-item').forEach(function (el, i) {
      el.classList.toggle('active', i === idx);
    });

    /* Build threat detail panel */
    var h = '<div class="fp-header">' +
      '<span class="fp-dot" style="background:' + feat.color + '"></span>' +
      '<strong>' + esc(feat.name) + '</strong>' +
      '<button class="fp-close" onclick="clearFeatureHighlight()" title="Close">&times;</button>' +
      '</div><div class="fp-body">';
    if (feat.goal) h += '<div class="fp-goal">' + esc(feat.goal) + '</div>';

    /* Data flows */
    if (feat.flows && feat.flows.length) {
      h += '<div class="fp-section"><div class="fp-section-title">Data Flows</div>' +
        '<div class="fp-flows">';
      feat.flows.forEach(function (f) { h += '<code>' + esc(f) + '</code>'; });
      h += '</div></div>';
    }

    /* Threats */
    var threats = feat.threats || [];
    if (threats.length) {
      h += '<div class="fp-section"><div class="fp-section-title">Threats (' + threats.length + ')</div>';
      threats.forEach(function (t) {
        var sc = sevColors[t.severity] || '#6b7280';
        var stc = strideColors[t.stride] || '#6b7280';
        h += '<div class="fp-threat" style="border-left-color:' + sc + '">' +
          '<div class="fp-threat-head">' +
          '<code>' + esc(t.id) + '</code> ' +
          '<span class="sev" style="background:' + sc + '">' + esc(t.severity.toUpperCase()) + '</span> ' +
          '<span class="stride-tag" style="background:' + stc + '">' + esc(t.stride) + '</span> ' +
          '<span>' + esc(t.name) + '</span></div>';
        if (t.mode === 'accepted') {
          h += '<div class="fp-mit"><span class="fp-mode">Risk accepted</span></div>';
        } else if (t.mode === 'unmapped') {
          h += '<div class="fp-mit"><span class="fp-mode">Mitigations not yet mapped</span></div>';
        } else {
          (t.mitigations || []).forEach(function (m) {
            h += '<div class="fp-mit"><code>' + esc(m.id) + '</code> ' + esc(m.description) + '</div>';
          });
          if (t.mode === 'default')
            h += '<div class="fp-mit"><span class="fp-mode">(from catalog defaults)</span></div>';
        }
        h += '</div>';
      });
      h += '</div>';
    } else {
      h += '<div class="fp-section"><div class="fp-section-title">Threats</div>' +
        '<div style="color:#999;font-style:italic;">No threats mapped</div></div>';
    }
    h += '</div>';
    fpanel.innerHTML = h;
    fpanel.style.display = 'block';
  }
  window.clearFeatureHighlight = clearFeatureHighlight;

  /* ----- Legend (clickable) --------------------------------------------- */
  var legendEl = document.getElementById('diagram-legend');
  if (data.legend && data.legend.length && legendEl) {
    var lh = '<div class="legend-title">Features <span style="font-weight:normal;font-size:0.85em;color:#aaa;">(click to inspect)</span></div>';
    data.legend.forEach(function (it, idx) {
      lh += '<div class="legend-item" data-idx="' + idx + '">' +
        '<span class="legend-dot" style="background:' + it.color + '"></span>' +
        esc(it.name) + '</div>';
    });
    legendEl.innerHTML = lh;
    legendEl.querySelectorAll('.legend-item').forEach(function (el) {
      el.addEventListener('click', function (e) {
        e.stopPropagation();
        var i = parseInt(this.getAttribute('data-idx'));
        showFeature(data.legend[i], i);
      });
    });
  }

  /* ----- Toolbar handlers ---------------------------------------------- */
  window._cyFit    = function () { cy.fit(null, 30); };
  window._cyZoomIn = function () {
    cy.zoom({ level: cy.zoom() * 1.3,
              renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  };
  window._cyZoomOut = function () {
    cy.zoom({ level: cy.zoom() / 1.3,
              renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  };
  window._cyReset = function () {
    cy.layout(layoutOpts).run();
    setTimeout(function () { cy.fit(null, 30); }, 50);
  };
})();
"""


def _build_interactive_diagram(threat_model):
    """Return the full HTML section for the interactive Cytoscape.js diagram."""
    nodes, edges, legend = _build_cytoscape_elements(threat_model)
    diagram_json = _safe_json({"nodes": nodes, "edges": edges, "legend": legend})

    return (
        '<div class="diagram-toolbar">'
        '  <button onclick="_cyFit()" title="Fit to screen">Fit</button>'
        '  <button onclick="_cyZoomIn()" title="Zoom in">+</button>'
        '  <button onclick="_cyZoomOut()" title="Zoom out">&minus;</button>'
        '  <button onclick="_cyReset()" title="Re-run layout">Reset Layout</button>'
        '  <span class="diagram-hint">Scroll to zoom &middot; Drag to pan &middot; Click nodes for details</span>'
        '</div>'
        '<div id="cy-wrapper">'
        '  <div id="cy"></div>'
        '  <div id="diagram-legend"></div>'
        '  <div id="node-info"></div>'
        '  <div id="feature-panel"></div>'
        '</div>'
        f'<script id="diagram-data" type="application/json">{diagram_json}</script>'
        '<script src="https://unpkg.com/cytoscape@3.30.4/dist/cytoscape.min.js"></script>'
        '<script src="https://unpkg.com/dagre@0.8.5/dist/dagre.min.js"></script>'
        '<script src="https://unpkg.com/cytoscape-dagre@2.5.0/cytoscape-dagre.js"></script>'
        f'<script>{_DIAGRAM_JS}</script>'
    )


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------


def generate_html_report(threat_model, system_name):
    """Generate the HTML content for the threat model report."""
    system = threat_model.get("system", {})
    actors = threat_model.get("actors", [])
    components = threat_model.get("components", [])
    features = threat_model.get("features", [])
    data_flows = threat_model.get("data_flows", [])
    threats = threat_model.get("threats", {})
    mitigations = threat_model.get("mitigations", {})
    threat_actors = threat_model.get("threat_actors", {})

    # Active usage stats
    total_threats_used = set()
    total_mitigations_used = set()
    for feature in features:
        feature_threats = feature.get("threats", {})
        if isinstance(feature_threats, list):
            # Flat list of threat IDs (no mitigations mapped yet)
            total_threats_used.update(feature_threats)
        elif isinstance(feature_threats, dict):
            for threat_id, mitigation_ids in feature_threats.items():
                total_threats_used.add(threat_id)
                if mitigation_ids == "default":
                    # Resolve from catalog suggested_mitigations
                    threat_def = threats.get(threat_id, {})
                    suggested = threat_def.get("suggested_mitigations", []) if isinstance(threat_def, dict) else []
                    total_mitigations_used.update(suggested)
                elif isinstance(mitigation_ids, list):
                    total_mitigations_used.update(mitigation_ids)

    # Review coverage stats
    reviewed_features = sum(1 for f in features if isinstance(f, dict) and f.get("reviewed_by"))

    # Build sections
    threats_rows = _build_threats_rows(threats, total_threats_used)
    mitigations_rows = _build_mitigations_rows(mitigations, total_mitigations_used)
    components_rows = _build_components_rows(components)
    flows_rows = _build_flows_rows(data_flows)
    features_html = _build_features_html(features, threats, mitigations)

    system_actors_html = _build_actor_items(actors)
    actors_html = "\n".join(
        f'<div class="actor-item"><code>{_esc(ta_id)}</code>: {_esc(ta_desc)}</div>'
        for ta_id, ta_desc in threat_actors.items()
    )

    diagram_section = _build_interactive_diagram(threat_model)

    esc_name = _esc(system_name)
    esc_desc = _esc(system.get("description", "Security Assessment"))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{esc_name} - Threat Model Report</title>
    <style>{_CSS}</style>
</head>
<body>
    <header><div class="container">
        <h1>{esc_name}</h1>
        <p class="subtitle">Threat Model Report &bull; {esc_desc}</p>
    </div></header>
    <div class="container">
        <div class="stats-grid">
            <div class="stat-card"><div class="number">{len(components)}</div><div class="label">Components</div></div>
            <div class="stat-card"><div class="number">{len(data_flows)}</div><div class="label">Data Flows</div></div>
            <div class="stat-card"><div class="number">{len(features)}</div><div class="label">Features</div></div>
            <div class="stat-card"><div class="number">{len(threats)}</div><div class="label">Threats</div></div>
            <div class="stat-card"><div class="number">{len(mitigations)}</div><div class="label">Mitigations</div></div>
            <div class="stat-card"><div class="number">{len(total_threats_used)}</div><div class="label">Active Threats</div></div>
            <div class="stat-card"><div class="number">{reviewed_features}/{len(features)}</div><div class="label">Features Reviewed</div></div>
        </div>

        <section><h2>System Diagram</h2>
            {diagram_section}
        </section>

        <section><h2>Features</h2>
            {features_html if features_html else '<p style="color:#666">No features defined yet.</p>'}
        </section>

        <section><h2>Components</h2><div style="overflow-x:auto;">
            <table><thead><tr><th>ID</th><th>Description</th><th>Type</th><th>Technology</th><th>Trust Boundary</th><th>Source Paths</th></tr></thead>
            <tbody>{components_rows}</tbody></table></div>
        </section>

        <section><h2>Data Flows</h2><div style="overflow-x:auto;">
            <table><thead><tr><th>ID</th><th>Path</th><th>Description</th><th>Protocol</th><th>Authentication</th></tr></thead>
            <tbody>{flows_rows}</tbody></table></div>
        </section>

        <section><h2>Threat Catalog</h2>
            <p style="color:#666;margin-bottom:0.75rem;">Faded rows indicate threats not currently mapped to any feature.</p>
            <div style="overflow-x:auto;">
            <table><thead><tr><th>ID</th><th>Name</th><th>Description</th><th>Severity</th><th>STRIDE</th><th>CWE</th><th>Suggested Mitigations</th></tr></thead>
            <tbody>{threats_rows}</tbody></table></div>
        </section>

        <section><h2>Mitigations Catalog</h2>
            <p style="color:#666;margin-bottom:0.75rem;">Faded rows indicate mitigations not currently applied to any feature.</p>
            <div style="overflow-x:auto;">
            <table><thead><tr><th>ID</th><th>Description</th></tr></thead>
            <tbody>{mitigations_rows}</tbody></table></div>
        </section>

        <div class="two-col">
            <section><h2>System Actors</h2>
                {system_actors_html if system_actors_html else '<p style="color:#666">No actors defined.</p>'}
            </section>
            <section><h2>Threat Actors</h2>
                {actors_html if actors_html else '<p style="color:#666">No threat actors defined.</p>'}
            </section>
        </div>
    </div>
    <footer><p>Generated by TMDD (Threat Modeling Driven Development) &bull; {esc_name}</p></footer>
</body>
</html>
"""


def generate_report(model_dir, output_dir=None, output_name=None, fmt="html"):
    """Generate threat model report in the specified format (html or md)."""
    from report_md import generate_markdown_report

    model_dir = resolve_model_dir(model_dir)
    threat_model = load_threat_model(model_dir)
    system_name = threat_model.get("system", {}).get("name", "Threat Model")

    if output_name is None:
        output_name = "tm.md" if fmt == "md" else "tm.html"

    out = Path(output_dir) if output_dir else get_output_dir()
    out.mkdir(parents=True, exist_ok=True)
    output_file = out / output_name

    if fmt == "md":
        content = generate_markdown_report(threat_model, system_name)
    else:
        content = generate_html_report(threat_model, system_name)

    output_file.write_text(content, encoding="utf-8")
    print(f"Generated: {output_file}")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Generate threat model report (HTML or Markdown)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  tmdd-report                          # HTML report (default)
  tmdd-report --format md              # Markdown report (GitHub-native)
  tmdd-report -p ./my-app
  tmdd-report -o ./reports -n security-report.html
        """,
    )
    parser.add_argument("-p", "--path", default=".tmdd", help="Threat model directory (default: .tmdd)")
    parser.add_argument("-o", "--output", help="Output directory (default: .tmdd/out/)")
    parser.add_argument("-n", "--name", help="Output filename (default: tm.html or tm.md)")
    parser.add_argument("-f", "--format", choices=["html", "md"], default="html",
                        help="Output format: html (interactive) or md (GitHub-native) (default: html)")
    args = parser.parse_args()
    try:
        return generate_report(args.path, args.output, args.name, args.format)
    except TMDDError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
