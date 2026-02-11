#!/usr/bin/env python3
"""TMDD Diagram Generator - Generate interactive threat model diagrams."""
import argparse
import sys
from html import escape

from src import load_threat_model, safe_name
from src.utils import get_output_dir, resolve_model_dir, TMDDError


def generate_diagram(model_dir, highlight_feature=None):
    """Generate an interactive HTML threat model diagram using Cytoscape.js."""
    from report import _build_cytoscape_elements, _safe_json, _DIAGRAM_JS

    model_dir = resolve_model_dir(model_dir)
    threat_model = load_threat_model(model_dir)
    system_name = threat_model.get("system", {}).get("name", "Threat Model")
    esc_name = escape(system_name)
    esc_feature = escape(highlight_feature) if highlight_feature else ""

    nodes, edges, legend = _build_cytoscape_elements(threat_model)
    diagram_json = _safe_json({
        "nodes": nodes,
        "edges": edges,
        "legend": legend,
        "highlightFeature": highlight_feature or "",
    })

    title_suffix = f" &mdash; {esc_feature}" if highlight_feature else ""

    highlight_js = r"""
    (function () {
      var data = JSON.parse(document.getElementById('diagram-data').textContent);
      var hf = data.highlightFeature;
      if (!hf || typeof _cy === 'undefined') return;
      _cy.edges().forEach(function (edge) {
        var feats = edge.data('features') || [];
        var match = feats.some(function (f) { return f.toLowerCase() === hf.toLowerCase(); });
        if (!match) {
          edge.style({ 'opacity': 0.15, 'width': 1 });
        } else {
          edge.style({ 'width': 4 });
        }
      });
    })();
    """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{esc_name} - Threat Model Diagram{title_suffix}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: Arial, sans-serif; background: #f8f9fa; }}
.toolbar {{
  display: flex; align-items: center; gap: 0.5rem;
  padding: 0.5rem 1rem; background: #fff;
  border-bottom: 1px solid #ddd; box-shadow: 0 1px 3px rgba(0,0,0,0.06);
}}
.toolbar h1 {{ font-size: 1rem; color: #333; margin-right: auto; }}
.toolbar button {{
  padding: 0.3rem 0.75rem; border: 1px solid #ccc; background: #fff;
  cursor: pointer; font-size: 0.85rem; border-radius: 3px;
  transition: background 0.15s;
}}
.toolbar button:hover {{ background: #e9e9e9; }}
.hint {{ font-size: 0.75rem; color: #999; margin-left: 0.5rem; }}
#cy {{ width: 100%; height: calc(100vh - 44px); background: #fafbfc; }}
#cy-wrapper {{ position: relative; }}
#diagram-legend {{
  position: absolute; bottom: 12px; left: 12px;
  background: rgba(255,255,255,0.94); border: 1px solid #ddd;
  border-radius: 5px; padding: 0.5rem 0.75rem;
  font-size: 0.8rem; max-height: 240px; overflow-y: auto;
  z-index: 5; box-shadow: 0 1px 6px rgba(0,0,0,0.08);
}}
.legend-title {{
  font-weight: bold; margin-bottom: 0.3rem; font-size: 0.7rem;
  color: #555; text-transform: uppercase; letter-spacing: 0.5px;
}}
.legend-item {{ display: flex; align-items: center; gap: 0.4rem; padding: 0.12rem 0; }}
.legend-dot {{ width: 10px; height: 10px; border-radius: 2px; flex-shrink: 0; }}
#node-info {{
  position: absolute; top: 12px; right: 12px;
  background: rgba(255,255,255,0.95); border: 1px solid #ddd;
  border-radius: 5px; padding: 0.6rem 0.85rem;
  font-size: 0.85rem; max-width: 320px; z-index: 5;
  box-shadow: 0 2px 8px rgba(0,0,0,0.12);
  display: none; line-height: 1.45;
}}
#node-info strong {{ display: block; margin-bottom: 0.2rem; }}
.info-label {{ color: #888; font-size: 0.8em; }}
.legend-item {{ cursor: pointer; padding: 0.2rem 0.35rem; border-radius: 3px; transition: background 0.15s; }}
.legend-item:hover {{ background: rgba(0,0,0,0.06); }}
.legend-item.active {{ background: rgba(0,0,0,0.1); font-weight: bold; }}
#feature-panel {{
  position: absolute; top: 12px; right: 12px; width: 360px;
  max-height: calc(100% - 24px); overflow-y: auto;
  background: rgba(255,255,255,0.97); border: 1px solid #ddd;
  border-radius: 5px; padding: 0; z-index: 10;
  box-shadow: 0 2px 12px rgba(0,0,0,0.15); display: none;
  font-size: 0.83rem; line-height: 1.45;
}}
#feature-panel .fp-header {{ display: flex; align-items: center; gap: 0.5rem; padding: 0.6rem 0.75rem; border-bottom: 1px solid #eee; background: #f8f9fa; border-radius: 5px 5px 0 0; }}
#feature-panel .fp-header .fp-dot {{ width: 12px; height: 12px; border-radius: 3px; flex-shrink: 0; }}
#feature-panel .fp-header strong {{ flex: 1; font-size: 0.9rem; }}
#feature-panel .fp-close {{ border: none; background: none; cursor: pointer; font-size: 1.1rem; color: #999; padding: 0 0.2rem; }}
#feature-panel .fp-close:hover {{ color: #333; }}
#feature-panel .fp-body {{ padding: 0.6rem 0.75rem; }}
#feature-panel .fp-goal {{ color: #555; margin-bottom: 0.5rem; font-style: italic; }}
#feature-panel .fp-section {{ margin-bottom: 0.5rem; }}
#feature-panel .fp-section-title {{ font-weight: bold; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.4px; color: #888; margin-bottom: 0.25rem; }}
.fp-threat {{ padding: 0.4rem 0.5rem; margin-bottom: 0.35rem; background: #f8f9fa; border-left: 3px solid #ccc; border-radius: 0 3px 3px 0; }}
.fp-threat-head {{ display: flex; align-items: center; gap: 0.4rem; margin-bottom: 0.2rem; flex-wrap: wrap; }}
.fp-threat-head code {{ font-weight: bold; }}
.fp-threat-head .sev {{ display: inline-block; padding: 0.05rem 0.35rem; font-size: 0.7rem; font-weight: bold; color: #fff; border-radius: 2px; }}
.fp-threat-head .stride-tag {{ display: inline-block; padding: 0.05rem 0.3rem; font-size: 0.7rem; font-weight: bold; color: #fff; border-radius: 2px; }}
.fp-threat .fp-mit {{ padding-left: 0.75rem; color: #555; font-size: 0.8rem; }}
.fp-threat .fp-mit code {{ font-size: 0.78rem; color: #333; margin-right: 0.2rem; }}
.fp-threat .fp-mode {{ font-size: 0.75rem; color: #999; font-style: italic; }}
.fp-flows {{ display: flex; flex-wrap: wrap; gap: 0.3rem; }}
.fp-flows code {{ font-size: 0.78rem; background: #eef; padding: 0.1rem 0.3rem; border-radius: 2px; }}
</style>
</head>
<body>
<div class="toolbar">
  <h1>{esc_name}{title_suffix}</h1>
  <button onclick="_cyFit()" title="Fit to screen">Fit</button>
  <button onclick="_cyZoomIn()" title="Zoom in">+</button>
  <button onclick="_cyZoomOut()" title="Zoom out">&minus;</button>
  <button onclick="_cyReset()" title="Re-run layout">Reset</button>
  <span class="hint">Scroll to zoom &middot; Drag to pan &middot; Click nodes for details</span>
</div>
<div id="cy-wrapper">
  <div id="cy"></div>
  <div id="diagram-legend"></div>
  <div id="node-info"></div>
  <div id="feature-panel"></div>
</div>
<script id="diagram-data" type="application/json">{diagram_json}</script>
<script src="https://unpkg.com/cytoscape@3.30.4/dist/cytoscape.min.js"></script>
<script src="https://unpkg.com/dagre@0.8.5/dist/dagre.min.js"></script>
<script src="https://unpkg.com/cytoscape-dagre@2.5.0/cytoscape-dagre.js"></script>
<script>{_DIAGRAM_JS}</script>
<script>{highlight_js if highlight_feature else ""}</script>
</body>
</html>
"""

    out = get_output_dir()
    out.mkdir(parents=True, exist_ok=True)
    fname = "diagram"
    if highlight_feature:
        fname = f"diagram_{safe_name(highlight_feature)}"
    output_path = out / f"{fname}.html"
    output_path.write_text(html, encoding="utf-8")
    print(f"Generated: {output_path}")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Generate interactive threat model diagram (HTML)",
    )
    parser.add_argument("-p", "--path", default=".tmdd",
                        help="Threat model directory (default: .tmdd)")
    parser.add_argument("-f", "--feature",
                        help="Highlight a specific feature")
    args = parser.parse_args()
    try:
        return generate_diagram(args.path, args.feature)
    except TMDDError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
