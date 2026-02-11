"""Generate secure coding prompts for AI agents."""
from pathlib import Path

from ..utils import get_mitigation_desc, get_mitigation_refs


def generate_agent_prompt(tm, output_path, feature_name=None):
    """Generate AI agent prompt for secure code generation.

    Writes the prompt to *output_path* and returns the text that was written,
    so callers can decide independently whether/what to print.
    """
    threats = tm.get("threats", {})
    mitigations = tm.get("mitigations", {})
    system = tm.get("system", {})

    lines = [
        "# SECURE CODING AGENT INSTRUCTIONS\n",
        "You are a security-conscious coding agent. Follow the threat model below.\n",
        "=" * 70,
        f"# SYSTEM: {system.get('name', 'Unknown')}",
        f"# {system.get('description', '')}",
        "=" * 70,
        "\n## ARCHITECTURE\n",
    ]

    for c in tm.get("components", []):
        cid = c.get("id", "unknown")
        lines.append(f"- **{c.get('name', cid)}** ({cid}): {c.get('description', '')}")

    lines.append("\n## DATA FLOWS")
    for f in tm.get("data_flows", []):
        lines.append(f"- {f.get('source', '?')} -> {f.get('destination', '?')}: {f.get('data_description', '')}")

    lines.append("\n## KNOWN THREATS")
    for tid, t in threats.items():
        if not isinstance(t, dict):
            continue
        lines.append(f"- [{t.get('severity', '?').upper()}] {t.get('name', tid)} ({tid}): {t.get('description', '')}")

    lines.append("\n## SECURITY CONTROLS")
    for mid, entry in mitigations.items():
        desc = get_mitigation_desc(entry, mid)
        refs = get_mitigation_refs(entry)
        lines.append(f"- {mid}: {desc}")
        for ref in refs:
            loc = ref.get("file", "")
            if ref.get("lines"):
                loc += f":{ref['lines']}"
            lines.append(f"  - ref: {loc}")

    features = [
        f for f in tm.get("features", [])
        if not feature_name or f.get("name", "").strip().lower() == feature_name.strip().lower()
    ]
    if features:
        lines.append("\n## FEATURE REQUIREMENTS")
        for feat in features:
            lines.append(f"\n### {feat.get('name', 'Unknown')}\n**Goal**: {feat.get('goal', '')}")
            feat_threats = feat.get("threats")
            if feat_threats:
                lines.append("\n**Required Controls:**")

                # Flat list of threat IDs (mitigations not yet mapped)
                if isinstance(feat_threats, list):
                    for tid in feat_threats:
                        threat_info = threats.get(tid, {})
                        threat_label = threat_info.get("name", tid) if isinstance(threat_info, dict) else tid
                        lines.append(f"\n[!] {threat_label}")
                        lines.append("  - Mitigations not yet defined")

                # Dict mapping threat IDs -> mitigations
                elif isinstance(feat_threats, dict):
                    for tid, mits in feat_threats.items():
                        threat_info = threats.get(tid, {})
                        threat_label = threat_info.get("name", tid) if isinstance(threat_info, dict) else tid
                        lines.append(f"\n[!] {threat_label}")
                        if mits == "accepted":
                            lines.append("  - Risk Accepted")
                        elif mits == "default":
                            # Resolve from catalog suggested_mitigations
                            suggested = threat_info.get("suggested_mitigations", []) if isinstance(threat_info, dict) else []
                            if suggested:
                                for mid in suggested:
                                    lines.append(f"  - [ ] {get_mitigation_desc(mitigations.get(mid, mid), mid)} (default)")
                            else:
                                lines.append("  - No suggested mitigations in catalog")
                        elif isinstance(mits, list):
                            for mid in mits:
                                lines.append(f"  - [ ] {get_mitigation_desc(mitigations.get(mid, mid), mid)}")

    lines.append(
        "\n## SECURE CODING RULES\n"
        "- Validate ALL inputs\n"
        "- Use parameterized queries\n"
        "- Check auth on every request\n"
        "- Encrypt sensitive data\n"
        "- Never log secrets"
    )

    content = "\n".join(lines)
    Path(output_path).write_text(content, encoding="utf-8")
    return content
