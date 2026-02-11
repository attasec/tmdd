"""TMDD lint command - Validate threat model files."""
import re

from ..utils import load_yaml, resolve_model_dir

ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")
THREAT_PATTERN = re.compile(r"^T\d+$")
MITIGATION_PATTERN = re.compile(r"^M\d+$")
ACTOR_PATTERN = re.compile(r"^TA\d+$")
SEVERITY_VALUES = {"low", "medium", "high", "critical"}
STRIDE_VALUES = {"S", "T", "R", "I", "D", "E"}


def cmd_lint(args):
    """Validate threat model files."""
    model_dir = resolve_model_dir(args.path)
    threats_dir = model_dir / "threats"

    errors = []
    data = {}

    def add_error(loc, msg):
        errors.append(f"{loc}: {msg}")

    # --- check required files exist ---
    main_files = ["system.yaml", "actors.yaml", "components.yaml", "features.yaml", "data_flows.yaml"]
    threat_files = ["catalog.yaml", "mitigations.yaml", "threat_actors.yaml"]

    missing = [f for f in main_files if not (model_dir / f).exists()]
    if not threats_dir.is_dir():
        missing.append("threats/")
    else:
        missing += [f"threats/{f}" for f in threat_files if not (threats_dir / f).exists()]

    if missing:
        print(f"Missing: {', '.join(missing)}")
        return 2

    # --- load all files ---
    for f in main_files:
        data[f] = load_yaml(model_dir / f, strict=True)
    for f in threat_files:
        data[f"threats/{f}"] = load_yaml(threats_dir / f, strict=True)

    if None in data.values():
        print("YAML parse error")
        return 2

    print(f"Linting: {model_dir.absolute()}\n")

    # --- catalog-style validation (threats/mitigations/threat_actors) ---
    def validate_catalog(filename, key, pattern):
        catalog = data[filename].get(key, {})
        if not isinstance(catalog, dict):
            add_error(filename, f"'{key}' must be mapping")
            return set()
        valid_ids = set()
        for item_id, desc in catalog.items():
            if not pattern.match(str(item_id)):
                add_error(filename, f"invalid ID '{item_id}'")
            elif not desc or not isinstance(desc, str):
                add_error(filename, f"'{item_id}' needs description")
            else:
                valid_ids.add(item_id)
        return valid_ids

    def validate_mitigation_catalog(filename):
        """Validate mitigations catalog - supports string or rich object format."""
        catalog = data[filename].get("mitigations", {})
        if not isinstance(catalog, dict):
            add_error(filename, "'mitigations' must be mapping")
            return set()
        valid_ids = set()
        for item_id, entry in catalog.items():
            loc = f"{filename}:{item_id}"
            if not MITIGATION_PATTERN.match(str(item_id)):
                add_error(loc, "invalid ID")
                continue
            # Simple format: M001: "description string"
            if isinstance(entry, str):
                if not entry:
                    add_error(loc, "needs description")
                else:
                    valid_ids.add(item_id)
            # Rich format: M001: { description: "...", references: [...] }
            elif isinstance(entry, dict):
                desc = entry.get("description")
                if not desc or not isinstance(desc, str):
                    add_error(loc, "needs 'description' string")
                    continue
                refs = entry.get("references")
                if refs is not None:
                    if not isinstance(refs, list):
                        add_error(loc, "'references' must be a list")
                        continue
                    for i, ref in enumerate(refs):
                        if not isinstance(ref, dict):
                            add_error(loc, f"references[{i}] must be an object")
                        elif not ref.get("file") or not isinstance(ref.get("file"), str):
                            add_error(loc, f"references[{i}] missing 'file'")
                valid_ids.add(item_id)
            else:
                add_error(loc, "must be a string or object with 'description'")
        return valid_ids

    mitigations = validate_mitigation_catalog("threats/mitigations.yaml")
    threat_actors = validate_catalog("threats/threat_actors.yaml", "threat_actors", ACTOR_PATTERN)

    # --- threats catalog (richer structure) ---
    threats = set()
    catalog = data["threats/catalog.yaml"].get("threats", {})
    if not isinstance(catalog, dict):
        add_error("threats/catalog.yaml", "'threats' must be mapping")
    else:
        for threat_id, threat in catalog.items():
            loc = f"threats/catalog.yaml:{threat_id}"
            if not THREAT_PATTERN.match(str(threat_id)):
                add_error(loc, "invalid ID")
                continue
            if not isinstance(threat, dict):
                add_error(loc, "must be object")
                continue
            threats.add(threat_id)
            for field in ["name", "description"]:
                if not threat.get(field):
                    add_error(loc, f"missing '{field}'")
            if threat.get("severity") and threat["severity"] not in SEVERITY_VALUES:
                add_error(loc, "invalid severity")
            if threat.get("stride") and threat["stride"] not in STRIDE_VALUES:
                add_error(loc, "invalid stride")
            for mit_id in threat.get("suggested_mitigations", []):
                if mit_id not in mitigations:
                    add_error(loc, f"unknown mitigation '{mit_id}'")

    # --- system.yaml ---
    system_data = data["system.yaml"].get("system", {})
    for field in ["name", "description", "version"]:
        if not system_data.get(field):
            add_error("system.yaml", f"missing '{field}'")

    # --- list-style validation (actors/components/data_flows) ---
    def validate_items(filename, key, required_fields):
        items = data[filename].get(key, [])
        if not isinstance(items, list):
            add_error(filename, f"'{key}' must be list")
            return set()
        valid_ids = set()
        for index, item in enumerate(items):
            loc = f"{filename}:[{index}]"
            if not isinstance(item, dict):
                add_error(loc, "must be object")
                continue
            item_id = item.get("id")
            if not item_id:
                add_error(loc, "missing 'id'")
            elif not ID_PATTERN.match(item_id):
                add_error(loc, f"invalid ID '{item_id}'")
            else:
                valid_ids.add(item_id)
            for field in required_fields:
                if field != "id" and not item.get(field):
                    add_error(loc, f"missing '{field}'")
        return valid_ids

    actors = validate_items("actors.yaml", "actors", ["id", "description"])
    components = validate_items("components.yaml", "components", ["id", "description"])
    flows = validate_items("data_flows.yaml", "data_flows", ["id", "source", "destination"])
    endpoints = actors | components

    # --- cross-reference: data flow endpoints ---
    for index, flow in enumerate(data["data_flows.yaml"].get("data_flows", [])):
        if not isinstance(flow, dict):
            continue
        for field in ["source", "destination"]:
            value = flow.get(field)
            if value and value not in endpoints:
                add_error(f"data_flows.yaml:[{index}]", f"unknown {field} '{value}'")

    # --- cross-reference: features ---
    no_mitigations = getattr(args, "no_mitigations", False)
    for index, feature in enumerate(data["features.yaml"].get("features", [])):
        if not isinstance(feature, dict):
            add_error(f"features.yaml:[{index}]", "must be object")
            continue
        loc = f"features.yaml:[{index}]"
        fname = feature.get("name", f"[{index}]")
        if not feature.get("name"):
            add_error(loc, "missing 'name'")
        if not feature.get("goal"):
            add_error(loc, "missing 'goal'")
        for ref in feature.get("data_flows", []):
            if ref not in flows:
                add_error(loc, f"unknown data_flow '{ref}'")
        for ref in feature.get("threat_actors", []):
            if ref not in threat_actors:
                add_error(loc, f"unknown threat_actor '{ref}'")
        feature_threats = feature.get("threats", {})

        # Flat list of threat IDs (no mitigation mapping)
        if isinstance(feature_threats, list):
            if not no_mitigations:
                add_error(loc, f"'{fname}' threats must map to mitigations (use --no-mitigations to allow unmapped threats)")
            else:
                for threat_id in feature_threats:
                    if threat_id not in threats:
                        add_error(loc, f"unknown threat '{threat_id}'")

        # Dict mapping threat IDs -> mitigations (the required default format)
        elif isinstance(feature_threats, dict):
            for threat_id, mits in feature_threats.items():
                if threat_id not in threats:
                    add_error(loc, f"unknown threat '{threat_id}'")
                    continue
                if mits == "accepted" or (isinstance(mits, dict) and mits.get("status") == "accepted"):
                    continue
                # "default" -> inherit suggested_mitigations from catalog
                if mits == "default":
                    threat_def = catalog.get(threat_id, {})
                    suggested = threat_def.get("suggested_mitigations", []) if isinstance(threat_def, dict) else []
                    if not suggested:
                        add_error(loc, f"'{threat_id}' has no suggested_mitigations in catalog (cannot use 'default')")
                    else:
                        for mit_id in suggested:
                            if mit_id not in mitigations:
                                add_error(loc, f"unknown mitigation '{mit_id}' (via '{threat_id}' default)")
                    continue
                if not isinstance(mits, list):
                    add_error(loc, f"'{threat_id}' needs list, 'default', or 'accepted'")
                    continue
                for mit_id in mits:
                    if mit_id not in mitigations:
                        add_error(loc, f"unknown mitigation '{mit_id}'")

    # --- report results ---
    if errors:
        print(f"{len(errors)} error(s):\n")
        for error in errors:
            print(f"  [x] {error}")
        return 1

    print(f"  {len(actors)} actors, {len(components)} components, {len(flows)} flows")
    print(f"  {len(threats)} threats, {len(mitigations)} mitigations\nOK")
    return 0
