"""TMDD compile command - Generate consolidated files."""
import yaml
from datetime import date

from ..utils import load_threat_model, safe_name, get_output_dir, resolve_model_dir, TMDDError
from ..generators.agent_prompt import generate_agent_prompt


def cmd_compile(args):
    """Compile threat model to consolidated files."""
    model_dir = resolve_model_dir(args.path)
    tm = load_threat_model(model_dir)

    system_name = tm.get("system", {}).get("name")
    if not system_name:
        raise TMDDError("system.yaml is missing or has no system name. Run 'tmdd lint' first.")

    sname = safe_name(system_name)
    out = get_output_dir()

    # Generate YAML
    yaml_path = out / f"{sname}.tm.yaml"
    resolved = {"$schema": "https://tmdd.dev/schema/v0.5", "generated": date.today().isoformat(), **tm}
    yaml_path.write_text(yaml.dump(resolved, default_flow_style=False, allow_unicode=True), encoding="utf-8")
    print(f"Generated: {yaml_path}")

    # Generate prompt
    fname = safe_name(args.feature) if args.feature else sname
    prompt_path = out / f"{fname}.prompt.txt"
    generate_agent_prompt(tm, prompt_path, args.feature)
    print(f"Generated: {prompt_path}")
    return 0
