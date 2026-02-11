"""TMDD feature command - Threat-model-first feature workflow."""
from ..utils import load_threat_model, safe_name, get_output_dir, resolve_model_dir
from ..generators.threat_prompt import generate_threat_model_prompt
from ..generators.agent_prompt import generate_agent_prompt


def cmd_feature(args):
    """Threat-model-first feature workflow."""
    model_dir = resolve_model_dir(args.path)
    tm = load_threat_model(model_dir)
    out = get_output_dir()
    fname = safe_name(args.name)

    # Normalize feature names for comparison (case + whitespace)
    existing = [f.get("name", "").strip().lower() for f in tm.get("features", [])]
    query = args.name.strip().lower()

    if query in existing:
        print(f"Feature '{args.name}' found")
        prompt_path = out / f"{fname}.prompt.txt"
        generate_agent_prompt(tm, prompt_path, args.name)
        print(f"Implementation prompt: {prompt_path}\nNext: Give this to your coding agent")
    else:
        print(f"Feature '{args.name}' not in threat model - generating threat modeling prompt...")
        prompt_path = out / f"{fname}.threatmodel.txt"
        content = generate_threat_model_prompt(tm, args.name, args.description or "[describe feature]", model_dir)
        prompt_path.write_text(content, encoding="utf-8")
        print(f"Generated: {prompt_path}\n")
        print(f"1. Give prompt to AI  2. AI edits YAML files  3. tmdd lint  4. tmdd feature \"{args.name}\"")
    return 0
