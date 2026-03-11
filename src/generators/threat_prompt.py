"""Generate threat modeling prompts for AI agents."""
from datetime import date


def generate_threat_model_prompt(tm, feature_name, feature_description, model_dir):
    """Generate prompt for AI to create threat model for a new feature.

    Returns the prompt text as a string (caller writes to file).
    """
    threats = tm.get("threats", {})
    mitigations = tm.get("mitigations", {})
    threat_actors = tm.get("threat_actors", [])
    components = tm.get("components", [])
    data_flows = tm.get("data_flows", [])

    comp_ids = ", ".join(c.get("id", "?") for c in components) or "None"
    flow_ids = ", ".join(f.get("id", "?") for f in data_flows) or "None"
    threat_ids = ", ".join(threats.keys()) or "None"
    mitigation_ids = ", ".join(mitigations.keys()) or "None"
    actor_ids = ", ".join(ta.get("id", "?") for ta in threat_actors) or "None"

    return f"""# THREAT MODELING TASK - ACTION REQUIRED

**YOU MUST EDIT THE FILES LISTED BELOW. DO NOT JUST OUTPUT YAML.**

## NEW FEATURE: {feature_name}
**Description**: {feature_description}

---

## REQUIRED ACTIONS

### 1. Add to `{model_dir}/features.yaml`:
```yaml
- name: {feature_name}
  goal: <what this feature achieves>
  input_data: [<sensitive inputs>]
  output_data: [<sensitive outputs>]
  data_flows: [<data flow IDs>]
  threat_actors: [<threat_actor_id, ...>]
  threats:
    threat_name: default            # Use catalog's suggested_mitigations
    other_threat: [mit_a, mit_b]   # Explicit mitigation list (override)
    known_risk: accepted            # Risk accepted without mitigation
  last_updated: {date.today().isoformat()}
```

### 2. Add new data flows to `{model_dir}/data_flows.yaml` (if needed)
### 3. Add new components to `{model_dir}/components.yaml` (if needed)
### 4. Add new threats to `{model_dir}/threats/threats.yaml` (if needed)
### 5. Add new mitigations to `{model_dir}/threats/mitigations.yaml` (if needed)
```yaml
# Simple format
rate_limiting: "Rate limiting per client/IP"
# Rich format with code references (optional)
webhook_signature_verify:
  description: "HMAC-SHA256 webhook signature verification"
  references:
    - file: "src/webhooks/verify.ts"
      lines: "23-41"
```

---

## EXISTING CONTEXT

**Components**: {comp_ids}
**Data Flows**: {flow_ids}
**Threats**: {threat_ids}
**Mitigations**: {mitigation_ids}
**Threat Actors**: {actor_ids}

---

## STRIDE CHECKLIST

For each component/flow, consider:
- **S**poofing: Can identities be faked?
- **T**ampering: Can data be modified?
- **R**epudiation: Can actions be denied?
- **I**nformation Disclosure: Can data leak?
- **D**enial of Service: Can availability be impacted?
- **E**levation of Privilege: Can permissions be bypassed?

**EDIT THE FILES. DO NOT JUST OUTPUT YAML.**
"""
