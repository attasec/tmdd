# Workflow: Add a feature to an existing model

Use for "threat model the <feature>", "add <feature>", or a `tmdd feature` prompt the user
pasted. The model must already exist (otherwise run `workflows/model.md` first).
Read `reference/schema.md`; consult `reference/methodology.md` sections 6 to 13 and
`reference/discovery.md` sections 2 to 5 for the relevant stack.

## Steps

1. **Read the model.** All of `.tmdd/*.yaml` and `.tmdd/threats/*.yaml`. Note existing
   component, flow, threat, mitigation, and actor IDs so you reuse them.
2. **Generate the prompt file** (it also records the feature in `.tmdd/out/`):
   `tmdd feature "<Name>" -d "<one-line description>"`. Read
   `.tmdd/out/<name>.threatmodel.txt`; it lists the existing IDs to reuse.
   If the feature already exists in `features.yaml`, the command instead emits the
   implementation prompt; in that case you are updating, not adding: edit the existing entry.
3. **Analyze the feature's code impact.** If code exists, read it; if not, work from the
   description and say so. Answer with file references:
   - New entry points and code paths (routes, jobs, CLI args, tool definitions).
   - Existing components touched; new components or external services introduced.
   - Data handled and its sensitivity; new flows across trust boundaries.
   - Controls already in the path (auth middleware, validators, signing), each checked
     against the bypass questions (`methodology.md` section 12).
   - Traces (`discovery.md` section 5) from each new input to the sinks it reaches.
   - New dependencies, audited (`discovery.md` section 2).
   - New rows or columns for the authorization matrix (`methodology.md` section 6) when
     the feature adds a resource, operation, or role.
4. **Abuse cases** for the feature (at least three, one per reaching threat actor), the
   **sequence and state checklist** (`methodology.md` section 8) if the feature is
   multi-step or has one-time semantics, then **STRIDE over the feature's flows and any
   new components**. Run the **reachability check** (section 10) on each candidate before
   assigning severity. Append the rows, traces, and reachability notes to
   `.tmdd/analysis/stride_matrix.md` under a heading with the feature name and date.
5. **Edit YAML in this order**, appending or editing, never rewriting files:
   1. `components.yaml` — new units with narrow `source_paths`.
   2. `actors.yaml` — new roles or external initiators.
   3. `data_flows.yaml` — new per-feature flows (source/destination must exist).
   4. `threats/threat_actors.yaml` — only if a genuinely new adversary appears.
   5. `threats/mitigations.yaml` — reuse mechanisms; add new ones with `references` only
      when the control exists.
   6. `threats/threats.yaml` — feature-specific threats with location, severity by rubric,
      `stride`, `cwe`, `suggested_mitigations`. Reuse an existing threat ID when it is the
      same weakness in the same place; create a new one when the location differs.
   7. `features.yaml` — the feature entry: `goal`, `input_data`, `output_data`, `data_flows`,
      `threat_actors`, `threats` (mapping, object form with `flows` and `status`),
      `last_updated` today, `reviewed_at: "2000-01-01"`, no `reviewed_by`.
6. **Validate:** `tmdd lint` until exit 0; report warnings.
7. **Check review precision:** `tmdd review --files <a file of this feature>` should surface
   this feature and not unrelated ones. Fix hubs if it does not.
8. **Implementation prompt:** `tmdd feature "<Name>"` now writes
   `.tmdd/out/<name>.prompt.txt` with the threat-to-mitigation checklist. If the user is
   about to implement the feature, read it back and carry its required controls into the
   implementation plan; if you implement the code yourself, treat each `[ ]` control as a
   requirement and, once implemented, update the mitigation `references` and set
   `status: implemented` for the corresponding feature threats.
9. Summarize per `SKILL.md` Step 3.
