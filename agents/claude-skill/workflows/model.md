# Workflow: Threat-model an existing codebase

Use when code exists and `.tmdd/` is absent, holds only template placeholders, or is far
behind the code. Produces a complete, lint-clean model plus the analysis file.
Read `reference/methodology.md` and `reference/discovery.md` before Phase 2.

## Phase 0 — Mode

- `.tmdd/` absent: creation mode. Scaffold later (Phase 4), not now.
- `.tmdd/` exists with real entries: switch to `workflows/audit.md` unless the user asked
  for a rebuild. If they did, still read every existing file first and preserve IDs the
  user may reference elsewhere (CI, PR comments).
- `.tmdd/` exists with only template content (`My System`, `end_user`, generic threats):
  creation mode, but edit the scaffolded files rather than re-running `tmdd init`.

## Phase 1 — Scope

1. Orientation from `reference/discovery.md` section 1.
2. Draft answers to the scoping interview (`methodology.md` section 1) from the code, then
   ask the user in one message. Proceed on your best guesses if no answer arrives, and log
   them as assumptions.
3. Agree the scope boundary: which directories, which services, what is out.

## Phase 2 — Discover (evidence gathering)

Work through `discovery.md` sections 2 to 5 for the stack in front of you. Keep a
scratch list (in your working notes, not yet YAML) with, for each item, the file:line:

- Components: id, type, technology, trust boundary, files/globs, one-line role.
- Entry points and flows: source -> destination, data, protocol, auth, sensitivity.
- Existing controls: validation, authn/authz, escaping, rate limits, logging, signing,
  with the file:line where each is enforced.
- Suspicious sites: raw queries, subprocesses, HTML sinks, file writes with user input,
  unsafe loaders, secrets, generated artifacts.
- Traces (`discovery.md` section 5): for every entry point, each untrusted input followed
  to the sinks it reaches, with the controls on the path. This is the evidence the
  threats will cite; grep hits alone are not.
- Dependency audit results (`discovery.md` section 2): vulnerable or unpinned packages
  and unpinned CI actions.
- Assets and who can reach what.

Read the actual handler/middleware/data-access files; do not infer from names alone.

## Phase 3 — Analyze

1. Threat actors in scope (methodology section 5).
2. Authorization matrix (section 6) when there is more than one role, tenant, or owner;
   every `MISSING` cell is a threat candidate.
3. Abuse cases per candidate feature (section 7). Features are user-visible capabilities
   or, for tools/libraries, commands and public operations. Aim for 4 to 12 features; group
   endpoints that share flows and threats.
4. Sequence, state, and race checklist (section 8) for every multi-step or one-time
   operation.
5. STRIDE-per-element matrix (section 9) over every component and flow. Fill every cell,
   drawing candidates from the traces, the authorization matrix, and the state checklist.
   Use the per-stack prompts and the AI/LLM checklist from `discovery.md` sections 6 and 7
   where they apply.
6. Reachability check (section 10) for every candidate threat: entry point, path,
   preconditions, and a demonstration where cheap and safe.
7. Assign severity by the rubric (section 11) with the controls that survived the bypass
   analysis (section 12) in mind.
8. For each threat, decide the mitigation state (section 13): verified in code (bypass
   analysis done), missing, or candidate for acceptance (ask, do not decide).

Write `.tmdd/analysis/stride_matrix.md` now, before YAML, with all of its sections
(assumptions, authorization matrix, traces, sequence and state, dependencies,
reachability, matrix, not modeled), so the model is derived from it.

## Phase 4 — Write the model

Creation mode: `tmdd init .tmdd --template minimal -n "<System>" -d "<one-line description>"`
(choose `web-app` or `api` only if you intend to specialize its catalog; then replace every
placeholder threat, actor, and component). Then edit the files in this order, following
`reference/schema.md` exactly:

1. `system.yaml` — name, description, version.
2. `components.yaml` — from Phase 2. Narrow `source_paths`. Comment why any component
   has none.
3. `actors.yaml` — legitimate roles and external initiators.
4. `data_flows.yaml` — one per real path; per-feature paths, no dispatcher hub.
5. `threats/threat_actors.yaml` — from Phase 3.1.
6. `threats/mitigations.yaml` — mechanisms first, reused across threats; rich form with
   `references` only for controls that exist.
7. `threats/threats.yaml` — from the matrix; every entry names its location; `stride`,
   `severity`, `cwe`, `suggested_mitigations` (non-empty if any feature will use `default`).
8. `features.yaml` — one entry per feature; `data_flows` covering its path; `threat_actors`
   derived from flow sources; `threats` as a mapping in the object form with `flows` and
   `status`; `last_updated` today; `reviewed_at: "2000-01-01"`; no `reviewed_by`.

Every threat in `threats.yaml` should be mapped by at least one feature; otherwise it never
appears in reports or reviews. Every feature should have at least one threat or a comment
explaining why none applies.

## Phase 5 — Validate and close

1. `tmdd lint` -> fix errors until exit 0. Then `tmdd lint --strict-refs` to see which
   references are placeholders; remove any that point to non-existent files.
2. Sanity-check the review mapping with a representative file:
   `tmdd review --files <one handler file>` — confirm only the expected features and threats
   surface. If everything surfaces, you built a hub; split components or flows.
3. `tmdd-report --format md` and `tmdd-diagram` so the user can read the result.
4. Summarize per `SKILL.md` Step 3. Include: features awaiting `reviewed_by`, candidate
   acceptances awaiting a decision, directories deliberately not modeled.
