# Workflow: New system at design stage

Use when the user is designing something that has little or no code yet ("we are going to
build X", an RFC, an architecture doc). The model is design-time: components and flows come
from the design, controls are all `required`, and `source_paths`/`references` are omitted
until code exists. Read `reference/methodology.md` first.

## Phase 1 — Elicit the design

Gather, from documents the user points at and a fuller interview than usual:

- Purpose and users (actors), and the adversaries they worry about.
- Planned components and where each runs (trust boundaries), technologies if decided.
- Data: what is collected, stored, sent to third parties; classification.
- Every planned entry point (APIs, jobs, webhooks, admin tools, CLIs).
- Non-functional constraints: compliance, multi-tenancy, availability targets.
- Intended repo layout if known (so `source_paths` can be pre-declared as planned globs;
  mark them in a comment as planned).

Ask in one message; proceed on stated assumptions if unanswered.

## Phase 2 — Analyze

Same as `workflows/model.md` Phase 3: threat actors, authorization matrix from the
intended policy (enforcement column left as `planned`), abuse cases per feature, the
sequence and state checklist for every multi-step workflow in the design, full
STRIDE-per-element matrix, severity by rubric (likelihood judged on the design's stated
controls; reachability is by design path, nothing can be demonstrated yet), mitigation
decisions (all `required` unless the design already commits to a control that will exist
at launch; still `required` until code lands). Skip traces and the dependency audit
until code exists; list planned dependencies instead.

Write `.tmdd/analysis/stride_matrix.md` with a clear "design-time model" note and the date.

## Phase 3 — Write the model

`tmdd init .tmdd --template minimal -n "<System>" -d "<description>"`, then populate in the
order from `workflows/model.md` Phase 4 and the formats in `reference/schema.md`.
Differences from a code-grounded model:

- Threat descriptions reference the design element ("the planned /export endpoint")
  rather than files, and say what would make the threat real.
- Mitigations are simple-form strings (no `references`), written as acceptance criteria
  the implementation must meet ("all `/admin/*` routes go through `require_role('admin')`
  middleware registered before any handler").
- Feature threats use the object form with `flows` and `status: required`.
- `system.yaml` `version` starts at `0.1` and the description says it is a design-time model.

## Phase 4 — Hand-off

1. `tmdd lint` -> exit 0.
2. `tmdd compile` produces `.tmdd/out/<system>.prompt.txt`: the secure-implementation
   prompt for whoever writes the code. Point the user at it and at
   `tmdd feature "<Feature>"` for per-feature prompts.
3. Tell the user to switch to `workflows/audit.md` once code exists, to attach
   `source_paths` and `references` and to flip statuses to `implemented`.
4. Summarize per `SKILL.md` Step 3.
