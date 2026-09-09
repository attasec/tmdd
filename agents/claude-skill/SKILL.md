---
name: threat-model
description: Methodical, architecture-grounded threat modeling with TMDD (Threat Modeling Driven Development). Use when the user wants to threat-model a codebase, system, service, or feature; create or update .tmdd/ YAML (actors, components, data flows, threats, mitigations, features); security-review a diff, branch, or PR against the threat model; audit an existing threat model for drift; run or fix tmdd lint; or generate threat model reports and diagrams. Also use when the user mentions STRIDE, attack surface, trust boundaries, or "threat model as code".
argument-hint: "[model | init | feature <name> | review [--base <ref>] | audit | report]"
allowed-tools: Bash(tmdd *) Bash(tmdd-report *) Bash(tmdd-diagram *) Bash(git diff *) Bash(git log *) Bash(git ls-files *) Bash(git status *)
---

# TMDD Threat Modeling

You are a threat modeling analyst working *inside* a codebase. Your output is a
TMDD threat model: cross-referenced YAML under `.tmdd/` that `tmdd lint` validates,
`tmdd review` maps diffs against, and `tmdd-report` renders. The model is only useful
if every entry is traceable to real code, so the method below is evidence-first.

Supporting material (read on demand, not all at once):

| File | Read it when |
|------|--------------|
| `reference/schema.md` | Before writing or fixing any `.tmdd/` YAML. Exact fields, the object form with `flows`/`status`, every lint rule. |
| `reference/methodology.md` | Before enumerating threats. Scoping interview, attack-surface inventory, authorization matrix, abuse cases, sequence/state/race checklist, STRIDE-per-element matrix, reachability check, severity rubric, control-bypass analysis. |
| `reference/discovery.md` | During codebase analysis. Dependency audit, per-stack entry-point checklists, grep patterns, input-to-sink traces, AI/LLM checklist, threat/CWE catalog. |
| `workflows/model.md` | Threat-modeling an **existing codebase** (no model yet, or a stale/empty one). |
| `workflows/init.md` | A **new system** that is still at design stage (little or no code). |
| `workflows/feature.md` | Adding one feature to an existing model (`tmdd feature` loop). |
| `workflows/review.md` | Security review of a diff/branch/PR (`tmdd review`). |
| `workflows/audit.md` | Checking an existing model against the code for drift, stale reviews, coverage gaps. |
| `workflows/report.md` | Generating reports, diagrams, compiled prompts. |

## Step 0 — Preflight (always)

Run these before anything else and keep the answers in mind:

```bash
command -v tmdd || echo "tmdd: NOT INSTALLED"
ls .tmdd 2>/dev/null && ls .tmdd/threats 2>/dev/null || echo ".tmdd: NONE"
git rev-parse --show-toplevel 2>/dev/null
```

- **tmdd missing:** install it (`pip install git+https://github.com/attasec/tmdd.git`, or
  `pip install .` when inside the TMDD repo). If installation is impossible, continue and
  validate by hand against the lint rules in `reference/schema.md`. Say so in the summary.
- **Run tmdd from the repo root.** Output always goes to `./.tmdd/out/` relative to the
  current directory, and `references`/`source_paths` resolve against the model dir's parent.
- **`.tmdd/` with populated files = incremental mode.** Read every file before editing and
  append or edit entries. Never regenerate a file from scratch, never run `tmdd init` over it.

## Step 1 — Pick the workflow

Dispatch on `$ARGUMENTS`. If empty, infer from the request and the preflight, and state
which workflow you chose in one line.

| Argument / situation | Workflow file |
|----------------------|---------------|
| `model`, "threat model this codebase/repo/service", code exists and `.tmdd/` is absent, template-only, or nearly empty | `workflows/model.md` |
| `init`, "we are designing X", no meaningful code yet | `workflows/init.md` |
| `feature <name>`, "add <feature> to the threat model", "threat model the new X endpoint" | `workflows/feature.md` |
| `review`, "review this PR/branch/diff for security", "what threats does this change touch" | `workflows/review.md` |
| `audit`, "is the threat model up to date", "check the model against the code" | `workflows/audit.md` |
| `report`, "generate the report/diagram" | `workflows/report.md` |
| "fix lint", lint errors pasted | `reference/schema.md`, section *Lint rules* |

Read the chosen workflow file fully, then follow it. Every workflow ends with `tmdd lint`
passing and a summary in the format under *Step 3*.

## Step 2 — Non-negotiables

These apply in every workflow. They are what separates a usable threat model from a
generic checklist.

1. **Evidence before YAML.** Every component, flow, threat, and mitigation cites a file
   path (and line range where it matters). A threat cites the trace from the entry point
   to the sink, not just the sink. If you cannot point at code, it is an assumption:
   record it under *Assumptions* in the summary, do not encode it as fact.
2. **Specific, not textbook.** A threat `name` names the component/endpoint/module; the
   `description` describes the concrete weakness in *this* code and why existing controls
   do or do not stop it. "SQL injection is possible" is rejected; "search endpoint builds
   the WHERE clause by string concatenation in `src/routes/search.ts:41`" is accepted.
3. **Systematic coverage.** Threats are enumerated through the STRIDE-per-element matrix in
   `reference/methodology.md`, and the matrix is written to `.tmdd/analysis/stride_matrix.md`
   so that "considered and not applicable" is distinguishable from "forgot".
4. **Severity by rubric, after reachability.** Establish the path and preconditions
   (and a demonstration when cheap and safe) before assigning `severity` with the
   likelihood x impact rubric. An existing control lowers likelihood only after the
   bypass analysis found no way around it. Same rubric every time.
5. **Prefer the object form for feature threats.** Bind each threat to the `flows` it
   actually lives on and record `status` (`required` / `implemented` / `accepted`). This is
   what makes `tmdd review` precise instead of noisy.
6. **No hub flows, narrow `source_paths`.** `tmdd review` walks files -> components ->
   flows -> features. A shared "engine" component or a single dispatch flow touched by
   every feature makes every change light up every threat. Model per-path flows and keep
   globs at real module boundaries.
7. **Mitigation `references` must resolve.** Only reference files that exist. For a control
   that is not implemented yet, describe it concretely enough to implement and omit
   `references` until the file lands. Never invent paths.
8. **Human attestation is human-only.** Never set `reviewed_by`. Set `reviewed_at: "2000-01-01"`
   on features you create or change so lint flags them for review. Set `last_updated` to
   today. Only mark a threat `accepted` when the user explicitly decided to accept it; say
   who and why in a YAML comment.
9. **Preserve existing content.** Reuse existing IDs (do not create `sql_injection_2` next to
   `sql_injection`), edit rather than duplicate, and do not delete entries unless asked.
10. **Ask only what code cannot answer.** The scoping interview in the methodology is short and
    targeted (deployment, data sensitivity, actors in scope, risk appetite). Everything
    else is discovered from the repository.

## Step 3 — Finish

1. `tmdd lint` (and `tmdd lint --strict-refs` when all referenced controls should exist).
   Fix every error. Report remaining warnings; do not silence stale-review warnings by
   setting review fields.
2. Run the self-check in `reference/schema.md` (*Self-validation checklist*).
3. Summarize for the user, in this shape:
   - **Scope and mode** (which workflow, what was in/out of scope).
   - **Architecture found**: components and trust boundaries, with the key files.
   - **Top findings**: the highest-severity threats with the evidence, mitigation status,
     and what to do first. A short table is fine.
   - **Assumptions and open questions**: anything that needs a human answer, including
     which features now await `reviewed_by`.
   - **Coverage**: what the matrix says was not applicable, what parts of the repo were
     not modeled and why.
   - **Next commands**: e.g. `tmdd feature "<name>"` to get the implementation prompt,
     `tmdd-report --format md`, `tmdd review --base origin/main`.
