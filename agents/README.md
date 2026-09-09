# TMDD Agent Instructions

Pre-built AI agent instructions for Claude Code and Cursor that teach the model how to
create and maintain valid TMDD threat models grounded in the actual codebase.

## Contents

```
agents/
  claude-skill/                      # Claude Code skill: /threat-model
    SKILL.md                         #   router + non-negotiables + finish criteria
    reference/schema.md              #   exact YAML formats, flows/status object form, every lint rule
    reference/methodology.md         #   scoping, attack surface, authz matrix, abuse cases, state/race checklist, STRIDE matrix, reachability, severity, bypass analysis
    reference/discovery.md           #   dependency audit, per-stack discovery checklists, grep patterns, input-to-sink traces, AI/LLM checklist
    workflows/model.md               #   threat-model an existing codebase
    workflows/init.md                #   design-time model for a system with no code yet
    workflows/feature.md             #   add a feature (tmdd feature loop)
    workflows/review.md              #   diff/branch/PR review (tmdd review)
    workflows/audit.md               #   drift check of model vs code
    workflows/report.md              #   reports, diagrams, compiled prompts
  cursor-skill/SKILL.md              # Cursor Skill (architecture-aware workflow + schema reference)
  AGENTS.md                          # Lightweight Claude Code instructions (copy into .tmdd/)
  README.md                          # This file
```

## Installation

### Claude Code skill

```bash
# personal (all projects)
cp -r agents/claude-skill ~/.claude/skills/threat-model

# or project-scoped (commit .claude/skills/ with the repo)
cp -r agents/claude-skill .claude/skills/threat-model
```

Invoke explicitly or let it trigger on natural requests:

```
/threat-model model                       # existing codebase, no model yet
/threat-model init                        # new system at design stage
/threat-model feature "Password Reset"    # add one feature
/threat-model review --base origin/main   # PR / branch security review
/threat-model audit                       # model vs code drift
/threat-model report                      # reports, diagram, compiled prompts
```

The skill expects the `tmdd` CLI on `PATH` and offers to install it if missing. It loads
its reference files on demand, so the always-loaded part stays small.

### Cursor Skill (global, all projects)

```bash
# macOS / Linux
cp -r agents/cursor-skill ~/.cursor/skills/tmdd-threat-modeling

# Windows (PowerShell)
Copy-Item -Recurse agents/cursor-skill "$env:USERPROFILE\.cursor\skills\tmdd-threat-modeling"
```

Activates when you ask the agent to threat-model a system or feature, and when editing
`.tmdd/**/*.yaml` files.

### Claude Code, lightweight (per project)

```bash
cp agents/AGENTS.md .tmdd/AGENTS.md
```

Claude Code discovers `AGENTS.md` and uses it as context when working in that directory.
Use this when you want the schema rules without the full workflow.

## How They Work

| Component | Scope | Triggers On | Purpose |
|-----------|-------|-------------|---------|
| **Claude Code skill** | Personal or project | `/threat-model ...`, or requests to threat-model, review a PR, audit the model | Scoping interview, attack-surface inventory, dependency audit, input-to-sink traces, authorization matrix, sequence/state checklist, STRIDE-per-element matrix, reachability check, control-bypass analysis, severity rubric, YAML with `flows`/`status`, lint-clean output |
| **Cursor Skill** | Global | User asks to threat-model, or editing `.tmdd/*.yaml` | Architecture-first workflow, CLI commands, YAML schemas, cross-ref rules |
| **AGENTS.md** | Project | Claude Code in `.tmdd/` dir | Schema and workflow rules as passive context |

## What These Solve

Without agent instructions, AI models commonly:
- Produce generic textbook threats instead of codebase-specific ones
- Skip architecture analysis and jump straight to YAML editing
- Enumerate threats unsystematically, so gaps are indistinguishable from "not applicable"
- Assign severity by gut feel
- Build hub components and dispatcher flows, so `tmdd review` lights up every threat on every change
- Use flat lists for threats instead of the required dict mapping
- Invent IDs like `Payment-API` instead of `payment_api`
- Reference data flows, components, or files that don't exist
- Set human attestation fields (`reviewed_by`) themselves
- Output YAML in chat instead of editing files directly

With these instructions, the model first analyzes the codebase, records what it considered
in a coverage matrix, and produces threats tied to real components, endpoints, files, and
data flows, with mitigations whose status and code references `tmdd lint` and `tmdd review`
can check.
