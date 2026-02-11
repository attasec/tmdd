# TMDD Agent Instructions

Pre-built AI agent instructions for Cursor and Claude Code that teach the model
how to create and edit valid TMDD threat models grounded in actual codebase architecture.

## Contents

```
agents/
  cursor-skill/SKILL.md              # Cursor Skill (architecture-aware workflow + schema reference)
  AGENTS.md                          # Claude Code instructions
  README.md                         # This file
```

## Installation

### Cursor Skill (global, all projects)

Copy the skill directory to your personal Cursor skills folder:

```bash
# macOS / Linux
cp -r agents/cursor-skill ~/.cursor/skills/tmdd-threat-modeling

# Windows (PowerShell)
Copy-Item -Recurse agents/cursor-skill "$env:USERPROFILE\.cursor\skills\tmdd-threat-modeling"
```

The skill activates when you ask the agent to threat-model a system or feature,
and also auto-activates when editing `.tmdd/**/*.yaml` files.

### Claude Code (per project)

Copy `AGENTS.md` into your `.tmdd/` directory:

```bash
cp agents/AGENTS.md .tmdd/AGENTS.md
```

Claude Code automatically discovers `AGENTS.md` files and uses them as context
when working in that directory.

## How They Work

| Component | Scope | Triggers On | Purpose |
|-----------|-------|-------------|---------|
| **Cursor Skill** | Global | User asks to threat-model, or editing `.tmdd/*.yaml` | Architecture-first workflow, CLI commands, YAML schemas, cross-ref rules |
| **AGENTS.md** | Project | Claude Code in `.tmdd/` dir | Same content, for Claude Code users |

## What These Solve

Without agent instructions, AI models commonly:
- Produce generic textbook threats instead of codebase-specific ones
- Skip architecture analysis and jump straight to YAML editing
- Use flat lists for threats instead of the required dict mapping
- Invent IDs like `Payment-API` instead of `payment_api`
- Reference data flows or components that don't exist
- Skip STRIDE analysis and produce shallow threat lists
- Output YAML in chat instead of editing files directly
- Create mitigations without referencing actual implementation files

With these instructions, the model first analyzes the codebase architecture,
then produces threat models with specific, actionable threats tied to real
components, endpoints, and data flows.
