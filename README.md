# TMDD - Threat Modeling Driven Development

_Threat model as code integrated into your development workflow._

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python Version](https://img.shields.io/badge/python-%3E%3D3.8-blue)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-0.5.1-green.svg)](https://github.com/attasec/tmdd)
[![GitHub issues](https://img.shields.io/github/issues/attasec/tmdd)](https://github.com/attasec/tmdd/issues)
[![GitHub stars](https://img.shields.io/github/stars/attasec/tmdd)](https://github.com/attasec/tmdd/stargazers)

> **[View TMDD's own threat model report](.tmdd/out/tm.md)** — TMDD threat-models itself. This is a live example of what the tool produces.

---

## What is TMDD?

`tmdd` is a lightweight, YAML-based threat modeling framework that lives in your repo. You define actors, components, data flows, threats, and mitigations as structured YAML — then use TMDD to validate cross-references, generate AI prompts, and produce reports.

If you use AI coding assistants (Cursor, Claude Code, etc.), TMDD generates **security-aware prompts** so your AI writes safer code from the start. The workflow is simple: threat-model a feature first, then let the AI implement it with the threat model as guardrails.

---

## Quick Start

### Install

```bash
git clone https://github.com/attasec/tmdd.git
cd tmdd
pip install .
```

### Create a threat model

```bash
tmdd init --template web-app -n "My App" -d "App description"
```

### The feature workflow

```bash
# 1. Declare a new feature — generates a threat modeling prompt
tmdd feature "Password Reset" -d "Reset password via email link"

# 2. Give the prompt to your AI assistant (or edit YAML manually)

# 3. Validate
tmdd lint

# 4. Same command again — feature now exists, so it generates
#    a secure implementation prompt with threat-to-mitigation mappings
tmdd feature "Password Reset"

# 5. Give the implementation prompt to your coding AI
```

Repeat for every feature. The threat model grows alongside your codebase.

For full command reference and options, see **[DOCS.md](DOCS.md)**.

---

## Using TMDD with AI

TMDD ships with agent instructions that teach AI coding assistants to build architecture-grounded threat models. The AI analyzes your actual codebase — frameworks, routes, DB, auth — before writing any YAML, producing specific, actionable threats tied to real code rather than generic checklists.

### Cursor

**1.** Copy the skill to your Cursor skills folder:

```bash
# macOS / Linux
cp -r agents/cursor-skill ~/.cursor/skills/tmdd-threat-modeling

# Windows (PowerShell)
Copy-Item -Recurse agents\cursor-skill "$env:USERPROFILE\.cursor\skills\tmdd-threat-modeling"
```

**2.** Open any project in Cursor and ask the agent:

```
/threat-model this codebase
```

The skill activates automatically. It also auto-triggers when you edit any `.tmdd/**/*.yaml` file.

### Claude Code

**1.** Install the skill (once per machine, or per project):

```bash
# personal skill, available in every project
cp -r agents/claude-skill ~/.claude/skills/threat-model

# or project-scoped, committed with the repo
cp -r agents/claude-skill .claude/skills/threat-model
```

**2.** Open your project in Claude Code and ask:

```
/threat-model model                      # threat-model the existing codebase
/threat-model feature "Password Reset"   # add one feature to the model
/threat-model review --base origin/main  # security-review a branch against the model
/threat-model audit                      # check the model for drift against the code
```

The skill also triggers on plain requests such as "threat model this repo" or "review this
PR for security". It runs a short scoping interview, inventories the attack surface and
audits dependencies, traces every untrusted input to the sinks it reaches, builds an
authorization matrix, fills a STRIDE-per-element coverage matrix (saved to
`.tmdd/analysis/`), checks reachability and control bypasses before assigning severity
with a fixed rubric, and writes the YAML with `flows`/`status` bindings so `tmdd review`
stays precise. See [agents/README.md](agents/README.md) for details.

The lighter-weight alternative is still supported: copy `agents/AGENTS.md` to
`.tmdd/AGENTS.md` and Claude Code will pick it up as context.

### What the agent instructions solve

Without these instructions, AI models commonly produce unusable threat models:

| Problem | With TMDD agent instructions |
|---------|------------------------------|
| Generic threats ("SQL injection is possible") | Specific threats ("SQL injection via raw query in `src/routes/search.ts`") |
| No architecture analysis | Scans codebase first, maps real components |
| Flat threat lists | Structured mappings with threat-to-mitigation links |
| Dangling references | All cross-references validated by `tmdd lint` |
| Mitigations without code refs | Rich format with file paths and line numbers |

---

## Generate outputs

```bash
tmdd lint                          # validate the model (+ check mitigation references resolve)
tmdd review --base origin/main     # map a diff to the threats it affects
tmdd-report                        # HTML report
tmdd-report --format md            # Markdown report
tmdd-diagram                       # interactive architecture diagram (HTML)
tmdd compile                       # consolidated YAML + AI prompt
```

### Closing the loop with your code

Two features keep the threat model honest against the actual codebase:

- **`tmdd review`** maps a code diff to the threats it touches. Changed files are matched to
  components via their `source_paths` globs, then traced through data flows and features to the
  affected threats and their required mitigations — a deterministic, review-ready checklist.
  Feed `--format json`/`md` to an AI reviewer or PR bot so it focuses on the threats a change
  actually affects. It also flags coverage gaps (changed files matching no component).
- **`tmdd lint`** verifies that mitigation `references` point at files that actually exist,
  catching drift and hallucinated paths. Missing files are warnings by default; `--strict-refs`
  makes them CI-gating errors.

---

## Documentation

See **[DOCS.md](DOCS.md)** for the full command reference, threat model file structure, templates, editor integration, and project layout.

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
