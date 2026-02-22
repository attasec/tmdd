# TMDD - Threat Modeling Driven Development

> Place this file at `.tmdd/AGENTS.md` in your project for Claude Code auto-discovery.

## Overview

This directory contains a TMDD threat model. Files are cross-referenced YAML
validated by `tmdd lint`. Follow the rules below when editing.

**Core Principle:** Every threat model must be grounded in the actual codebase.
Before editing YAML, analyze the code to discover real components, data flows,
technologies, and attack surface. Never produce generic threats.

## Commands

```bash
tmdd init .tmdd --template web-app -n "Name" -d "Description"  # scaffold
tmdd lint .tmdd                                                  # validate
tmdd feature "Name" -d "Description"                            # new feature
tmdd feature "Name"                                             # get impl prompt
tmdd compile .tmdd                                              # generate output
```

## Architecture-First Workflow

### Before writing any YAML:

1. **Scan the codebase** — identify languages, frameworks, entry points, directory layout
2. **Map real components** — route handlers → `api`, DB models → `database`, frontend → `frontend`, etc.
3. **Trace data flows** — follow how data moves through the code (HTTP, DB queries, external calls)
4. **Identify security patterns** — auth, validation, error handling, logging, rate limiting, CORS

### Then populate YAML files in order:

1. `components.yaml` — one component per real architectural unit, with actual technology
2. `actors.yaml` — real users and external systems
3. `data_flows.yaml` — traced from actual code paths, with specific data types
4. `threats/catalog.yaml` — threats referencing specific components, endpoints, or files
5. `threats/mitigations.yaml` — controls with code references to implementation files
6. `threats/threat_actors.yaml` — adversary profiles
7. `features.yaml` — features with threat-to-mitigation dict mapping

## File Structure

| File | Purpose |
|------|---------|
| `system.yaml` | System name, description, version |
| `actors.yaml` | Who interacts with the system (`id` + `description`) |
| `components.yaml` | Architecture blocks (`id`, `description`, `type`, `technology`, `trust_boundary`, optional `source_paths`) |
| `data_flows.yaml` | Data movement (`id`, `source`, `destination`, `data_description`, `protocol`, `authentication`) |
| `features.yaml` | Features with threat-to-mitigation mappings (`last_updated`, `reviewed_at`, `reviewed_by`) |
| `threats/catalog.yaml` | Threat definitions (`T001`: name, description, severity, stride, cwe, suggested_mitigations) |
| `threats/mitigations.yaml` | Security controls (`M001`: description string or {description, references}) |
| `threats/threat_actors.yaml` | Adversary profiles (`TA001`: description string) |

## ID Conventions

- Entities: `^[a-z][a-z0-9_]*$` (e.g. `api_backend`)
- Threats: `^T\d+$` (e.g. `T001`)
- Mitigations: `^M\d+$` (e.g. `M001`)
- Threat Actors: `^TA\d+$` (e.g. `TA001`)

## Critical: Feature Threat Format

The `threats` field in `features.yaml` **must** be a dict. Each value is one of:
- `default` — inherit `suggested_mitigations` from `threats/catalog.yaml`
- `[M001, M002]` — explicit mitigation list
- `accepted` — risk accepted

```yaml
# CORRECT
threats:
  T001: default
  T002: [M001, M002]
  T003: accepted
last_updated: "2026-02-22"   # agent sets to today's date
reviewed_at: "2000-01-01"    # sentinel — human updates after review
# reviewed_by: — only set by human reviewer, never by AI agent

# WRONG
threats: [T001, T002]
```

## Human Review Fields

Features support `reviewed_by`, `reviewed_at`, and `last_updated` fields:
- `reviewed_by` — name/username of the human analyst who reviewed the threat mappings.
  **AI agents MUST NOT set this.** Only a human adds it after manual review.
- `reviewed_at` — date of last review (YYYY-MM-DD). AI agents MUST set this to `"2000-01-01"`
  as a sentinel so that `last_updated > reviewed_at` always triggers a stale-review lint warning.
  The human updates this to the real date when they review.
- `last_updated` — date the feature was last created or modified (YYYY-MM-DD).
  AI agents SHOULD set this to today's date.
- Lint warns if a feature has `accepted` threats but no `reviewed_by`
- Lint warns if `last_updated > reviewed_at` (stale review, needs re-review)

## Threat Quality Rules

- `name` must reference the specific component, endpoint, or module affected
- `description` must describe the concrete risk in this codebase, referencing file paths where possible
- `severity` must reflect actual exploitability and impact in this system
- Mitigations should use the rich format with `references` to actual implementation files when known

## Cross-References (enforced by lint)

- `data_flows` source/destination must exist in actors or components
- `features` data_flows/threat_actors must exist in their respective files
- `features` threat keys must exist in `threats/catalog.yaml`
- `features` mitigation values must exist in `threats/mitigations.yaml`

## STRIDE Checklist

For each component/flow: **S**poofing, **T**ampering, **R**epudiation,
**I**nformation Disclosure, **D**enial of Service, **E**levation of Privilege.

## Workflow for Adding a Feature

**NEVER overwrite existing YAML content.** Read each file before editing.
Append new entries and continue existing ID sequences (T006 after T005, etc.).

1. **Analyze the feature's code impact** — new endpoints, DB tables, external calls, sensitive data
2. Add components/actors/data_flows if the feature introduces new ones
3. Add threats to `threats/catalog.yaml` specific to the feature's code 
4. Add mitigations to `threats/mitigations.yaml` with code references
5. Add feature to `features.yaml` with `threats:` dict mapping
6. Run `tmdd lint .tmdd` and fix all errors
