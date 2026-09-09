# TMDD Documentation

Detailed reference for all commands, file formats, and configuration options.
For a quick overview, see the [README](README.md).

---

## Commands

| Command | Description |
|---------|-------------|
| `tmdd init` | Create a new TMDD project from template |
| `tmdd lint` | Validate threat model files |
| `tmdd feature` | Threat-model-first feature workflow |
| `tmdd review` | Map a code diff to the threats it may affect |
| `tmdd compile` | Generate consolidated YAML and prompts |
| `tmdd-diagram` | Generate interactive architecture diagram (HTML) |
| `tmdd-report` | Generate threat model report (HTML or Markdown) |

All commands default to `.tmdd/` in the current directory.

### init

```bash
# List available templates
tmdd init --list

# Create minimal project (in .tmdd/)
tmdd init

# Create with web-app template
tmdd init --template web-app -n "E-Commerce" -d "Online store"

# Create API project
tmdd init --template api -n "User API"

# Custom directory
tmdd init ./my-project --template web-app -n "E-Commerce" -d "Online store"
```

### lint

```bash
# Validate threat model (uses .tmdd/ by default)
tmdd lint

# Specify a directory
tmdd lint ./my-project
```

Exit codes: `0` = OK, `1` = validation errors, `2` = fatal (missing files)

**Reference resolution.** Mitigations using the rich format may point at implementation
files via `references`. `lint` checks that each referenced file exists on disk, catching
drift and hallucinated paths — the "closing the loop" check between the model and the code.

- File paths resolve against `--repo-root` (default: the parent of the model dir, i.e. the
  repo root when `.tmdd/` sits at the top level).
- A missing referenced file is a **warning** by default (a control may point at a *planned*
  file that doesn't exist yet).
- `--strict-refs` promotes missing references to **errors** — useful for CI gating once
  controls are expected to be implemented.

```bash
tmdd lint                      # missing references -> warnings
tmdd lint --strict-refs        # missing references -> errors (exit 1)
tmdd lint --repo-root ..       # resolve reference paths against a different root
```

### review

Maps a code diff to the threats it may affect, closing the loop from changed files back to
the threat model:

```
changed files --(component.source_paths globs)--> components
              --(data_flows source/destination)--> data flows
              --(features.data_flows)------------> features
              --(features.threats)---------------> threats + mitigations
```

The output is a deterministic, review-ready checklist of the threats a change touches, plus
coverage gaps (changed files that match no component's `source_paths`, and components that
have no `source_paths` at all and are therefore invisible to the mapping).

```bash
# Review the working-tree diff vs HEAD (default)
tmdd review

# Review a branch against its base (PR-style, uses <base>...HEAD)
tmdd review --base origin/main

# Review only staged changes
tmdd review --staged

# Bypass git — pass an explicit file list (handy in CI or from another tool)
tmdd review --files src/routes/search.ts src/db/queries.ts

# Machine-readable output for agents / PR bots
tmdd review --base origin/main --format json
tmdd review --base origin/main --format md
```

Options: `--base <ref>`, `--staged`, `--files <paths...>`, `--repo-root <dir>`,
`--format {text,json,md}`. Changed-file paths (from git or `--files`) are matched against
component `source_paths` relative to `--repo-root` (default: the parent of the model dir).

This requires components to declare `source_paths` globs. See the threat model structure
below.

### feature

Behaves differently depending on whether the feature already exists in `features.yaml`:

- **New feature** (not in `features.yaml`): Generates a threat modeling prompt at `.tmdd/out/<name>.threatmodel.txt` with existing system context and STRIDE guidance.
- **Existing feature** (already in `features.yaml`): Generates a secure implementation prompt at `.tmdd/out/<name>.prompt.txt` with the feature's threat-to-mitigation mappings as a security requirements checklist.

```bash
# New feature -> threat modeling prompt
tmdd feature "Password Reset" -d "Reset password via email"

# After threat modeling + lint, same command -> implementation prompt
tmdd feature "Password Reset"
```

Use `-p ./my-project` to target a different directory.

### compile

Merges all `.tmdd/` files into consolidated output:

- **Consolidated YAML** (`.tmdd/out/<system>.tm.yaml`): Single-file export of the entire threat model.
- **AI implementation prompt** (`.tmdd/out/<system>.prompt.txt`): Full-system security requirements prompt.

```bash
# Entire system
tmdd compile

# Scoped to a single feature
tmdd compile --feature "Password Reset"

# Custom directory
tmdd compile ./my-project
```

### tmdd-diagram

Generates interactive architecture diagrams using [Cytoscape.js](https://js.cytoscape.org/).

```bash
tmdd-diagram                      # uses .tmdd/ by default
tmdd-diagram -p ./my-project      # specify path
tmdd-diagram -f "User Login"      # highlight a specific feature
```

Output: `.tmdd/out/diagram.html`

### tmdd-report

Generates a threat model report in HTML or Markdown format.

```bash
tmdd-report                           # HTML (default)
tmdd-report --format md               # Markdown
tmdd-report -p ./my-project           # specify path
tmdd-report -o ./reports -n report    # custom output dir and name
```

Output: `.tmdd/out/tm.html` or `.tmdd/out/tm.md`

HTML reports and diagrams are self-contained files that load JavaScript from a CDN — an internet connection is needed when viewing them.

---

## Threat Model Structure

### Core Files

| File | Purpose |
|------|---------|
| `system.yaml` | System name, description, version |
| `actors.yaml` | Who interacts with the system |
| `components.yaml` | Architecture building blocks |
| `features.yaml` | Capabilities with threat mappings |
| `data_flows.yaml` | How data moves between components |

### Threat Files

| File | Purpose |
|------|---------|
| `threats/threats.yaml` | Threat definitions (sql_injection, csrf_attack...) |
| `threats/mitigations.yaml` | Security controls (parameterized_queries, input_validation...) |
| `threats/threat_actors.yaml` | Adversary profiles (external_attacker, insider_threat...) |

### ID Conventions

All IDs use the same pattern: `^[a-z][a-z0-9_]*$` — lowercase descriptive names.

| Type | Example |
|------|---------|
| Entity | `payment_api` |
| Threat | `sql_injection` |
| Mitigation | `parameterized_queries` |
| Threat Actor | `external_attacker` |
| Data Flow | `df_user_to_api` |

---

## Templates

| Template | Description |
|----------|-------------|
| `minimal` | Bare skeleton — one actor, one component, empty catalogs |
| `web-app` | Frontend + API + DB with 7 common web threats pre-loaded |
| `api` | API-focused with OWASP API Top 10 threats |

---

## Project Structure

```
tmdd/
├── src/                     # CLI package (tmdd command)
│   ├── commands/            # Subcommands (init, lint, feature, review, compile)
│   ├── generators/          # AI prompt generators (threat + implementation)
│   └── templates/           # Project templates (minimal, web-app, api)
├── agents/                  # Pre-built AI agent instructions
│   ├── claude-skill/        # Claude Code skill (/threat-model): workflows + methodology + schema
│   ├── cursor-skill/        # Cursor Skill for architecture-aware threat modeling
│   └── AGENTS.md            # Claude Code instructions (copy to .tmdd/)
├── diagram.py               # tmdd-diagram command
├── report.py                # tmdd-report command
├── report_md.py             # Markdown report generator
├── tmdd.schema.json         # JSON Schema for IDE autocomplete & validation
├── tests/                   # Test suite
└── .tmdd/                   # Demo threat model (TMDD modeling itself)
```

---

## Editor Integration

The `tmdd.schema.json` file provides JSON Schema definitions for IDE autocomplete and inline validation. This is separate from `tmdd lint` — the schema helps while editing, while `lint` performs full cross-reference validation.

### VS Code / Cursor

Add this comment to the top of your YAML files:

```yaml
# yaml-language-server: $schema=../path/to/tmdd.schema.json
```

Or configure globally in `.vscode/settings.json`:

```json
{
  "yaml.schemas": {
    "./tmdd.schema.json": [
      "**/system.yaml",
      "**/actors.yaml",
      "**/components.yaml",
      "**/features.yaml",
      "**/data_flows.yaml"
    ]
  }
}
```

This gives you field name autocomplete, type validation as you type, and hover documentation.

Always run `tmdd lint` for full cross-reference validation.

---

## Contributing

PRs and issues welcome! See the [issues page](https://github.com/attasec/tmdd/issues).

```bash
pip install -e ".[dev]"   # development install
pytest                     # run tests
black .                    # format code
```

---

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
