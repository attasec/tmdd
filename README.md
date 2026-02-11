# TMDD - Threat Modeling Driven Development

_Threat model as code integrated into your development workflow._

`tmdd` is a lightweight, YAML-based threat modeling framework designed for modern development workflows. It lets you define threat models alongside your codebase.

If you know basics of threat modelling, `tmdd` helps you to maintain threat model directly in your repo. If you use AI coding assistants, `tmdd` generates security-aware prompts so your AI writes safer code from the start. 

There's also Cursor skill provided, so your Cursor can build threat model in tmdd-compliant format by itself, and then you can generate your shiny threat modeling report using `tmdd-report`. 

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python Version](https://img.shields.io/badge/python-%3E%3D3.8-blue)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-0.5.0-green.svg)](https://github.com/attasec/tmdd)
[![GitHub issues](https://img.shields.io/github/issues/attasec/tmdd)](https://github.com/attasec/tmdd/issues)
[![GitHub stars](https://img.shields.io/github/stars/attasec/tmdd)](https://github.com/attasec/tmdd/stargazers)

---

## Get Started

### > Install

```bash
git clone https://github.com/attasec/tmdd.git
cd tmdd
pip install .
```

### > Create your first threat model

```bash
tmdd init --template web-app -n "My App" -d "App description"
tmdd lint
tmdd-diagram
tmdd-report
```

### > Threat-model a new feature (AI workflow)

```bash
tmdd feature "User Login" -d "Email/password authentication"
# Give the generated prompt to your AI assistant
tmdd lint
tmdd feature "User Login"
# Give the implementation prompt to your coding AI
```

### > Verify installation

```bash
tmdd --help
tmdd-diagram --help
tmdd-report --help
```

---

## How It Works

TMDD follows a **threat-model-first** development cycle. You define your system architecture and threats in YAML, then use those definitions to generate security-aware prompts for AI coding assistants — or as a structured reference for manual implementation.

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  tmdd feature   │────>│  AI edits YAML  │────>│   tmdd lint     │
│  (new feature)  │     │  (threat model) │     │   (validate)    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                        │
┌─────────────────┐     ┌─────────────────┐             │
│  AI implements  │<────│  tmdd feature   │<────────────┘
│  (secure code)  │     │  (get prompt)   │
└─────────────────┘     └─────────────────┘
```

The AI steps are optional — you can edit the YAML files manually and use `tmdd` purely as a structured threat modeling tool.

---

## Commands

| Command | Description |
|---------|-------------|
| `tmdd init` | Create a new TMDD project from template |
| `tmdd lint` | Validate threat model files |
| `tmdd feature` | Threat-model-first feature workflow |
| `tmdd compile` | Generate consolidated YAML and prompts |
| `tmdd-diagram` | Generate interactive architecture diagram (HTML) |
| `tmdd-report` | Generate HTML threat model report |

All commands default to `.tmdd/` in the current directory. You can specify a custom path if needed.

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

# Or specify a custom directory
tmdd init ./my-project --template web-app -n "E-Commerce" -d "Online store"
```

### lint

```bash
# Validate threat model (uses .tmdd/ by default)
tmdd lint

# Or specify a directory
tmdd lint ./my-project
```

Exit codes: `0` = OK, `1` = validation errors, `2` = fatal (missing files)

### feature

The threat-model-first workflow. This command behaves differently depending on whether the feature already exists in `features.yaml`:

- **New feature** (not in `features.yaml`): Generates a threat modeling prompt at `.tmdd/out/<name>.threatmodel.txt`. This prompt contains the existing system context (components, data flows, threats) and STRIDE guidance for the AI to analyze the feature and edit the YAML files.
- **Existing feature** (already in `features.yaml`): Generates a secure implementation prompt at `.tmdd/out/<name>.prompt.txt`. This prompt contains the feature's threat-to-mitigation mappings formatted as a security requirements checklist for a coding AI agent.

```bash
# Step 1: Start with a new feature (generates threat modeling prompt)
tmdd feature "Password Reset" -d "Reset password via email"

# Step 2: Give the prompt to AI (or edit YAML files manually)

# Step 3: Validate changes
tmdd lint

# Step 4: Generate implementation prompt (feature now exists)
tmdd feature "Password Reset"

# Step 5: Give implementation prompt to coding AI (or implement manually)
```

Use `-p ./my-project` to target a different directory.

### compile

Merges all `.tmdd/` files into consolidated output:

- **Consolidated YAML** (`.tmdd/out/<system>.tm.yaml`): Single-file export of the entire threat model — system metadata, all components, actors, data flows, threats, mitigations, and feature mappings. Useful for archiving, diffing, or feeding into other tools.
- **AI implementation prompt** (`.tmdd/out/<system>.prompt.txt`): Full-system security requirements prompt covering architecture, known threats, security controls, and feature requirements. Can be scoped to a single feature with `--feature`.

```bash
# Generate consolidated files for entire system
tmdd compile

# Generate for specific feature only
tmdd compile --feature "Password Reset"

# Or specify a directory
tmdd compile ./my-project
```

---

## Visualization

Diagrams and reports are generated as self-contained HTML files using [Cytoscape.js](https://js.cytoscape.org/) loaded from a CDN. No extra Python dependencies are required, but an **internet connection** is needed to load the JavaScript libraries when viewing the output.

### tmdd-diagram

Generates interactive architecture diagrams from your threat model.

```bash
# From project root (looks for .tmdd/ by default)
tmdd-diagram

# Specify path
tmdd-diagram -p ./my-project

# Highlight a specific feature
tmdd-diagram -f "User Login"
```

Output: `.tmdd/out/diagram.html`

### tmdd-report

Generates a standalone HTML threat model report.

```bash
# From project root (uses .tmdd/ by default)
tmdd-report

# Specify path
tmdd-report -p ./my-project

# Custom output
tmdd-report -o ./reports -n security-report.html
```

Output: `.tmdd/out/tm.html` (self-contained HTML)

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
| `threats/catalog.yaml` | Threat definitions (T001, T002...) |
| `threats/mitigations.yaml` | Security controls (M001, M002...) |
| `threats/threat_actors.yaml` | Adversary profiles (TA001...) |

### ID Conventions

| Type | Pattern | Example |
|------|---------|---------|
| Entity | `^[a-z][a-z0-9_]*$` | `payment_api` |
| Threat | `^T\d+$` | `T001` |
| Mitigation | `^M\d+$` | `M001` |
| Threat Actor | `^TA\d+$` | `TA001` |
| Data Flow | `df_{source}_to_{dest}` | `df_user_to_api` |

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
│   ├── commands/            # Subcommands (init, lint, feature, compile)
│   ├── generators/          # AI prompt generators (threat + implementation)
│   └── templates/           # Project templates (minimal, web-app, api)
├── agents/                  # Pre-built AI agent instructions
│   ├── cursor-skill/        # Cursor Skill for architecture-aware threat modeling
│   └── AGENTS.md            # Claude Code instructions (copy to .tmdd/)
├── diagram.py               # tmdd-diagram command
├── report.py                # tmdd-report command
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
    "./tmdd.schema.json": ["**/system.yaml", "**/actors.yaml", "**/components.yaml", "**/features.yaml", "**/data_flows.yaml"]
  }
}
```

This gives you:
- Field name autocomplete
- Type validation as you type
- Hover documentation for fields

**Note**: Always run `tmdd lint` for full validation.

---

## AI Agent Support

TMDD ships with pre-built instructions for AI coding agents:

- **[Cursor Skill](agents/cursor-skill/SKILL.md)** — Drop-in skill for Cursor's agent mode. Your Cursor can build a threat model in TMDD-compliant format by itself, and then you can generate your shiny threat modeling report using `tmdd-report`.
- **[Claude Code](agents/AGENTS.md)** — Copy to your `.tmdd/` directory for Claude Code integration.

These agents understand the TMDD YAML schema and can create, update, and validate threat models as part of your development workflow.

---

## Contributing

PRs and issues welcome! See the [issues page](https://github.com/attasec/tmdd/issues) for open tasks.

```bash
# Development install
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black .
```

---

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

---

**TMDD v0.5.0** — threat model as code.
