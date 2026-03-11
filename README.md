# TMDD - Threat Modeling Driven Development

_Threat model as code integrated into your development workflow._

`tmdd` is a lightweight, YAML-based threat modeling framework designed for modern development workflows. It lets you define threat models alongside your codebase.

If you know basics of threat modelling, `tmdd` helps you to maintain threat model directly in your repo. If you use AI coding assistants, `tmdd` generates security-aware prompts so your AI writes safer code from the start. 

There's also Cursor skill provided, so your Cursor can build threat model in tmdd-compliant format by itself, and then you can generate your shiny threat modeling report using `tmdd-report`. 

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python Version](https://img.shields.io/badge/python-%3E%3D3.8-blue)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-0.5.1-green.svg)](https://github.com/attasec/tmdd)
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

### > Verify installation

```bash
tmdd --help
tmdd-report --help
```


### > Create your first threat model

```bash
tmdd init --template web-app -n "My App" -d "App description"
```

### > Threat-model a new feature (AI workflow)

```bash
tmdd feature "User Login" -d "Email/password authentication"
# Give the generated prompt to your AI assistant
tmdd lint
tmdd feature "User Login"
# Give the implementation prompt to your coding AI
```
---

## AI Agent Setup

TMDD ships with agent instructions that teach AI coding assistants how to build
architecture-grounded threat models. Once installed, the AI analyzes your actual
codebase before writing any YAML; producing specific, actionable threats.

```
  ┌──────────────────────────────────────────────────────────────────┐
  │                    What the agent does for you                   │
  │                                                                  │
  │   1. Scans your codebase (frameworks, routes, DB, auth, etc.)   │
  │   2. Maps real code to TMDD components and data flows           │
  │   3. Runs STRIDE analysis against actual architecture           │
  │   4. Writes cross-referenced .tmdd/ YAML files                  │
  │   5. Validates with tmdd lint                                    │
  │                                                                  │
  │   You get: a threat model tied to your code, not a template.    │
  └──────────────────────────────────────────────────────────────────┘
```

### Option A: Cursor

**Step 1** — Copy the skill to your Cursor skills folder:

```bash
# macOS / Linux
cp -r agents/cursor-skill ~/.cursor/skills/tmdd-threat-modeling

# Windows (PowerShell)
Copy-Item -Recurse agents\cursor-skill "$env:USERPROFILE\.cursor\skills\tmdd-threat-modeling"
```

**Step 2** — Install the tmdd CLI (if you haven't already):

```bash
pip install .
```

**Step 3** — Open any project in Cursor and ask the agent:

```
/threat-model 
```
(or whatever you named your skill)
You can also provide additional context for the threat modeling after this command.

The skill activates automatically. It also auto-triggers when you edit any
`.tmdd/**/*.yaml` file. No further configuration needed.

```
  YOUR PROJECT                       CURSOR
  ┌──────────────┐    "/threat-model  ┌──────────────────────┐
  │  src/        │     this codebase" │      Skill activates │
  │  routes/     │  ────────────────> │  ┌────────────────┐  │
  │  models/     │                    │  │ 1. Scan code   │  │
  │  ...         │                    │  │ 2. Map arch    │  │
  │              │  <──────────────── │  │ 3. STRIDE      │  │
  │  .tmdd/      │    writes YAML     │  │ 4. Write YAML  │  │
  │    components│    runs tmdd lint  │  | 5. Lint        │  │
  │    threats/  │                    │  └────────────────┘  │
  └──────────────┘                    └──────────────────────┘
```

**Step 4** — Generate outputs:

```bash
tmdd lint                  # validate the model
tmdd-report                # HTML threat model report
```

### Option B: Claude Code

**Step 1** — Initialize a threat model in your project:

```bash
cd your-project
tmdd init --template web-app -n "My App" -d "Description"
```

**Step 2** — Copy the agent instructions into your `.tmdd/` directory:

```bash
cp path/to/tmdd/agents/AGENTS.md .tmdd/AGENTS.md
```

Claude Code auto-discovers `AGENTS.md` files and uses them as context when
working in that directory.

**Step 3** — Ask Claude Code to threat-model:

```
"Analyze this codebase and update the threat model in .tmdd/"
```

**Step 4** — Validate and generate outputs:

```bash
tmdd lint
tmdd-diagram
tmdd-report
```

### What the agent instructions solve

Without these instructions, AI models commonly produce unusable threat models:

| Problem | With TMDD agent instructions |
|---------|------------------------------|
| Generic threats ("SQL injection is possible") | Specific threats ("SQL injection via raw query in `src/routes/search.ts`") |
| No architecture analysis | Scans codebase first, maps real components |
| Flat threat lists | Dict mapping with threat-to-mitigation links |
| Invented IDs like `Payment-API` | Valid IDs: `payment_api`, `sql_injection`, `parameterized_queries` |
| Dangling references | All cross-references validated by `tmdd lint` |
| YAML dumped in chat | Files edited directly in the project |
| Mitigations without code refs | Rich format with file paths and line numbers |

---

## How It Works — Secure Vibe Coding with TMDD

TMDD puts threat modeling **alongside** implementation, so your AI writes secure
code from the start — not as an afterthought. Here's the full loop:

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │                                                                     │
  │   1. tmdd init          Initialize your threat model                │
  │          │                                                          │
  │          v                                                          │
  │   2. tmdd feature       "Password Reset" -d "Reset via email"       │
  │          │               generates threat modeling prompt           │
  │          v                                                          │
  │   3. AI threat-models   Give prompt to Cursor / Claude Code         │
  │          │               AI analyzes code, writes .tmdd/ YAML       │
  │          v                                                          │
  │   4. tmdd lint           Validate cross-references                  │
  │          │                                                          │
  │          v                                                          │
  │   5. tmdd feature       "Password Reset"  (no -d flag)              │
  │          │               feature exists -> implementation prompt    │
  │          v                                                          │
  │   6. AI implements      Vibe code — but securely.                   │
  │                         AI follows threat model as guardrails.      │
  │                                                                     │
  │          . . . repeat for each feature . . .                        │
  │                                                                     │
  └─────────────────────────────────────────────────────────────────────┘
```

### Step by step

**1. Initialize** — Create the threat model structure in your project (if it's not existing already):

```bash
tmdd init --template web-app -n "My App" -d "App description"
```

**2. Declare a feature** — Tell TMDD what you want to build. Since the feature
doesn't exist in `features.yaml` yet, this generates a **threat modeling prompt**:

```bash
tmdd feature "Password Reset" -d "Reset password via email link"
# -> .tmdd/out/password_reset.threatmodel.txt
```

**3. Threat-model it** — Give the prompt to your AI agent (Cursor skill does
this automatically) or edit the YAML files manually. The AI will:
- Analyze your codebase architecture
- Add components, data flows, threats, and mitigations to `.tmdd/`
- Map threats to the feature with STRIDE analysis

**4. Validate** — Check that all cross-references are intact:

```bash
tmdd lint
```

**5. Get the implementation prompt** — Now the feature exists in `features.yaml`,
so running the same command again generates a **secure coding prompt** with the
feature's threat-to-mitigation mappings as a requirements checklist:

```bash
tmdd feature "Password Reset"
# -> .tmdd/out/password_reset.prompt.txt
```

**6. Vibe code securely** — Give the implementation prompt to your coding AI.
It now knows potential threats that apply to this feature and which
mitigations to implement. Your code gets written with security built in, not
bolted on.

Repeat steps 2-6 for every feature. The threat model grows alongside your
codebase.

The AI steps are optional — you can edit YAML manually and use `tmdd` purely as
a structured threat modeling tool.

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
| `threats/threats.yaml` | Threat definitions (sql_injection, csrf_attack...) |
| `threats/mitigations.yaml` | Security controls (parameterized_queries, input_validation...) |
| `threats/threat_actors.yaml` | Adversary profiles (external_attacker, insider_threat...) |

### ID Conventions

All IDs use the same pattern: `^[a-z][a-z0-9_]*$` — lowercase descriptive names.

| Type | Pattern | Example |
|------|---------|---------|
| Entity | `^[a-z][a-z0-9_]*$` | `payment_api` |
| Threat | `^[a-z][a-z0-9_]*$` | `sql_injection` |
| Mitigation | `^[a-z][a-z0-9_]*$` | `parameterized_queries` |
| Threat Actor | `^[a-z][a-z0-9_]*$` | `external_attacker` |
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

**TMDD v0.5.1** — threat model as code.
