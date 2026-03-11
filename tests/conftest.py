"""Shared fixtures for TMDD tests."""
import textwrap
from argparse import Namespace
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Minimal valid YAML content for every threat-model file
# ---------------------------------------------------------------------------

SYSTEM_YAML = textwrap.dedent("""\
    system:
      name: Test System
      description: A system for testing
      version: "1.0"
""")

ACTORS_YAML = textwrap.dedent("""\
    actors:
      - id: user
        description: Primary user
      - id: admin
        description: Administrator
""")

COMPONENTS_YAML = textwrap.dedent("""\
    components:
      - id: web_app
        description: Web frontend
        type: frontend
      - id: api_server
        description: REST API
        type: api
      - id: db
        description: PostgreSQL database
        type: database
""")

DATA_FLOWS_YAML = textwrap.dedent("""\
    data_flows:
      - id: df_user_to_web
        source: user
        destination: web_app
        data_description: HTTP requests
        protocol: HTTPS
      - id: df_web_to_api
        source: web_app
        destination: api_server
        data_description: API calls
        protocol: HTTPS
      - id: df_api_to_db
        source: api_server
        destination: db
        data_description: SQL queries
        protocol: TCP
""")

FEATURES_YAML = textwrap.dedent("""\
    features:
      - name: User Login
        goal: Authenticate users
        input_data: [credentials]
        output_data: [session_token]
        data_flows: [df_user_to_web, df_web_to_api]
        threat_actors: [external_attacker]
        threats:
          sql_injection: [parameterized_queries]
          brute_force: accepted
        last_updated: "2025-01-01"
""")

CATALOG_YAML = textwrap.dedent("""\
    threats:
      sql_injection:
        name: SQL Injection
        description: Attacker injects SQL
        severity: high
        stride: T
        cwe: CWE-89
        suggested_mitigations: [parameterized_queries]
      brute_force:
        name: Brute Force
        description: Attacker brute-forces credentials
        severity: medium
        stride: S
        cwe: CWE-307
        suggested_mitigations: [account_lockout]
""")

MITIGATIONS_YAML = textwrap.dedent("""\
    mitigations:
      parameterized_queries: Use parameterized queries
      account_lockout: Implement account lockout
""")

MITIGATIONS_RICH_YAML = textwrap.dedent("""\
    mitigations:
      parameterized_queries:
        description: Use parameterized queries
        references:
          - file: "src/db/queries.ts"
            lines: "42-58"
      account_lockout: Implement account lockout
""")

THREAT_ACTORS_YAML = textwrap.dedent("""\
    threat_actors:
      - id: external_attacker
        description: External attacker via internet
      - id: malicious_insider
        description: Malicious insider
""")

VALID_MODEL_FILES = {
    "system.yaml": SYSTEM_YAML,
    "actors.yaml": ACTORS_YAML,
    "components.yaml": COMPONENTS_YAML,
    "data_flows.yaml": DATA_FLOWS_YAML,
    "features.yaml": FEATURES_YAML,
    "threats/threats.yaml": CATALOG_YAML,
    "threats/mitigations.yaml": MITIGATIONS_YAML,
    "threats/threat_actors.yaml": THREAT_ACTORS_YAML,
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def valid_model_dir(tmp_path):
    """Create a tmp directory containing a complete, valid threat model."""
    model_dir = tmp_path / ".tmdd"
    model_dir.mkdir()
    (model_dir / "threats").mkdir()
    for rel_path, content in VALID_MODEL_FILES.items():
        filepath = model_dir / rel_path
        filepath.write_text(content, encoding="utf-8")
    return model_dir


@pytest.fixture
def empty_model_dir(tmp_path):
    """Create an empty tmp directory (no YAML files)."""
    model_dir = tmp_path / ".tmdd"
    model_dir.mkdir()
    return model_dir


def make_args(**kwargs):
    """Helper: build an argparse.Namespace from keyword arguments."""
    return Namespace(**kwargs)
