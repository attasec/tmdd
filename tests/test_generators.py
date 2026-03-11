"""Tests for src/generators/agent_prompt.py and src/generators/threat_prompt.py."""
import pytest
from pathlib import Path

from src.generators.agent_prompt import generate_agent_prompt
from src.generators.threat_prompt import generate_threat_model_prompt


# ---------------------------------------------------------------------------
# Fixtures: sample threat model dicts
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_tm():
    """A realistic threat model dict (as returned by load_threat_model)."""
    return {
        "system": {"name": "Test System", "description": "A test system"},
        "actors": [
            {"id": "user", "description": "Primary user"},
        ],
        "components": [
            {"id": "web_app", "name": "Web App", "description": "Frontend"},
            {"id": "api", "name": "API", "description": "Backend API"},
        ],
        "data_flows": [
            {"id": "df1", "source": "user", "destination": "web_app", "data_description": "HTTP requests"},
            {"id": "df2", "source": "web_app", "destination": "api", "data_description": "API calls"},
        ],
        "features": [
            {
                "name": "User Login",
                "goal": "Authenticate users",
                "data_flows": ["df1"],
                "threats": {
                    "sql_injection": ["parameterized_queries"],
                    "brute_force": "accepted",
                },
            },
        ],
        "threats": {
            "sql_injection": {"name": "SQL Injection", "description": "Inject SQL", "severity": "high"},
            "brute_force": {"name": "Brute Force", "description": "Brute force attack", "severity": "medium"},
        },
        "mitigations": {
            "parameterized_queries": "Use parameterized queries",
            "rate_limiting": "Implement rate limiting",
        },
        "threat_actors": [
            {"id": "external_attacker", "description": "External attacker"},
        ],
    }


@pytest.fixture
def empty_tm():
    """An empty/minimal threat model."""
    return {
        "system": {},
        "actors": [],
        "components": [],
        "data_flows": [],
        "features": [],
        "threats": {},
        "mitigations": {},
        "threat_actors": [],
    }


# ===== generate_agent_prompt =====

class TestGenerateAgentPrompt:
    def test_writes_file_and_returns_content(self, sample_tm, tmp_path):
        out = tmp_path / "prompt.txt"
        content = generate_agent_prompt(sample_tm, out)
        assert out.exists()
        assert content == out.read_text(encoding="utf-8")

    def test_contains_system_name(self, sample_tm, tmp_path):
        content = generate_agent_prompt(sample_tm, tmp_path / "p.txt")
        assert "Test System" in content

    def test_contains_components(self, sample_tm, tmp_path):
        content = generate_agent_prompt(sample_tm, tmp_path / "p.txt")
        assert "Web App" in content
        assert "API" in content

    def test_contains_data_flows(self, sample_tm, tmp_path):
        content = generate_agent_prompt(sample_tm, tmp_path / "p.txt")
        assert "user" in content
        assert "web_app" in content

    def test_contains_threats(self, sample_tm, tmp_path):
        content = generate_agent_prompt(sample_tm, tmp_path / "p.txt")
        assert "SQL Injection" in content
        assert "Brute Force" in content

    def test_contains_mitigations(self, sample_tm, tmp_path):
        content = generate_agent_prompt(sample_tm, tmp_path / "p.txt")
        assert "parameterized_queries" in content
        assert "parameterized queries" in content

    def test_contains_secure_coding_rules(self, sample_tm, tmp_path):
        content = generate_agent_prompt(sample_tm, tmp_path / "p.txt")
        assert "SECURE CODING RULES" in content
        assert "Validate ALL inputs" in content

    def test_feature_filter(self, sample_tm, tmp_path):
        content = generate_agent_prompt(sample_tm, tmp_path / "p.txt", feature_name="User Login")
        assert "User Login" in content
        assert "Authenticate users" in content

    def test_feature_filter_case_insensitive(self, sample_tm, tmp_path):
        content = generate_agent_prompt(sample_tm, tmp_path / "p.txt", feature_name="user login")
        assert "User Login" in content

    def test_feature_filter_no_match(self, sample_tm, tmp_path):
        content = generate_agent_prompt(sample_tm, tmp_path / "p.txt", feature_name="Nonexistent")
        assert "FEATURE REQUIREMENTS" not in content

    def test_accepted_threat_shows_risk_accepted(self, sample_tm, tmp_path):
        content = generate_agent_prompt(sample_tm, tmp_path / "p.txt", feature_name="User Login")
        assert "Risk Accepted" in content

    def test_mitigated_threat_shows_checkbox(self, sample_tm, tmp_path):
        content = generate_agent_prompt(sample_tm, tmp_path / "p.txt", feature_name="User Login")
        assert "[ ]" in content

    def test_empty_model_produces_valid_output(self, empty_tm, tmp_path):
        content = generate_agent_prompt(empty_tm, tmp_path / "p.txt")
        assert "SECURE CODING AGENT" in content
        assert "Unknown" in content  # system name fallback

    def test_component_without_id_uses_fallback(self, empty_tm, tmp_path):
        empty_tm["components"] = [{"name": "NoID"}]
        content = generate_agent_prompt(empty_tm, tmp_path / "p.txt")
        assert "unknown" in content  # fallback id

    def test_data_flow_without_source_uses_fallback(self, empty_tm, tmp_path):
        empty_tm["data_flows"] = [{"id": "df1", "destination": "x"}]
        content = generate_agent_prompt(empty_tm, tmp_path / "p.txt")
        assert "?" in content

    def test_non_dict_threat_skipped(self, empty_tm, tmp_path):
        empty_tm["threats"] = {"some_threat": "just a string"}
        content = generate_agent_prompt(empty_tm, tmp_path / "p.txt")
        # Should not crash, and should not contain severity line for T001
        assert "SECURE CODING AGENT" in content


# ===== generate_threat_model_prompt =====

class TestGenerateThreatModelPrompt:
    def test_contains_feature_name(self, sample_tm):
        result = generate_threat_model_prompt(sample_tm, "Payment", "Handle payments", ".tmdd")
        assert "Payment" in result

    def test_contains_feature_description(self, sample_tm):
        result = generate_threat_model_prompt(sample_tm, "Payment", "Handle payments", ".tmdd")
        assert "Handle payments" in result

    def test_contains_model_dir_paths(self, sample_tm):
        result = generate_threat_model_prompt(sample_tm, "X", "Y", ".tmdd")
        assert ".tmdd/features.yaml" in result
        assert ".tmdd/data_flows.yaml" in result

    def test_contains_existing_context(self, sample_tm):
        result = generate_threat_model_prompt(sample_tm, "X", "Y", ".tmdd")
        assert "web_app" in result
        assert "sql_injection" in result
        assert "parameterized_queries" in result
        assert "external_attacker" in result

    def test_contains_stride_checklist(self, sample_tm):
        result = generate_threat_model_prompt(sample_tm, "X", "Y", ".tmdd")
        assert "**S**poofing" in result
        assert "**T**ampering" in result
        assert "**E**levation of Privilege" in result

    def test_empty_model_shows_none(self, empty_tm):
        result = generate_threat_model_prompt(empty_tm, "X", "Y", ".tmdd")
        assert "**Components**: None" in result
        assert "**Threats**: None" in result

    def test_contains_today_date(self, sample_tm):
        from datetime import date
        result = generate_threat_model_prompt(sample_tm, "X", "Y", ".tmdd")
        assert date.today().isoformat() in result

    def test_returns_string(self, sample_tm):
        result = generate_threat_model_prompt(sample_tm, "X", "Y", ".tmdd")
        assert isinstance(result, str)

    def test_component_without_id_uses_fallback(self, empty_tm):
        empty_tm["components"] = [{"name": "NoID"}]
        result = generate_threat_model_prompt(empty_tm, "X", "Y", ".tmdd")
        assert "?" in result


# ===== Rich mitigation format tests =====

class TestRichMitigationsInPrompt:
    """Verify agent_prompt handles rich mitigations (dict with references)."""

    @pytest.fixture
    def rich_tm(self, sample_tm):
        """A threat model with mixed simple and rich mitigations."""
        sample_tm["mitigations"] = {
            "parameterized_queries": {
                "description": "Parameterized queries via Prisma",
                "references": [
                    {"file": "src/db/queries.ts", "lines": "42-58"},
                    {"file": "src/db/utils.ts"},
                ],
            },
            "rate_limiting": "Simple rate limiting",
        }
        return sample_tm

    def test_rich_mitigation_description_in_controls(self, rich_tm, tmp_path):
        content = generate_agent_prompt(rich_tm, tmp_path / "p.txt")
        assert "Parameterized queries via Prisma" in content

    def test_rich_mitigation_references_in_controls(self, rich_tm, tmp_path):
        content = generate_agent_prompt(rich_tm, tmp_path / "p.txt")
        assert "ref: src/db/queries.ts:42-58" in content
        assert "ref: src/db/utils.ts" in content

    def test_simple_mitigation_still_works(self, rich_tm, tmp_path):
        content = generate_agent_prompt(rich_tm, tmp_path / "p.txt")
        assert "Simple rate limiting" in content

    def test_rich_mitigation_in_feature_requirements(self, rich_tm, tmp_path):
        """Rich mitigation description shows in feature required controls."""
        rich_tm["features"] = [{
            "name": "Login",
            "goal": "Authenticate",
            "threats": {"sql_injection": ["parameterized_queries"]},
        }]
        content = generate_agent_prompt(rich_tm, tmp_path / "p.txt", feature_name="Login")
        assert "Parameterized queries via Prisma" in content
