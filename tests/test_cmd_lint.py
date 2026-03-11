"""Tests for src/commands/lint.py."""
import pytest

from src.commands.lint import cmd_lint
from src.utils import ModelNotFoundError
from tests.conftest import make_args, VALID_MODEL_FILES, MITIGATIONS_RICH_YAML


def _write_model(model_dir, overrides=None):
    """Write the full valid model, with optional file overrides."""
    model_dir.mkdir(parents=True, exist_ok=True)
    (model_dir / "threats").mkdir(parents=True, exist_ok=True)
    files = {**VALID_MODEL_FILES, **(overrides or {})}
    for rel_path, content in files.items():
        filepath = model_dir / rel_path
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(content, encoding="utf-8")


class TestCmdLintValid:
    def test_valid_model_returns_0(self, valid_model_dir, capsys):
        args = make_args(path=str(valid_model_dir))
        result = cmd_lint(args)
        assert result == 0
        output = capsys.readouterr().out
        assert "OK" in output

    def test_reports_counts(self, valid_model_dir, capsys):
        args = make_args(path=str(valid_model_dir))
        cmd_lint(args)
        output = capsys.readouterr().out
        assert "2 actors" in output
        assert "3 components" in output
        assert "3 flows" in output
        assert "2 threats" in output
        assert "2 mitigations" in output


class TestCmdLintMissing:
    def test_nonexistent_dir_raises(self, tmp_path):
        args = make_args(path=str(tmp_path / "nope"))
        with pytest.raises(ModelNotFoundError):
            cmd_lint(args)

    def test_missing_files_returns_2(self, empty_model_dir, capsys):
        # Dir exists but no YAML files
        args = make_args(path=str(empty_model_dir))
        result = cmd_lint(args)
        assert result == 2
        output = capsys.readouterr().out
        assert "Missing" in output

    def test_missing_threats_dir_returns_2(self, tmp_path, capsys):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        # Write only main files, skip threats/
        for name in ["system.yaml", "actors.yaml", "components.yaml",
                      "features.yaml", "data_flows.yaml"]:
            (model_dir / name).write_text(VALID_MODEL_FILES[name], encoding="utf-8")

        args = make_args(path=str(model_dir))
        result = cmd_lint(args)
        assert result == 2
        output = capsys.readouterr().out
        assert "threats/" in output


class TestCmdLintYamlErrors:
    def test_invalid_yaml_returns_2(self, tmp_path, capsys):
        model_dir = tmp_path / "model"
        _write_model(model_dir, overrides={
            "system.yaml": ":\n  :\n    - ][",
        })
        args = make_args(path=str(model_dir))
        result = cmd_lint(args)
        assert result == 2


class TestCmdLintValidationErrors:
    def test_missing_system_fields(self, tmp_path, capsys):
        model_dir = tmp_path / "model"
        _write_model(model_dir, overrides={
            "system.yaml": "system:\n  name: Test\n",
        })
        args = make_args(path=str(model_dir))
        result = cmd_lint(args)
        assert result == 1
        output = capsys.readouterr().out
        assert "missing 'version'" in output or "missing 'description'" in output

    def test_invalid_actor_id(self, tmp_path, capsys):
        model_dir = tmp_path / "model"
        _write_model(model_dir, overrides={
            "actors.yaml": "actors:\n  - id: 123bad\n    description: Bad ID\n",
        })
        args = make_args(path=str(model_dir))
        result = cmd_lint(args)
        assert result == 1
        output = capsys.readouterr().out
        assert "invalid ID" in output

    def test_missing_actor_id(self, tmp_path, capsys):
        model_dir = tmp_path / "model"
        _write_model(model_dir, overrides={
            "actors.yaml": "actors:\n  - description: Missing ID\n",
        })
        args = make_args(path=str(model_dir))
        result = cmd_lint(args)
        assert result == 1
        output = capsys.readouterr().out
        assert "missing 'id'" in output

    def test_invalid_threat_id(self, tmp_path, capsys):
        model_dir = tmp_path / "model"
        _write_model(model_dir, overrides={
            "threats/threats.yaml": "threats:\n  123BAD:\n    name: Bad\n    description: Bad threat\n",
        })
        args = make_args(path=str(model_dir))
        result = cmd_lint(args)
        assert result == 1
        output = capsys.readouterr().out
        assert "invalid ID" in output

    def test_invalid_mitigation_id(self, tmp_path, capsys):
        model_dir = tmp_path / "model"
        _write_model(model_dir, overrides={
            "threats/mitigations.yaml": "mitigations:\n  123BAD: Some mitigation\n",
        })
        args = make_args(path=str(model_dir))
        result = cmd_lint(args)
        assert result == 1
        output = capsys.readouterr().out
        assert "invalid ID" in output

    def test_invalid_severity(self, tmp_path, capsys):
        model_dir = tmp_path / "model"
        _write_model(model_dir, overrides={
            "threats/threats.yaml": (
                "threats:\n"
                "  some_threat:\n"
                "    name: Threat\n"
                "    description: Desc\n"
                "    severity: extreme\n"
            ),
        })
        args = make_args(path=str(model_dir))
        result = cmd_lint(args)
        assert result == 1
        output = capsys.readouterr().out
        assert "invalid severity" in output

    def test_invalid_stride(self, tmp_path, capsys):
        model_dir = tmp_path / "model"
        _write_model(model_dir, overrides={
            "threats/threats.yaml": (
                "threats:\n"
                "  some_threat:\n"
                "    name: Threat\n"
                "    description: Desc\n"
                "    stride: X\n"
            ),
        })
        args = make_args(path=str(model_dir))
        result = cmd_lint(args)
        assert result == 1
        output = capsys.readouterr().out
        assert "invalid stride" in output

    def test_unknown_flow_endpoint(self, tmp_path, capsys):
        model_dir = tmp_path / "model"
        _write_model(model_dir, overrides={
            "data_flows.yaml": (
                "data_flows:\n"
                "  - id: df_ghost_to_web\n"
                "    source: ghost_actor\n"
                "    destination: web_app\n"
            ),
        })
        args = make_args(path=str(model_dir))
        result = cmd_lint(args)
        assert result == 1
        output = capsys.readouterr().out
        assert "unknown source" in output

    def test_unknown_threat_in_feature(self, tmp_path, capsys):
        model_dir = tmp_path / "model"
        _write_model(model_dir, overrides={
            "features.yaml": (
                "features:\n"
                "  - name: Bad Feature\n"
                "    goal: Test\n"
                "    threats:\n"
                "      nonexistent_threat: [parameterized_queries]\n"
            ),
        })
        args = make_args(path=str(model_dir))
        result = cmd_lint(args)
        assert result == 1
        output = capsys.readouterr().out
        assert "unknown threat" in output

    def test_unknown_mitigation_in_feature(self, tmp_path, capsys):
        model_dir = tmp_path / "model"
        _write_model(model_dir, overrides={
            "features.yaml": (
                "features:\n"
                "  - name: Bad Feature\n"
                "    goal: Test\n"
                "    threats:\n"
                "      sql_injection: [nonexistent_mitigation]\n"
            ),
        })
        args = make_args(path=str(model_dir))
        result = cmd_lint(args)
        assert result == 1
        output = capsys.readouterr().out
        assert "unknown mitigation" in output

    def test_accepted_threat_is_valid(self, tmp_path, capsys):
        model_dir = tmp_path / "model"
        _write_model(model_dir, overrides={
            "features.yaml": (
                "features:\n"
                "  - name: Feature\n"
                "    goal: Test\n"
                "    data_flows: [df_user_to_web]\n"
                "    threats:\n"
                "      sql_injection: accepted\n"
            ),
        })
        args = make_args(path=str(model_dir))
        result = cmd_lint(args)
        assert result == 0

    def test_unknown_data_flow_in_feature(self, tmp_path, capsys):
        model_dir = tmp_path / "model"
        _write_model(model_dir, overrides={
            "features.yaml": (
                "features:\n"
                "  - name: Feature\n"
                "    goal: Test\n"
                "    data_flows: [df_nonexistent]\n"
            ),
        })
        args = make_args(path=str(model_dir))
        result = cmd_lint(args)
        assert result == 1
        output = capsys.readouterr().out
        assert "unknown data_flow" in output

    def test_unknown_threat_actor_in_feature(self, tmp_path, capsys):
        model_dir = tmp_path / "model"
        _write_model(model_dir, overrides={
            "features.yaml": (
                "features:\n"
                "  - name: Feature\n"
                "    goal: Test\n"
                "    threat_actors: [nonexistent_actor]\n"
            ),
        })
        args = make_args(path=str(model_dir))
        result = cmd_lint(args)
        assert result == 1
        output = capsys.readouterr().out
        assert "unknown threat_actor" in output

    def test_missing_feature_name(self, tmp_path, capsys):
        model_dir = tmp_path / "model"
        _write_model(model_dir, overrides={
            "features.yaml": (
                "features:\n"
                "  - goal: Test\n"
            ),
        })
        args = make_args(path=str(model_dir))
        result = cmd_lint(args)
        assert result == 1
        output = capsys.readouterr().out
        assert "missing 'name'" in output

    def test_missing_feature_goal(self, tmp_path, capsys):
        model_dir = tmp_path / "model"
        _write_model(model_dir, overrides={
            "features.yaml": (
                "features:\n"
                "  - name: No Goal\n"
            ),
        })
        args = make_args(path=str(model_dir))
        result = cmd_lint(args)
        assert result == 1
        output = capsys.readouterr().out
        assert "missing 'goal'" in output


class TestCmdLintRichMitigations:
    """Tests for rich mitigation format (dict with description + references)."""

    def test_rich_mitigations_valid(self, tmp_path, capsys):
        model_dir = tmp_path / "model"
        _write_model(model_dir, overrides={
            "threats/mitigations.yaml": MITIGATIONS_RICH_YAML,
        })
        args = make_args(path=str(model_dir))
        result = cmd_lint(args)
        assert result == 0

    def test_rich_mitigation_without_references(self, tmp_path, capsys):
        model_dir = tmp_path / "model"
        _write_model(model_dir, overrides={
            "threats/mitigations.yaml": (
                "mitigations:\n"
                "  parameterized_queries:\n"
                "    description: Some control\n"
                "  account_lockout: Simple string\n"
            ),
        })
        args = make_args(path=str(model_dir))
        result = cmd_lint(args)
        assert result == 0

    def test_rich_mitigation_missing_description(self, tmp_path, capsys):
        model_dir = tmp_path / "model"
        _write_model(model_dir, overrides={
            "threats/mitigations.yaml": (
                "mitigations:\n"
                "  some_control:\n"
                "    references:\n"
                "      - file: foo.ts\n"
            ),
        })
        args = make_args(path=str(model_dir))
        result = cmd_lint(args)
        assert result == 1
        output = capsys.readouterr().out
        assert "needs 'description'" in output

    def test_rich_mitigation_references_not_list(self, tmp_path, capsys):
        model_dir = tmp_path / "model"
        _write_model(model_dir, overrides={
            "threats/mitigations.yaml": (
                "mitigations:\n"
                "  some_control:\n"
                "    description: Control\n"
                "    references: not_a_list\n"
            ),
        })
        args = make_args(path=str(model_dir))
        result = cmd_lint(args)
        assert result == 1
        output = capsys.readouterr().out
        assert "'references' must be a list" in output

    def test_rich_mitigation_reference_missing_file(self, tmp_path, capsys):
        model_dir = tmp_path / "model"
        _write_model(model_dir, overrides={
            "threats/mitigations.yaml": (
                "mitigations:\n"
                "  some_control:\n"
                "    description: Control\n"
                "    references:\n"
                "      - lines: '42'\n"
            ),
        })
        args = make_args(path=str(model_dir))
        result = cmd_lint(args)
        assert result == 1
        output = capsys.readouterr().out
        assert "missing 'file'" in output

    def test_rich_mitigation_reference_not_object(self, tmp_path, capsys):
        model_dir = tmp_path / "model"
        _write_model(model_dir, overrides={
            "threats/mitigations.yaml": (
                "mitigations:\n"
                "  some_control:\n"
                "    description: Control\n"
                "    references:\n"
                "      - just_a_string\n"
            ),
        })
        args = make_args(path=str(model_dir))
        result = cmd_lint(args)
        assert result == 1
        output = capsys.readouterr().out
        assert "must be an object" in output

    def test_mixed_simple_and_rich_valid(self, tmp_path, capsys):
        model_dir = tmp_path / "model"
        _write_model(model_dir, overrides={
            "threats/mitigations.yaml": (
                "mitigations:\n"
                "  parameterized_queries: Simple string control\n"
                "  account_lockout:\n"
                "    description: Rich control\n"
                "    references:\n"
                "      - file: src/auth.ts\n"
                "        lines: '10-20'\n"
                "      - file: src/utils.ts\n"
            ),
        })
        args = make_args(path=str(model_dir))
        result = cmd_lint(args)
        assert result == 0
