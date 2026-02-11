"""Tests for src/commands/compile.py."""
import pytest
import yaml

from src.commands.compile import cmd_compile
from src.utils import TMDDError, ModelNotFoundError
from tests.conftest import make_args


class TestCmdCompile:
    def test_generates_yaml_and_prompt(self, valid_model_dir, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        args = make_args(path=str(valid_model_dir), feature=None)
        result = cmd_compile(args)
        assert result == 0

        out_dir = tmp_path / ".tmdd" / "out"
        yaml_files = list(out_dir.glob("*.tm.yaml"))
        prompt_files = list(out_dir.glob("*.prompt.txt"))
        assert len(yaml_files) == 1
        assert len(prompt_files) == 1

    def test_generated_yaml_is_valid(self, valid_model_dir, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        args = make_args(path=str(valid_model_dir), feature=None)
        cmd_compile(args)

        out_dir = tmp_path / ".tmdd" / "out"
        yaml_file = list(out_dir.glob("*.tm.yaml"))[0]
        data = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
        assert data["system"]["name"] == "Test System"
        assert "$schema" in data
        assert "generated" in data

    def test_generated_prompt_has_content(self, valid_model_dir, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        args = make_args(path=str(valid_model_dir), feature=None)
        cmd_compile(args)

        out_dir = tmp_path / ".tmdd" / "out"
        prompt_file = list(out_dir.glob("*.prompt.txt"))[0]
        content = prompt_file.read_text(encoding="utf-8")
        assert "SECURE CODING AGENT" in content
        assert "Test System" in content

    def test_feature_filter(self, valid_model_dir, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        args = make_args(path=str(valid_model_dir), feature="User Login")
        result = cmd_compile(args)
        assert result == 0

        out_dir = tmp_path / ".tmdd" / "out"
        prompt_files = list(out_dir.glob("*.prompt.txt"))
        assert len(prompt_files) == 1
        assert "user_login" in prompt_files[0].name

    def test_nonexistent_dir_raises(self, tmp_path):
        args = make_args(path=str(tmp_path / "nope"), feature=None)
        with pytest.raises(ModelNotFoundError):
            cmd_compile(args)

    def test_empty_system_name_raises(self, tmp_path, monkeypatch):
        """A model with no system name should raise TMDDError."""
        monkeypatch.chdir(tmp_path)
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        (model_dir / "threats").mkdir()
        # Write system.yaml with empty name
        (model_dir / "system.yaml").write_text("system:\n  description: X\n", encoding="utf-8")
        for name in ["actors.yaml", "components.yaml", "features.yaml", "data_flows.yaml"]:
            (model_dir / name).write_text(f"{name.replace('.yaml', '')}: []\n", encoding="utf-8")
        for name in ["catalog.yaml", "mitigations.yaml", "threat_actors.yaml"]:
            key = name.replace(".yaml", "")
            (model_dir / "threats" / name).write_text(f"{key}: {{}}\n", encoding="utf-8")

        args = make_args(path=str(model_dir), feature=None)
        with pytest.raises(TMDDError, match="system name"):
            cmd_compile(args)
