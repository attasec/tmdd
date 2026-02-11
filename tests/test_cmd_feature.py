"""Tests for src/commands/feature.py."""
import pytest

from src.commands.feature import cmd_feature
from src.utils import ModelNotFoundError
from tests.conftest import make_args


class TestCmdFeatureExisting:
    """When the feature already exists in the model."""

    def test_existing_feature_generates_prompt(self, valid_model_dir, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        args = make_args(path=str(valid_model_dir), name="User Login", description=None)
        result = cmd_feature(args)
        assert result == 0

        out_dir = tmp_path / ".tmdd" / "out"
        prompt_files = list(out_dir.glob("*.prompt.txt"))
        assert len(prompt_files) == 1

    def test_existing_feature_case_insensitive(self, valid_model_dir, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        args = make_args(path=str(valid_model_dir), name="user login", description=None)
        result = cmd_feature(args)
        assert result == 0

        out_dir = tmp_path / ".tmdd" / "out"
        prompt_files = list(out_dir.glob("*.prompt.txt"))
        assert len(prompt_files) == 1

    def test_existing_feature_with_whitespace(self, valid_model_dir, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        args = make_args(path=str(valid_model_dir), name="  User Login  ", description=None)
        result = cmd_feature(args)
        assert result == 0

    def test_prints_found_message(self, valid_model_dir, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        args = make_args(path=str(valid_model_dir), name="User Login", description=None)
        cmd_feature(args)
        output = capsys.readouterr().out
        assert "found" in output.lower()


class TestCmdFeatureNew:
    """When the feature does NOT exist -- generates a threat modeling prompt."""

    def test_new_feature_generates_threatmodel(self, valid_model_dir, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        args = make_args(path=str(valid_model_dir), name="Payment Processing", description="Handle payments")
        result = cmd_feature(args)
        assert result == 0

        out_dir = tmp_path / ".tmdd" / "out"
        tm_files = list(out_dir.glob("*.threatmodel.txt"))
        assert len(tm_files) == 1

    def test_new_feature_prompt_contains_name(self, valid_model_dir, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        args = make_args(path=str(valid_model_dir), name="Payment Processing", description="Handle payments")
        cmd_feature(args)

        out_dir = tmp_path / ".tmdd" / "out"
        tm_file = list(out_dir.glob("*.threatmodel.txt"))[0]
        content = tm_file.read_text(encoding="utf-8")
        assert "Payment Processing" in content
        assert "Handle payments" in content

    def test_new_feature_no_description_uses_placeholder(self, valid_model_dir, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        args = make_args(path=str(valid_model_dir), name="New Thing", description=None)
        cmd_feature(args)

        out_dir = tmp_path / ".tmdd" / "out"
        tm_file = list(out_dir.glob("*.threatmodel.txt"))[0]
        content = tm_file.read_text(encoding="utf-8")
        assert "[describe feature]" in content

    def test_prints_guidance(self, valid_model_dir, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        args = make_args(path=str(valid_model_dir), name="New", description=None)
        cmd_feature(args)
        output = capsys.readouterr().out
        assert "not in threat model" in output.lower()


class TestCmdFeatureErrors:
    def test_nonexistent_dir_raises(self, tmp_path):
        args = make_args(path=str(tmp_path / "nope"), name="X", description=None)
        with pytest.raises(ModelNotFoundError):
            cmd_feature(args)
