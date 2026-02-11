"""Tests for src/cli.py (main entrypoint)."""
import pytest
from unittest.mock import patch

from src.cli import main


class TestCLINoCommand:
    def test_no_args_returns_0(self):
        with patch("sys.argv", ["tmdd"]):
            result = main()
        assert result == 0

    def test_help_flag(self, capsys):
        with patch("sys.argv", ["tmdd"]):
            result = main()
        assert result == 0
        output = capsys.readouterr().out
        assert "Threat Modeling Driven Development" in output


class TestCLIInit:
    def test_init_list(self, capsys):
        with patch("sys.argv", ["tmdd", "init", "--list"]):
            result = main()
        assert result == 0
        output = capsys.readouterr().out
        assert "minimal" in output

    def test_init_creates_model(self, tmp_path):
        dest = str(tmp_path / "model")
        with patch("sys.argv", ["tmdd", "init", dest, "-t", "minimal"]):
            result = main()
        assert result == 0
        assert (tmp_path / "model" / "system.yaml").exists()

    def test_init_invalid_template_returns_1(self, tmp_path, capsys):
        dest = str(tmp_path / "model")
        with patch("sys.argv", ["tmdd", "init", dest, "-t", "bad_template"]):
            result = main()
        assert result == 1
        stderr = capsys.readouterr().err
        assert "Error" in stderr


class TestCLILint:
    def test_lint_valid_model(self, valid_model_dir, capsys):
        with patch("sys.argv", ["tmdd", "lint", str(valid_model_dir)]):
            result = main()
        assert result == 0
        output = capsys.readouterr().out
        assert "OK" in output

    def test_lint_nonexistent_returns_1(self, tmp_path, capsys):
        with patch("sys.argv", ["tmdd", "lint", str(tmp_path / "nope")]):
            result = main()
        assert result == 1
        stderr = capsys.readouterr().err
        assert "Error" in stderr


class TestCLICompile:
    def test_compile_valid_model(self, valid_model_dir, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with patch("sys.argv", ["tmdd", "compile", str(valid_model_dir)]):
            result = main()
        assert result == 0

    def test_compile_nonexistent_returns_1(self, tmp_path, capsys):
        with patch("sys.argv", ["tmdd", "compile", str(tmp_path / "nope")]):
            result = main()
        assert result == 1


class TestCLIFeature:
    def test_feature_existing(self, valid_model_dir, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        with patch("sys.argv", ["tmdd", "feature", "User Login", "-p", str(valid_model_dir)]):
            result = main()
        assert result == 0
        output = capsys.readouterr().out
        assert "found" in output.lower()

    def test_feature_new(self, valid_model_dir, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        with patch("sys.argv", ["tmdd", "feature", "New Feature", "-p", str(valid_model_dir)]):
            result = main()
        assert result == 0
        output = capsys.readouterr().out
        assert "not in threat model" in output.lower()

    def test_feature_nonexistent_dir_returns_1(self, tmp_path, capsys):
        with patch("sys.argv", ["tmdd", "feature", "X", "-p", str(tmp_path / "nope")]):
            result = main()
        assert result == 1
