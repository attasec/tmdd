"""Tests for src/utils.py."""
import pytest
from pathlib import Path

from src.utils import (
    TMDDError,
    ModelNotFoundError,
    resolve_model_dir,
    safe_name,
    load_yaml,
    load_threat_model,
    get_output_dir,
    get_project_root,
)


# ===== safe_name =====

class TestSafeName:
    def test_basic_lowercase(self):
        assert safe_name("Hello World") == "hello_world"

    def test_hyphens_converted(self):
        assert safe_name("my-feature") == "my-feature"

    def test_special_characters_stripped(self):
        assert safe_name("Hello! @#$ World") == "hello_world"

    def test_dots_and_slashes_stripped(self):
        assert safe_name("../../etc/passwd") == "etc_passwd"

    def test_collapses_multiple_underscores(self):
        assert safe_name("a   b   c") == "a_b_c"

    def test_strips_leading_trailing_underscores(self):
        assert safe_name("  hello  ") == "hello"

    def test_empty_string_returns_unnamed(self):
        assert safe_name("") == "unnamed"

    def test_none_returns_unnamed(self):
        assert safe_name(None) == "unnamed"

    def test_whitespace_only_returns_unnamed(self):
        assert safe_name("   ") == "unnamed"

    def test_unicode_stripped(self):
        assert safe_name("café") == "caf"

    def test_all_special_chars_returns_unnamed(self):
        assert safe_name("!@#$%") == "unnamed"

    def test_mixed_case_numbers(self):
        assert safe_name("Feature 123 TEST") == "feature_123_test"


# ===== resolve_model_dir =====

class TestResolveModelDir:
    def test_valid_directory(self, tmp_path):
        result = resolve_model_dir(tmp_path)
        assert result == tmp_path
        assert isinstance(result, Path)

    def test_nonexistent_path_raises(self, tmp_path):
        fake = tmp_path / "nonexistent"
        with pytest.raises(ModelNotFoundError, match="Not a directory"):
            resolve_model_dir(fake)

    def test_file_path_raises(self, tmp_path):
        f = tmp_path / "file.txt"
        f.write_text("hi")
        with pytest.raises(ModelNotFoundError, match="Not a directory"):
            resolve_model_dir(f)

    def test_error_is_tmdd_error_subclass(self):
        assert issubclass(ModelNotFoundError, TMDDError)


# ===== load_yaml =====

class TestLoadYaml:
    def test_valid_yaml(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text("key: value\n", encoding="utf-8")
        result = load_yaml(f)
        assert result == {"key": "value"}

    def test_empty_yaml_returns_empty_dict(self, tmp_path):
        f = tmp_path / "empty.yaml"
        f.write_text("", encoding="utf-8")
        assert load_yaml(f) == {}

    def test_yaml_with_only_null(self, tmp_path):
        f = tmp_path / "null.yaml"
        f.write_text("~\n", encoding="utf-8")
        assert load_yaml(f) == {}

    def test_nonexistent_file_returns_empty_dict(self, tmp_path):
        assert load_yaml(tmp_path / "nope.yaml") == {}

    def test_nonexistent_file_strict_returns_none(self, tmp_path):
        assert load_yaml(tmp_path / "nope.yaml", strict=True) is None

    def test_invalid_yaml_returns_empty_dict(self, tmp_path):
        f = tmp_path / "bad.yaml"
        f.write_text(":\n  :\n    - ][", encoding="utf-8")
        assert load_yaml(f) == {}

    def test_invalid_yaml_strict_returns_none(self, tmp_path):
        f = tmp_path / "bad.yaml"
        f.write_text(":\n  :\n    - ][", encoding="utf-8")
        assert load_yaml(f, strict=True) is None

    def test_nested_structure(self, tmp_path):
        f = tmp_path / "nested.yaml"
        f.write_text("system:\n  name: Test\n  version: '1.0'\n", encoding="utf-8")
        result = load_yaml(f)
        assert result["system"]["name"] == "Test"
        assert result["system"]["version"] == "1.0"

    def test_list_yaml(self, tmp_path):
        f = tmp_path / "list.yaml"
        f.write_text("items:\n  - a\n  - b\n", encoding="utf-8")
        result = load_yaml(f)
        assert result["items"] == ["a", "b"]


# ===== load_threat_model =====

class TestLoadThreatModel:
    def test_loads_valid_model(self, valid_model_dir):
        tm = load_threat_model(valid_model_dir)
        assert tm["system"]["name"] == "Test System"
        assert len(tm["actors"]) == 2
        assert len(tm["components"]) == 3
        assert len(tm["data_flows"]) == 3
        assert len(tm["features"]) == 1
        assert "T001" in tm["threats"]
        assert "M001" in tm["mitigations"]
        assert "TA01" in tm["threat_actors"]

    def test_nonexistent_dir_raises(self, tmp_path):
        with pytest.raises(ModelNotFoundError):
            load_threat_model(tmp_path / "nonexistent")

    def test_empty_dir_returns_empty_collections(self, empty_model_dir):
        """An empty dir (no YAML files) should load without crashing."""
        tm = load_threat_model(empty_model_dir)
        assert tm["system"] == {}
        assert tm["actors"] == []
        assert tm["components"] == []
        assert tm["threats"] == {}

    def test_returns_all_expected_keys(self, valid_model_dir):
        tm = load_threat_model(valid_model_dir)
        expected_keys = {"system", "actors", "components", "features",
                         "data_flows", "threats", "mitigations", "threat_actors"}
        assert set(tm.keys()) == expected_keys


# ===== get_output_dir =====

class TestGetOutputDir:
    def test_creates_directory(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        out = get_output_dir()
        assert out.is_dir()
        assert out == tmp_path / ".tmdd" / "out"

    def test_idempotent(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        out1 = get_output_dir()
        out2 = get_output_dir()
        assert out1 == out2
        assert out1.is_dir()


# ===== get_project_root =====

class TestGetProjectRoot:
    def test_returns_path_with_templates(self):
        root = get_project_root()
        assert isinstance(root, Path)
        # The project root should contain a templates/ directory
        assert (root / "templates").is_dir()
