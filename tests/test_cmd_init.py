"""Tests for src/commands/init.py."""
import pytest

from src.commands.init import cmd_init
from src.utils import TMDDError
from tests.conftest import make_args


class TestCmdInit:
    def test_init_creates_files_minimal(self, tmp_path):
        dest = tmp_path / "my_model"
        args = make_args(
            path=str(dest), name="My System", description="A test system",
            template="minimal", list=False,
        )
        result = cmd_init(args)
        assert result == 0
        assert (dest / "system.yaml").exists()
        assert (dest / "actors.yaml").exists()
        assert (dest / "components.yaml").exists()
        assert (dest / "data_flows.yaml").exists()
        assert (dest / "features.yaml").exists()
        assert (dest / "threats" / "catalog.yaml").exists()
        assert (dest / "threats" / "mitigations.yaml").exists()
        assert (dest / "threats" / "threat_actors.yaml").exists()

    def test_init_substitutes_placeholders(self, tmp_path):
        dest = tmp_path / "model"
        args = make_args(
            path=str(dest), name="FooBar", description="My desc",
            template="minimal", list=False,
        )
        cmd_init(args)
        content = (dest / "system.yaml").read_text(encoding="utf-8")
        assert "FooBar" in content
        assert "My desc" in content
        assert "{{name}}" not in content
        assert "{{description}}" not in content

    def test_init_skips_existing_files(self, tmp_path):
        dest = tmp_path / "model"
        dest.mkdir()
        (dest / "system.yaml").write_text("existing content", encoding="utf-8")

        args = make_args(
            path=str(dest), name="Test", description="Desc",
            template="minimal", list=False,
        )
        result = cmd_init(args)
        assert result == 0
        # The existing file should NOT be overwritten
        assert (dest / "system.yaml").read_text(encoding="utf-8") == "existing content"

    def test_init_list_templates(self, capsys):
        args = make_args(
            path=".", name="X", description="X",
            template="minimal", list=True,
        )
        result = cmd_init(args)
        assert result == 0
        output = capsys.readouterr().out
        assert "minimal" in output

    def test_init_invalid_template_raises(self, tmp_path):
        args = make_args(
            path=str(tmp_path / "out"), name="X", description="X",
            template="nonexistent_template_xyz", list=False,
        )
        with pytest.raises(TMDDError, match="not found"):
            cmd_init(args)

    def test_init_creates_nested_dirs(self, tmp_path):
        dest = tmp_path / "deep" / "nested" / "model"
        args = make_args(
            path=str(dest), name="Test", description="D",
            template="minimal", list=False,
        )
        result = cmd_init(args)
        assert result == 0
        assert dest.is_dir()

    def test_init_web_app_template(self, tmp_path):
        dest = tmp_path / "model"
        args = make_args(
            path=str(dest), name="Web App", description="A web app",
            template="web-app", list=False,
        )
        result = cmd_init(args)
        assert result == 0
        assert (dest / "system.yaml").exists()

    def test_init_api_template(self, tmp_path):
        dest = tmp_path / "model"
        args = make_args(
            path=str(dest), name="API", description="An API",
            template="api", list=False,
        )
        result = cmd_init(args)
        assert result == 0
        assert (dest / "system.yaml").exists()
