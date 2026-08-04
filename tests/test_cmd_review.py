"""Tests for src/commands/review.py."""

import copy
import json
import subprocess

import pytest

from src.commands.review import (
    cmd_review,
    map_changed_files,
    changed_files_from_git,
    format_text,
    format_markdown,
)
from src.utils import ModelNotFoundError, TMDDError
from tests.conftest import make_args


# ---------------------------------------------------------------------------
# A small threat model with source_paths wired end-to-end:
#   web_app  <- src/web/**
#   api      <- src/api/**
#   db       (no source_paths)
# data flow api<->db is used by "User Login", which carries sql_injection.
# ---------------------------------------------------------------------------

TM = {
    "system": {"name": "Test"},
    "components": [
        {
            "id": "web_app",
            "type": "frontend",
            "description": "UI",
            "source_paths": ["src/web/**"],
        },
        {
            "id": "api",
            "type": "api",
            "description": "API",
            "source_paths": ["src/api/**"],
        },
        {"id": "db", "type": "database", "description": "DB"},  # no source_paths
    ],
    "data_flows": [
        {"id": "df_web_to_api", "source": "web_app", "destination": "api"},
        {"id": "df_api_to_db", "source": "api", "destination": "db"},
    ],
    "features": [
        {
            "name": "User Login",
            "goal": "Auth",
            "data_flows": ["df_web_to_api", "df_api_to_db"],
            "reviewed_by": "alice",
            "threats": {"sql_injection": "default", "brute_force": "accepted"},
        },
        {
            "name": "Static Page",
            "goal": "Serve",
            "data_flows": ["df_unrelated"],
            "threats": {"clickjacking": ["frame_options"]},
        },
    ],
    "threats": {
        "sql_injection": {
            "name": "SQL Injection",
            "severity": "high",
            "stride": "T",
            "cwe": "CWE-89",
            "suggested_mitigations": ["parameterized_queries"],
        },
        "brute_force": {"name": "Brute Force", "severity": "medium", "stride": "S"},
        "clickjacking": {"name": "Clickjacking", "severity": "low", "stride": "T"},
    },
    "mitigations": {
        "parameterized_queries": "Use parameterized queries",
        "frame_options": "Set X-Frame-Options",
    },
}


class TestMapChangedFiles:
    def test_file_maps_to_component(self):
        result = map_changed_files(TM, ["src/api/routes.py"])
        assert [c["id"] for c in result["affected_components"]] == ["api"]

    def test_maps_through_to_threats(self):
        result = map_changed_files(TM, ["src/api/routes.py"])
        assert [f["name"] for f in result["affected_features"]] == ["User Login"]
        ids = [t["id"] for t in result["affected_threats"]]
        assert "sql_injection" in ids
        assert "brute_force" in ids
        # unrelated feature's threat is not pulled in
        assert "clickjacking" not in ids

    def test_default_mitigations_resolved_from_catalog(self):
        result = map_changed_files(TM, ["src/api/routes.py"])
        sqli = next(t for t in result["affected_threats"] if t["id"] == "sql_injection")
        assert sqli["status"] == "required"
        assert sqli["mitigations"] == ["Use parameterized queries"]

    def test_accepted_threat_marked(self):
        result = map_changed_files(TM, ["src/api/routes.py"])
        bf = next(t for t in result["affected_threats"] if t["id"] == "brute_force")
        assert bf["status"] == "accepted"
        assert bf["mitigations"] == []

    def test_threats_sorted_by_severity(self):
        result = map_changed_files(TM, ["src/api/routes.py"])
        severities = [t["severity"] for t in result["affected_threats"]]
        assert severities == ["high", "medium"]  # high before medium

    def test_unmapped_file_flagged(self):
        result = map_changed_files(TM, ["README.md", "src/api/routes.py"])
        assert result["unmapped_files"] == ["README.md"]

    def test_component_without_source_paths_reported(self):
        result = map_changed_files(TM, ["src/api/routes.py"])
        assert "db" in result["components_without_source_paths"]

    def test_no_matches_is_clean(self):
        result = map_changed_files(TM, ["docs/guide.md"])
        assert result["affected_components"] == []
        assert result["affected_threats"] == []
        assert result["unmapped_files"] == ["docs/guide.md"]

    def test_feature_reached_via_shared_component_only(self):
        """A web-only change reaches User Login via df_web_to_api."""
        result = map_changed_files(TM, ["src/web/app.js"])
        assert [f["name"] for f in result["affected_features"]] == ["User Login"]

    def test_threat_lists_source_feature(self):
        result = map_changed_files(TM, ["src/api/routes.py"])
        sqli = next(t for t in result["affected_threats"] if t["id"] == "sql_injection")
        assert sqli["features"] == ["User Login"]


class TestFormatters:
    def test_text_contains_threat_and_gap(self):
        result = map_changed_files(TM, ["src/api/routes.py", "README.md"])
        out = format_text(result)
        assert "SQL Injection" in out
        assert "README.md" in out
        assert "ACCEPTED" in out

    def test_text_lists_changed_files_with_components(self):
        result = map_changed_files(TM, ["src/api/routes.py", "README.md"])
        out = format_text(result)
        assert "Changed files" in out
        # mapped file shows the component it resolved to
        assert "src/api/routes.py" in out
        assert "-> api" in out
        # unmapped file is marked and explained inline
        assert "? README.md" in out
        assert "no component matched" in out
        # paths are listed once, not repeated in a trailing gap section
        assert out.count("README.md") == 1

    def test_markdown_lists_changed_files(self):
        result = map_changed_files(TM, ["src/api/routes.py", "README.md"])
        out = format_markdown(result)
        assert "### Changed files" in out
        assert "`src/api/routes.py`" in out
        assert "_no component matched_" in out

    def test_markdown_is_a_table(self):
        result = map_changed_files(TM, ["src/api/routes.py"])
        out = format_markdown(result)
        assert "| Severity |" in out
        assert "`sql_injection`" in out

    def test_json_roundtrips(self):
        result = map_changed_files(TM, ["src/api/routes.py"])
        # result must be JSON-serializable
        assert json.loads(json.dumps(result))["affected_threats"]


# ---------------------------------------------------------------------------
# cmd_review — explicit --files path (no git needed)
# ---------------------------------------------------------------------------


class TestCmdReviewExplicitFiles:
    def test_returns_0_and_prints(self, valid_model_dir, capsys):
        # valid_model_dir components have no source_paths -> everything unmapped
        args = make_args(
            path=str(valid_model_dir),
            files=["src/api/x.py"],
            base=None,
            staged=False,
            repo_root=None,
            format="text",
        )
        assert cmd_review(args) == 0
        assert "changed file" in capsys.readouterr().out

    def test_json_format(self, valid_model_dir, capsys):
        args = make_args(
            path=str(valid_model_dir),
            files=["a.py"],
            base=None,
            staged=False,
            repo_root=None,
            format="json",
        )
        assert cmd_review(args) == 0
        data = json.loads(capsys.readouterr().out)
        assert data["changed_files"] == ["a.py"]

    def test_nonexistent_model_raises(self, tmp_path):
        args = make_args(
            path=str(tmp_path / "nope"),
            files=["a.py"],
            base=None,
            staged=False,
            repo_root=None,
            format="text",
        )
        with pytest.raises(ModelNotFoundError):
            cmd_review(args)


# ---------------------------------------------------------------------------
# git integration
# ---------------------------------------------------------------------------


def _git(repo, *args):
    subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    )


@pytest.fixture
def git_repo(tmp_path):
    repo = tmp_path / "repo"
    (repo / "src" / "api").mkdir(parents=True)
    _git(repo, "init")
    _git(repo, "config", "user.email", "t@t.com")
    _git(repo, "config", "user.name", "t")
    (repo / "src" / "api" / "routes.py").write_text("x = 1\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "init")
    return repo


class TestGitIntegration:
    def test_changed_files_working_tree(self, git_repo):
        (git_repo / "src" / "api" / "routes.py").write_text("x = 2\n")
        files = changed_files_from_git(git_repo)
        assert "src/api/routes.py" in files

    def test_changed_files_staged(self, git_repo):
        (git_repo / "src" / "api" / "new.py").write_text("y = 1\n")
        _git(git_repo, "add", "src/api/new.py")
        files = changed_files_from_git(git_repo, staged=True)
        assert "src/api/new.py" in files

    def test_bad_ref_raises_tmdd_error(self, git_repo):
        with pytest.raises(TMDDError):
            changed_files_from_git(git_repo, base="no-such-ref")


class TestFlowBoundThreats:
    """Threats that name their own flows surface only when those flows change."""

    def _model(self):
        tm = copy.deepcopy(TM)
        tm["features"][0]["threats"] = {
            # reachable from either component
            "sql_injection": {"mitigations": "default", "flows": ["df_web_to_api"]},
            # only on the api->db leg, which src/web/** does not touch
            "brute_force": {"mitigations": "accepted", "flows": ["df_api_to_db"]},
        }
        return tm

    def test_threat_hidden_when_its_flow_untouched(self):
        result = map_changed_files(self._model(), ["src/web/app.js"])
        ids = [t["id"] for t in result["affected_threats"]]
        assert ids == ["sql_injection"]

    def test_threat_shown_when_its_flow_touched(self):
        # src/api/** sits on both flows
        result = map_changed_files(self._model(), ["src/api/routes.py"])
        ids = sorted(t["id"] for t in result["affected_threats"])
        assert ids == ["brute_force", "sql_injection"]

    def test_binding_preserves_mitigation_resolution(self):
        result = map_changed_files(self._model(), ["src/api/routes.py"])
        sqli = next(t for t in result["affected_threats"] if t["id"] == "sql_injection")
        assert sqli["mitigations"] == ["Use parameterized queries"]
        bf = next(t for t in result["affected_threats"] if t["id"] == "brute_force")
        assert bf["status"] == "accepted"

    def test_unbound_threats_keep_previous_behaviour(self):
        # TM uses the scalar form throughout -> no filtering
        result = map_changed_files(TM, ["src/web/app.js"])
        ids = sorted(t["id"] for t in result["affected_threats"])
        assert ids == ["brute_force", "sql_injection"]


class TestImplementedStatus:
    """A shipped control reads as re-verify, not as outstanding work."""

    def _model(self, status):
        tm = copy.deepcopy(TM)
        tm["features"][0]["threats"] = {
            "sql_injection": {"mitigations": "default", "status": status},
        }
        return tm

    def _sqli(self, status):
        result = map_changed_files(self._model(status), ["src/api/routes.py"])
        return next(t for t in result["affected_threats"] if t["id"] == "sql_injection")

    def test_implemented_status_reaches_output(self):
        assert self._sqli("implemented")["status"] == "implemented"

    def test_implemented_still_lists_its_mitigations(self):
        # the control is shipped, but reviewers still need to know what it is
        assert self._sqli("implemented")["mitigations"] == ["Use parameterized queries"]

    def test_default_is_required(self):
        assert self._sqli("required")["status"] == "required"

    def test_omitted_status_defaults_to_required(self):
        tm = copy.deepcopy(TM)
        tm["features"][0]["threats"] = {"sql_injection": {"mitigations": "default"}}
        result = map_changed_files(tm, ["src/api/routes.py"])
        assert result["affected_threats"][0]["status"] == "required"

    def test_unknown_status_fails_safe_to_required(self):
        # a typo must not silently hide outstanding work
        assert self._sqli("done")["status"] == "required"

    def test_text_marks_implemented_for_reverify(self):
        result = map_changed_files(self._model("implemented"), ["src/api/routes.py"])
        out = format_text(result)
        assert "IMPLEMENTED - re-verify" in out
        assert "- [x] Use parameterized queries" in out
        assert "- [ ]" not in out

    def test_text_keeps_empty_box_when_required(self):
        result = map_changed_files(self._model("required"), ["src/api/routes.py"])
        out = format_text(result)
        assert "- [ ] Use parameterized queries" in out
        assert "IMPLEMENTED" not in out

    def test_markdown_status_column(self):
        out = format_markdown(
            map_changed_files(self._model("implemented"), ["src/api/routes.py"])
        )
        assert "| Status |" in out
        assert "**re-verify**" in out
        assert "- [x] Use parameterized queries" in out

    def test_accepted_beats_implemented_and_is_not_reverify(self):
        tm = copy.deepcopy(TM)
        tm["features"][0]["threats"] = {"sql_injection": {"mitigations": "accepted"}}
        result = map_changed_files(tm, ["src/api/routes.py"])
        t = result["affected_threats"][0]
        assert t["status"] == "accepted"
        assert "ACCEPTED" in format_text(result)
        assert "re-verify" not in format_text(result)

    def test_status_composes_with_flow_binding(self):
        tm = copy.deepcopy(TM)
        tm["features"][0]["threats"] = {
            "sql_injection": {
                "mitigations": "default",
                "status": "implemented",
                "flows": ["df_api_to_db"],
            },
        }
        # web-only change does not touch df_api_to_db -> nothing to re-verify
        assert map_changed_files(tm, ["src/web/app.js"])["affected_threats"] == []
        # api change does -> surfaces as re-verify
        t = map_changed_files(tm, ["src/api/routes.py"])["affected_threats"][0]
        assert t["status"] == "implemented"
