from __future__ import annotations

from finalreview.config import load_settings
from finalreview.models import Confidence, ProviderKind, Severity


def test_configuration_precedence(tmp_path, monkeypatch):
    project = tmp_path / "repo"
    project.mkdir()
    (project / "pyproject.toml").write_text(
        """
[tool.finalreview]
provider = "none"
fail-on = "low"
min-confidence = "low"
""".strip()
        + "\n",
        encoding="utf-8",
    )
    config_file = project / "finalreview.toml"
    config_file.write_text(
        """
[finalreview]
fail-on = "medium"
min-confidence = "medium"
""".strip()
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("FINALREVIEW_PROVIDER", "openai")
    monkeypatch.setenv("FINALREVIEW_MIN_CONFIDENCE", "high")

    settings = load_settings(
        project,
        config_path=config_file,
        cli_overrides={"fail_on": Severity.CRITICAL},
    )

    assert settings.provider == ProviderKind.OPENAI
    assert settings.fail_on == Severity.CRITICAL
    assert settings.min_confidence == Confidence.HIGH


def test_config_paths_are_resolved_against_source_file(tmp_path):
    project = tmp_path / "repo"
    project.mkdir()
    config_dir = project / "config"
    config_dir.mkdir()
    config_file = config_dir / "finalreview.toml"
    config_file.write_text(
        """
[finalreview]
json-output = "../artifacts/report.json"
""".strip()
        + "\n",
        encoding="utf-8",
    )

    settings = load_settings(project, config_path=config_file)

    assert settings.json_output == (config_dir / "../artifacts/report.json").resolve()
