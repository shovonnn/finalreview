from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


def test_build_artifacts_can_be_created(tmp_path):
    pytest.importorskip("hatchling")
    pytest.importorskip("hatch_vcs")
    project_root = Path(__file__).resolve().parents[1]
    subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--outdir",
            str(tmp_path),
        ],
        cwd=project_root,
        check=True,
    )

    assert list(tmp_path.glob("*.tar.gz"))
    assert list(tmp_path.glob("*.whl"))
