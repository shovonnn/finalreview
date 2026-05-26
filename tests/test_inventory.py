from __future__ import annotations

from finalreview.config import AppSettings
from finalreview.inventory import build_repository_summary


def test_inventory_respects_gitignore_and_skips_binary_vendor(tmp_path):
    (tmp_path / ".gitignore").write_text("ignored.py\n", encoding="utf-8")
    (tmp_path / "ignored.py").write_text("print('ignore')\n", encoding="utf-8")
    vendor_dir = tmp_path / "vendor"
    vendor_dir.mkdir()
    (vendor_dir / "dep.py").write_text("print('vendor')\n", encoding="utf-8")
    (tmp_path / "keep.py").write_text("print('keep')\n", encoding="utf-8")
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01\x02\x03")

    summary = build_repository_summary(tmp_path, AppSettings(scan_path=tmp_path))
    scanned = {source_file.relative_path for source_file in summary.files}

    assert "keep.py" in scanned
    assert "ignored.py" not in scanned
    assert "vendor/dep.py" not in scanned
    assert "blob.bin" not in scanned
