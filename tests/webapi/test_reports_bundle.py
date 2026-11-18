import io
import os
import zipfile

from src.webapi import reports


def _setup(tmp_path, sid="s1"):
    d = tmp_path / "repo" / ".vigilo" / sid / "deliverables"
    (d / "evidence").mkdir(parents=True)
    (d / "ledger").mkdir()
    (d / "evidence" / "VG-1.md").write_text("ev")
    (d / "ledger" / "a.jsonl").write_text("{}")
    (d / "report.md").write_text("r")
    return d


def _names(buf):
    return set(zipfile.ZipFile(io.BytesIO(buf.read())).namelist())


def test_bundle_contains_nested_files(tmp_path):
    _setup(tmp_path)
    buf = reports.build_bundle_zip(str(tmp_path), "s1")
    assert _names(buf) == {
        "deliverables/evidence/VG-1.md", "deliverables/ledger/a.jsonl", "deliverables/report.md",
    }


def test_bundle_skips_symlinks_locks_dotfiles(tmp_path):
    d = _setup(tmp_path)
    secret = tmp_path / "secret.txt"
    secret.write_text("x")
    outdir = tmp_path / "outside"
    outdir.mkdir()
    (outdir / "leak.txt").write_text("x")
    os.symlink(secret, d / "link.md")
    os.symlink(outdir, d / "linkdir")
    (d / "evidence" / "ln.md").symlink_to(secret)
    (d / "x.lock").write_text("")
    (d / ".verify_patches.lock").write_text("")
    (d / ".hidden").write_text("h")
    names = _names(reports.build_bundle_zip(str(tmp_path), "s1"))
    assert names == {
        "deliverables/evidence/VG-1.md", "deliverables/ledger/a.jsonl", "deliverables/report.md",
    }


def test_bundle_size_cap(tmp_path, monkeypatch):
    _setup(tmp_path)
    monkeypatch.setattr(reports, "BUNDLE_MAX_BYTES", 2)
    names = _names(reports.build_bundle_zip(str(tmp_path), "s1"))
    assert "deliverables/report.md" not in names or len(names) < 3


def test_available_artifacts_lists_bundle(tmp_path):
    assert reports.available_artifacts(str(tmp_path), "s1") == []
    assert reports.build_bundle_zip(str(tmp_path), "s1") is None
    d = _setup(tmp_path)
    assert "bundle" in reports.available_artifacts(str(tmp_path), "s1")
    for p in d.rglob("*"):
        if p.is_file():
            p.unlink()
    assert "bundle" not in reports.available_artifacts(str(tmp_path), "s1")
