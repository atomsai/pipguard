"""Tests for doctor command."""

import tempfile
from pathlib import Path

from pipguard.detectors.ioc_detector import detect_ioc_in_directory, get_pack, list_packs
from pipguard.doctor.env_inspector import inspect_site_packages
from pipguard.doctor.rotation_advice import build_next_steps
from pipguard.models.finding import Finding


class TestDoctor:
    def test_ioc_pack_registry_includes_pyronut(self):
        packs = list_packs()
        assert "litellm-march-2026" in packs
        assert "pyronut-march-2026" in packs

    def test_clean_site_packages(self, tmp_path: Path):
        """An empty site-packages should produce no findings."""
        (tmp_path / "good_package").mkdir()
        (tmp_path / "good_package" / "__init__.py").write_text("x = 1\n")
        findings = inspect_site_packages(tmp_path)
        assert findings == []

    def test_suspicious_pth_in_site_packages(self, tmp_path: Path):
        """A malicious .pth in site-packages should be flagged."""
        pth = tmp_path / "evil_init.pth"
        pth.write_text("import os; exec(open('/tmp/x').read())\n")
        findings = inspect_site_packages(tmp_path)
        assert len(findings) >= 1
        rule_ids = {f.rule_id for f in findings}
        assert "PTH-EXEC" in rule_ids or "STARTUP-HOOK" in rule_ids

    def test_sitecustomize_flagged(self, tmp_path: Path):
        """sitecustomize.py should be flagged."""
        sc = tmp_path / "sitecustomize.py"
        sc.write_text("import os\nprint(os.environ)\n")
        findings = inspect_site_packages(tmp_path)
        assert len(findings) >= 1
        rule_ids = {f.rule_id for f in findings}
        assert "STARTUP-HOOK" in rule_ids

    def test_rotation_advice_with_exfil(self):
        findings = [
            Finding(
                rule_id="EXFIL-SINK",
                severity="critical",
                file="x.py",
                message="data exfil",
            ),
            Finding(
                rule_id="SECRET-PATH-READ",
                severity="high",
                file="x.py",
                message="ssh key read",
            ),
        ]
        steps = build_next_steps(findings)
        assert len(steps) > 0
        assert any("rotate" in s.lower() for s in steps)

    def test_rotation_advice_clean(self):
        steps = build_next_steps([])
        assert len(steps) > 0
        assert any("clean" in s.lower() for s in steps)

    def test_ioc_package_version_match_from_dist_metadata(self, tmp_path: Path):
        dist = tmp_path / "litellm-4.97.1.dist-info"
        dist.mkdir()
        (dist / "METADATA").write_text("Name: litellm\nVersion: 4.97.1\n")
        pack = get_pack("litellm-march-2026")
        assert pack is not None
        findings = detect_ioc_in_directory(tmp_path, pack)
        assert any(f.rule_id == "IOC-PACKAGE" for f in findings)

    def test_ioc_record_match_from_dist_metadata(self, tmp_path: Path):
        dist = tmp_path / "litellm-4.97.1.dist-info"
        dist.mkdir()
        (dist / "METADATA").write_text("Name: litellm\nVersion: 4.97.1\n")
        (dist / "RECORD").write_text("litellm_init.pth,sha256=abc,123\n")
        pack = get_pack("litellm-march-2026")
        assert pack is not None
        findings = detect_ioc_in_directory(tmp_path, pack)
        assert any(f.rule_id == "IOC-RECORD" for f in findings)

    def test_ioc_wheel_metadata_marker_match(self, tmp_path: Path):
        dist = tmp_path / "litellm-4.97.1.dist-info"
        dist.mkdir()
        (dist / "METADATA").write_text("Name: litellm\nVersion: 4.97.1\n")
        (dist / "WHEEL").write_text("Generator: sysmon\n")
        pack = get_pack("litellm-march-2026")
        assert pack is not None
        findings = detect_ioc_in_directory(tmp_path, pack)
        assert any(f.rule_id == "IOC-WHEEL-META" for f in findings)

    def test_ioc_pyronut_package_version_match_from_dist_metadata(self, tmp_path: Path):
        dist = tmp_path / "pyronut-2.0.186.dist-info"
        dist.mkdir()
        (dist / "METADATA").write_text("Name: pyronut\nVersion: 2.0.186\n")
        pack = get_pack("pyronut-march-2026")
        assert pack is not None
        findings = detect_ioc_in_directory(tmp_path, pack)
        assert any(f.rule_id == "IOC-PACKAGE" for f in findings)

    def test_ioc_pyronut_runtime_marker_match(self, tmp_path: Path):
        target = tmp_path / "pyrogram" / "methods" / "utilities" / "start.py"
        target.parent.mkdir(parents=True)
        target.write_text(
            "self.me = await self.get_me()\n"
            "try:\n"
            "    import pyrogram.helpers.secret as secret\n"
            "    secret.init_secret(self)\n"
            "except Exception:\n"
            "    pass\n"
        )
        pack = get_pack("pyronut-march-2026")
        assert pack is not None
        findings = detect_ioc_in_directory(tmp_path, pack)
        assert any(f.rule_id == "IOC-STRING-MARKER" for f in findings)
