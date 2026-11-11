import tempfile
import unittest
from pathlib import Path
from repodoctor.scanner import scan_repository
from repodoctor.reporters import summary,json_report,sarif_report

class ScannerTests(unittest.TestCase):
    def test_missing_project_files_are_reported(self):
        with tempfile.TemporaryDirectory() as d:
            ids={f.rule_id for f in scan_repository(d)}
            self.assertTrue({"RD100","RD101","RD103","RD104"}.issubset(ids))
    def test_secret_is_redacted(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d)/"app.py").write_text('API_KEY = "abcdefghijklmnop1234567890"')
            fs=scan_repository(d); found=[f for f in fs if f.rule_id=="RD002"]
            self.assertTrue(found); self.assertNotIn("abcdefghijklmnop",str([f.to_dict() for f in found]))
    def test_clean_project(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for n in ("README.md","LICENSE","pyproject.toml"): (root/n).write_text("x")
            (root/".github/workflows").mkdir(parents=True); (root/".github/workflows/ci.yml").write_text("name: CI")
            (root/"tests").mkdir(); (root/"tests/test_ok.py").write_text("def test_ok(): pass")
            self.assertEqual(scan_repository(root),[])
    def test_reports(self):
        with tempfile.TemporaryDirectory() as d:
            fs=scan_repository(d); self.assertEqual(summary(fs)["total"],len(fs)); self.assertIn('"findings"',json_report(fs,d)); self.assertIn('"version": "2.1.0"',sarif_report(fs))

if __name__=="__main__": unittest.main()
