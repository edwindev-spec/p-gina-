import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY_SCRIPT = ROOT / "moonveil_deobfuscator.py"
JS_SCRIPT = ROOT / "moonveil_deobfuscator.js"


class CrossLanguageParityTests(unittest.TestCase):
    def _run_pair(self, source_text: str, include_tokens: bool = False):
        with tempfile.TemporaryDirectory(prefix="moonveil-parity-") as tmp:
            tmp = Path(tmp)
            source = tmp / "input.lua"
            source.write_text(source_text, encoding="utf-8")
            py_out, js_out = tmp / "py", tmp / "js"
            py_args = [sys.executable, str(PY_SCRIPT), str(source), "-o", str(py_out)]
            js_args = ["node", str(JS_SCRIPT), str(source), "-o", str(js_out)]
            if not include_tokens:
                py_args.append("--no-token-dump")
                js_args.append("--no-token-dump")
            subprocess.run(py_args, check=True, capture_output=True, text=True)
            subprocess.run(js_args, check=True, capture_output=True, text=True)
            files = ["normalized.lua", "analysis_report.md", "extracted_strings.txt", "string_decodings.txt", "triage_notes.md", "largest_string_candidate.txt"]
            if include_tokens:
                files.append("tokens.tsv")
            for name in files:
                with self.subTest(file=name):
                    self.assertEqual((py_out / name).read_bytes(), (js_out / name).read_bytes())
            return (py_out / "analysis_report.md").read_text(encoding="utf-8")

    def test_unicode_small_input_parity(self):
        report = self._run_pair('local s="😀\\u{1F600}"; local x=1..2\n-- bit32 getfenv()\n', include_tokens=True)
        self.assertIn("Caracteres: 54", report)
        self.assertIn("bit32_references: 0", report)

    def test_sample_parity(self):
        sample = (ROOT / "sample_obfuscated.lua").read_text(encoding="utf-8")
        report = self._run_pair(sample)
        self.assertIn("Tokens: 33511", report)
        self.assertIn("Cadenas: 143", report)


if __name__ == "__main__":
    unittest.main(verbosity=2)
