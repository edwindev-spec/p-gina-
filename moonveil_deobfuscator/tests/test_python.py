import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import moonveil_deobfuscator as md


class LexerTests(unittest.TestCase):
    def test_concat_does_not_consume_decimal_point(self):
        tokens = md.tokenize("local x=1..2; local y=1.5..3")
        values = [t.value for t in tokens]
        self.assertEqual(values, ["local", "x", "=", "1", "..", "2", ";", "local", "y", "=", "1.5", "..", "3"])

    def test_long_brackets_template_strings_and_long_comments(self):
        tokens, diagnostics = md.lex("local s=[==[hello ]=] world]==] --[=[ note ]=]\nlocal t=`hello {name}`")
        self.assertEqual(diagnostics, [])
        strings = [t.value for t in tokens if t.kind == "string"]
        comments = [t.value for t in tokens if t.kind == "comment"]
        self.assertEqual(strings, ["[==[hello ]=] world]==]", "`hello {name}`"])
        self.assertEqual(comments, ["--[=[ note ]=]"])

    def test_unterminated_literals_are_reported(self):
        _, diagnostics = md.lex('local s = "unterminated\n--[=[unterminated')
        codes = {d["code"] for d in diagnostics}
        self.assertIn("unterminated_string", codes)
        self.assertIn("unterminated_long_comment", codes)

    def test_unicode_codepoint_offsets(self):
        source = 'local x="😀";'
        tokens = md.tokenize(source)
        semicolon = next(t for t in tokens if t.value == ";")
        self.assertEqual(semicolon.start, source.index(";"))
        self.assertEqual(semicolon.end, source.index(";") + 1)

    def test_numeric_normalization_options(self):
        self.assertEqual(md.normalize_number("0b110"), "6")
        self.assertEqual(md.normalize_number("0xFF", all_numbers=True), "255")
        self.assertEqual(md.normalize_number("0xA.Fp1", all_numbers=True), "0xA.Fp1")
        self.assertEqual(md.normalize_number("0b110", binary_numbers=False), "0b110")

    def test_lua_string_escapes(self):
        self.assertEqual(md.lua_unescape(r'"A\x42\067\z  C\u{1F600}"'), "ABCC😀")
        self.assertEqual(md.lua_unescape("[=[\nhello]=]"), "hello")

    def test_normalizer_preserves_token_stream(self):
        source = 'local s="a -- b"; local x=0b101; if x>0 then x=x.."z" else x=2 end -- tail\n'
        tokens = md.tokenize(source)
        normalized = md.format_tokens(tokens)
        normalized_tokens = md.tokenize(normalized)
        expected = [(t.kind, md.normalize_number(t.value) if t.kind == "number" else t.value) for t in tokens]
        actual = [(t.kind, t.value) for t in normalized_tokens]
        self.assertEqual(actual, expected)

    def test_patterns_inside_strings_and_comments_are_not_signals(self):
        source = '-- bit32 getfenv() while true do\nlocal s="bit32 getfenv() while true do"\n'
        tokens, diags = md.lex(source)
        strings = md.extract_strings(tokens)
        report = md.analyze(source, tokens, strings, "test.lua", diags, [])
        self.assertEqual(report["signals"]["bit32_references"], 0)
        self.assertEqual(report["signals"]["getfenv_references"], 0)
        self.assertEqual(report["signals"]["while_true_loops"], 0)


class SampleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sample = ROOT / "sample_obfuscated.lua"
        cls.source = cls.sample.read_text(encoding="utf-8")
        cls.tokens, cls.diagnostics = md.lex(cls.source)
        cls.strings = md.extract_strings(cls.tokens)

    def test_sample_signature(self):
        self.assertEqual(len(self.tokens), 33511)
        self.assertEqual(len(self.strings), 143)
        self.assertEqual(self.diagnostics, [])
        report = md.analyze(self.source, self.tokens, self.strings, self.sample.name, self.diagnostics, md.decode_candidates(self.strings))
        self.assertEqual(report["detected_moonveil_version"], "2.1.0")
        self.assertEqual(report["vm_structure"]["returned_table_element_count"], 38)
        self.assertEqual(report["vm_structure"]["likely_runtime_name_table"]["count"], 35)

    def test_sample_normalization_preserves_token_order(self):
        normalized = md.format_tokens(self.tokens)
        re_tokens = md.tokenize(normalized)
        expected = [(t.kind, md.normalize_number(t.value) if t.kind == "number" else t.value) for t in self.tokens]
        self.assertEqual([(t.kind, t.value) for t in re_tokens], expected)

    def test_custom_base85_is_marked_experimental(self):
        decodings = md.decode_candidates(self.strings)
        self.assertEqual(len(decodings), 1)
        self.assertEqual(decodings[0]["encoding_candidate"], "custom-base85")
        self.assertEqual(decodings[0]["confidence"], "experimental")
        self.assertEqual(decodings[0]["decoded_bytes"], 195)
        self.assertEqual(decodings[0]["decoded_sha256"], "7401c6f35c4888dc73fabc1f2ed9977c84bf9000dc6307f9eb940a56e78677bf")


class AstTests(unittest.TestCase):
    @staticmethod
    def parse(src):
        import moonveil_ast as ma
        return ma, ma.parse(md.lex(src)[0])

    def roundtrip(self, src):
        ma, chunk = self.parse(src)
        printed = ma.Printer().chunk(chunk)
        self.assertEqual(printed, ma.Printer().chunk(ma.parse(md.lex(printed)[0])))
        return printed

    def test_precedence_is_preserved(self):
        out = self.roundtrip("x = (a + b) * c; y = a - (b - c); z = (a .. b) .. c; w = a ^ (b ^ c); v = (-a) ^ b; u = -(a ^ b); t = not (a == b)")
        self.assertIn("x = (a + b) * c", out)
        self.assertIn("y = a - (b - c)", out)
        self.assertIn("z = (a .. b) .. c", out)
        self.assertIn("w = a ^ b ^ c", out)
        self.assertIn("v = (-a) ^ b", out)
        self.assertIn("u = -a ^ b", out)
        self.assertIn("t = not (a == b)", out)

    def test_luau_syntax_parses(self):
        out = self.roundtrip("local x: number = 1\n" if False else "local t = {a = 1, [2] = 'x'; 3}\nx += 0b101\nlocal f = function(...) return if x then ... else nil end\ncontinue = 1")
        self.assertIn("x += 5", out)
        self.assertIn("(if x then ... else nil)", out)

    def test_constant_folding_and_box_resolution(self):
        ma, chunk = self.parse("local a = 0x10 + 0b11 * 2; local s = 'a' .. \"\\98\" .. 1; if 1 > 2 then dead() else live() end; y = B[1][B[3]]")
        folded, stats = ma.fold_chunk(chunk)
        out = ma.Printer().chunk(folded)
        self.assertIn("local a = 22", out)
        self.assertIn('local s = "ab1"', out)
        self.assertNotIn("dead", out)
        self.assertIn("live()", out)
        self.assertIn("y = B[2]", out)
        self.assertEqual(stats.resolved_boxes, 1)

    def test_parenthesis_truncation_is_kept(self):
        ma, chunk = self.parse("x = (f()); y = (a)")
        out = ma.Printer().chunk(ma.fold_chunk(chunk)[0])
        self.assertIn("x = (f())", out)
        self.assertIn("y = a", out)

    def test_dispatcher_is_unflattened(self):
        src = "local l = 10\nwhile true do if l < 20 then a(); l = 30 elseif l < 40 then if k then l = 10 else l = 50 end; b() else return c end end"
        ma, chunk = self.parse(src)
        ds = ma.find_dispatchers(chunk)
        self.assertEqual(len(ds), 1)
        self.assertEqual(ds[0].entry, 10)
        self.assertEqual(len(ds[0].nodes), 3)
        self.assertEqual(ds[0].opaque, [])
        out = ma.render_unflattened(chunk, ds)
        self.assertIn("::s_10::", out)
        self.assertIn("do\n    return c\nend", out.replace("        ", "    "))

    def test_ternary_state_and_oracle(self):
        src = "local l = 1\nrepeat if l == 1 then l = q and 2 or X.U[7] or X:M(1) elseif l == 2 then return 1 else return 2 end until false"
        ma, chunk = self.parse(src)
        d = ma.find_dispatchers(chunk)[0]
        self.assertEqual(d.opaque, ["U[7]"])
        d2 = ma.find_dispatchers(chunk, ma.load_oracle("7\t3\n"))[0]
        self.assertEqual(d2.opaque, [])
        self.assertIn(("s", 3.0), d2.nodes)

    def test_sample_ast_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = md.run(ROOT / "sample_obfuscated.lua", Path(tmp), include_tokens=False)
            self.assertTrue(report["ast"]["parsed"])
            self.assertGreater(report["ast"]["dispatchers"], 10)
            self.assertGreater(report["ast"]["boxes"], 100)
            for name in ("deobfuscated.lua", "unflattened.lua", "deobfuscation_report.md"):
                self.assertTrue((Path(tmp) / name).is_file(), name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
