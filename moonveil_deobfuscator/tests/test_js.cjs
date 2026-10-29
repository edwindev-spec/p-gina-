'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const md = require('../moonveil_deobfuscator.js');
const ROOT = path.resolve(__dirname, '..');

test('lexer keeps concatenation distinct from numeric literals', () => {
  const got = md.tokenize('local x=1..2; local y=1.5..3').map(t=>t.value);
  assert.deepEqual(got, ['local','x','=','1','..','2',';','local','y','=','1.5','..','3']);
});

test('long strings, Luau templates/comments and diagnostics', () => {
  const a=md.lex('local s=[==[hello ]=] world]==] --[=[ note ]=]\nlocal t=`hello {name}`');
  assert.equal(a.diagnostics.length,0);
  assert.deepEqual(a.tokens.filter(t=>t.kind==='string').map(t=>t.value),['[==[hello ]=] world]==]','`hello {name}`']);
  const b=md.lex('local s="unterminated');
  assert.ok(b.diagnostics.some(d=>d.code==='unterminated_string'));
  const c=md.lex('local t=`unterminated');
  assert.ok(c.diagnostics.some(d=>d.code==='unterminated_template_string'));
});

test('numeric normalization options preserve numeric values', () => {
  assert.equal(md.normalizeNumber('0b110'),'6');
  assert.equal(md.normalizeNumber('0xFF',true),'255');
  assert.equal(md.normalizeNumber('0xA.Fp1',true),'0xA.Fp1');
  assert.equal(md.normalizeNumber('0b110',false,false),'0b110');
});

test('Unicode offsets count code points', () => {
  const src='local x="😀";';
  const semicolon=md.tokenize(src).find(t=>t.value===';');
  assert.equal(semicolon.start, Array.from(src.slice(0,src.indexOf(';'))).length);
  assert.equal(semicolon.end, semicolon.start+1);
});

test('Lua escapes decode identically', () => {
  assert.equal(md.luaUnescape('"A\\x42\\067\\z  C\\u{1F600}"'),'ABCC😀');
  assert.equal(md.luaUnescape('[=[\nhello]=]'),'hello');
});

test('source strings/comments are excluded from VM signals', () => {
  const source='-- bit32 getfenv() while true do\nlocal s="bit32 getfenv() while true do"\n';
  const {tokens,diagnostics}=md.lex(source), strings=md.extractStrings(tokens);
  const report=md.analyze(source,tokens,strings,'test.lua',diagnostics,[]);
  assert.equal(report.signals.bit32_references,0);
  assert.equal(report.signals.getfenv_references,0);
  assert.equal(report.signals.while_true_loops,0);
});

test('sample structure and candidate decoding are classified conservatively', () => {
  const src=fs.readFileSync(path.join(ROOT,'sample_obfuscated.lua'),'utf8');
  const {tokens,diagnostics}=md.lex(src), strings=md.extractStrings(tokens), candidates=md.decodeCandidates(strings);
  const report=md.analyze(src,tokens,strings,'sample_obfuscated.lua',diagnostics,candidates);
  assert.equal(report.detected_moonveil_version,'2.1.0');
  assert.equal(tokens.length,33511);
  assert.equal(strings.length,143);
  assert.equal(report.vm_structure.returned_table_element_count,38);
  assert.equal(report.vm_structure.likely_runtime_name_table.count,35);
  assert.equal(candidates.length,1);
  assert.equal(candidates[0].confidence,'experimental');
  assert.equal(candidates[0].decoded_bytes,195);
});
