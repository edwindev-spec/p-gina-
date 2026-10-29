#!/usr/bin/env node
'use strict';
// Static-only Lua/MoonVeil triage. The input is never evaluated or executed.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const VERSION = '3.0.0';
const TOOL_NAME = 'MoonVeil Static Deobfuscator';
const KEYWORDS = new Set(['and','break','continue','do','else','elseif','end','false','for','function','if','in','local','nil','not','or','repeat','return','then','true','until','while']);
const OPERATORS = ['...','..=','//','==','~=','<=','>=','<<','>>','::','+=','-=','*=','/=','%=','^=','..','->','??'].sort((a,b) => b.length-a.length);
const LONG_OPEN = /^\[(=*)\[/;
const NUMBER_RE = /^(?:0[bB][01]+|0[xX](?:[0-9a-fA-F]+(?:\.(?!\.)[0-9a-fA-F]*)?|\.[0-9a-fA-F]+)(?:[pP][+-]?\d+)?|(?:\d+\.(?!\.)\d*|\.\d+|\d+)(?:[eE][+-]?\d+)?)/;
const IDENT_RE = /^[A-Za-z_][A-Za-z0-9_]*/;
const CUSTOM_BASE85 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~';

function longBracket(src, start) {
  const m = src.slice(start).match(LONG_OPEN);
  if (!m) return null;
  const close = `]${m[1]}]`;
  const at = src.indexOf(close, start + m[0].length);
  return {end: at < 0 ? src.length : at + close.length, bodyStart: start + m[0].length, closed: at >= 0};
}
function offsetMap(src) {
  // The public offset convention is Unicode code points, not JS UTF-16 units.
  const map = new Int32Array(src.length + 1);
  let u = 0, cp = 0;
  while (u < src.length) {
    map[u] = cp;
    const code = src.codePointAt(u), width = code > 0xFFFF ? 2 : 1;
    if (width === 2) map[u+1] = cp;
    u += width; cp++;
    map[u] = cp;
  }
  return map;
}
function lex(src) {
  const tokens = [], diagnostics = []; let i = 0;
  const push = (kind, start, end) => tokens.push({kind, value: src.slice(start,end), _start:start, _end:end});
  while (i < src.length) {
    const c = src[i];
    if (/\s/.test(c)) { i++; continue; }
    const start = i;
    if (src.startsWith('--', i)) {
      const lb = longBracket(src, i+2);
      if (lb) {
        i = lb.end;
        if (!lb.closed) diagnostics.push({severity:'error',code:'unterminated_long_comment',_offset:start,message:'Comentario largo sin delimitador de cierre.'});
      } else { const nl = src.indexOf('\n',i); i = nl < 0 ? src.length : nl; }
      push('comment',start,i); continue;
    }
    if (c === '`') {
      i++; let closed = false;
      while (i < src.length) {
        if (src[i] === '\\') { i += 2; continue; }
        if (src[i] === '`') { i++; closed = true; break; }
        i++;
      }
      i = Math.min(i,src.length); push('string',start,i);
      if (!closed) diagnostics.push({severity:'error',code:'unterminated_template_string',_offset:start,message:'Cadena de plantilla Luau sin acento grave de cierre.'});
      continue;
    }
    if (c === '"' || c === "'") {
      const q = c; i++; let closed = false;
      while (i < src.length) {
        if (src[i] === '\\') {
          if (i+2<src.length&&src[i+1]==='\r'&&src[i+2]==='\n') i+=3;
          else i+=2;
          continue;
        }
        if (src[i] === q) { i++; closed = true; break; }
        if (src[i] === '\r' || src[i] === '\n') break;
        i++;
      }
      i = Math.min(i,src.length); push('string',start,i);
      if (!closed) diagnostics.push({severity:'error',code:'unterminated_string',_offset:start,message:'Literal de cadena sin comilla de cierre.'});
      continue;
    }
    if (c === '[') {
      const lb = longBracket(src,i);
      if (lb) {
        i = lb.end; push('string',start,i);
        if (!lb.closed) diagnostics.push({severity:'error',code:'unterminated_long_string',_offset:start,message:'Cadena larga sin delimitador de cierre.'});
        continue;
      }
    }
    if (/\d/.test(c) || (c === '.' && i+1 < src.length && /\d/.test(src[i+1]))) {
      const m = src.slice(i).match(NUMBER_RE);
      if (m) { i += m[0].length; push('number',start,i); continue; }
    }
    const id = src.slice(i).match(IDENT_RE);
    if (id) { i += id[0].length; push(KEYWORDS.has(id[0]) ? 'keyword':'ident',start,i); continue; }
    const op = OPERATORS.find(x => src.startsWith(x,i));
    if (op) { i += op.length; push('symbol',start,i); }
    else { i++; push('symbol',start,i); }
  }
  const map = offsetMap(src);
  for (const t of tokens) { t.start = map[t._start]; t.end = map[t._end]; delete t._start; delete t._end; }
  for (const d of diagnostics) { d.offset = map[d._offset]; delete d._offset; }
  return {tokens,diagnostics};
}
function tokenize(src) { return lex(src).tokens; }
function normalizeNumber(s, allNumbers=false, binaryNumbers=true) {
  try {
    if (binaryNumbers && /^0b/i.test(s)) return BigInt(`0b${s.slice(2)}`).toString();
    if (allNumbers && /^0x/i.test(s) && !/[.p]/i.test(s)) return BigInt(s).toString();
  } catch (_) { return s; }
  return s;
}
function formatTokens(tokens, allNumbers=false, binaryNumbers=true) {
  const lines=[]; let cur=[], depth=0, pendingFunctionHeader=false;
  const blockOpenAfter=new Set(['then','do','repeat']);
  const closingWords=new Set(['end','else','elseif','until']);
  const statementStarts=new Set(['local','return','if','while','for','function','repeat','end','else','elseif','until','break','continue']);
  const parenFunctionStack=[];
  const flush=()=>{if(cur.length){lines.push('    '.repeat(Math.max(0,depth))+cur.join(' ').trim());cur=[];}};
  for(const t of tokens) {
    const val=t.kind==='number'?normalizeNumber(t.value,allNumbers,binaryNumbers):t.value;
    if(t.kind==='comment'){flush();lines.push('    '.repeat(Math.max(0,depth))+val);continue;}
    if(closingWords.has(val)){flush();depth=Math.max(0,depth-1);}
    else if(statementStarts.has(val))flush();
    cur.push(val);
    if(t.kind==='keyword'&&val==='function')pendingFunctionHeader=true;
    if(t.kind==='symbol'&&val==='('){parenFunctionStack.push(pendingFunctionHeader);pendingFunctionHeader=false;}
    else if(t.kind==='symbol'&&val===')'){
      const wasFunctionParams=parenFunctionStack.length?parenFunctionStack.pop():false;
      if(wasFunctionParams){flush();depth++;}
    }
    if(blockOpenAfter.has(val)){flush();depth++;}
    else if(val==='else'){flush();depth++;}
    else if(val==='end'||val===';')flush();
  }
  flush();return lines.join('\n')+(lines.length?'\n':'');
}
function luaUnescape(literal) {
  if(literal.length>=2&&literal[0]==='`'&&literal[literal.length-1]==='`')return literal.slice(1,-1);
  const m=literal.match(/^\[(=*)\[/);
  if(m) {const close=`]${m[1]}]`; let body=literal.slice(m[0].length); if(body.endsWith(close)) body=body.slice(0,-close.length); if(body.startsWith('\n')) body=body.slice(1); return body;}
  if(literal.length<2 || ![`'`,`"`].includes(literal[0]) || literal[literal.length-1]!==literal[0]) return literal;
  const body=literal.slice(1,-1), out=[]; let i=0;
  const simple={a:'\x07',b:'\b',f:'\f',n:'\n',r:'\r',t:'\t',v:'\x0b','\\':'\\','"':'"',"'":"'"};
  while(i<body.length) {
    if(body[i]!=='\\'||i+1>=body.length) {out.push(body[i++]);continue;}
    i++; const c=body[i];
    if(Object.prototype.hasOwnProperty.call(simple,c)) {out.push(simple[c]);i++;}
    else if(c==='z') {i++;while(i<body.length&&/\s/u.test(body[i]))i++;}
    else if(c==='x'&&i+2<body.length&&/^[0-9a-fA-F]{2}$/.test(body.slice(i+1,i+3))) {out.push(String.fromCharCode(parseInt(body.slice(i+1,i+3),16)));i+=3;}
    else if(c==='u'&&body[i+1]==='{') {const end=body.indexOf('}',i+2), raw=end<0?'':body.slice(i+2,end); if(end>=0&&/^[0-9a-fA-F]+$/.test(raw)&&parseInt(raw,16)<=0x10FFFF){out.push(String.fromCodePoint(parseInt(raw,16)));i=end+1;}else{out.push('u');i++;}}
    else if(/\d/.test(c)) {let j=i;while(j<Math.min(body.length,i+3)&&/\d/.test(body[j]))j++;out.push(String.fromCharCode(parseInt(body.slice(i,j),10)%256));i=j;}
    else if(c==='\n') {out.push('\n');i++;}
    else if(c==='\r') {i++;if(body[i]==='\n')i++;out.push('\n');}
    else {out.push(c);i++;}
  }
  return out.join('');
}
const cpArray = value => Array.from(value);
function entropy(value) {
  const chars=cpArray(value); if(!chars.length)return 0;
  const counts=new Map(); for(const c of chars)counts.set(c,(counts.get(c)||0)+1);
  let h=0;for(const n of counts.values()){const p=n/chars.length;h-=p*Math.log2(p);}return Math.round(h*10000)/10000;
}
function printableRatioBytes(data) {
  if(!data.length)return 1;
  let count=0;for(const b of data)if(b===9||b===10||b===13||(b>=32&&b<=126))count++;
  return Math.round(count/data.length*10000)/10000;
}
function extractStrings(tokens) {
  const result=[];
  for(const t of tokens) if(t.kind==='string') {
    const value=luaUnescape(t.value), len=cpArray(value).length;
    const ratio= len?Math.round(cpArray(value).filter(ch=>ch==='\t'||ch==='\n'||ch==='\r'||(ch>=' '&&ch<='~')).length/len*10000)/10000:1;
    result.push({index:result.length,literal:t.value,value,length:len,entropy:entropy(value),printable_ratio:ratio,start:t.start,end:t.end});
  }
  return result;
}
function base85DecodeCustom(value) {
  if(value.length<10||!Array.from(value).every(ch=>CUSTOM_BASE85.includes(ch))||value.length%5===1)return null;
  const indexes=new Map(Array.from(CUSTOM_BASE85).map((ch,i)=>[ch,i])), out=[];
  const write32=n=>out.push((n>>>24)&255,(n>>>16)&255,(n>>>8)&255,n&255);
  const full=Math.floor(value.length/5);
  for(let i=0;i<full;i++) {
    let n=0;for(const ch of value.slice(i*5,i*5+5))n=n*85+indexes.get(ch);
    if(n>0xFFFFFFFF)return null;write32(n);
  }
  const rem=value.length%5;
  if(rem) {let n=0;for(const ch of value.slice(full*5)+CUSTOM_BASE85[0].repeat(5-rem))n=n*85+indexes.get(ch);if(n>0xFFFFFFFF)return null;const temp=[(n>>>24)&255,(n>>>16)&255,(n>>>8)&255,n&255];out.push(...temp.slice(0,rem-1));}
  return Buffer.from(out);
}
function percentDecodeBytes(value) {
  const parts=[];
  for(let i=0;i<value.length;) {
    if(value[i]==='%'&&i+2<value.length&&/^[0-9a-fA-F]{2}$/.test(value.slice(i+1,i+3))) {parts.push(Buffer.from([parseInt(value.slice(i+1,i+3),16)]));i+=3;}
    else {const cp=value.codePointAt(i),ch=String.fromCodePoint(cp);parts.push(Buffer.from(ch,'utf8'));i+=cp>0xFFFF?2:1;}
  }
  return Buffer.concat(parts);
}
function decodeCandidates(strings) {
  const results=[];
  for(const s of strings) {
    const value=s.value;if(s.length<12)continue;
    const candidate=[];
    if(s.length>=20&&s.length%2===0&&/^[0-9a-fA-F]+$/.test(value)) {try{candidate.push(['hex',Buffer.from(value,'hex'),'strict: cadena hexadecimal par']);}catch(_){}}
    if(s.length>=20&&/^[A-Za-z0-9+/]*={0,2}$/.test(value)&&value.length%4===0) {
      try{const b=Buffer.from(value,'base64');if(b.length&&b.toString('base64')===value)candidate.push(['base64',b,'strict: alfabeto y padding Base64 válidos']);}catch(_){}
    }
    if(s.length>=20&&/^[A-Za-z0-9_-]*={0,2}$/.test(value)&&value.replace(/=+$/,'').length%4!==1) {
      try{const raw=value.replace(/=+$/,'');const b=Buffer.from(raw.replace(/-/g,'+').replace(/_/g,'/'),'base64');if(b.length&&b.toString('base64url')===raw)candidate.push(['base64url',b,'strict: round-trip Base64URL válido']);}catch(_){}
    }
    if(s.length>=20&&(value.match(/%[0-9a-fA-F]{2}/g)||[]).length>=3) {const b=percentDecodeBytes(value);if(b.toString('utf8')!==value)candidate.push(['percent-encoding',b,'heuristic: secuencias %HH encontradas']);}
    if(s.length>=20&&!(value.length===CUSTOM_BASE85.length&&new Set(Array.from(value)).size===CUSTOM_BASE85.length&&Array.from(value).every(ch=>CUSTOM_BASE85.includes(ch)))&&Array.from(value).every(ch=>CUSTOM_BASE85.includes(ch))) {const b=base85DecodeCustom(value);if(b&&b.length)candidate.push(['custom-base85',b,'experimental: alfabeto Base85 candidato; formato no confirmado']);}
    const seen=new Set();
    for(const [encoding,data,basis] of candidate) {
      const digest=crypto.createHash('sha256').update(data).digest('hex'), key=encoding+':'+digest;if(seen.has(key))continue;seen.add(key);
      let preview,preview_kind='utf8';
      try{preview=new TextDecoder('utf-8',{fatal:true}).decode(data);preview=cpArray(preview).slice(0,100).join('');}
      catch(_){preview=data.subarray(0,48).toString('hex').replace(/(..)/g,'$1 ').trim();preview_kind='hex';}
      results.push({source_string_index:s.index,source_length:s.length,encoding_candidate:encoding,confidence:encoding==='custom-base85'?'experimental':'heuristic',basis,decoded_bytes:data.length,decoded_sha256:digest,entropy_bytes:entropy(data.toString('latin1')),printable_ratio:printableRatioBytes(data),preview_kind,preview});
    }
  }
  return results;
}
function withLocations(src,tokens) {
  const starts=[0],map=offsetMap(src);for(let i=0;i<src.length;i++)if(src[i]==='\n')starts.push(map[i+1]);
  function lineColumn(cpOffset) {
    let lo=0,hi=starts.length;while(lo<hi){const mid=(lo+hi)>>1;if(starts[mid]<=cpOffset)lo=mid+1;else hi=mid;}
    const index=Math.max(0,lo-1);return {line:index+1,column:cpOffset-starts[index]+1,lineStart:starts[index]};
  }
  return tokens.map(t=>{const a=lineColumn(t.start),b=lineColumn(t.end);return {kind:t.kind,value:t.value,start:t.start,end:t.end,line:a.line,column:a.column,end_line:b.line,end_column:t.end-b.lineStart+1};});
}
function inspectVMStructure(tokens,strings) {
  const code=tokens.filter(t=>t.kind!=='comment');
  const pairFor={')':'(',']':'[','}':'{'}, stack=[], matching=new Map();
  for(let i=0;i<code.length;i++) {
    const t=code[i];if(t.kind!=='symbol')continue;
    if(['(','[','{'].includes(t.value))stack.push([t.value,i]);
    else if(Object.prototype.hasOwnProperty.call(pairFor,t.value)&&stack.length&&stack[stack.length-1][0]===pairFor[t.value]) {const opening=stack.pop()[1];matching.set(opening,i);matching.set(i,opening);}
  }
  let rootOpen=null;
  for(let i=0;i<code.length-2;i++)if(code[i].kind==='keyword'&&code[i].value==='return'&&code[i+1].value==='('&&code[i+2].value==='{'){rootOpen=i+2;break;}
  const rootEntries=[];let rootStart=null,rootEnd=null,rootFinish=null;
  if(rootOpen!==null&&matching.has(rootOpen)) {
    rootEnd=matching.get(rootOpen);rootStart=code[rootOpen].start;rootFinish=code[rootEnd].end;
    const delimStack=['{'],blockStack=[];let itemStart=rootOpen+1;
    for(let i=rootOpen+1;i<rootEnd;i++) {
      const tok=code[i],v=tok.value;
      if(tok.kind==='symbol') {
        if(['(','[','{'].includes(v))delimStack.push(v);
        else if(Object.prototype.hasOwnProperty.call(pairFor,v)&&delimStack.length>1&&delimStack[delimStack.length-1]===pairFor[v])delimStack.pop();
      }
      if(tok.kind==='keyword') {
        if(['function','if','for','while','repeat'].includes(v))blockStack.push(v);
        else if(v==='do'){if(!(blockStack.length&&['for','while'].includes(blockStack[blockStack.length-1])))blockStack.push('do');}
        else if(v==='end'){if(blockStack.length)blockStack.pop();}
        else if(v==='until'){if(blockStack.length&&blockStack[blockStack.length-1]==='repeat')blockStack.pop();}
      }
      if(tok.kind==='symbol'&&v===','&&delimStack.length===1&&blockStack.length===0){if(itemStart<i)rootEntries.push(code.slice(itemStart,i));itemStart=i+1;}
    }
    if(itemStart<rootEnd)rootEntries.push(code.slice(itemStart,rootEnd));
  }
  function tokenPreview(part,limit=18) {
    return part.slice(0,limit).map(t=>t.kind==='string'?`<string:${Math.max(0,cpArray(luaUnescape(t.value)).length)}>`:t.value.slice(0,28)).join(' ');
  }
  const rootSummary=[];
  for(let idx=0;idx<rootEntries.length;idx++) {
    const part=rootEntries[idx];if(!part.length)continue;
    let functions=0,cache=0,bit32=0,whileTrue=0;
    for(let i=0;i<part.length;i++) {
      const t=part[i];if(t.kind==='keyword'&&t.value==='function')functions++;
      if(t.kind==='ident'&&t.value==='bit32')bit32++;
      if(i+3<part.length&&part[i].kind==='ident'&&part[i+1].value==='.'&&part[i+2].value==='U'&&part[i+3].value==='[')cache++;
      if(i+2<part.length&&part[i].kind==='keyword'&&part[i].value==='while'&&part[i+1].value==='true'&&part[i+2].value==='do')whileTrue++;
    }
    const stringIndices=strings.filter(s=>part[0].start<=s.start&&s.end<=part[part.length-1].end).map(s=>s.index);
    rootSummary.push({index:idx,start:part[0].start,end:part[part.length-1].end,token_count:part.length,first_token_kind:part[0].kind,first_token:part[0].kind!=='string'?part[0].value:'<string>',function_keyword_count:functions,bit32_references:bit32,while_true_loops:whileTrue,vm_cache_style_accesses:cache,string_indices:stringIndices,preview:tokenPreview(part)});
  }
  const nameTables=[];
  for(let i=0;i<code.length;i++) {
    const tok=code[i];if(tok.kind!=='symbol'||tok.value!=='{'||!matching.has(i))continue;
    const close=matching.get(i);let directValues=[],valid=true,depth=1;
    for(let j=i+1;j<close;j++) {
      const t=code[j];
      if(t.kind==='symbol'&&['(','[','{'].includes(t.value))depth++;
      else if(t.kind==='symbol'&&[')',']','}'].includes(t.value))depth--;
      else if(depth===1) {
        if(t.kind==='string')directValues.push(luaUnescape(t.value));
        else if(t.kind==='symbol'&&t.value===',')continue;
        else {valid=false;break;}
      }
    }
    if(valid&&directValues.length>=8)nameTables.push({start:tok.start,end:code[close].end,count:directValues.length,values:directValues});
  }
  nameTables.sort((a,b)=>b.count-a.count||a.start-b.start);
  const likely=nameTables.filter(x=>x.values.every(v=>cpArray(v).length>0&&cpArray(v).length<=8));
  const selected=likely.length?likely[0]:(nameTables.length?nameTables[0]:null);
  return {returned_table_found:rootOpen!==null&&rootEnd!==null,returned_table_start:rootStart,returned_table_end:rootOpen!==null&&rootEnd!==null?rootFinish:null,returned_table_element_count:rootSummary.length,returned_table_elements:rootSummary,string_array_candidates:nameTables.slice(0,10),likely_runtime_name_table:selected,name_alignment:'not inferred: the returned table contains mixed values/nested closures; position-by-position mapping would be speculative'};
}
function analyze(src,tokens,strings,filename,diagnostics=[],decodings=[],rawBytes=Buffer.from(src,'utf8')) {
  const header=src.slice(0,300),v=header.match(/MoonVeil\s+([\w.-]+)/i);
  const visible=tokens.filter(t=>t.kind!=='comment'), vals=visible.map(t=>t.value),typeCounts={};
  for(const t of tokens)typeCounts[t.kind]=(typeCounts[t.kind]||0)+1;
  const idents=new Map(),symbols=new Map(),keywords=new Map();
  for(const t of visible){const target=t.kind==='ident'?idents:t.kind==='symbol'?symbols:t.kind==='keyword'?keywords:null;if(target)target.set(t.value,(target.get(t.value)||0)+1);}
  const top=(map,keyName)=>[...map.entries()].sort((a,b)=>b[1]-a[1]||(a[0]<b[0]?-1:a[0]>b[0]?1:0)).slice(0,30).map(([name,count])=>({[keyName]:name,count}));
  const seqCount=seq=>{let c=0;for(let i=0;i<=vals.length-seq.length;i++)if(seq.every((v,j)=>vals[i+j]===v))c++;return c;};
  const identRef=name=>visible.filter(t=>t.kind==='ident'&&t.value===name).length;
  let anon=0, funcs=0,cache=0;
  for(let i=0;i<vals.length;i++){if(vals[i]==='function'){funcs++;if(vals[i+1]==='(')anon++;}if(i+3<visible.length&&visible[i].kind==='ident'&&vals[i+1]==='.'&&vals[i+2]==='U'&&vals[i+3]==='[')cache++;}
  const signals={anonymous_function_literals:anon,function_keywords:funcs,while_true_loops:seqCount(['while','true','do']),repeat_blocks:vals.filter(v=>v==='repeat').length,bit32_references:identRef('bit32'),getfenv_references:identRef('getfenv'),setfenv_references:identRef('setfenv'),loadstring_references:identRef('loadstring'),load_references:identRef('load'),debug_references:identRef('debug'),require_references:identRef('require'),vm_cache_style_accesses:cache,hex_literals:tokens.filter(t=>t.kind==='number'&&/^0x/i.test(t.value)).length,binary_literals:tokens.filter(t=>t.kind==='number'&&/^0b/i.test(t.value)).length};
  const alphabetCandidates=strings.filter(s=>s.length>=70&&cpArray(s.value).length===new Set(cpArray(s.value)).size&&cpArray(s.value).every(ch=>CUSTOM_BASE85.includes(ch))&&s.length>=80&&s.length<=99);
  const vmStructure=inspectVMStructure(tokens,strings);
  const longCandidates=[...strings].filter(s=>s.length>=32).sort((a,b)=>b.length-a.length||a.index-b.index);
  const topStrings=[...strings].sort((a,b)=>b.length-a.length||a.index-b.index).slice(0,10);
  const hash=crypto.createHash('sha256').update(rawBytes).digest('hex');
  return {tool:TOOL_NAME,tool_version:VERSION,input_file:filename,offset_unit:'Unicode code points (0-based start, end-exclusive)',input_characters:cpArray(src).length,input_bytes_utf8:rawBytes.length,sha256:hash,header:src.split(/\r?\n/,1)[0]||'',detected_moonveil_version:v?v[1]:null,token_count:tokens.length,token_counts:Object.fromEntries(Object.entries(typeCounts).sort(([a],[b])=>a<b?-1:a>b?1:0)),keyword_frequency:Object.fromEntries(top(keywords,'name').map(x=>[x.name,x.count])),top_identifiers:top(idents,'name'),top_operators:top(symbols,'operator'),string_literal_count:strings.length,largest_string_literals:topStrings.map(s=>({index:s.index,length:s.length,entropy:s.entropy,printable_ratio:s.printable_ratio,preview:cpArray(s.value).slice(0,72).join('')})),long_string_candidates:longCandidates.slice(0,20).map(s=>({index:s.index,length:s.length,entropy:s.entropy,start:s.start,end:s.end,preview:cpArray(s.value).slice(0,100).join('')})),custom_base85_alphabet_candidates:alphabetCandidates.map(s=>({index:s.index,length:s.length,value:s.value})),signals,vm_structure:vmStructure,decoder_candidates:decodings.map(d=>({source_string_index:d.source_string_index,encoding_candidate:d.encoding_candidate,confidence:d.confidence,decoded_bytes:d.decoded_bytes,decoded_sha256:d.decoded_sha256,entropy_bytes:d.entropy_bytes,printable_ratio:d.printable_ratio,preview_kind:d.preview_kind,preview:d.preview})),lexical_diagnostics:diagnostics,assessment:['El análisis excluye cadenas y comentarios al contar referencias a funciones y patrones de VM, reduciendo falsos positivos.','La salida normalizada conserva el orden de tokens; la indentación es heurística y no equivale a un AST.','Las decodificaciones generadas son hipótesis estáticas. En particular, custom-base85 no confirma por sí sola el formato del bytecode.','El patrón observado es compatible con un dispatcher/VM. Recuperar el fuente requeriría reconstruir la semántica de su cargador y sus opcodes.'],safety:'No se ejecutó el sample ni se evaluó código Lua; solo se analizaron sus bytes/texto y tokens.'};
}
function writeJsonl(file,items) {fs.writeFileSync(file,items.map(x=>JSON.stringify(x)).join('\n')+(items.length?'\n':''),'utf8');}
function run(inputPath,outDir,options={}) {
  const rawBytes=fs.readFileSync(inputPath),src=rawBytes.toString('utf8'),{tokens,diagnostics}=lex(src),strings=extractStrings(tokens),decodings=decodeCandidates(strings);
  const report=analyze(src,tokens,strings,path.basename(inputPath),diagnostics,decodings,rawBytes);
  fs.mkdirSync(outDir,{recursive:true});
  // Remove stale JSON artifacts from previous releases; this version emits no JSON.
  const removeStale=(dir)=>{for(const ent of fs.readdirSync(dir,{withFileTypes:true})){const p=path.join(dir,ent.name);if(ent.isDirectory())removeStale(p);else if(/\.(json|jsonl)$/i.test(ent.name))fs.unlinkSync(p);}};removeStale(outDir);
  fs.writeFileSync(path.join(outDir,'normalized.lua'),formatTokens(tokens,!!options.allNumbers,options.binaryNumbers!==false),'utf8');
  const reportLines=[`# ${TOOL_NAME} ${VERSION}`,'',`- Entrada: \`${path.basename(inputPath)}\``,`- SHA-256: \`${report.sha256}\``,`- Versión MoonVeil detectada: \`${report.detected_moonveil_version||'no detectada'}\``,`- Caracteres: ${report.input_characters}`,`- Bytes UTF-8: ${report.input_bytes_utf8}`,`- Tokens: ${report.token_count}`,`- Cadenas: ${report.string_literal_count}`,'','## Señales estáticas','',...Object.entries(report.signals).map(([k,v])=>`- ${k}: ${v}`),'','## Diagnósticos léxicos','',...(diagnostics.map(d=>`- ${d.severity} \`${d.code}\` offset ${d.offset}: ${d.message}`).length?diagnostics.map(d=>`- ${d.severity} \`${d.code}\` offset ${d.offset}: ${d.message}`):['- Sin diagnósticos léxicos.']),'','## Evaluación','',...report.assessment.map(x=>`- ${x}`),'','No se ejecutó el código Lua.',''];
  fs.writeFileSync(path.join(outDir,'analysis_report.md'),reportLines.join('\n'),'utf8');
  const flatten=(v,p='')=>Object.entries(v||{}).flatMap(([k,x])=>x&&typeof x==='object'?[`${p}${k}:`,flatten(x,p+'  ')].flat():[`${p}${k}: ${x}`]).join('\n');
  fs.writeFileSync(path.join(outDir,'vm_structure.txt'),flatten(report.vm_structure)+'\n','utf8');
  const stringLines=[];for(const s of strings)stringLines.push(`CADENA #${s.index} | longitud=${s.length} | entropía=${s.entropy} | offsets=${s.start}:${s.end}`,s.value,'='.repeat(72));
  fs.writeFileSync(path.join(outDir,'extracted_strings.txt'),stringLines.join('\n')+'\n','utf8');
  const decodeLines=decodings.map(d=>`Cadena #${d.source_string_index} | candidato=${d.encoding_candidate} | confianza=${d.confidence} | bytes=${d.decoded_bytes} | sha256=${d.decoded_sha256} | ratio imprimible=${d.printable_ratio}\nBase: ${d.basis}\nVista previa: ${d.preview}\n`);
  fs.writeFileSync(path.join(outDir,'string_decodings.txt'),decodeLines.join('\n')||'No se encontraron candidatos de decodificación.\n','utf8');
  if(options.includeTokens!==false){const esc=v=>String(v).replace(/\\/g,'\\\\').replace(/\t/g,'\\t').replace(/\r/g,'\\r').replace(/\n/g,'\\n');const rows=['index\tkind\tstart\tend\tvalue',...tokens.map((t,i)=>`${i}\t${t.kind}\t${t.start}\t${t.end}\t${esc(t.value)}`)];fs.writeFileSync(path.join(outDir,'tokens.tsv'),rows.join('\n')+'\n','utf8');}
  const decodedDir=path.join(outDir,'decoded_candidates'),written=new Set();
  for(const d of decodings)if(d.encoding_candidate==='custom-base85') {
    const key=`${d.source_string_index}:${d.encoding_candidate}`;if(written.has(key))continue;written.add(key);
    const payload=base85DecodeCustom(strings[d.source_string_index].value);if(!payload)continue;
    fs.mkdirSync(decodedDir,{recursive:true});const stem=`string_${String(d.source_string_index).padStart(4,'0')}_custom_base85`;
    fs.writeFileSync(path.join(decodedDir,stem+'.bin'),payload);fs.writeFileSync(path.join(decodedDir,stem+'.hex.txt'),payload.toString('hex').match(/.{1,2}/g).join(' ')+'\n','utf8');
  }
  const candidates=strings.filter(s=>s.length>=32);
  fs.writeFileSync(path.join(outDir,'largest_string_candidate.txt'),candidates.length?candidates.sort((a,b)=>b.length-a.length)[0].value:'No string literal of 32 or more characters was found.\n','utf8');
  const notes=['# Static triage notes','','- Input: `'+path.basename(inputPath)+'`','- SHA-256: `'+report.sha256+'`','- Detected MoonVeil version: `'+(report.detected_moonveil_version||'not detected')+'`','- Tokens: `'+tokens.length+'`; string literals: `'+strings.length+'`','- Lexical diagnostics: `'+diagnostics.length+'`','','## Largest string candidates',''];
  if(candidates.length)for(const s of [...candidates].sort((a,b)=>b.length-a.length||a.index-b.index).slice(0,10))notes.push('- String #'+s.index+' at offsets '+s.start+'–'+s.end+': length '+s.length+', entropy '+s.entropy+'; preview `'+cpArray(s.value).slice(0,80).join('').replace(/`/g,'\\`')+'`');
  else notes.push('- None');
  notes.push('','## Decoder candidates','');
  if(decodings.length)for(const d of decodings)notes.push('- String #'+d.source_string_index+': `'+d.encoding_candidate+'` ('+d.confidence+'), '+d.decoded_bytes+' bytes, SHA-256 `'+d.decoded_sha256+'`; printable ratio '+d.printable_ratio+'. '+d.basis);
  else notes.push('- No supported candidate encoding met the current thresholds.');
  notes.push('','## Important limitation','','This report is static triage, not a recovered original source or a proven VM disassembly. No Lua runtime was invoked.','');
  fs.writeFileSync(path.join(outDir,'triage_notes.md'),notes.join('\n'),'utf8');
  console.log(`${TOOL_NAME} ${VERSION}`);console.log(`Input: ${inputPath} (${cpArray(src).length} characters; ${rawBytes.length} source bytes)`);console.log(`Detected version: ${report.detected_moonveil_version||'not detected'}`);console.log(`Tokens: ${tokens.length} | strings: ${strings.length} | decoder candidates: ${decodings.length} | lexical diagnostics: ${diagnostics.length}`);console.log(`Output: ${path.resolve(outDir)}`);console.log('Static analysis only; the Lua input was not executed.');
  return report;
}
function usage(){console.log('MoonVeil Static Deobfuscator '+VERSION+'\nUsage: node moonveil_deobfuscator.js <input.lua> [-o output_dir] [--normalize-all-numbers] [--preserve-binary-literals] [--no-token-dump] [--strict]');}
function main(argv) {
  let input='sample_obfuscated.lua',outDir='moonveil_out',allNumbers=false,binaryNumbers=true,includeTokens=true,strict=false;
  for(let i=0;i<argv.length;i++) {const a=argv[i];if(a==='-h'||a==='--help'){usage();return 0;}if(a==='-o'||a==='--out-dir'){if(!argv[i+1])throw new Error(`Falta el valor de ${a}`);outDir=argv[++i];}else if(a==='--normalize-all-numbers')allNumbers=true;else if(a==='--preserve-binary-literals')binaryNumbers=false;else if(a==='--no-token-dump')includeTokens=false;else if(a==='--strict')strict=true;else if(a.startsWith('-'))throw new Error(`Opción desconocida: ${a}`);else{input=a;}}
  if(!fs.existsSync(input)||!fs.statSync(input).isFile())throw new Error(`No existe el archivo de entrada: ${input}`);
  const report=run(input,outDir,{allNumbers,binaryNumbers,includeTokens});return strict&&report.lexical_diagnostics.length?3:0;
}
if(require.main===module) {try{process.exitCode=main(process.argv.slice(2));}catch(e){console.error('Error: '+e.message);process.exitCode=2;}}
module.exports={VERSION,KEYWORDS,OPERATORS,CUSTOM_BASE85,lex,tokenize,normalizeNumber,formatTokens,luaUnescape,entropy,extractStrings,base85DecodeCustom,decodeCandidates,inspectVMStructure,analyze,run};
