# Static triage notes

- Input: `sample_obfuscated.lua`
- SHA-256: `f7596cc93af39832c4054625aab4bca9770fabf0fc782bd09e5d228366b10d4a`
- Detected MoonVeil version: `2.1.0`
- Tokens: `33511`; string literals: `143`
- Lexical diagnostics: `0`

## Largest string candidates

- String #60 at offsets 16351–16597: length 244, entropy 6.0138; preview `{|EtG1Uo%3IsXAI0X$6@^#uR%1G\`_Y5%C%SuN?Fd^BwL2|F0h81g;k79RK74t_HPV?H~W(6yyT(U$#U4`
- String #61 at offsets 17326–17413: length 85, entropy 6.4094; preview `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`

## Decoder candidates

- String #60: `custom-base85` (experimental), 195 bytes, SHA-256 `7401c6f35c4888dc73fabc1f2ed9977c84bf9000dc6307f9eb940a56e78677bf`; printable ratio 0.2974. experimental: alfabeto Base85 candidato; formato no confirmado

## Important limitation

This report is static triage, not a recovered original source or a proven VM disassembly. No Lua runtime was invoked.
