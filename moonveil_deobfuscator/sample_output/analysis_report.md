# MoonVeil Static Deobfuscator 2.1.0

- Entrada: `sample_obfuscated.lua`
- SHA-256: `f7596cc93af39832c4054625aab4bca9770fabf0fc782bd09e5d228366b10d4a`
- Versión MoonVeil detectada: `2.1.0`
- Caracteres: 70082
- Bytes UTF-8: 70082
- Tokens: 33511
- Cadenas: 143

## Señales estáticas

- anonymous_function_literals: 51
- function_keywords: 52
- while_true_loops: 14
- repeat_blocks: 7
- bit32_references: 7
- getfenv_references: 1
- setfenv_references: 0
- loadstring_references: 0
- load_references: 0
- debug_references: 0
- require_references: 0
- vm_cache_style_accesses: 523
- hex_literals: 2450
- binary_literals: 1712

## Diagnósticos léxicos

- Sin diagnósticos léxicos.

## Evaluación

- El análisis excluye cadenas y comentarios al contar referencias a funciones y patrones de VM, reduciendo falsos positivos.
- La salida normalizada conserva el orden de tokens; la indentación es heurística y no equivale a un AST.
- Las decodificaciones generadas son hipótesis estáticas. En particular, custom-base85 no confirma por sí sola el formato del bytecode.
- El patrón observado es compatible con un dispatcher/VM. Recuperar el fuente requeriría reconstruir la semántica de su cargador y sus opcodes.

No se ejecutó el código Lua.
