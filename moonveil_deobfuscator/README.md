# MoonVeil Static Deobfuscator — Python + JavaScript

Versión de la herramienta: **2.1.0**. Diseñada y probada con el sample proporcionado, cuya cabecera indica **MoonVeil 2.1.0**. Incluye ambos analizadores, el sample de entrada, pruebas de regresión y una ejecución de referencia. Esta versión elimina archivos JSON/JSONL antiguos de la carpeta de salida y solo genera Lua, Markdown, TXT, TSV y artefactos binarios experimentales.

> **Alcance real:** es un normalizador y analizador estático, con extracción de candidatos de datos y estructura de VM. No debe describirse como un devirtualizador completo: no reconstruye por sí solo el fuente original ni confirma la semántica de los opcodes.

## Mejoras de esta versión

- Lexer para Lua/Luau con literales entre comillas, cadenas largas `[=[...]=]`, comentarios largos, cadenas de plantilla con acento grave, operadores compuestos y números binarios/hexadecimales.
- Diagnósticos para cadenas, comentarios largos y cadenas de plantilla que no se cierran. `--strict` devuelve código de salida `3` cuando existen dichos diagnósticos.
- Normalizador con indentación más estable. La salida conserva el flujo de tokens; las conversiones de números opcionales conservan el valor numérico.
- Métricas de cadenas (longitud, entropía aproximada y proporción ASCII imprimible), inventario de identificadores/operadores y referencias a funciones de entorno.
- Las señales de VM se cuentan a partir de tokens de código, no de expresiones regulares aplicadas al archivo completo. Las cadenas y los comentarios ya no inflan esas métricas.
- Extracción de tablas de la estructura retornada y de listas que parecen contener nombres de métodos de la VM. **No se asignan nombres a closures por posición** cuando la estructura no prueba esa correspondencia.
- Decodificadores estáticos candidatos para hexadecimal, Base64/Base64URL, escapes de URL y un alfabeto Base85 personalizado. Cada resultado incluye hash y métricas. El candidato Base85 del sample está marcado como `experimental`; no se afirma que sea el formato verdadero del bytecode.
- Salidas de texto/Markdown/TSV legibles, mapa de tokens con offsets en puntos de código Unicode y versiones de Python/JavaScript con paridad de resultados comprobada sobre el sample y un caso Unicode.
- Nunca se invoca Lua/Luau, `load`, `loadstring`, `eval` ni se ejecuta el sample.

## Requisitos

Python 3.10+ y Node.js 18+. No necesita paquetes externos.

## Ejecución

Python:

```bash
python moonveil_deobfuscator.py sample_obfuscated.lua -o out_py
```

JavaScript:

```bash
node moonveil_deobfuscator.js sample_obfuscated.lua -o out_js
```

Opciones disponibles en ambas versiones:

```text
--normalize-all-numbers      Convertir también enteros hexadecimales a decimal
--preserve-binary-literals    Mantener 0b101 en normalized.lua
--no-token-dump               No generar tokens.tsv
--strict                     Código de salida 3 si hay errores léxicos
-h, --help                   Ayuda
```

Ejemplo para conservar los literales binarios y no generar el volcado grande de tokens:

```bash
python moonveil_deobfuscator.py sample_obfuscated.lua -o out --preserve-binary-literals --no-token-dump
node moonveil_deobfuscator.js sample_obfuscated.lua -o out_js --preserve-binary-literals --no-token-dump
```

## Archivos generados

| Archivo | Contenido |
|---|---|
| `normalized.lua` | Lua/Luau con espacios y saltos de línea normalizados; indentación heurística. |
| `analysis_report.md` | Hash de entrada, versión detectada, contadores, señales, diagnóstico léxico y resumen de estructura. |
| `vm_structure.txt` | Elementos de la tabla retornada, intervalos de origen, referencias por elemento y tablas candidatas de nombres. |
| `tokens.tsv` | Un token por fila tabulada, con tipo, valor, intervalo y ubicación. Omitible con `--no-token-dump`. |
| `extracted_strings.txt` | Literales de cadena, texto extraído, longitud, entropía y offsets. |
| `string_decodings.txt` | Decodificaciones candidatas con método, nivel de confianza, hash y métricas. |
| `decoded_candidates/*.bin` | Artefactos binarios candidatos; no se asumen como bytecode validado. |
| `decoded_candidates/*.hex.txt` | Volcado hexadecimal de los artefactos candidatos. |
| `largest_string_candidate.txt` | Cadena más larga con al menos 32 caracteres. |
| `triage_notes.md` | Resumen legible para una primera revisión manual. |

Los offsets (`start`, `end`) se expresan en **puntos de código Unicode**, con inicio incluido y final excluido. Los hashes SHA-256 corresponden a los bytes originales de entrada o del artefacto decodificado.

## Ejecución de pruebas

Desde la carpeta del proyecto:

```bash
python -m unittest discover -s tests -v
node --test tests/test_js.cjs
```

Las pruebas verifican tokenización de concatenación/números, cadenas y comentarios largos, escapes, offsets Unicode, diagnósticos, exclusión de falsos positivos en comentarios/cadenas, resumen del sample y paridad Python/JavaScript.

## Hallazgos del sample incluido

La ejecución de referencia detecta 33.511 tokens, 143 literales de cadena y una estructura retornada con 38 elementos. También encuentra una tabla candidata con 35 nombres simbólicos. Esa diferencia importa: el analizador registra ambos hechos pero no infiere una relación posicional que podría ser incorrecta.

Una cadena de 244 caracteres puede decodificarse como **candidato experimental** usando el alfabeto Base85 observado. El resultado es un artefacto binario de 195 bytes con su propio hash y volcado hex. La coincidencia del alfabeto no demuestra que la transformación sea la codificación correcta, por lo que el programa no renombra el resultado como fuente Lua ni lo ejecuta.

## Límite de devirtualización

La documentación oficial de MoonVeil describe que el modo VM compila funciones a un conjunto de instrucciones propio ejecutado por un intérprete incluido en el bundle y que el conjunto de instrucciones se genera por build. Por ello, recuperar instrucciones y reconstruir flujo de control requiere analizar el intérprete y el cargador de **esta muestra concreta**; la normalización textual no lo sustituye. Referencia: [documentación oficial de MoonVeil — VM mode e implementaciones](https://moonveil.cc/docs/overview/).

La recuperación del fuente original tampoco puede restaurar nombres locales, comentarios ni formato que se hayan eliminado durante la compilación/obfuscación. Esta herramienta deja visibles las incógnitas en vez de inventar una descompilación que parezca correcta.
