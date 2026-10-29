# Registro de cambios

## 2.1.0
- Al iniciar, limpia archivos `.json` y `.jsonl` obsoletos en el directorio de salida, para cumplir el requisito de no generar JSON.
- Eliminado el helper JSONL no utilizado en Python.
- Versiones Python y JavaScript alineadas.
- Verificación: 13 pruebas Python y 7 pruebas Node.js aprobadas; paridad entre lenguajes aprobada.

## 2.0.0

- Corregido el diagnóstico del alfabeto: el alfabeto detectado tiene 85 caracteres.
- Lexer ampliado para Luau, incluidos templates y diagnósticos de literales sin cierre.
- Corregido el cálculo de indentación de `elseif`, que producía crecimiento artificial en la versión anterior.
- Añadidos inventario estructural de tabla retornada, candidatos de tablas de nombres y dumps de tokens con offsets Unicode.
- Añadidos candidatos de decodificación estática con SHA-256, entropía, proporción imprimible y artefactos binarios/hex.
- Reducidos falsos positivos al no analizar cadenas y comentarios como código.
- Añadidas pruebas Python, Node y paridad cruzada para el sample y Unicode.

## 2.0.1
- Eliminada la generación de archivos JSON/JSONL. Los informes y datos de análisis se emiten en Markdown, texto plano y TSV.
- Pruebas de paridad actualizadas para validar los formatos legibles.
