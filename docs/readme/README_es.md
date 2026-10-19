[English](../../README.md) · [简体中文](README_zh.md) · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](README_ko.md) · [Türkçe](README_tr.md) · [Русский](README_ru.md) · [Tiếng Việt](README_vi.md) · [ไทย](README_th.md) · [Deutsch](README_de.md) · **Español** · [Français](README_fr.md) · [Українська](README_uk.md) · [Polski](README_pl.md) · [Português (Brasil)](README_pt-BR.md) · [العربية](README_ar.md) · [فارسی](README_fa.md) · [Bahasa Indonesia](README_id.md) · [Italiano](README_it.md) · [Ελληνικά](README_el.md) · [മലയാളം](README_ml.md)

# ANTI-REA

### Un único MCP para proteger binarios, aplicaciones y lógica central contra el análisis de REA.

**¿Tienes una función clave que quieres proteger? Evita que la analicen o clonen hasta el nivel binario.**

[![Defense vs REA](https://img.shields.io/badge/Defense_vs_REA-25%25-4bbd9c?style=flat-square)](#roadmap)
[![MCP + CLI](https://img.shields.io/badge/MCP-stdio_%2B_CLI-5c4ee5?style=flat-square)](#quick-start)
[![Python requirements](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)](#quick-start)
[![Engines](https://img.shields.io/badge/Engines-ANTI--REA_Engine_%7C_VMP_%7C_Themida_%7C_CV-cb3837?style=flat-square)](#engines)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](../../LICENSE)

Herramientas de ingeniería inversa como [REA](https://github.com/morluto/rea) permiten que un agente inspeccione un binario y reimplemente su lógica exacta cuando le pides: *«Analiza cómo funciona esta característica en esa aplicación y crea una igual en mi proyecto»*.

**¿Ataque agéntico? Entonces respondemos con defensa agéntica: una defensa que se vuelve más fuerte con el tiempo.** El objetivo final de **ANTI-REA** es **bloquear absolutamente todo lo que REA puede analizar**. Solo pídele a tu agente en lenguaje natural: **«Protege la lógica central de mi programa para que REA no pueda analizarla ni clonarla»**, y el agente localizará el código clave y las pistas cercanas, aplicará ofuscación y virtualización (VM), comprobará que la funcionalidad siga intacta y medirá a qué porcentaje de la velocidad original se ejecuta.

No necesitas montar un laboratorio complejo de ataque y defensa por tu cuenta. **Todos los días enfrentamos nuestro PC de defensa contra un PC de ataque con REA independiente para ver cómo se vulnera la VM en TestApp, corregir los puntos débiles y fortalecer la defensa día tras día.** Tú solo conectas ANTI-REA a tu agente y lo usas.

---

## Nivel actual de defensa y hoja de ruta (TestApp VM vs. ataque real de REA)

![TestApp VM Defense vs. REA 25%](../../docs/assets/defense-roadmap.svg)

Este porcentaje no es un cronograma abstracto, sino **cuánto resiste nuestra TestApp protegida con VM frente a ataques directos de REA desde otro equipo**.

### Etapas de fortalecimiento (Objetivo final: Bloquear todo lo que analiza REA)

- **25 % (Actual) · Bloqueo de reconstrucción estática inicial:** La diversificación de manejadores y el contexto de operandos impiden que el análisis estático de REA recupere la fórmula central de una vez.
- **50 % · Bloqueo de análisis estático e inferencia de contexto:** Ocultar funciones auxiliares del despachador y pistas en el grafo de llamadas.
- **75 % · Defensa contra trazado dinámico y depuración:** Proteger la lógica y las constantes frente a depuradores, Frida, trazas de ejecución y volcados de memoria.
- **100 % · Defensa total en todos los objetivos y rutas de REA:** Expandir la protección de binarios nativos (C/C++, Rust, Go) a .NET, Java/Kotlin, JavaScript/Electron, Python y macOS (Mach-O/ARM64).

---

## Inicio rápido

### 1. Instalación y conexión con tu agente (`Set up your agent`)

Sin tocar comandos de terminal ni archivos JSON manualmente; simplemente pídele a tu agente (Claude Code, Cursor, Codex, Gemini CLI, etc.):

```text
Instala ANTI-REA en un entorno virtual local de Python (.venv) y conecta el servidor antirea.defense_mcp a tu configuración MCP para poder usarlo de inmediato.
```

### 2. Pídeselo a tu agente en lenguaje natural (`Ask your agent`)

```text
Protege la lógica de cálculo central y las pistas cercanas en mi proyecto para que REA no pueda analizarlas ni clonarlas, y dime si la funcionalidad original sigue intacta y a qué porcentaje de la velocidad original corre.
```

```text
Crea primero un plan de protección con VMProtect para app.exe, muéstramelo y ejecútalo cuando lo apruebe.
```

### 3. Uso directo desde la terminal (`Use the terminal`)

```powershell
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json providers
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json doctor
```

---

## Cómo funciona y cómo mejora cada día

![ANTI-REA Overview](../../docs/assets/antirea-overview.svg)

| Iteration | Protection | REA Outcome |
|---|---|---|

---

## Motores compatibles

Aunque el motor de código abierto incluido (`ANTI-REA Engine`) mejora cada día, **si necesitas una protección aún más fuerte ahora mismo, puedes adquirir Themida, VMProtect o Code Virtualizer, conectarlo a ANTI-REA y simplemente escribirle a tu agente en lenguaje natural qué rendimiento de ejecución y qué nivel de defensa deseas.**

```text
Usa VMProtect (o Themida / Code Virtualizer) manteniendo al menos el 80 % de la velocidad original mientras defiendes la lógica central al máximo.
```

| Engine | Connection | Status |
|---|---|---|
| **ANTI-REA Engine** | C++/LLVM defense pipeline | Active VM protection, automated verification & daily hardening (Windows x86-64) |
| **Themida** | Defense MCP/CLI (`.tmd`/`.tm`) | Windows native x86/x64 PE adapter implemented |
| **VMProtect** | Defense MCP/CLI (`.vmp`) | Windows native x86/x64 PE adapter implemented |
| **Code Virtualizer** | Defense MCP/CLI (`.cv`) | Windows native x86/x64 PE adapter implemented |

---

## Desarrollo y pruebas

```powershell
python -m unittest discover -s tests -v
```

Este proyecto se distribuye bajo la licencia [MIT License](../../LICENSE) (los motores de protección conectados siguen sus propias licencias).
