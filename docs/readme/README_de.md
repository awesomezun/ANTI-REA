[English](../../README.md) · [简体中文](README_zh.md) · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](README_ko.md) · [Türkçe](README_tr.md) · [Русский](README_ru.md) · [Tiếng Việt](README_vi.md) · [ไทย](README_th.md) · **Deutsch** · [Español](README_es.md) · [Français](README_fr.md) · [Українська](README_uk.md) · [Polski](README_pl.md) · [Português (Brasil)](README_pt-BR.md) · [العربية](README_ar.md) · [فارسی](README_fa.md) · [Bahasa Indonesia](README_id.md) · [Italiano](README_it.md) · [Ελληνικά](README_el.md) · [മലയാളം](README_ml.md)

# ANTI-REA

### Ein einziger MCP zum Schutz von Binärdateien, Anwendungen und Kernlogik vor REA-Analysen.

**Haben Sie eine Kernfunktion, die Sie schützen möchten? Verhindern Sie Analyse und Nachbau bis auf die Binärebene.**

[![Defense vs REA](https://img.shields.io/badge/Defense_vs_REA-25%25-4bbd9c?style=flat-square)](#roadmap)
[![MCP + CLI](https://img.shields.io/badge/MCP-stdio_%2B_CLI-5c4ee5?style=flat-square)](#quick-start)
[![Python requirements](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)](#quick-start)
[![Engines](https://img.shields.io/badge/Engines-Kagura_%7C_VMP_%7C_Themida_%7C_CV-cb3837?style=flat-square)](#engines)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](../../LICENSE)

Reverse-Engineering-Tools wie [REA](https://github.com/morluto/rea) ermöglichen es einem Agenten, eine Binärdatei zu zerlegen und die ursprüngliche Logik exakt nachzubauen, sobald man sagt: *„Analysiere, wie diese Funktion in jener App funktioniert, und baue sie für mein Projekt nach.“*

**Agentischer Angriff? Dann ist unsere Antwort agentische Verteidigung — eine Verteidigung, die mit der Zeit immer stärker wird.** Das ultimative Ziel von **ANTI-REA** ist es, **alles zu blockieren, was REA analysieren kann**. Sagen Sie Ihrem Agenten einfach in natürlicher Sprache: **„Schütze die Kernlogik meines Programms davor, von REA analysiert oder kopiert zu werden“**, und der Agent findet den Kerncode samt umgebenden Hinweisen, wendet Obfuskation und Virtualisierung (VM) an, prüft die korrekte Funktion und misst, mit wie viel Prozent der ursprünglichen Geschwindigkeit das Programm läuft.

Sie müssen kein eigenes Angriffs- und Verteidigungslabor aufbauen. **Wir lassen jeden Tag unseren Verteidigungs-PC gegen einen separaten REA-Angriffs-PC antreten, prüfen, wie die VM in TestApp angegriffen wird, schließen die Lücken und machen die Verteidigung täglich robuster.** Sie verbinden das gehärtete ANTI-REA einfach mit Ihrem Agenten.

---

## Aktuelle Verteidigungsstärke & Roadmap (TestApp-VM vs. echte REA-Angriffe)

![TestApp VM Defense vs. REA 25%](../../docs/assets/defense-roadmap.svg)

Dieser Wert ist kein abstrakter Projektplan, sondern zeigt, **wie gut unsere VM-geschützte TestApp direkten REA-Angriffen von einem separaten Rechner standhält**.

### Ausbaustufen der Verteidigung (Endziel: Alles blockieren, was REA analysiert)

- **25 % (Aktuell) · Erste statische Rekonstruktion gestoppt:** Handler-Diversifizierung und Operanden-Kontextkopplung verhindern die direkte statische Rekonstruktion der Kernformel.
- **50 % · Statische Analyse & Kontextableitung blockieren:** Interne Hilfsfunktionen im Dispatcher und Hinweise im Aufrufgraphen verbergen.
- **75 % · Schutz gegen dynamisches Tracing & Debugging:** Schutz von Kernlogik und Konstanten gegen Debugger, Frida, Ausführungs-Traces und Speicherauszüge.
- **100 % · Vollständiger Schutz für alle REA-Ziele und -Pfade:** Ausweitung von nativen Binärdateien (C/C++, Rust, Go) auf .NET, Java/Kotlin, JavaScript/Electron, Python und macOS (Mach-O/ARM64).

---

## Schnellstart

### 1. Installation & Agent-Verbindung (`Set up your agent`)

Keine manuellen Terminalbefehle oder Konfigurationsdateien nötig. Sagen Sie Ihrem Agenten (Claude Code, Cursor, Codex, Gemini CLI usw.) einfach:

```text
Installiere ANTI-REA in einer lokalen virtuellen Python-Umgebung (.venv) und verbinde den Server antirea.defense_mcp mit deiner MCP-Konfiguration, damit du ihn sofort nutzen kannst.
```

### 2. Den Agenten in natürlicher Sprache anweisen (`Ask your agent`)

```text
Schütze die zentrale Berechnungslogik und umgebende Hinweise in meinem Projekt vor Analyse und Nachbau durch REA, und teile mir mit, ob die ursprüngliche Funktion erhalten bleibt und bei wie viel Prozent der Originalgeschwindigkeit sie läuft.
```

```text
Erstelle zuerst einen VMProtect-Schutzplan für app.exe, zeige ihn mir und führe ihn nach meiner Freigabe aus.
```

### 3. Direkt im Terminal nutzen (`Use the terminal`)

```powershell
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json providers
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json doctor
```

---

## Funktionsweise & tägliche Härtungsschleife

![ANTI-REA Overview](../../docs/assets/antirea-overview.svg)

| Iteration | Protection | REA Outcome |
|---|---|---|

---

## Unterstützte Engines

Während die integrierte Open-Source-Engine (`Kagura + ANTI-REA`) täglich stärker wird, **können Sie – falls Sie sofort noch stärkeren Schutz benötigen – Themida, VMProtect oder Code Virtualizer erwerben, anbinden und Ihrem Agenten über ANTI-REA einfach in natürlicher Sprache mitteilen, welche Ausführungsgeschwindigkeit und welches Schutzniveau Sie wünschen.**

```text
Verwende VMProtect (oder Themida / Code Virtualizer), um die Ausführungsgeschwindigkeit bei mindestens 80 % des Originals zu halten und gleichzeitig die Kernlogik maximal zu schützen.
```

| Engine | Connection | Status |
|---|---|---|
| **Kagura + ANTI-REA** | C++/LLVM defense pipeline | Active VM protection, automated verification & daily hardening (Windows x86-64) |
| **Themida** | Defense MCP/CLI (`.tmd`/`.tm`) | Windows native x86/x64 PE adapter implemented |
| **VMProtect** | Defense MCP/CLI (`.vmp`) | Windows native x86/x64 PE adapter implemented |
| **Code Virtualizer** | Defense MCP/CLI (`.cv`) | Windows native x86/x64 PE adapter implemented |

---

## Entwicklung & Tests

```powershell
python -m unittest discover -s tests -v
```

Dieses Projekt wird unter der [MIT-Lizenz](../../LICENSE) veröffentlicht (angebundene Schutz-Engines unterliegen ihren jeweiligen eigenen Lizenzen).
