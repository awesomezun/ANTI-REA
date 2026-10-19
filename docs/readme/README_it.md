[English](README_en.md) · [简体中文](README_zh.md) · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](../../README.md) · [Türkçe](README_tr.md) · [Русский](README_ru.md) · [Tiếng Việt](README_vi.md) · [ไทย](README_th.md) · [Deutsch](README_de.md) · [Español](README_es.md) · [Français](README_fr.md) · [Українська](README_uk.md) · [Polski](README_pl.md) · [Português (Brasil)](README_pt-BR.md) · [العربية](README_ar.md) · [فارسی](README_fa.md) · [Bahasa Indonesia](README_id.md) · **Italiano** · [Ελληνικά](README_el.md) · [മലയാളം](README_ml.md)

# ANTI-REA

### Un unico MCP per proteggere file binari, applicazioni e logica core dall'analisi di REA.

**Hai una funzionalità chiave da proteggere? Impedisci che venga analizzata o clonata fino al livello binario.**

[![Defense vs REA](https://img.shields.io/badge/Defense_vs_REA-25%25-4bbd9c?style=flat-square)](#roadmap)
[![MCP + CLI](https://img.shields.io/badge/MCP-stdio_%2B_CLI-5c4ee5?style=flat-square)](#quick-start)
[![Python requirements](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)](#quick-start)
[![Engines](https://img.shields.io/badge/Engines-Kagura_%7C_VMP_%7C_Themida_%7C_CV-cb3837?style=flat-square)](#engines)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](../../LICENSE)

Strumenti di reverse engineering come [REA](https://github.com/morluto/rea) permettono a un agente di ispezionare un binario e reimplementarne l'esatta logica originale semplicemente chiedendo: *«Analizza come funziona questa funzione in quell'app e ricreala nel mio progetto»*.

**Attacco agentico? La nostra risposta è la difesa agentica — una difesa che diventa più forte col passare del tempo.** L'obiettivo finale di **ANTI-REA** è **bloccare tutto ciò che REA è in grado di analizzare**.Ti basta chiedere al tuo agente in linguaggio naturale: **«Proteggi la logica core del mio programma affinché REA non possa analizzarla né clonarla»**; l'agente individuerà il codice critico e gli indizi circostanti, applicherà offuscamento e virtualizzazione (VM), verificherà che il comportamento originale sia intatto e misurerà a quale percentuale della velocità originale gira il programma.

Non devi allestire da solo un complesso laboratorio di attacco e difesa. **Ogni giorno facciamo scontrare il nostro PC di difesa con un PC di attacco REA separato per vedere come viene attaccata la VM su TestApp, chiudere le falle e rendere la difesa sempre più solida.** Tu devi solo collegare ANTI-REA al tuo agente.

---

## Forza di difesa attuale e Roadmap (TestApp VM vs. attacchi REA reali)

![TestApp VM Defense vs. REA 25%](../../docs/assets/defense-roadmap.svg)

Questo valore non è una tabella di marcia astratta, ma indica **quanto la nostra TestApp protetta da VM resista agli attacchi diretti di REA lanciati da un'altra macchina**.

### Fasi di potenziamento (Obiettivo finale: Bloccare tutto ciò che REA analizza)

- **25% (Attuale) · Blocco della ricostruzione statica iniziale:** La diversificazione degli handler e il contesto degli operandi impediscono all'analisi statica di REA di ricostruire la formula in un colpo solo.
- **50% · Blocco dell'analisi statica e dell'inferenza del contesto:** Nascondere le funzioni ausiliarie interne del dispatcher e gli indizi nel grafo delle chiamate.
- **75% · Difesa contro tracciamento dinamico e debugging:** Proteggere logica e costanti da debugger, Frida, tracce di esecuzione e dump di memoria.
- **100% · Difesa completa su tutti i target e percorsi di REA:** Estendere la protezione dai binari nativi (C/C++, Rust, Go) a .NET, Java/Kotlin, JavaScript/Electron, Python e macOS (Mach-O/ARM64).

---

## Avvio rapido

### 1. Installazione e collegamento all'agente (`Set up your agent`)

Senza digitare comandi nel terminale o modificare file JSON a mano, chiedi semplicemente al tuo agente (Claude Code, Cursor, Codex, Gemini CLI, ecc.):

```text
Installa ANTI-REA in un ambiente virtuale Python locale (.venv) e collega il server antirea.defense_mcp alla tua configurazione MCP per usarlo subito.
```

### 2. Chiedi al tuo agente in linguaggio naturale (`Ask your agent`)

```text
Proteggi la logica di calcolo principale e gli indizi circostanti nel mio progetto affinché REA non possa analizzarli né clonarli, e dimmi se la funzionalità originale è intatta e a quale percentuale della velocità originale gira.
```

```text
Crea prima un piano di protezione VMProtect per app.exe, mostramelo ed eseguilo dopo la mia approvazione.
```

### 3. Uso diretto da terminale (`Use the terminal`)

```powershell
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json providers
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json doctor
```

---

## Come funziona e come migliora ogni giorno

![ANTI-REA Overview](../../docs/assets/antirea-overview.svg)

| Iteration | Protection | REA Outcome |
|---|---|---|

---

## Motori supportati

Sebbene il motore open-source integrato (`Kagura + ANTI-REA`) diventi più forte ogni giorno, **se hai bisogno subito di una protezione ancora più spinta puoi acquistare Themida, VMProtect o Code Virtualizer, collegarlo ad ANTI-REA e indicare semplicemente in linguaggio naturale al tuo agente quali prestazioni di esecuzione e quale livello di difesa desideri.**

```text
Usa VMProtect (o Themida / Code Virtualizer) mantenendo la velocità di esecuzione sopra l'80% dell'originale e difendendo al massimo la logica core.
```

| Engine | Connection | Status |
|---|---|---|
| **Kagura + ANTI-REA** | C++/LLVM defense pipeline | Active VM protection, automated verification & daily hardening (Windows x86-64) |
| **Themida** | Defense MCP/CLI (`.tmd`/`.tm`) | Windows native x86/x64 PE adapter implemented |
| **VMProtect** | Defense MCP/CLI (`.vmp`) | Windows native x86/x64 PE adapter implemented |
| **Code Virtualizer** | Defense MCP/CLI (`.cv`) | Windows native x86/x64 PE adapter implemented |

---

## Sviluppo e test

```powershell
python -m unittest discover -s tests -v
```

Questo progetto è distribuito sotto licenza [MIT License](../../LICENSE) (i motori di protezione collegati seguono le rispettive licenze).
