[English](README_en.md) · [简体中文](README_zh.md) · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](../../README.md) · [Türkçe](README_tr.md) · [Русский](README_ru.md) · [Tiếng Việt](README_vi.md) · [ไทย](README_th.md) · [Deutsch](README_de.md) · [Español](README_es.md) · **Français** · [Українська](README_uk.md) · [Polski](README_pl.md) · [Português (Brasil)](README_pt-BR.md) · [العربية](README_ar.md) · [فارسی](README_fa.md) · [Bahasa Indonesia](README_id.md) · [Italiano](README_it.md) · [Ελληνικά](README_el.md) · [മലയാളം](README_ml.md)

# ANTI-REA

### Un seul MCP pour protéger vos binaires, applications et logiques métier contre l'analyse de REA.

**Vous avez une fonctionnalité clé à protéger ? Empêchez son analyse et son clonage jusqu'au niveau binaire.**

[![Defense vs REA](https://img.shields.io/badge/Defense_vs_REA-25%25-4bbd9c?style=flat-square)](#roadmap)
[![MCP + CLI](https://img.shields.io/badge/MCP-stdio_%2B_CLI-5c4ee5?style=flat-square)](#quick-start)
[![Python requirements](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)](#quick-start)
[![Engines](https://img.shields.io/badge/Engines-Kagura_%7C_VMP_%7C_Themida_%7C_CV-cb3837?style=flat-square)](#engines)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](../../LICENSE)

Les outils de rétro-ingénierie comme [REA](https://github.com/morluto/rea) permettent à un agent d'inspecter un binaire et d'en réimplémenter la logique exacte dès que vous demandez : *« Analyse comment fonctionne cette fonctionnalité dans cette application et reproduis-la dans mon projet »*.

**Attaque agentique ? Voici la défense agentique — une défense qui se renforce avec le temps.** L'objectif ultime d'**ANTI-REA** est de **bloquer tout ce que REA est capable d'analyser**. Demandez simplement à votre agent en langage naturel : **« Protège la logique cœur de mon programme pour que REA ne puisse ni l'analyser ni la cloner »** ; l'agent repère le code critique et les indices environnants, applique l'obfuscation et la virtualisation (VM), vérifie que le comportement reste intact et mesure à quel pourcentage de la vitesse d'origine le programme s'exécute.

Inutile de monter vous-même un laboratoire complexe d'attaque et de défense. **Chaque jour, nous confrontons notre PC de défense à un PC d'attaque REA dédié pour observer comment la VM de TestApp est contournée, corriger les faiblesses et renforcer la protection.** Il vous suffit de connecter ANTI-REA à votre agent.

---

## Niveau de défense actuel et feuille de route (VM TestApp vs attaques REA réelles)

![TestApp VM Defense vs. REA 25%](../../docs/assets/defense-roadmap.svg)

Ce pourcentage n'est pas un simple calendrier de projet : il indique **à quel point notre TestApp protégée par VM résiste aux attaques directes de REA lancées depuis une autre machine**.

### Étapes de renforcement (Objectif final : Bloquer tout ce que REA analyse)

- **25 % (Actuel) · Blocage de la reconstruction statique initiale :** La diversification des handlers et le couplage contextuel des opérandes empêchent l'analyse statique REA de reconstruire la formule d'un seul coup.
- **50 % · Blocage de l'analyse statique et de l'inférence de contexte :** Masquer les fonctions auxiliaires internes du répartiteur (dispatcher) et les indices du graphe d'appels.
- **75 % · Défense contre le traçage dynamique et le débogage :** Protéger la logique et les constantes face aux débogueurs, à Frida, aux traces d'exécution et aux dumps mémoire.
- **100 % · Défense complète sur toutes les cibles et voies de REA :** Étendre la protection des binaires natifs (C/C++, Rust, Go) vers .NET, Java/Kotlin, JavaScript/Electron, Python et macOS (Mach-O/ARM64).

---

## Démarrage rapide

### 1. Installation et connexion à l'agent (`Set up your agent`)

Pas besoin de taper des commandes ou d'éditer des fichiers JSON à la main. Demandez simplement à votre agent (Claude Code, Cursor, Codex, Gemini CLI, etc.) :

```text
Installe ANTI-REA dans un environnement virtuel Python local (.venv) et connecte le serveur antirea.defense_mcp à ta configuration MCP pour pouvoir l'utiliser tout de suite.
```

### 2. Demandez en langage naturel (`Ask your agent`)

```text
Protège la logique de calcul principale et les indices environnants de mon projet pour que REA ne puisse ni les analyser ni les cloner, et dis-moi si le fonctionnement d'origine est intact et à quel pourcentage de la vitesse initiale il tourne.
```

```text
Prépare d'abord un plan de protection VMProtect pour app.exe, montre-le-moi et exécute-le après mon accord.
```

### 3. Utilisation directe dans le terminal (`Use the terminal`)

```powershell
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json providers
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json doctor
```

---

## Fonctionnement et boucle d'amélioration quotidienne

![ANTI-REA Overview](../../docs/assets/antirea-overview.svg)

| Iteration | Protection | REA Outcome |
|---|---|---|

---

## Moteurs pris en charge

Bien que le moteur open-source intégré (`Kagura + ANTI-REA`) se renforce chaque jour, **si vous avez besoin d'une protection encore plus poussée dès maintenant, vous pouvez acheter Themida, VMProtect ou Code Virtualizer, le connecter à ANTI-REA et simplement indiquer en langage naturel à votre agent le niveau de performance et de défense souhaité.**

```text
Utilise VMProtect (ou Themida / Code Virtualizer) pour conserver au moins 80 % de la vitesse d'exécution initiale tout en protégeant au maximum la logique cœur.
```

| Engine | Connection | Status |
|---|---|---|
| **Kagura + ANTI-REA** | C++/LLVM defense pipeline | Active VM protection, automated verification & daily hardening (Windows x86-64) |
| **Themida** | Defense MCP/CLI (`.tmd`/`.tm`) | Windows native x86/x64 PE adapter implemented |
| **VMProtect** | Defense MCP/CLI (`.vmp`) | Windows native x86/x64 PE adapter implemented |
| **Code Virtualizer** | Defense MCP/CLI (`.cv`) | Windows native x86/x64 PE adapter implemented |

---

## Développement et tests

```powershell
python -m unittest discover -s tests -v
```

Ce projet est distribué sous licence [MIT License](../../LICENSE) (les moteurs de protection tiers connectés relèvent de leurs propres licences).
