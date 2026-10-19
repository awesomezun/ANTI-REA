[English](../../README.md) · [简体中文](README_zh.md) · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](README_ko.md) · [Türkçe](README_tr.md) · [Русский](README_ru.md) · [Tiếng Việt](README_vi.md) · [ไทย](README_th.md) · [Deutsch](README_de.md) · [Español](README_es.md) · [Français](README_fr.md) · [Українська](README_uk.md) · **Polski** · [Português (Brasil)](README_pt-BR.md) · [العربية](README_ar.md) · [فارسی](README_fa.md) · [Bahasa Indonesia](README_id.md) · [Italiano](README_it.md) · [Ελληνικά](README_el.md) · [മലയാളം](README_ml.md)

# ANTI-REA

### Jeden serwer MCP chroniący pliki binarne, aplikacje i kluczową logikę przed analizą REA.

**Masz kluczową funkcję, którą chcesz chronić? Zablokuj jej analizę i kopiowanie aż do poziomu binarnego.**

[![Defense vs REA](https://img.shields.io/badge/Defense_vs_REA-25%25-4bbd9c?style=flat-square)](#roadmap)
[![MCP + CLI](https://img.shields.io/badge/MCP-stdio_%2B_CLI-5c4ee5?style=flat-square)](#quick-start)
[![Python requirements](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)](#quick-start)
[![Engines](https://img.shields.io/badge/Engines-Kagura_%7C_VMP_%7C_Themida_%7C_CV-cb3837?style=flat-square)](#engines)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](../../LICENSE)

Narzędzia do inżynierii wstecznej, takie jak [REA](https://github.com/morluto/rea), pozwalają agentowi przeanalizować plik binarny i wiernie odtworzyć oryginalną logikę po jednym poleceniu: *„Sprawdź, jak działa ta funkcja w tamtej aplikacji, i zbuduj taką samą w moim projekcie”*.

**Agentyczny atak? Naszą odpowiedzią jest agentyczna obrona — obrona, która z czasem staje się coraz silniejsza.** Ostatecznym celem **ANTI-REA** jest **zablokowanie wszystkiego, co REA potrafi przeanalizować**. Wystarczy powiedzieć swojemu agentowi w języku naturalnym: **„Zabezpiecz kluczową logikę mojego programu przed analizą i sklonowaniem przez REA”**, a agent znajdzie główny kod oraz otaczające wskazówki, zastosuje zaciemnianie (obfuscation) i wirtualizację (VM), проверит poprawność działania oraz zmierzy, ile procent oryginalnej prędkości osiąga program.

Nie musisz samodzielnie budować skomplikowanego środowiska testowego. **Codziennie zestawiamy nasz komputer obronny z osobnym komputerem atakującym (REA), sprawdzamy, jak łamana jest maszyna VM w TestApp, łatamy słabe punkty i wzmacniamy ochronę.** Ty po prostu podłączasz zahartowane ANTI-REA do swojego agenta.

---

## Obecna siła obrony i mapa drogowa (TestApp VM vs. rzeczywiste ataki REA)

![TestApp VM Defense vs. REA 25%](../../docs/assets/defense-roadmap.svg)

Powyższa wartość to nie abstrakcyjny harmonogram prac, lecz **rzeczywista odporność chronionej przez nas aplikacji TestApp na bezpośrednie ataki REA z osobnego komputera**.

### Etapy wzmacniania obrony (Cel ostateczny: Zablokować wszystko, co analizuje REA)

- **25% (Obecnie) · Zablokowanie statycznej rekonstrukcji 1. stopnia:** Dywersyfikacja handlerów i powiązanie kontekstu operandów uniemożliwiły statycznej analizie REA odtworzenie głównego wzoru.
- **50% · Blokada analizy statycznej i wnioskowania z kontekstu:** Ukrycie funkcji pomocniczych wewnątrz dyspozytora (dispatcher) oraz wskazówek w grafie wywołań.
- **75% · Obrona przed dynamicznym śledzeniem i debugowaniem:** Ochrona logiki i stałych przed debuggerami, Fridą, śledzeniem wykonania i zrzutami pamięci.
- **100% · Pełna ochrona wszystkich celów i ścieżek REA:** Rozszerzenie ochrony z natywnych plików binarnych (C/C++, Rust, Go) na .NET, Java/Kotlin, JavaScript/Electron, Python oraz macOS (Mach-O/ARM64).

---

## Szybki start

### 1. Instalacja i połączenie z agentem (`Set up your agent`)

Bez ręcznego wpisywania poleceń w terminalu czy edycji plików JSON — po prostu poleć swojemu agentowi (Claude Code, Cursor, Codex, Gemini CLI itp.):

```text
Zainstaluj ANTI-REA w lokalnym środowisku wirtualnym Pythona (.venv) i podłącz serwer antirea.defense_mcp do konfiguracji MCP, abyś mógł od razu z niego korzystać.
```

### 2. Wydawaj polecenia w języku naturalnym (`Ask your agent`)

```text
Zabezpiecz kluczową logikę obliczeniową i otaczające wskazówki w moim projekcie przed analizą i sklonowaniem przez REA, a następnie powiedz mi, czy oryginalna funkcjonalność działa poprawnie i jaki procent pierwotnej prędkości osiąga.
```

```text
Najpierw przygotuj i pokaż mi plan ochrony pliku app.exe za pomocą VMProtect, a po moim zatwierdzeniu uruchom go.
```

### 3. Bezpośrednie użycie z terminala (`Use the terminal`)

```powershell
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json providers
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json doctor
```

---

## Jak to działa i jak staje się silniejsze każdego dnia

![ANTI-REA Overview](../../docs/assets/antirea-overview.svg)

| Iteration | Protection | REA Outcome |
|---|---|---|

---

## Obsługiwane silniki

Choć wbudowany silnik open-source (`Kagura + ANTI-REA`) staje się silniejszy każdego dnia, **jeśli potrzebujesz jeszcze mocniejszej ochrony od zaraz, możesz zakupić Themida, VMProtect lub Code Virtualizer, podłączyć go do ANTI-REA i po prostu napisać agentowi w języku naturalnym, jakiej wydajności i jakiego poziomu ochrony oczekujesz.**

```text
Użyj VMProtect (lub Themida / Code Virtualizer), aby utrzymać prędkość działania powyżej 80% oryginału, jednocześnie maksymalnie chroniąc kluczową logikę.
```

| Engine | Connection | Status |
|---|---|---|
| **Kagura + ANTI-REA** | C++/LLVM defense pipeline | Active VM protection, automated verification & daily hardening (Windows x86-64) |
| **Themida** | Defense MCP/CLI (`.tmd`/`.tm`) | Windows native x86/x64 PE adapter implemented |
| **VMProtect** | Defense MCP/CLI (`.vmp`) | Windows native x86/x64 PE adapter implemented |
| **Code Virtualizer** | Defense MCP/CLI (`.cv`) | Windows native x86/x64 PE adapter implemented |

---

## Rozwój i testowanie

```powershell
python -m unittest discover -s tests -v
```

Ten projekt jest rozpowszechniany na licencji [MIT License](../../LICENSE) (podłączane silniki ochrony podlegają swoim własnym licencjom).
