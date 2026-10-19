[English](../../README.md) · [简体中文](README_zh.md) · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](README_ko.md) · [Türkçe](README_tr.md) · **Русский** · [Tiếng Việt](README_vi.md) · [ไทย](README_th.md) · [Deutsch](README_de.md) · [Español](README_es.md) · [Français](README_fr.md) · [Українська](README_uk.md) · [Polski](README_pl.md) · [Português (Brasil)](README_pt-BR.md) · [العربية](README_ar.md) · [فارسی](README_fa.md) · [Bahasa Indonesia](README_id.md) · [Italiano](README_it.md) · [Ελληνικά](README_el.md) · [മലയാളം](README_ml.md)

# ANTI-REA

### Единый MCP для защиты бинарных файлов, приложений и ключевой логики от анализа REA.

**Есть важная функция, которую нужно защитить? Не дайте проанализировать или скопировать её вплоть до бинарного уровня.**

[![Defense vs REA](https://img.shields.io/badge/Defense_vs_REA-25%25-4bbd9c?style=flat-square)](#roadmap)
[![MCP + CLI](https://img.shields.io/badge/MCP-stdio_%2B_CLI-5c4ee5?style=flat-square)](#quick-start)
[![Python requirements](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)](#quick-start)
[![Engines](https://img.shields.io/badge/Engines-ANTI--REA_Engine_%7C_VMP_%7C_Themida_%7C_CV-cb3837?style=flat-square)](#engines)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](../../LICENSE)

Инструменты реверс-инжиниринга вроде [REA](https://github.com/morluto/rea) позволяют агенту разобрать бинарный файл и в точности воссоздать исходную логику по одной фразе: *«Разберись, как работает эта функция в том приложении, и сделай так же в моём проекте»*.

**Агентная атака? Наш ответ — агентная защита, которая становится сильнее со временем.** Конечная цель **ANTI-REA** — **полностью заблокировать всё, что способен анализировать REA**. Просто скажите своему агенту на естественном языке: **«Защити ключевую логику моей программы от анализа и копирования через REA»**, и агент найдёт основные функции и косвенные улики, применит обфускацию и виртуализацию (VM), проверит сохранность функциональности и измерит, сколько процентов от исходной скорости составляет производительность.

Вам не нужно самостоятельно разворачивать сложный полигон для атак и защиты. **Мы каждый день сталкиваем наш защитный ПК с отдельным атакующим ПК (REA), смотрим, как взламывается VM в TestApp, закрываем уязвимости и делаем защиту всё крепче.** Вам остаётся лишь подключить закалённый ANTI-REA к своему агенту.

---

## Текущий уровень защиты и дорожная карта (TestApp VM против реальных атак REA)

![TestApp VM Defense vs. REA 25%](../../docs/assets/defense-roadmap.svg)

Этот показатель — не абстрактный план разработки, а **реальная стойкость защищённого нами TestApp против прямых атак REA с отдельной машины**.

### Этапы усиления защиты (Конечная цель: заблокировать всё, что анализирует REA)

- **25% (Сейчас) · Блокировка первичного статического восстановления:** Диверсификация обработчиков и связывание контекста операндов не дали внешнему статическому анализу REA восстановить ключевую формулу.
- **50% · Блокировка статического анализа и вывода из контекста:** Сокрытие вспомогательных функций внутри диспетчера и улик в графе вызовов.
- **75% · Защита от динамической трассировки и отладки:** Защита ключевой логики и констант от отладчиков, Frida, трассировки выполнения и дампов памяти.
- **100% · Полная защита всех целей и путей анализа REA:** Расширение защиты с нативных бинарников (C/C++, Rust, Go) на .NET, Java/Kotlin, JavaScript/Electron, Python и macOS (Mach-O/ARM64).

---

## Быстрый старт

### 1. Установка и подключение к агенту (`Set up your agent`)

Не нужно вручную вводить команды или править конфиги. Просто поручите это своему агенту (Claude Code, Cursor, Codex, Gemini CLI и др.):

```text
Установи ANTI-REA в локальное виртуальное окружение Python (.venv) и подключи сервер antirea.defense_mcp к MCP, чтобы ты мог сразу его использовать.
```

### 2. Поручите защиту на естественном языке (`Ask your agent`)

```text
Защити ключевую расчётную логику и окружающий контекст в моём проекте от анализа и копирования через REA, а затем проверь, не сломалась ли функциональность и сколько процентов от исходной скорости выдаёт программа.
```

```text
Сначала составь и покажи мне план защиты app.exe с помощью VMProtect, а после моего одобрения выполни его.
```

### 3. Прямое использование из терминала (`Use the terminal`)

```powershell
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json providers
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json doctor
```

---

## Как это работает и становится сильнее каждый день

![ANTI-REA Overview](../../docs/assets/antirea-overview.svg)

| Iteration | Protection | REA Outcome |
|---|---|---|

---

## Поддерживаемые движки

Встроенный открытый движок (`ANTI-REA Engine`) усиливается каждый день, но **если вам прямо сейчас нужна ещё более мощная защита, вы можете приобрести Themida, VMProtect или Code Virtualizer, подключить их к ANTI-REA и просто написать агенту на естественном языке, какую скорость работы и какой уровень защиты вы хотите получить.**

```text
Используй VMProtect (или Themida / Code Virtualizer), чтобы сохранить скорость выполнения не ниже 80% от исходной и при этом максимально защитить ключевую логику.
```

| Engine | Connection | Status |
|---|---|---|
| **ANTI-REA Engine** | C++/LLVM defense pipeline | Active VM protection, automated verification & daily hardening (Windows x86-64) |
| **Themida** | Defense MCP/CLI (`.tmd`/`.tm`) | Windows native x86/x64 PE adapter implemented |
| **VMProtect** | Defense MCP/CLI (`.vmp`) | Windows native x86/x64 PE adapter implemented |
| **Code Virtualizer** | Defense MCP/CLI (`.cv`) | Windows native x86/x64 PE adapter implemented |

---

## Разработка и тестирование

```powershell
python -m unittest discover -s tests -v
```

Проект распространяется по лицензии [MIT License](../../LICENSE) (подключаемые движки защиты используют собственные лицензии).
