[English](../../README.md) · [简体中文](README_zh.md) · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](README_ko.md) · [Türkçe](README_tr.md) · [Русский](README_ru.md) · [Tiếng Việt](README_vi.md) · [ไทย](README_th.md) · [Deutsch](README_de.md) · [Español](README_es.md) · [Français](README_fr.md) · **Українська** · [Polski](README_pl.md) · [Português (Brasil)](README_pt-BR.md) · [العربية](README_ar.md) · [فارسی](README_fa.md) · [Bahasa Indonesia](README_id.md) · [Italiano](README_it.md) · [Ελληνικά](README_el.md) · [മലയാളം](README_ml.md)

# ANTI-REA

### Єдиний MCP для захисту бінарних файлів, застосунків і ключової логіки від аналізу REA.

**Маєте важливу функцію, яку потрібно захистити? Унеможливте її аналіз та копіювання аж до бінарного рівня.**

[![Defense vs REA](https://img.shields.io/badge/Defense_vs_REA-25%25-4bbd9c?style=flat-square)](#roadmap)
[![MCP + CLI](https://img.shields.io/badge/MCP-stdio_%2B_CLI-5c4ee5?style=flat-square)](#quick-start)
[![Python requirements](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)](#quick-start)
[![Engines](https://img.shields.io/badge/Engines-Kagura_%7C_VMP_%7C_Themida_%7C_CV-cb3837?style=flat-square)](#engines)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](../../LICENSE)

Інструменти реверс-інжинірингу на кшталт [REA](https://github.com/morluto/rea) дозволяють агенту розібрати бінарний файл і точно відтворити вихідну логіку за одним запитом: *«Проаналізуй, як працює ця функція в тому застосунку, і зроби так само в моєму проєкті»*.

**Агентна атака? Тоді наша відповідь — агентний захист, що стає сильнішим із часом.** Кінцева мета **ANTI-REA** — **повністю заблокувати все, що здатний аналізувати REA**. Просто скажіть своєму агенту природною мовою: **«Захисти ключову логіку моєї програми від аналізу та клонування через REA»**, і агент знайде основний код та непрямі підказки, застосує обфускацію та віртуалізацію (VM), перевірить збереження функціональності й виміряє, скільки відсотків від початкової швидкості становить продуктивність.

Вам не потрібно самостійно будувати складне середовище для атак і захисту. **Ми щодня протиставляємо наш захисний ПК окремому атакувальному ПК із REA, перевіряємо, де пробивається VM у TestApp, усуваємо слабкі місця та посилюємо захист.** Ви просто підключаєте загартований ANTI-REA до свого агента.

---

## Поточний рівень захисту та дорожня карта (TestApp VM проти реальних атак REA)

![TestApp VM Defense vs. REA 25%](../../docs/assets/defense-roadmap.svg)

Цей показник відображає не абстрактний план розробки, а **реальну стійкість нашого захищеного TestApp проти прямих атак REA з іншого комп'ютера**.

### Етапи посилення захисту (Кінцева мета: заблокувати все, що аналізує REA)

- **25% (Зараз) · Блокування первинного статичного відновлення:** Диверсифікація обробників і зв'язування контексту операндів завадили статичному аналізу REA відновити формулу.
- **50% · Блокування статичного аналізу та висновків із контексту:** Приховування допоміжних функцій диспетчера та підказок у графі викликів.
- **75% · Захист від динамічного трасування та налагодження:** Захист логіки й констант від налагоджувачів, Frida, трасування виконання та дампів пам'яті.
- **100% · Повний захист усіх цілей і шляхів REA:** Розширення захисту з нативних бінарників (C/C++, Rust, Go) на .NET, Java/Kotlin, JavaScript/Electron, Python і macOS (Mach-O/ARM64).

---

## Швидкий старт

### 1. Встановлення та підключення до агента (`Set up your agent`)

Не потрібно вручну вводити команди чи редагувати файли налаштувань. Просто скажіть своєму агенту (Claude Code, Cursor, Codex, Gemini CLI тощо):

```text
Встанови ANTI-REA в локальне віртуальне середовище Python (.venv) і підключи сервер antirea.defense_mcp до MCP, щоб ти міг одразу ним користуватися.
```

### 2. Накажіть агенту природною мовою (`Ask your agent`)

```text
Захисти ключову обчислювальну логіку та навколишні підказки в моєму проєкті від аналізу й клонування через REA, а також скажи, чи збереглася вихідна функціональність і скільки відсотків від початкової швидкості видає програма.
```

```text
Спочатку склади й покажи мені план захисту app.exe за допомогою VMProtect, а після мого підтвердження виконай його.
```

### 3. Пряме використання з термінала (`Use the terminal`)

```powershell
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json providers
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json doctor
```

---

## Як це працює та стає сильнішим щодня

![ANTI-REA Overview](../../docs/assets/antirea-overview.svg)

| Iteration | Protection | REA Outcome |
|---|---|---|

---

## Підтримувані рушії

Хоча вбудований відкритий рушій (`Kagura + ANTI-REA`) посилюється щодня, **якщо вам просто зараз потрібен іще потужніший захист, ви можете придбати Themida, VMProtect або Code Virtualizer, підключити їх до ANTI-REA і просто написати агенту природною мовою, яку швидкість виконання та який рівень захисту ви хочете отримати.**

```text
Використай VMProtect (або Themida / Code Virtualizer), щоб зберегти швидкість виконання на рівні не менше 80% від початкової та максимально захистити ключову логіку.
```

| Engine | Connection | Status |
|---|---|---|
| **Kagura + ANTI-REA** | C++/LLVM defense pipeline | Active VM protection, automated verification & daily hardening (Windows x86-64) |
| **Themida** | Defense MCP/CLI (`.tmd`/`.tm`) | Windows native x86/x64 PE adapter implemented |
| **VMProtect** | Defense MCP/CLI (`.vmp`) | Windows native x86/x64 PE adapter implemented |
| **Code Virtualizer** | Defense MCP/CLI (`.cv`) | Windows native x86/x64 PE adapter implemented |

---

## Розробка та тестування

```powershell
python -m unittest discover -s tests -v
```

Проєкт поширюється за ліцензією [MIT License](../../LICENSE) (підключені рушії захисту використовують власні ліцензії).
