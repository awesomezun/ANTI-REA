[English](README_en.md) · [简体中文](README_zh.md) · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](../../README.md) · [Türkçe](README_tr.md) · [Русский](README_ru.md) · [Tiếng Việt](README_vi.md) · [ไทย](README_th.md) · [Deutsch](README_de.md) · [Español](README_es.md) · [Français](README_fr.md) · [Українська](README_uk.md) · [Polski](README_pl.md) · [Português (Brasil)](README_pt-BR.md) · [العربية](README_ar.md) · **فارسی** · [Bahasa Indonesia](README_id.md) · [Italiano](README_it.md) · [Ελληνικά](README_el.md) · [മലയാളം](README_ml.md)

# ANTI-REA

### یک سرور MCP واحد برای محافظت از فایل‌های باینری، برنامه‌ها و منطق اصلی در برابر تحلیل REA.

**ویژگی کلیدی و مهمی دارید که می‌خواهید از آن محافظت کنید؟ جلوی تحلیل و کپی‌برداری از آن را تا سطح باینری بگیرید.**

[![Defense vs REA](https://img.shields.io/badge/Defense_vs_REA-25%25-4bbd9c?style=flat-square)](#roadmap)
[![MCP + CLI](https://img.shields.io/badge/MCP-stdio_%2B_CLI-5c4ee5?style=flat-square)](#quick-start)
[![Python requirements](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)](#quick-start)
[![Engines](https://img.shields.io/badge/Engines-Kagura_%7C_VMP_%7C_Themida_%7C_CV-cb3837?style=flat-square)](#engines)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](../../LICENSE)

ابزارهای مهندسی معکوس مانند [REA](https://github.com/morluto/rea) به ایجنت اجازه می‌دهند تنها با این درخواست که *«بفهم این قابلیت در آن برنامه چطور کار می‌کند و مشابهش را در پروژه من بساز»* فایل باینری را کالبدشکافی کرده و منطق اصلی را عیناً بازنویسی کند.

**حمله ایجنتیک؟ پس پاسخ ما دفاع ایجنتیک است — دفاعی که با گذشت زمان قوی‌تر می‌شود.** هدف نهایی **ANTI-REA** این است که **هر هدف و روشی را که REA قادر به تحلیل آن است به طور کامل مسدود کند**. کافی است به زبان طبیعی به ایجنت خود بگویید: **«منطق اصلی برنامه من را طوری محافظت کن که REA نتواند آن را تحلیل یا کپی کند»**؛ ایجنت کدهای حساس و سرنخ‌های اطراف را پیدا می‌کند، مبهم‌سازی و مجازی‌سازی (VM) را اعمال می‌کند، سالم ماندن عملکرد اصلی را بررسی کرده و اعلام می‌کند سرعت اجرا چند درصدِ سرعت اولیه است.

نیازی نیست خودتان یک آزمایشگاه پیچیده حمله و دفاع راه‌اندازی کنید. **ما هر روز سیستم دفاعی خود را در برابر یک سیستم حمله مجزای مجهز به REA قرار می‌دهیم، بررسی می‌کنیم VM روی TestApp از کجا نفوذپذیر است، نقاط ضعف را می‌بندیم و دفاع را روزبه‌روز قوی‌تر می‌کنیم.** شما فقط ANTI-REA را به ایجنت خود متصل کرده و استفاده می‌کنید.

---

## قدرت دفاعی فعلی و نقشه راه (TestApp VM در برابر حمله واقعی REA)

![TestApp VM Defense vs. REA 25%](../../docs/assets/defense-roadmap.svg)

عدد بالا یک برنامه زمانی انتزاعی نیست، بلکه نشان می‌دهد **برنامه TestApp محافظت‌شده با VM ما در برابر حملات مستقیم REA از یک سیستم دیگر چقدر مقاومت می‌کند**.

### مراحل تقویت دفاع (هدف نهایی: مسدود کردن هر آنچه REA تحلیل می‌کند)

- **۲۵٪ (فعلی) · توقف بازسازی ایستای مرحله اول:** تنوع‌بخشی به هندلرها و پیوند بافت عملوندها مانع از بازسازی یک‌باره فرمول اصلی توسط تحلیل ایستای REA شد.
- **۵۰٪ · مسدودسازی تحلیل ایستا و استنتاج بافت اطراف:** پنهان‌کردن توابع کمکی داخل دیسپچر و سرنخ‌های گراف فراخوانی.
- **۷۵٪ · دفاع در برابر ردیابی پویا و دیباگ:** محافظت از منطق و ثوابت در برابر دیباگرها، Frida، ردیابی اجرا و دامپ حافظه.
- **۱۰۰٪ · دفاع کامل در برابر تمام اهداف و مسیرهای REA:** گسترش محافظت از باینری‌های بومی (C/C++, Rust, Go) به .NET، Java/Kotlin، JavaScript/Electron، Python و macOS.

---

## شروع سریع

### 1. نصب و اتصال به ایجنت (`Set up your agent`)

نیازی به اجرای دستی دستورات ترمینال یا ویرایش فایل‌های تنظیمات نیست؛ کافی است به ایجنت خود (Claude Code، Cursor، Codex، Gemini CLI و غیره) بگویید:

```text
بسته ANTI-REA را در یک محیط مجازی محلی پایتون (.venv) نصب کن و سرور antirea.defense_mcp را به تنظیمات MCP خود متصل کن تا بلافاصله بتوانی از آن استفاده کنی.
```

### 2. دستور به ایجنت با زبان طبیعی (`Ask your agent`)

```text
منطق محاسباتی اصلی و سرنخ‌های اطراف آن را در پروژه من طوری محافظت کن که REA نتواند تحلیل یا کپی کند، و به من بگو آیا عملکرد اصلی سالم مانده و سرعت اجرا چند درصد سرعت اولیه است.
```

```text
ابتدا یک برنامه محافظت با VMProtect برای app.exe بساز و به من نشان بده، و پس از تأیید من آن را اجرا کن.
```

### 3. استفاده مستقیم در ترمینال (`Use the terminal`)

```powershell
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json providers
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json doctor
```

---

## نحوه کار و چرخه تقویت روزانه

![ANTI-REA Overview](../../docs/assets/antirea-overview.svg)

| Iteration | Protection | REA Outcome |
|---|---|---|

---

## موتورهای پشتیبانی‌شده

در حالی که موتور متن‌باز داخلی (`Kagura + ANTI-REA`) هر روز قوی‌تر می‌شود، **اگر همین الان به محافظت قوی‌تری نیاز دارید، می‌توانید Themida، VMProtect یا Code Virtualizer را خریداری کرده و متصل کنید، و از طریق ANTI-REA به زبان طبیعی به ایجنت بگویید چه سطحی از سرعت اجرا و چه میزان دفاعی را می‌خواهید.**

```text
از VMProtect (یا Themida / Code Virtualizer) طوری استفاده کن که سرعت اجرا بالای ۸۰٪ سرعت اولیه بماند و در عین حال منطق اصلی با بیشترین قدرت محافظت شود.
```

| Engine | Connection | Status |
|---|---|---|
| **Kagura + ANTI-REA** | C++/LLVM defense pipeline | Active VM protection, automated verification & daily hardening (Windows x86-64) |
| **Themida** | Defense MCP/CLI (`.tmd`/`.tm`) | Windows native x86/x64 PE adapter implemented |
| **VMProtect** | Defense MCP/CLI (`.vmp`) | Windows native x86/x64 PE adapter implemented |
| **Code Virtualizer** | Defense MCP/CLI (`.cv`) | Windows native x86/x64 PE adapter implemented |

---

## توسعه و تست

```powershell
python -m unittest discover -s tests -v
```

این پروژه تحت مجوز [MIT License](../../LICENSE) منتشر می‌شود (موتورهای محافظتی متصل‌شده تابع مجوزهای مربوط به خود هستند).
