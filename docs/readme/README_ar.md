[English](README_en.md) · [简体中文](README_zh.md) · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](../../README.md) · [Türkçe](README_tr.md) · [Русский](README_ru.md) · [Tiếng Việt](README_vi.md) · [ไทย](README_th.md) · [Deutsch](README_de.md) · [Español](README_es.md) · [Français](README_fr.md) · [Українська](README_uk.md) · [Polski](README_pl.md) · [Português (Brasil)](README_pt-BR.md) · **العربية** · [فارسی](README_fa.md) · [Bahasa Indonesia](README_id.md) · [Italiano](README_it.md) · [Ελληνικά](README_el.md) · [മലയാളം](README_ml.md)

# ANTI-REA

### خادم MCP واحد لحماية الملفات الثنائية والتطبيقات والمنطق الأساسي من تحليل REA.

**هل لديك ميزة أساسية تريد حمايتها؟ امنع تحليلها أو استنساخها حتى المستوى الثنائي (Binary).**

[![Defense vs REA](https://img.shields.io/badge/Defense_vs_REA-25%25-4bbd9c?style=flat-square)](#roadmap)
[![MCP + CLI](https://img.shields.io/badge/MCP-stdio_%2B_CLI-5c4ee5?style=flat-square)](#quick-start)
[![Python requirements](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)](#quick-start)
[![Engines](https://img.shields.io/badge/Engines-Kagura_%7C_VMP_%7C_Themida_%7C_CV-cb3837?style=flat-square)](#engines)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](../../LICENSE)

تتيح أدوات الهندسة العكسية مثل [REA](https://github.com/morluto/rea) للوكيل الذكي تفكيك الملف الثنائي وإعادة كتابة المنطق الأصلي بالكامل بمجرد أن تطلب منه: *«افهم كيف تعمل هذه الميزة في ذلك التطبيق وابنِ مثلها في مشروعي»*.

**هجوم بالوكلاء الأذكياء؟ إذن ردنا هو دفاع بالوكلاء الأذكياء — دفاع يزداد قوة بمرور الوقت.** الهدف النهائي لمشروع **ANTI-REA** هو **منع كل ما يستطيع REA تحليله بشكل كامل**. ما عليك سوى أن تطلب من وكيلك باللغة الطبيعية: **«احمِ المنطق الأساسي لبرنامجي حتى لا يتمكن REA من تحليله أو نسخه»**، وسيقوم الوكيل بتحديد الكود الحساس والقرائن المحيطة به، وتطبيق التعمية والمحاكاة الافتراضية (VM)، والتحقق من سلامة الوظيفة الأصلية، وقياس النسبة المئوية لسرعة التشغيل مقارنة بالسرعة الأصلية.

لست بحاجة إلى بناء بيئة تجارب هجوم ودفاع معقدة بنفسك. **نحن نقوم يومياً بمواجهة بين حاسوب الدفاع وحاسوب هجوم منفصل يعمل بـ REA لاختبار كيفية اختراق VM في TestApp، وسد الثغرات، وتعزيز قوة الدفاع يوماً بعد يوم.** كل ما عليك فعله هو ربط ANTI-REA بوكيلك واستخدامه.

---

## قوة الدفاع الحالية وخارطة الطريق (TestApp VM مقابل هجمات REA الفعلية)

![TestApp VM Defense vs. REA 25%](../../docs/assets/defense-roadmap.svg)

الرقم أعلاه ليس جدولاً زمنياً نظرياً، بل يمثل **مدى صمود تطبيق TestApp المحمي بـ VM أمام الهجمات المباشرة من REA على جهاز منفصل**.

### مراحل تعزيز الدفاع (الهدف النهائي: حظر كل ما يحلله REA)

- **25% (حالياً) · إيقاف الاستعادة الثابتة من المرحلة الأولى:** تنويع المعالجات وربط سياق المعاملات منعا التحليل الثابت لـ REA من استعادة المعادلة الأساسية.
- **50% · حظر التحليل الثابت واستنتاج السياق المحيط:** إخفاء الدوال المساعدة داخل الموزع (Dispatcher) والقرائن في مخطط الاستدعاءات.
- **75% · الدفاع ضد التتبع الديناميكي وتصحيح الأخطاء (Debugging):** حماية المنطق والثوابت ضد مصححات الأخطاء وFrida وتتبع التنفيذ وتفريغ الذاكرة.
- **100% · دفاع شامل عبر جميع أهداف ومسارات REA:** توسيع الحماية من الملفات الثنائية الأصلية (C/C++, Rust, Go) إلى .NET وJava/Kotlin وJavaScript/Electron وPython وmacOS.

---

## البدء السريع

### 1. التثبيت وربط الوكيل (`Set up your agent`)

لا حاجة لكتابة أوامر الطرفية أو تعديل ملفات الإعداد يدوياً؛ فقط اطلب من وكيلك (Claude Code أو Cursor أو Codex أو Gemini CLI إلخ):

```text
قم بتثبيت ANTI-REA في بيئة Python افتراضية محلية (.venv) واربط خادم antirea.defense_mcp بإعدادات MCP لديك لتتمكن من استخدامه فوراً.
```

### 2. اطلب من وكيلك باللغة الطبيعية (`Ask your agent`)

```text
احمِ منطق الحساب الأساسي والقرائن المحيطة به في مشروعي حتى لا يتمكن REA من تحليلها أو استنساخها، وأخبرني ما إذا كانت الوظيفة الأصلية سليمة وكم تبلغ نسبة سرعة التشغيل مقارنة بالسرعة الأصلية.
```

```text
أنشئ أولاً خطة حماية لملف app.exe باستخدام VMProtect واعرضها عليّ، ونفذها بعد موافقتي.
```

### 3. الاستخدام المباشر عبر الطرفية (`Use the terminal`)

```powershell
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json providers
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json doctor
```

---

## كيف يعمل وكيف يزداد قوة كل يوم

![ANTI-REA Overview](../../docs/assets/antirea-overview.svg)

| Iteration | Protection | REA Outcome |
|---|---|---|

---

## المحركات المدعومة

بينما يزداد المحرك مفتوح المصدر المدمج (`Kagura + ANTI-REA`) قوة كل يوم، **إذا كنت بحاجة إلى حماية أقوى الآن، يمكنك شراء Themida أو VMProtect أو Code Virtualizer وربطه بـ ANTI-REA، ثم إخبار وكيلك باللغة الطبيعية بمستوى سرعة الأداء وقوة الدفاع التي تريدها.**

```text
استخدم VMProtect (أو Themida / Code Virtualizer) للحفاظ على سرعة التشغيل فوق 80% من السرعة الأصلية مع حماية المنطق الأساسي بأقصى درجة ممكنة.
```

| Engine | Connection | Status |
|---|---|---|
| **Kagura + ANTI-REA** | C++/LLVM defense pipeline | Active VM protection, automated verification & daily hardening (Windows x86-64) |
| **Themida** | Defense MCP/CLI (`.tmd`/`.tm`) | Windows native x86/x64 PE adapter implemented |
| **VMProtect** | Defense MCP/CLI (`.vmp`) | Windows native x86/x64 PE adapter implemented |
| **Code Virtualizer** | Defense MCP/CLI (`.cv`) | Windows native x86/x64 PE adapter implemented |

---

## التطوير والاختبار

```powershell
python -m unittest discover -s tests -v
```

يُوزع هذا المشروع بموجب ترخيص [MIT License](../../LICENSE) (تخضع محركات الحماية المرتبطة لتراخيصها الخاصة).
