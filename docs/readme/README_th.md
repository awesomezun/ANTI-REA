[English](README_en.md) · [简体中文](README_zh.md) · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](../../README.md) · [Türkçe](README_tr.md) · [Русский](README_ru.md) · [Tiếng Việt](README_vi.md) · **ไทย** · [Deutsch](README_de.md) · [Español](README_es.md) · [Français](README_fr.md) · [Українська](README_uk.md) · [Polski](README_pl.md) · [Português (Brasil)](README_pt-BR.md) · [العربية](README_ar.md) · [فارسی](README_fa.md) · [Bahasa Indonesia](README_id.md) · [Italiano](README_it.md) · [Ελληνικά](README_el.md) · [മലയാളം](README_ml.md)

# ANTI-REA

### MCP เดียวสำหรับปกป้องไบนารี แอปพลิเคชัน และลอจิกหลักจากการวิเคราะห์ของ REA

**มีฟีเจอร์สำคัญที่ต้องการปกป้องใช่ไหม? ป้องกันไม่ให้ถูกวิเคราะห์หรือลอกเลียนแบบลงลึกถึงระดับไบนารี**

[![Defense vs REA](https://img.shields.io/badge/Defense_vs_REA-25%25-4bbd9c?style=flat-square)](#roadmap)
[![MCP + CLI](https://img.shields.io/badge/MCP-stdio_%2B_CLI-5c4ee5?style=flat-square)](#quick-start)
[![Python requirements](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)](#quick-start)
[![Engines](https://img.shields.io/badge/Engines-Kagura_%7C_VMP_%7C_Themida_%7C_CV-cb3837?style=flat-square)](#engines)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](../../LICENSE)

เครื่องมือวิศวกรรมย้อนกลับอย่าง [REA](https://github.com/morluto/rea) ช่วยให้เอเจนต์แกะไฟล์ไบนารีและเขียนลอจิกเดิมขึ้นมาใหม่ได้ทันทีเพียงสั่งว่า *"วิเคราะห์ว่าฟีเจอร์นี้ในแอปนั้นทำงานอย่างไร แล้วสร้างแบบเดียวกันในโปรเจกต์ของฉัน"*

**การโจมตีแบบเอเจนต์? งั้นเราก็คือการป้องกันแบบเอเจนต์ — การป้องกันที่แข็งแกร่งขึ้นตามกาลเวลา** เป้าหมายสูงสุดของ **ANTI-REA** คือ **การบล็อกทุกเป้าหมายและทุกวิธีการที่ REA สามารถวิเคราะห์ได้** เพียงสั่งเอเจนต์ของคุณด้วยภาษาธรรมชาติว่า **"ปกป้องลอจิกหลักของโปรแกรมไม่ให้ REA วิเคราะห์หรือลอกเลียนแบบได้"** เอเจนต์จะค้นหาโค้ดหลักและเบาะแสรอบข้าง ใช้การทำให้สับสน (Obfuscation) และการจำลองเสมือน (VM) ตรวจสอบว่าฟีเจอร์เดิมไม่เสียหาย และวัดว่าความเร็วในการทำงานคิดเป็นกี่เปอร์เซ็นต์ของความเร็วเดิม

คุณไม่จำเป็นต้องสร้างสภาพแวดล้อมทดสอบการโจมตีและป้องกันที่ซับซ้อนด้วยตัวเอง **ทุกวันเรานำ PC ฝั่งป้องกันมาปะทะกับ PC โจมตีที่ใช้ REA แยกต่างหาก เพื่อดูว่า VM บน TestApp ถูกเจาะอย่างไร ปิดจุดอ่อน และพัฒนาการป้องกันให้แข็งแกร่งขึ้นทุกวัน** คุณเพียงแค่เชื่อมต่อ ANTI-REA เข้ากับเอเจนต์ของคุณแล้วใช้งานได้ทันที

---

## ระดับการป้องกันปัจจุบันและโรดแมป (TestApp VM ปะทะ การโจมตีจริงจาก REA)

![TestApp VM Defense vs. REA 25%](../../docs/assets/defense-roadmap.svg)

ตัวเลขด้านบนไม่ใช่ตารางงานทั่วไป แต่แสดงถึง **ความทนทานของ TestApp ที่ใช้ VM ของเราเมื่อถูกโจมตีโดยตรงจาก REA บนเครื่องอื่น**

### ระยะการยกระดับการป้องกัน (เป้าหมายสูงสุด: บล็อกทุกสิ่งที่ REA วิเคราะห์ได้)

- **25% (ปัจจุบัน) · สกัดกั้นการกู้คืนเชิงสถิตระยะที่ 1:** การทำให้แฮนด์เลอร์หลากหลายและผูกบริบทของตัวถูกดำเนินการช่วยป้องกันไม่ให้ REA กู้คืนสูตรคำนวณหลักได้ในครั้งเดียว
- **50% · บล็อกการวิเคราะห์เชิงสถิตและการอนุมานบริบทรอบข้าง:** ซ่อนฟังก์ชันช่วยภายในดิสแพตเชอร์และเบาะแสในกราฟการเรียกฟังก์ชัน
- **75% · ป้องกันการติดตามแบบไดนามิกและการดีบัก:** ปกป้องลอจิกและค่าคงที่เมื่อผู้โจมตีใช้ดีบักเกอร์, Frida, การติดตามการทำงาน และการดัมพ์หน่วยความจำ
- **100% · ป้องกันทุกเป้าหมายและทุกเส้นทางที่ REA รองรับ:** ขยายจากไบนารีเนทีฟ (C/C++, Rust, Go) ไปยัง .NET, Java/Kotlin, JavaScript/Electron, Python และ macOS (Mach-O/ARM64)

---

## เริ่มต้นอย่างรวดเร็ว

### 1. ติดตั้งและเชื่อมต่อเอเจนต์ (`Set up your agent`)

ไม่ต้องพิมพ์คำสั่งเทอร์มินัลหรือแก้ไฟล์ตั้งค่าเอง เพียงสั่งเอเจนต์ของคุณ (Claude Code, Cursor, Codex, Gemini CLI ฯลฯ) ว่า:

```text
ติดตั้ง ANTI-REA ลงในสภาพแวดล้อมจำลอง Python (.venv) และเชื่อมต่อเซิร์ฟเวอร์ antirea.defense_mcp เข้ากับ MCP เพื่อให้พร้อมใช้งานทันที
```

### 2. สั่งงานเอเจนต์ด้วยภาษาธรรมชาติ (`Ask your agent`)

```text
ปกป้องลอจิกการคำนวณหลักและเบาะแสรอบข้างในโปรเจกต์ของฉันไม่ให้ REA วิเคราะห์หรือลอกเลียนแบบได้ แล้วบอกฉันว่าฟีเจอร์เดิมยังทำงานปกติไหม และความเร็วคิดเป็นกี่ % ของของเดิม
```

```text
สร้างแผนการป้องกันสำหรับ app.exe ด้วย VMProtect ให้ฉันดูก่อน เมื่อฉันอนุมัติแล้วค่อยรัน
```

### 3. ใช้งานผ่านเทอร์มินัลโดยตรง (`Use the terminal`)

```powershell
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json providers
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json doctor
```

---

## ทำงานอย่างไรและแข็งแกร่งขึ้นทุกวันได้อย่างไร

![ANTI-REA Overview](../../docs/assets/antirea-overview.svg)

| Iteration | Protection | REA Outcome |
|---|---|---|

---

## เอนจินที่รองรับ

แม้เอนจินโอเพนซอร์สในตัว (`Kagura + ANTI-REA`) จะแข็งแกร่งขึ้นทุกวัน **แต่หากคุณต้องการการปกป้องที่แข็งแกร่งยิ่งขึ้นในทันที คุณสามารถซื้อ Themida, VMProtect หรือ Code Virtualizer มาเชื่อมต่อ แล้วสั่งเอเจนต์ผ่าน ANTI-REA ด้วยภาษาธรรมชาติได้เลยว่าต้องการประสิทธิภาพการทำงานและระดับการป้องกันมากน้อยเพียงใด**

```text
ใช้ VMProtect (หรือ Themida / Code Virtualizer) เพื่อรักษาความเร็วในการทำงานให้ได้มากกว่า 80% ของของเดิม พร้อมทั้งป้องกันลอจิกหลักให้แน่นหนาที่สุด
```

| Engine | Connection | Status |
|---|---|---|
| **Kagura + ANTI-REA** | C++/LLVM defense pipeline | Active VM protection, automated verification & daily hardening (Windows x86-64) |
| **Themida** | Defense MCP/CLI (`.tmd`/`.tm`) | Windows native x86/x64 PE adapter implemented |
| **VMProtect** | Defense MCP/CLI (`.vmp`) | Windows native x86/x64 PE adapter implemented |
| **Code Virtualizer** | Defense MCP/CLI (`.cv`) | Windows native x86/x64 PE adapter implemented |

---

## การพัฒนาและการทดสอบ

```powershell
python -m unittest discover -s tests -v
```

โปรเจกต์นี้เผยแพร่ภายใต้สัญญาอนุญาต [MIT License](../../LICENSE) (เอนจินการป้องกันที่เชื่อมต่อจะเป็นไปตามสัญญาอนุญาตของแต่ละเครื่องมือ)
