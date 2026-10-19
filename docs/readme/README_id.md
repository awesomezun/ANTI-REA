[English](README_en.md) · [简体中文](README_zh.md) · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](../../README.md) · [Türkçe](README_tr.md) · [Русский](README_ru.md) · [Tiếng Việt](README_vi.md) · [ไทย](README_th.md) · [Deutsch](README_de.md) · [Español](README_es.md) · [Français](README_fr.md) · [Українська](README_uk.md) · [Polski](README_pl.md) · [Português (Brasil)](README_pt-BR.md) · [العربية](README_ar.md) · [فارسی](README_fa.md) · **Bahasa Indonesia** · [Italiano](README_it.md) · [Ελληνικά](README_el.md) · [മലയാളം](README_ml.md)

# ANTI-REA

### Satu MCP untuk melindungi biner, aplikasi, dan logika inti dari analisis REA.

**Punya fitur inti yang ingin dilindungi? Cegah analisis dan penggandaan hingga ke level biner.**

[![Defense vs REA](https://img.shields.io/badge/Defense_vs_REA-25%25-4bbd9c?style=flat-square)](#roadmap)
[![MCP + CLI](https://img.shields.io/badge/MCP-stdio_%2B_CLI-5c4ee5?style=flat-square)](#quick-start)
[![Python requirements](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)](#quick-start)
[![Engines](https://img.shields.io/badge/Engines-Kagura_%7C_VMP_%7C_Themida_%7C_CV-cb3837?style=flat-square)](#engines)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](../../LICENSE)

Alat rekayasa balik (reverse engineering) seperti [REA](https://github.com/morluto/rea) memungkinkan agen membongkar file biner dan menulis ulang logika aslinya secara persis saat Anda meminta: *"Pahami cara kerja fitur ini di aplikasi tersebut dan buatkan yang serupa di proyek saya"*.

**Serangan agen? Maka jawaban kami adalah pertahanan agen — pertahanan yang makin kuat seiring waktu.** Tujuan akhir **ANTI-REA** adalah **memblokir semua target dan metode analisis yang dapat dilakukan REA**. Cukup minta agen Anda dengan bahasa alami: **"Lindungi logika inti program saya agar tidak bisa dianalisis atau dikloning oleh REA"**, maka agen akan mencari kode inti beserta petunjuk di sekitarnya, menerapkan obfuskasi dan virtualisasi (VM), memastikan fungsi asli tidak rusak, serta mengukur berapa persen kecepatan eksekusinya dibandingkan kecepatan semula.

Anda tidak perlu repot membangun lab uji serang-bertahan sendiri. **Setiap hari kami mengadu PC pertahanan kami dengan PC penyerang REA terpisah untuk melihat bagaimana VM pada TestApp ditembus, menambal celahnya, dan meningkatkan daya tahan setiap hari.** Anda cukup menghubungkan ANTI-REA ke agen Anda dan langsung menggunakannya.

---

## Kekuatan Pertahanan Saat Ini & Peta Jalan (VM TestApp vs. Serangan REA Nyata)

![TestApp VM Defense vs. REA 25%](../../docs/assets/defense-roadmap.svg)

Angka di atas bukan jadwal proyek biasa, melainkan **seberapa tangguh TestApp berpelindung VM kami bertahan menghadapi serangan langsung REA dari PC lain**.

### Tahapan Penguatan Pertahanan (Tujuan Akhir: Memblokir Semua yang Dianalisis REA)

- **25% (Saat Ini) · Menghentikan Rekonstruksi Statis Tahap 1:** Diversifikasi handler dan pengikatan konteks operan mencegah analisis statis REA memulihkan rumus inti sekaligus.
- **50% · Memblokir Analisis Statis & Inferensi Konteks Sekitar:** Menyembunyikan fungsi pembantu di dalam dispatcher serta petunjuk pada grafik pemanggilan.
- **75% · Pertahanan terhadap Pelacakan Dinamis & Debugging:** Melindungi logika inti dan konstanta dari debugger, Frida, jejak eksekusi, dan dump memori.
- **100% · Pertahanan Penuh di Semua Target & Jalur REA:** Memperluas perlindungan dari biner native (C/C++, Rust, Go) ke .NET, Java/Kotlin, JavaScript/Electron, Python, dan macOS (Mach-O/ARM64).

---

## Mulai Cepat

### 1. Instalasi & Hubungkan ke Agen (`Set up your agent`)

Tidak perlu mengetik perintah terminal atau mengedit file JSON secara manual; cukup perintahkan agen Anda (Claude Code, Cursor, Codex, Gemini CLI, dll.):

```text
Instal ANTI-REA di lingkungan virtual Python lokal (.venv) dan hubungkan server antirea.defense_mcp ke konfigurasi MCP agar bisa langsung digunakan.
```

### 2. Perintahkan Agen dengan Bahasa Alami (`Ask your agent`)

```text
Lindungi logika perhitungan inti dan petunjuk di sekitarnya pada proyek saya agar tidak dapat dianalisis atau dikloning oleh REA, lalu beri tahu saya apakah fungsi aslinya tetap berjalan normal dan berapa persen kecepatan eksekusinya dibandingkan aslinya.
```

```text
Buat rencana proteksi VMProtect untuk app.exe terlebih dahulu, tunjukkan kepada saya, dan jalankan setelah saya setujui.
```

### 3. Gunakan Langsung dari Terminal (`Use the terminal`)

```powershell
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json providers
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json doctor
```

---

## Cara Kerja & Siklus Penguatan Harian

![ANTI-REA Overview](../../docs/assets/antirea-overview.svg)

| Iteration | Protection | REA Outcome |
|---|---|---|

---

## Mesin Pelindung yang Didukung

Meskipun mesin open-source bawaan (`Kagura + ANTI-REA`) makin kuat setiap hari, **jika Anda membutuhkan perlindungan yang lebih kuat saat ini juga, Anda dapat membeli Themida, VMProtect, atau Code Virtualizer, menghubungkannya ke ANTI-REA, lalu cukup tuliskan dalam bahasa alami kepada agen Anda seberapa besar performa eksekusi dan tingkat pertahanan yang Anda inginkan.**

```text
Gunakan VMProtect (atau Themida / Code Virtualizer) dengan menjaga kecepatan eksekusi di atas 80% dari aslinya sambil melindungi logika inti sekuat mungkin.
```

| Engine | Connection | Status |
|---|---|---|
| **Kagura + ANTI-REA** | C++/LLVM defense pipeline | Active VM protection, automated verification & daily hardening (Windows x86-64) |
| **Themida** | Defense MCP/CLI (`.tmd`/`.tm`) | Windows native x86/x64 PE adapter implemented |
| **VMProtect** | Defense MCP/CLI (`.vmp`) | Windows native x86/x64 PE adapter implemented |
| **Code Virtualizer** | Defense MCP/CLI (`.cv`) | Windows native x86/x64 PE adapter implemented |

---

## Pengembangan & Pengujian

```powershell
python -m unittest discover -s tests -v
```

Proyek ini didistribusikan di bawah lisensi [MIT License](../../LICENSE) (setiap mesin pelindung yang dihubungkan mengikuti lisensinya masing-masing).
