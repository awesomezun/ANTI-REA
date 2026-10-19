[English](README_en.md) · [简体中文](README_zh.md) · **繁體中文** · [日本語](README_ja.md) · [한국어](../../README.md) · [Türkçe](README_tr.md) · [Русский](README_ru.md) · [Tiếng Việt](README_vi.md) · [ไทย](README_th.md) · [Deutsch](README_de.md) · [Español](README_es.md) · [Français](README_fr.md) · [Українська](README_uk.md) · [Polski](README_pl.md) · [Português (Brasil)](README_pt-BR.md) · [العربية](README_ar.md) · [فارسی](README_fa.md) · [Bahasa Indonesia](README_id.md) · [Italiano](README_it.md) · [Ελληνικά](README_el.md) · [മലയാളം](README_ml.md)

# ANTI-REA

### 保護二進位檔案、應用程式與核心邏輯免受 REA 分析的統一 MCP。

**有想要保護的核心功能嗎？從二進位層面防止它被分析或複製。**

[![Defense vs REA](https://img.shields.io/badge/Defense_vs_REA-25%25-4bbd9c?style=flat-square)](#當前防禦力與路線圖-testapp-vm-vs-真實-rea-攻擊)
[![MCP + CLI](https://img.shields.io/badge/MCP-stdio_%2B_CLI-5c4ee5?style=flat-square)](#快速開始)
[![Python requirements](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)](#快速開始)
[![Engines](https://img.shields.io/badge/Engines-Kagura_%7C_VMP_%7C_Themida_%7C_CV-cb3837?style=flat-square)](#支援的引擎)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](../../LICENSE)

像 [REA](https://github.com/morluto/rea) 這樣的逆向工程工具，只要你對代理（Agent）說*「分析一下那個應用裡的這個功能是怎麼運作的，並在我的專案裡照著做一個」*，它就會拆解二進位檔案並原樣重寫核心邏輯。

**代理式攻擊？那我們就用代理式防禦——隨著時間推移越來越強的防禦。** **ANTI-REA** 的最終目標是**徹底阻斷 REA 所能分析的一切目標與分析方式**。只需用自然語言對你的代理說：**「保護我程式的核心功能，防止被 REA 分析和複製」**，代理就會找出核心程式碼與周邊線索，套用混淆與虛擬化（VM），並檢查原有功能是否完好、測量執行速度相當於原來的百分之多少。

你無需自己搭建複雜的攻防實驗環境。**我們每天都在讓防禦 PC 與獨立的 REA 攻擊 PC 對抗，觀察 TestApp 上的 VM 是如何被攻破的，修補弱點，打造隨時間推移越來越強的防禦。** 你只需將千錘百鍊的 ANTI-REA 連接到自己的代理即可使用。

---

## 當前防禦力與路線圖 (TestApp VM vs. 真實 REA 攻擊)

![針對真實 REA 攻擊的 TestApp VM 防禦力 25%](../../docs/assets/defense-roadmap.svg)

上面的數值不是抽象的開發進度，而是**套用了自研保護的 TestApp 在面對另一台 PC 上 REA 的直接攻擊時，實際能抵禦多少攻擊（防禦力）**。

### 防禦力強化階段（最終目標：阻斷 REA 所能分析的一切）

- **25%（當前）· 第一階段阻止靜態還原：** 從預設 VM 被輕易攻破起步，透過處理器多樣化與運算元上下文耦合，阻止外部 REA 靜態分析一次性還原核心計算公式。
- **50% · 阻斷靜態分析與周邊上下文推斷：** 隱藏調度器內部輔助函式與呼叫圖周邊的殘留線索，使僅靠靜態反編譯無法推斷原始邏輯。
- **75% · 動態追蹤與除錯防禦：** 當靜態分析受阻、攻擊代理動用除錯器、Frida、執行追蹤和記憶體傾印時，依然保護核心邏輯與常數不被輕易暴露。
- **100% · 全面防禦 REA 支援的所有目標與路徑：** 不僅限於原生二進位（C/C++, Rust, Go），還將擴展到 .NET、Java/Kotlin、JavaScript/Electron、Python 以及 macOS（Mach-O/ARM64），在 REA 支援的所有目標和平台上阻斷其分析與重寫。

---

## 快速開始

### 1. 安裝並連接代理 (`Set up your agent`)

無需手動輸入終端機指令或修改設定檔，直接用自然語言對你的代理（Claude Code、Cursor、Codex、Gemini CLI 等）說：

```text
將 ANTI-REA 安裝到本地 Python 虛擬環境 (.venv) 中，並把 antirea.defense_mcp 伺服器連接到 MCP，以便你直接使用。
```

### 2. 用自然語言指揮代理 (`Ask your agent`)

設定完成後，直接用自然語言提出要求即可：

```text
保護我專案中的核心計算邏輯和周邊線索，防止被 REA 分析和複製，並告訴我原有功能是否正常、執行速度是原來的百分之多少。
```

如果你已經有編譯好的執行檔和商業保護工具設定，也可以這樣說：

```text
先用 VMProtect 為 app.exe 制定一份保護計畫給我看，等我批准後再執行。
```

### 3. 在終端機直接使用 (`Use the terminal`)

```powershell
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json providers
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json doctor
```

---

## 運作原理與每日攻防循環

![ANTI-REA 概覽](../../docs/assets/antirea-overview.svg)

- **探索核心函式之外的周邊線索：** 只隱藏一個核心函式很容易透過前後呼叫程式碼或常數被推導出邏輯。ANTI-REA 會沿著 LLVM IR 的呼叫關係和資料流找出需要一併隱藏的周邊函式。
- **先確認計畫再安全執行：** 預先鎖定輸入檔案雜湊值和執行指令產生計畫（Plan），僅在批准後執行。
- **功能保持與速度比例測量：** 啟用 VM 必然會帶來效能開銷。ANTI-REA 會檢查保護後的輸出是否與原版完全一致，並測量執行速度相當於原版的百分之多少。

---

## 支援的引擎

雖然內建的免費開源引擎（`Kagura + ANTI-REA 加固`）每天都在變強，但**如果你眼下就需要更強的保護，可以購買商業版 Themida、VMProtect 或 Code Virtualizer 並接入 ANTI-REA，然後直接用自然語言告訴代理你期望的執行效能（速度保持率）和防禦強度即可。**

```text
使用 VMProtect（或 Themida / Code Virtualizer），在保持執行速度不低於原版 80% 的同時，盡可能高強度地保護核心邏輯。
```

| 引擎 | 連接方式 | 當前狀態 |
|---|---|---|
| **Kagura + ANTI-REA 加固** | C++/LLVM 建置與防禦管線 | 已在 Windows x86-64 C++ 樣本上套用真實 VM、自動檢驗功能與效能，並每日迭代加固 |
| **Themida** | 防禦 MCP/CLI（`.tmd`/`.tm`） | Windows 原生 x86/x64 PE 轉接器已實作（需本地安裝商業版） |
| **VMProtect** | 防禦 MCP/CLI（`.vmp`） | Windows 原生 x86/x64 PE 轉接器已實作（需本地安裝商業版） |
| **Code Virtualizer** | 防禦 MCP/CLI（`.cv`） | Windows 原生 x86/x64 PE 轉接器已實作（支援 Legacy / v4，需本地安裝） |

---

## 開發與測試

```powershell
python -m unittest discover -s tests -v
```

歡迎貢獻商業保護工具實測、新 VM 混淆思路、通用專案建置整合以及 macOS 支援。本專案基於 [MIT License](../../LICENSE) 發布（所連接的各保護引擎遵循其各自的授權條款）。
