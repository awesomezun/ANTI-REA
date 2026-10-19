[English](../../README.md) · **简体中文** · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](README_ko.md) · [Türkçe](README_tr.md) · [Русский](README_ru.md) · [Tiếng Việt](README_vi.md) · [ไทย](README_th.md) · [Deutsch](README_de.md) · [Español](README_es.md) · [Français](README_fr.md) · [Українська](README_uk.md) · [Polski](README_pl.md) · [Português (Brasil)](README_pt-BR.md) · [العربية](README_ar.md) · [فارسی](README_fa.md) · [Bahasa Indonesia](README_id.md) · [Italiano](README_it.md) · [Ελληνικά](README_el.md) · [മലയാളം](README_ml.md)

# ANTI-REA

### 保护二进制文件、应用程序与核心逻辑免受 REA 分析的统一 MCP。

**有想要保护的核心功能吗？从二进制层面防止它被分析或克隆。**

[![Defense vs REA](https://img.shields.io/badge/Defense_vs_REA-25%25-4bbd9c?style=flat-square)](#当前防御力与路线图-testapp-vm-vs-真实-rea-攻击)
[![MCP + CLI](https://img.shields.io/badge/MCP-stdio_%2B_CLI-5c4ee5?style=flat-square)](#快速开始)
[![Python requirements](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)](#快速开始)
[![Engines](https://img.shields.io/badge/Engines-Kagura_%7C_VMP_%7C_Themida_%7C_CV-cb3837?style=flat-square)](#支持的引擎)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](../../LICENSE)

像 [REA](https://github.com/morluto/rea) 这样的逆向工程工具，只要你对智能体说*“分析一下那个应用里的这个功能是怎么工作的，并在我的项目里照着做一个”*，它就会拆解二进制文件并原样重写核心逻辑。

**智能体攻击？那我们就用智能体防御——随着时间推移越来越强的防御。** **ANTI-REA** 的最终目标是**彻底阻断 REA 所能分析的一切目标与分析方式**。只需用自然语言对你的智能体说：**“保护我程序的核心功能，防止被 REA 分析和克隆”**，智能体就会找出核心代码与周边线索，应用混淆与虚拟化（VM），并检查原有功能是否完好、测量运行速度相当于原来的百分之多少。

你无需自己搭建复杂的攻防实验环境。**我们每天都在让防御 PC 与独立的 REA 攻击 PC 对抗，观察 TestApp 上的 VM 是如何被攻破的，修补弱点，打造随时间推移越来越强的防御。** 你只需将千锤百炼的 ANTI-REA 连接到自己的智能体即可使用。

---

## 当前防御力与路线图 (TestApp VM vs. 真实 REA 攻击)

![针对真实 REA 攻击的 TestApp VM 防御力 25%](../../docs/assets/defense-roadmap.svg)

上面的数值不是抽象的开发进度，而是**应用了自研保护的 TestApp 在面对另一台 PC 上 REA 的直接攻击时，实际能抵御多少攻击（防御力）**。

### 防御力强化阶段（最终目标：阻断 REA 所能分析的一切）

- **25%（当前）· 第一阶段阻止静态还原：** 从默认 VM 被轻易攻破起步，通过处理器多样化与操作数上下文耦合，阻止外部 REA 静态分析一次性还原核心计算公式。
- **50% · 阻断静态分析与周边上下文推断：** 隐藏调度器内部辅助函数与调用图周边的残留线索，使仅靠静态反编译无法推断原始逻辑。
- **75% · 动态追踪与调试防御：** 当静态分析受阻、攻击智能体动用调试器、Frida、执行追踪和内存转储时，依然保护核心逻辑与常量不被轻易暴露。
- **100% · 全面防御 REA 支持的所有目标与路径：** 不仅限于原生二进制（C/C++, Rust, Go），还将扩展到 .NET、Java/Kotlin、JavaScript/Electron、Python 以及 macOS（Mach-O/ARM64），在 REA 支持的所有目标和平台上阻断其分析与重写。

---

## 快速开始

### 1. 安装并连接智能体 (`Set up your agent`)

无需手动输入终端命令或修改配置文件，直接用自然语言对你的智能体（Claude Code、Cursor、Codex、Gemini CLI 等）说：

```text
将 ANTI-REA 安装到本地 Python 虚拟环境 (.venv) 中，并把 antirea.defense_mcp 服务器连接到 MCP，以便你直接使用。
```

### 2. 用自然语言指挥智能体 (`Ask your agent`)

配置完成后，直接用自然语言提出要求即可：

```text
保护我项目中的核心计算逻辑和周边线索，防止被 REA 分析和克隆，并告诉我原有功能是否正常、运行速度是原来的百分之多少。
```

如果你已经有编译好的可执行文件和商业保护工具配置，也可以这样说：

```text
先用 VMProtect 为 app.exe 制定一份保护计划给我看，等我批准后再执行。
```

### 3. 在终端直接使用 (`Use the terminal`)

```powershell
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json providers
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json doctor
```

---

## 工作原理与每日攻防循环

![ANTI-REA 概览](../../docs/assets/antirea-overview.svg)

- **探索核心函数之外的周边线索：** 只隐藏一个核心函数很容易通过前后调用代码或常量被推导出逻辑。ANTI-REA 会沿着 LLVM IR 的调用关系和数据流找出需要一并隐藏的周边函数。
- **先确认计划再安全执行：** 预先锁定输入文件哈希和执行命令生成计划（Plan），仅在批准后执行。
- **功能保持与速度比例测量：** 启用 VM 必然会带来性能开销。ANTI-REA 会检查保护后的输出是否与原版完全一致，并测量运行速度相当于原版的百分之多少。

---

## 支持的引擎

虽然内置的免费开源引擎（`Kagura + ANTI-REA 加固`）每天都在变强，但**如果你眼下就需要更强的保护，可以购买商业版 Themida、VMProtect 或 Code Virtualizer 并接入 ANTI-REA，然后直接用自然语言告诉智能体你期望的运行性能（速度保持率）和防御强度即可。**

```text
使用 VMProtect（或 Themida / Code Virtualizer），在保持运行速度不低于原版 80% 的同时，尽可能高强度地保护核心逻辑。
```

| 引擎 | 连接方式 | 当前状态 |
|---|---|---|
| **Kagura + ANTI-REA 加固** | C++/LLVM 构建与防御流水线 | 已在 Windows x86-64 C++ 样本上应用真实 VM、自动检验功能与性能，并每日迭代加固 |
| **Themida** | 防御 MCP/CLI（`.tmd`/`.tm`） | Windows 原生 x86/x64 PE 适配器已实现（需本地安装商业版） |
| **VMProtect** | 防御 MCP/CLI（`.vmp`） | Windows 原生 x86/x64 PE 适配器已实现（需本地安装商业版） |
| **Code Virtualizer** | 防御 MCP/CLI（`.cv`） | Windows 原生 x86/x64 PE 适配器已实现（支持 Legacy / v4，需本地安装） |

---

## 开发与测试

```powershell
python -m unittest discover -s tests -v
```

欢迎贡献商业保护工具实测、新 VM 混淆思路、通用项目构建集成以及 macOS 支持。本项目基于 [MIT License](../../LICENSE) 发布（所连接的各保护引擎遵循其各自的许可证）。
