[English](../../README.md) · [简体中文](README_zh.md) · [繁體中文](README_zh-TW.md) · **日本語** · [한국어](README_ko.md) · [Türkçe](README_tr.md) · [Русский](README_ru.md) · [Tiếng Việt](README_vi.md) · [ไทย](README_th.md) · [Deutsch](README_de.md) · [Español](README_es.md) · [Français](README_fr.md) · [Українська](README_uk.md) · [Polski](README_pl.md) · [Português (Brasil)](README_pt-BR.md) · [العربية](README_ar.md) · [فارسی](README_fa.md) · [Bahasa Indonesia](README_id.md) · [Italiano](README_it.md) · [Ελληνικά](README_el.md) · [മലയാളം](README_ml.md)

# ANTI-REA

### バイナリ、アプリケーション、コアロジックをREAの解析から守る単一のMCP。

**守りたいコア機能がありますか？バイナリレベルまで解析・複製されないように保護しましょう。**

[![Defense vs REA](https://img.shields.io/badge/Defense_vs_REA-25%25-4bbd9c?style=flat-square)](#現在の防御力とロードマップ-testapp-vm-vs-実際のrea攻撃)
[![MCP + CLI](https://img.shields.io/badge/MCP-stdio_%2B_CLI-5c4ee5?style=flat-square)](#クイックスタート)
[![Python requirements](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)](#クイックスタート)
[![Engines](https://img.shields.io/badge/Engines-ANTI--REA_Engine_%7C_VMP_%7C_Themida_%7C_CV-cb3837?style=flat-square)](#対応エンジン)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](../../LICENSE)

[REA](https://github.com/morluto/rea)のようなリバースエンジニアリングツールは、エージェントに*「あのアプリのこの機能がどう動いているか解析して、自分のプロジェクトに同じものを作って」*と頼むだけで、バイナリを解析して元のロジックをそのまま再実装してしまいます。

**エージェンティック攻撃？ならばこちらはエージェンティック防御——時間が経つほど強くなる防御です。** **ANTI-REA**の最終目標は、**REAが解析できるすべての対象と解析手法を最終的にすべて阻止すること**です。自分のエージェントに**「プログラムのコア機能がREAに解析・複製されないように保護して」**と自然言語で伝えるだけで、エージェントがコアコードと周辺の手がかりを見つけて難読化・仮想化（VM）を適用し、元の機能が壊れていないか、実行速度が元の何%で動作するかまで測定して教えてくれます。

ユーザー自身が複雑な攻撃・防御の実験環境を構築する必要はありません。**私たちが毎日、防御PCと別環境のREA攻撃PCをぶつけ合い、TestAppにかけたVMがどこでどう突破されるかを確認し、弱点を補強して時間を追うごとに強くなる防御を作り上げています。** ユーザーはそのように日々鍛え上げられたANTI-REAを自分のエージェントに接続して使うだけです。

---

## 現在の防御力とロードマップ (TestApp VM vs. 実際のREA攻撃)

![実際のREA攻撃に対するTestApp VM防御力 25%](../../docs/assets/defense-roadmap.svg)

上の数値は単なる開発スケジュールではなく、**独自保護を適用したTestAppを別PCのREAが直接攻撃した際にどれだけ突破されないか（防御力）**を示しています。

### 防御力強化フェーズ（最終目標：REAが解析するすべての対象を遮断）

- **25%（現在）· 第1段階 静的復元の阻止：** 標準VMがそのまま突破されていた状態から、ハンドラ多様化とオペランド文脈結合により、外部REAの静的解析がコア計算式を一度に復元できないよう阻止した段階です。
- **50% · 静的解析および周辺文脈推論の遮断：** ディスパッチャ内部の補助関数やコールグラフ周辺に残る手がかりまで隠し、静的デコンパイルだけでは元のロジックを推測できないようにします。
- **75% · 動的トレースおよびデバッグ防御：** 静的解析が詰まった際に攻撃エージェントが使うデバッガ、Frida、実行トレース、メモリダンプでもコアロジックや定数が露出しないよう防御します。
- **100% · REAが解析する全対象・全経路の完全防御：** ネイティブバイナリ（C/C++, Rust, Go）だけでなく、.NET、Java/Kotlin、JavaScript/Electron、Pythonなど、REAが対応するすべての解析対象とプラットフォーム（Windows, macOSなど）でREAの解析・再実装を阻止することが最終目標です。

---

## クイックスタート

### 1. インストールとエージェント接続 (`Set up your agent`)

ターミナルコマンドや設定ファイルを直接触る必要はありません。お使いのエージェント（Claude Code, Cursor, Codex, Gemini CLIなど）に次のように指示するだけで、インストールからMCPサーバー接続まで自動で行います。

```text
ANTI-REAをローカルのPython仮想環境(.venv)にインストールして、すぐに使えるように antirea.defense_mcp サーバーをMCPに接続して。
```

### 2. エージェントに自然言語で指示する (`Ask your agent`)

設定が終わったら、複雑なオプションを覚えることなく自然言語で依頼できます。

```text
プロジェクトのコア計算ロジックと周辺の手がかりがREAに解析・複製されないように保護をかけて、元の機能が壊れていないかと、実行速度が元の何%で動くか教えて。
```

ビルド済みの実行ファイルと商用プロテクター設定がある場合は、次のようにも依頼できます：

```text
app.exeにVMProtectで保護計画を先に立てて見せて。承認したら実行して。
```

### 3. ターミナルから直接使う (`Use the terminal`)

```powershell
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json providers
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json doctor
```

---

## 仕組みと毎日の防御強化ループ

![ANTI-REA 概要](../../docs/assets/antirea-overview.svg)

- **コア関数だけでなく周辺の手がかりまで保護範囲を探索：** コア関数1つだけを隠しても、前後の呼び出しや定数から推測されてしまいます。LLVM IRの呼び出し関係とデータを辿り、一緒に隠すべき周辺関数を特定します。
- **計画確認後の安全な実行：** 入力ファイルのハッシュと実行コマンドを事前に計画（Plan）として固定し、承認された処理のみを実行します。
- **機能保持と速度比率の測定：** VMを適用すると実行速度にオーバーヘッドが生じます。保護後も元のバイナリと出力が完全一致するかを検査し、実行速度が元の何%で動作するかを測定して報告します。

| 回次 / 実験 | 適用した保護 | REA攻撃結果と観察 |
|---|---|---|

---

## 対応エンジン

標準搭載の無料・オープンソースエンジン（`ANTI-REA Engine 補強`）も毎日強化されていますが、**今すぐさらに強力な保護が必要な場合は、Themida、VMProtect、Code Virtualizerを有料で購入して接続し、ANTI-REAを通じて「どの程度の実行性能（速度維持率）とどの程度の防御強度を望むか」を自然言語でエージェントに伝えるだけで使えます。**

```text
VMProtect（または Themida / Code Virtualizer）を使って、実行速度は元の80%以上を維持しつつ、コアロジックを最大限強く防御して。
```

| エンジン | 接続方式 | 現在の対応状況 |
|---|---|---|
| **ANTI-REA Engine 補強** | C++/LLVMビルドおよび防御パイプライン | Windows x86-64 C++サンプルへのVM適用、機能・性能自動検査、毎日の防御強化を適用中 |
| **Themida** | 防御MCP/CLI（`.tmd`/`.tm`） | Windowsネイティブ x86/x64 PEアダプタ実装済み（ローカル環境へのインストールが必要） |
| **VMProtect** | 防御MCP/CLI（`.vmp`） | Windowsネイティブ x86/x64 PEアダプタ実装済み（ローカル環境へのインストールが必要） |
| **Code Virtualizer** | 防御MCP/CLI（`.cv`） | Windowsネイティブ x86/x64 PEアダプタ実装済み（Legacy / v4対応、ローカルインストールが必要） |

---

## 開発とテスト

```powershell
python -m unittest discover -s tests -v
```

商用プロテクター連携の再現、新しいVM難読化のアイデア、一般プロジェクトのビルド接続、macOS対応などのコントリビューションを歓迎します。本プロジェクトは [MIT License](../../LICENSE) の下で配布されています（連携する各保護エンジンはそれぞれのライセンスに従います）。
