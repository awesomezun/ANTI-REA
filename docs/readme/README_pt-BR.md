[English](../../README.md) · [简体中文](README_zh.md) · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](README_ko.md) · [Türkçe](README_tr.md) · [Русский](README_ru.md) · [Tiếng Việt](README_vi.md) · [ไทย](README_th.md) · [Deutsch](README_de.md) · [Español](README_es.md) · [Français](README_fr.md) · [Українська](README_uk.md) · [Polski](README_pl.md) · **Português (Brasil)** · [العربية](README_ar.md) · [فارسی](README_fa.md) · [Bahasa Indonesia](README_id.md) · [Italiano](README_it.md) · [Ελληνικά](README_el.md) · [മലയാളം](README_ml.md)

# ANTI-REA

### Um único MCP para proteger binários, aplicações e a lógica principal contra a análise do REA.

**Tem uma funcionalidade essencial que precisa proteger? Impeça que ela seja analisada ou clonada até o nível binário.**

[![Defense vs REA](https://img.shields.io/badge/Defense_vs_REA-25%25-4bbd9c?style=flat-square)](#roadmap)
[![MCP + CLI](https://img.shields.io/badge/MCP-stdio_%2B_CLI-5c4ee5?style=flat-square)](#quick-start)
[![Python requirements](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)](#quick-start)
[![Engines](https://img.shields.io/badge/Engines-Kagura_%7C_VMP_%7C_Themida_%7C_CV-cb3837?style=flat-square)](#engines)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](../../LICENSE)

Ferramentas de engenharia reversa como o [REA](https://github.com/morluto/rea) permitem que um agente inspecione um binário e reimplemente sua lógica exata quando você pede: *"Entenda como esse recurso funciona naquele aplicativo e crie um igual no meu projeto"*.

**Ataque agêntico? Então nossa resposta é defesa agêntica — uma defesa que fica mais forte com o tempo.** O objetivo final do **ANTI-REA** é **bloquear tudo o que o REA consegue analisar**. Basta pedir ao seu agente em linguagem natural: **"Proteja a lógica principal do meu programa para que o REA não consiga analisá-la nem cloná-la"**, e o agente encontrará o código crítico e as pistas ao redor, aplicará ofuscação e virtualização (VM), verificará se o funcionamento original continua intacto e medirá a qual porcentagem da velocidade original ele roda.

Você não precisa montar um laboratório complexo de ataque e defesa por conta própria. **Todos os dias colocamos nosso PC de defesa contra um PC de ataque com REA separado para ver como a VM no TestApp é violada, corrigir as brechas e tornar a defesa cada vez mais forte.** Você só precisa conectar o ANTI-REA ao seu agente e usar.

---

## Força de Defesa Atual e Roadmap (VM do TestApp vs. Ataques Reais do REA)

![TestApp VM Defense vs. REA 25%](../../docs/assets/defense-roadmap.svg)

O número acima não é um cronograma abstrato, mas sim **o quanto nosso TestApp protegido por VM resiste a ataques diretos do REA vindos de outra máquina**.

### Etapas de Fortalecimento (Objetivo Final: Bloquear Tudo o que o REA Analisa)

- **25% (Atual) · Bloqueio da Reconstrução Estática Inicial:** A diversificação de handlers e o acoplamento de contexto de operandos impediram a análise estática do REA de recuperar a fórmula principal.
- **50% · Bloqueio de Análise Estática e Inferência de Contexto:** Ocultar funções auxiliares internas do dispatcher e pistas no grafo de chamadas.
- **75% · Defesa contra Rastreamento Dinâmico e Depuração:** Proteger a lógica e as constantes contra depuradores, Frida, rastros de execução e dumps de memória.
- **100% · Defesa Completa em Todos os Alvos e Caminhos do REA:** Expandir a proteção de binários nativos (C/C++, Rust, Go) para .NET, Java/Kotlin, JavaScript/Electron, Python e macOS (Mach-O/ARM64).

---

## Início Rápido

### 1. Instalação e Conexão com o Agente (`Set up your agent`)

Sem precisar digitar comandos no terminal ou editar arquivos JSON manualmente; basta pedir ao seu agente (Claude Code, Cursor, Codex, Gemini CLI, etc.):

```text
Instale o ANTI-REA em um ambiente virtual Python local (.venv) e conecte o servidor antirea.defense_mcp à sua configuração MCP para usá-lo imediatamente.
```

### 2. Peça ao seu Agente em Linguagem Natural (`Ask your agent`)

```text
Proteja a lógica principal de cálculo e as pistas ao redor no meu projeto para que o REA não possa analisá-las nem cloná-las, e me diga se a funcionalidade original continua intacta e a qual porcentagem da velocidade original ela está rodando.
```

```text
Crie primeiro um plano de proteção com o VMProtect para o app.exe, mostre para mim e execute quando eu aprovar.
```

### 3. Uso Direto pelo Terminal (`Use the terminal`)

```powershell
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json providers
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json doctor
```

---

## Como Funciona e Como Fica Mais Forte Todos os Dias

![ANTI-REA Overview](../../docs/assets/antirea-overview.svg)

| Iteration | Protection | REA Outcome |
|---|---|---|

---

## Motores Suportados

Embora o motor open-source integrado (`Kagura + ANTI-REA`) fique mais forte a cada dia, **se você precisar de uma proteção ainda mais pesada agora mesmo, pode adquirir o Themida, VMProtect ou Code Virtualizer, conectá-lo ao ANTI-REA e simplesmente dizer em linguagem natural ao seu agente qual desempenho de execução e qual nível de defesa você deseja.**

```text
Use o VMProtect (ou Themida / Code Virtualizer) mantendo a velocidade de execução acima de 80% da original enquanto protege a lógica principal o máximo possível.
```

| Engine | Connection | Status |
|---|---|---|
| **Kagura + ANTI-REA** | C++/LLVM defense pipeline | Active VM protection, automated verification & daily hardening (Windows x86-64) |
| **Themida** | Defense MCP/CLI (`.tmd`/`.tm`) | Windows native x86/x64 PE adapter implemented |
| **VMProtect** | Defense MCP/CLI (`.vmp`) | Windows native x86/x64 PE adapter implemented |
| **Code Virtualizer** | Defense MCP/CLI (`.cv`) | Windows native x86/x64 PE adapter implemented |

---

## Desenvolvimento e Testes

```powershell
python -m unittest discover -s tests -v
```

Este projeto é distribuído sob a licença [MIT License](../../LICENSE) (os motores de proteção conectados seguem suas respectivas licenças).
