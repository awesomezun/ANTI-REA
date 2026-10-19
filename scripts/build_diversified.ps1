[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InputBuildDir,
    [Parameter(Mandatory = $true)][string]$OutputDir,
    [ValidateRange(1, 2147483647)][int]$Seed = 7192026,
    [string]$Workspace = ''
)

$ErrorActionPreference = 'Stop'
if (-not $Workspace) { $Workspace = Split-Path -Parent $PSScriptRoot }
$Workspace = [IO.Path]::GetFullPath($Workspace)
$InputBuildDir = [IO.Path]::GetFullPath($InputBuildDir)
$OutputDir = [IO.Path]::GetFullPath($OutputDir)
$allowedOutput = [IO.Path]::GetFullPath((Join-Path $Workspace '.runs\defense-iterations')) + [IO.Path]::DirectorySeparatorChar
if (-not $OutputDir.StartsWith($allowedOutput, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Output must be a fresh subdirectory of .runs/defense-iterations.'
}
if (Test-Path -LiteralPath $OutputDir) { throw 'Output directory already exists; refusing to overwrite.' }
$manifest = Join-Path $Workspace '.tools\kagura-toolchain.json'
$toolchain = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
if ($toolchain.kagura_commit -ne 'ac2136ee0408677cf7cdee55307e9b16edd5f4d5') { throw 'Unexpected Kagura version.' }
foreach ($entry in @(@($toolchain.optimizer, $toolchain.optimizer_sha256), @($toolchain.runtime, $toolchain.runtime_sha256))) {
    if ((Get-FileHash -LiteralPath $entry[0] -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry[1]) { throw 'Toolchain hash mismatch.' }
}
$originalCoverage = Get-Content -LiteralPath (Join-Path $InputBuildDir 'coverage.json') -Raw | ConvertFrom-Json
if ($originalCoverage.protection -ne 'layered' -or -not $originalCoverage.target_virtualized) {
    throw 'This experimental adapter requires an existing layered Kagura build.'
}
$sourceHashes = [ordered]@{}
foreach ($name in @('core.after.ll', 'core.prevm.ll', 'main.obj', 'coverage.json')) {
    $sourceHashes[$name] = (Get-FileHash -LiteralPath (Join-Path $InputBuildDir $name) -Algorithm SHA256).Hash.ToLowerInvariant()
}
& $toolchain.developer_shell -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null
New-Item -ItemType Directory -Path $OutputDir | Out-Null
$commands = [System.Collections.Generic.List[object]]::new()
function Write-Json([string]$Path, [object]$Value) {
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 16), [Text.UTF8Encoding]::new($false))
}
function Invoke-Recorded([string]$Program, [string[]]$Arguments) {
    $record = [ordered]@{program=$Program; arguments=$Arguments; exit_code=$null}
    $commands.Add($record)
    Write-Host ('> ' + $Program + ' ' + ($Arguments -join ' '))
    & $Program @Arguments
    $record.exit_code = $LASTEXITCODE
    Write-Json (Join-Path $OutputDir 'build-commands.json') $commands
    if ($record.exit_code -ne 0) { throw "$Program failed ($($record.exit_code))." }
}
$python = (Get-Command python.exe -ErrorAction Stop).Source
Invoke-Recorded $python @((Join-Path $Workspace 'antirea\diversify.py'),
    '--input-ir', (Join-Path $InputBuildDir 'core.after.ll'),
    '--runtime-source', (Join-Path $toolchain.kagura_source 'runtime\core\vm_interpreter.c'),
    '--opcode-source', (Join-Path $toolchain.kagura_source 'include\kagura\VMOpcodes.def'),
    '--output-dir', $OutputDir, '--seed', "$Seed")
$diversificationPath = Join-Path $OutputDir 'diversification.json'
$diversification = Get-Content -LiteralPath $diversificationPath -Raw | ConvertFrom-Json
$symbol = $diversification.dispatcher_symbol
if ($symbol -notmatch '^antirea_dispatch_[a-f0-9]{16}$') { throw 'Unsafe generated dispatcher symbol.' }
$coreIR = Join-Path $OutputDir 'core.diversified.ll'
$runtimeC = Join-Path $OutputDir 'runtime.generated.c'
$runtimeBefore = Join-Path $OutputDir 'runtime.before.ll'
$runtimeAfter = Join-Path $OutputDir 'runtime.after.ll'
$runtimeObj = Join-Path $OutputDir 'runtime.obj'
$coreObj = Join-Path $OutputDir 'core.obj'
$executable = Join-Path $OutputDir 'app.exe'
Invoke-Recorded $toolchain.clang @('-std=c11', '-O1', '-fno-inline', '-S', '-emit-llvm', $runtimeC, '-o', $runtimeBefore)
Invoke-Recorded $toolchain.optimizer @('-O1', '-kagura-fla', '-kagura-sub', '-kagura-co',
    "-kagura-allow=$symbol", "-kagura-seed=$Seed", '-S', $runtimeBefore, '-o', $runtimeAfter)
$runtimeText = Get-Content -LiteralPath $runtimeAfter -Raw
$escapedSymbol = [regex]::Escape($symbol)
$runtimeFunction = [regex]::Match($runtimeText, "(?ms)^define\s+[^\r\n]*@$escapedSymbol\([^\r\n]*\)[^\r\n]*\{\r?\n(?<body>.*?)^\}")
$body = $runtimeFunction.Groups['body'].Value
$runtimeEvidence = [ordered]@{
    function = $symbol; ir = $runtimeAfter; function_found = $runtimeFunction.Success
    fla_dispatcher = $body.Contains('kagura.loop:') -and $body.Contains('switch i32')
    substitution_instructions = [regex]::Matches($body, '(?m)^\s+%sub\.[^\r\n]*=').Count
    constant_obfuscation_instructions = [regex]::Matches($body, '(?m)^\s+%co\.[^\r\n]*=').Count
    requested_passes = @('fla', 'sub', 'co'); nested_vm = $false
    evidence_kind = 'Actual generated dispatcher IR structure, not generic metadata'
    codegen_optimization = 'O0 after protective runtime passes'
}
if (-not $runtimeEvidence.function_found -or -not $runtimeEvidence.fla_dispatcher -or
    $runtimeEvidence.substitution_instructions -lt 1 -or $runtimeEvidence.constant_obfuscation_instructions -lt 1) {
    throw 'Actual generated dispatcher lacks required FLA/SUB/CO evidence.'
}
Invoke-Recorded $toolchain.clang @('-O0', '-c', $runtimeAfter, '-o', $runtimeObj)
Invoke-Recorded $toolchain.clangxx @('-O1', '-c', $coreIR, '-o', $coreObj)
Invoke-Recorded $toolchain.clangxx @('-fuse-ld=lld', (Join-Path $InputBuildDir 'main.obj'), $coreObj, $runtimeObj,
    '-o', $executable, '-Wl,/DEBUG:NONE', '-Wl,/INCREMENTAL:NO')
$ir = Get-Content -LiteralPath $coreIR -Raw
$target = [regex]::Match($ir, '(?ms)^define\s+[^\r\n]*@antirea_score\([^\r\n]*\)[^\r\n]*\{\r?\n(?<body>.*?)^\}')
$vmCallCount = [regex]::Matches($ir, "call\s+i64\s+@$escapedSymbol\(").Count
$blobCount = [regex]::Matches($ir, '(?m)^@kagura_vm_bc_[^\r\n]*constant\s+\[').Count
if (-not $target.Success -or -not $target.Groups['body'].Value.Contains("@$symbol(") -or $vmCallCount -lt 1 -or $blobCount -lt 1) {
    throw 'Transformed target lacks the specialized VM wrapper/blob.'
}
foreach ($name in $sourceHashes.Keys) {
    if ((Get-FileHash -LiteralPath (Join-Path $InputBuildDir $name) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $sourceHashes[$name]) {
        throw "Original input changed during build: $name"
    }
}
$coverage = [ordered]@{
    schema_version=1; protection='diversified-layered'; target_function='antirea_score'
    target_virtualized=$true; vm_call_count=$vmCallCount; bytecode_blob_count=$blobCount; nonempty_bytecode=$true
    requested_core_passes=@('fla','sub','co','vm'); inherited_pre_vm_evidence=$originalCoverage.pre_vm_evidence
    source_build=$InputBuildDir; source_artifacts=$sourceHashes
    executable=$executable; executable_sha256=(Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash.ToLowerInvariant()
    executable_bytes=(Get-Item -LiteralPath $executable).Length
    after_ir=$coreIR; generated_runtime=$runtimeC; runtime_evidence=$runtimeEvidence
    runtime_after_ir_sha256=(Get-FileHash -LiteralPath $runtimeAfter -Algorithm SHA256).Hash.ToLowerInvariant()
    diversification_manifest=$diversificationPath
    diversification_sha256=(Get-FileHash -LiteralPath $diversificationPath -Algorithm SHA256).Hash.ToLowerInvariant()
    diversification=$diversification; kagura_commit=$toolchain.kagura_commit; llvm_version=$toolchain.llvm_version; seed=$Seed
    functional_evaluation='pending'; external_attack_evaluation='not_evaluated'
    scope='Build coverage only; format guard is not security evidence. Independent functional and external attack gates remain separate.'
}
Write-Json (Join-Path $OutputDir 'coverage.json') $coverage
Write-Host "Built defense-only diversified candidate: $executable"
