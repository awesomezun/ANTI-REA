[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SourceDir,
    [Parameter(Mandatory = $true)][string]$OutputDir,
    [Parameter(Mandatory = $true)][string]$ConfigInclude,
    [ValidateSet('vm', 'none', 'layered')][string]$Protection = 'vm',
    [ValidateRange(1, 2147483647)][int]$Seed = 1729,
    [string]$Workspace = ''
)

$ErrorActionPreference = 'Stop'
if (-not $Workspace) { $Workspace = Split-Path -Parent $PSScriptRoot }
$Workspace = [IO.Path]::GetFullPath($Workspace)
$SourceDir = [IO.Path]::GetFullPath($SourceDir)
$OutputDir = [IO.Path]::GetFullPath($OutputDir)
$ConfigInclude = [IO.Path]::GetFullPath($ConfigInclude)
$manifestPath = Join-Path $Workspace '.tools\kagura-toolchain.json'
if (-not (Test-Path -LiteralPath $manifestPath)) { throw 'Run scripts/bootstrap_kagura.ps1 first.' }
$toolchain = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
& $toolchain.developer_shell -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null
foreach ($required in @((Join-Path $SourceDir 'core.cpp'), (Join-Path $SourceDir 'main.cpp'), (Join-Path $ConfigInclude 'generated_config.h'))) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Input missing: $required" }
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$commands = [System.Collections.Generic.List[object]]::new()
function Invoke-Recorded([string]$Program, [string[]]$Arguments) {
    $record = [ordered]@{ program = $Program; arguments = $Arguments; exit_code = $null }
    $commands.Add($record)
    Write-Host ('> ' + $Program + ' ' + ($Arguments -join ' '))
    & $Program @Arguments
    $exitCode = $LASTEXITCODE
    $record.exit_code = $exitCode
    [IO.File]::WriteAllText((Join-Path $OutputDir 'build-commands.json'), ($commands | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
    if ($exitCode -ne 0) { throw "$Program failed with exit code $exitCode" }
}

function Get-LayerEvidence([string]$IRPath, [string]$FunctionName) {
    $text = Get-Content -LiteralPath $IRPath -Raw
    $escapedName = [regex]::Escape($FunctionName)
    $functionMatch = [regex]::Match($text, "(?ms)^define\s+[^\r\n]*@$escapedName\([^\r\n]*\)[^\r\n]*\{\r?\n(?<body>.*?)^\}")
    $body = $functionMatch.Groups['body'].Value
    $evidence = [ordered]@{
        function = $FunctionName
        ir = $IRPath
        function_found = $functionMatch.Success
        fla_dispatcher = $body.Contains('kagura.loop:') -and $body.Contains('switch i32')
        substitution_instructions = [regex]::Matches($body, '(?m)^\s+%sub\.[^\r\n]*=').Count
        constant_obfuscation_instructions = [regex]::Matches($body, '(?m)^\s+%co\.[^\r\n]*=').Count
        evidence_kind = 'IR structural evidence; upstream FLA/SUB/CO do not emit per-pass function metadata'
    }
    if (-not $evidence.function_found -or -not $evidence.fla_dispatcher -or
        $evidence.substitution_instructions -lt 1 -or $evidence.constant_obfuscation_instructions -lt 1) {
        throw "Layered passes did not leave required structural evidence in $FunctionName ($IRPath)."
    }
    return $evidence
}

$beforeIR = Join-Path $OutputDir 'core.before.ll'
$afterIR = Join-Path $OutputDir 'core.after.ll'
$coreObject = Join-Path $OutputDir 'core.obj'
$mainObject = Join-Path $OutputDir 'main.obj'
$executable = Join-Path $OutputDir 'app.exe'
$baseFlags = @('-std=c++17', '-O1', '-fno-inline', '-fno-exceptions', '-fno-rtti', '-I', $ConfigInclude)
Invoke-Recorded $toolchain.clangxx ($baseFlags + @('-S', '-emit-llvm', (Join-Path $SourceDir 'core.cpp'), '-o', $beforeIR))
$optimizerArgs = @('-O1')
$preVMFlags = @()
$preVMEvidence = $null
$runtimeEvidence = $null
$runtimeObject = $null
if ($Protection -eq 'layered') {
    $preVMFlags = @('-kagura-fla', '-kagura-sub', '-kagura-co')
    $preVMIR = Join-Path $OutputDir 'core.prevm.ll'
    # This parallel evidence build uses the same initial IR, seed and pass
    # sequence as the final build, stopping immediately before VM lowering.
    # Do not feed it through a second optimizer: that could undo the MBA.
    Invoke-Recorded $toolchain.optimizer (@('-O1') + $preVMFlags + @("-kagura-seed=$Seed", '-S', $beforeIR, '-o', $preVMIR))
    $preVMEvidence = Get-LayerEvidence $preVMIR 'antirea_score'
    $optimizerArgs += $preVMFlags
}
if ($Protection -ne 'none') { $optimizerArgs += @('-kagura-vm', "-kagura-seed=$Seed") }
# Give the baseline the same optimization pipeline, with protection disabled.
Invoke-Recorded $toolchain.optimizer ($optimizerArgs + @('-S', $beforeIR, '-o', $afterIR))
$compileIR = $afterIR
$vmCallCount = 0
$bytecodeCount = 0
$bytecodeSizes = @()
$targetVirtualized = $false
if ($Protection -ne 'none') {
    $ir = Get-Content -LiteralPath $afterIR -Raw
    $vmCallCount = [regex]::Matches($ir, 'call\s+i64\s+@kagura_vm_execute\(').Count
    $bytecodeCount = [regex]::Matches($ir, '(?m)^@kagura_vm_bc_[^\r\n]*constant\s+\[').Count
    $bytecodeSizes = @([regex]::Matches($ir, '(?m)^@kagura_vm_bc_[^\r\n]*constant\s+\[(\d+) x i8\]') | ForEach-Object { [int]$_.Groups[1].Value })
    $functionMatch = [regex]::Match($ir, '(?ms)^define\s+[^\r\n]*@antirea_score\([^\r\n]*\)[^\r\n]*\{\r?\n(?<body>.*?)^\}')
    $targetVirtualized = $functionMatch.Success -and $functionMatch.Groups['body'].Value.Contains('@kagura_vm_execute(')
    if (-not $targetVirtualized -or $bytecodeCount -lt 1) {
        throw 'Kagura did not virtualize antirea_score with a bytecode blob. Refusing to label this build protected.'
    }
} else {
    $ir = Get-Content -LiteralPath $afterIR -Raw
    if ($ir.Contains('@kagura_vm_execute(') -or $ir.Contains('@kagura_vm_bc_')) {
        throw 'Baseline unexpectedly contains Kagura VM protection.'
    }
}

if ($Protection -eq 'layered') {
    $runtimeBefore = Join-Path $OutputDir 'runtime.before.ll'
    $runtimeAfter = Join-Path $OutputDir 'runtime.after.ll'
    $runtimeObject = Join-Path $OutputDir 'runtime.obj'
    $runtimeSource = Join-Path $toolchain.kagura_source 'runtime\core\vm_interpreter.c'
    $runtimeInclude = Join-Path $toolchain.kagura_source 'include'
    # Kagura intentionally excludes kagura_* helpers even from allowlists.
    # Rename ONLY at preprocessing/link time so the actual dispatcher can be
    # transformed without patching upstream or changing the bytecode contract.
    Invoke-Recorded $toolchain.clang @('-std=c11', '-O1', '-fno-inline',
        '-Dkagura_vm_execute=antirea_vm_execute', '-I', $runtimeInclude,
        '-S', '-emit-llvm', $runtimeSource, '-o', $runtimeBefore)
    Invoke-Recorded $toolchain.optimizer (@('-O1') + $preVMFlags +
        @('-kagura-allow=antirea_vm_execute', "-kagura-seed=$Seed", '-S', $runtimeBefore, '-o', $runtimeAfter))
    $runtimeEvidence = Get-LayerEvidence $runtimeAfter 'antirea_vm_execute'
    $runtimeEvidence['requested_passes'] = @('fla', 'sub', 'co')
    $runtimeEvidence['nested_vm'] = $false
    $runtimeEvidence['symbol_mapping'] = 'kagura_vm_execute -> antirea_vm_execute (link-time alternate name)'
    $runtimeEvidence['codegen_optimization'] = 'O0: avoid another optimizer simplifying runtime obfuscation'
    # Native code generation only. The dispatcher is NOT virtualized again.
    Invoke-Recorded $toolchain.clang @('-O0', '-c', $runtimeAfter, '-o', $runtimeObject)
}

# Compile the transformed IR separately; never rerun whole-program optimization
# or mix runtime implementation into the IR being virtualized.
Invoke-Recorded $toolchain.clangxx @('-O1', '-c', $compileIR, '-o', $coreObject)
Invoke-Recorded $toolchain.clangxx ($baseFlags + @('-c', (Join-Path $SourceDir 'main.cpp'), '-o', $mainObject))
$linkArgs = @('-fuse-ld=lld', $mainObject, $coreObject, '-o', $executable, '-Wl,/DEBUG:NONE', '-Wl,/INCREMENTAL:NO')
if ($Protection -eq 'vm') { $linkArgs += $toolchain.runtime }
if ($Protection -eq 'layered') {
    $linkArgs += @($runtimeObject, '-Wl,/alternatename:kagura_vm_execute=antirea_vm_execute')
}
Invoke-Recorded $toolchain.clangxx $linkArgs

$coverage = [ordered]@{
    schema_version = 1
    protection = $Protection
    target_function = 'antirea_score'
    target_virtualized = $targetVirtualized
    vm_call_count = $vmCallCount
    bytecode_blob_count = $bytecodeCount
    bytecode_sizes = $bytecodeSizes
    requested_core_passes = @(if ($Protection -eq 'layered') { 'fla'; 'sub'; 'co'; 'vm' } elseif ($Protection -eq 'vm') { 'vm' })
    pre_vm_evidence = $preVMEvidence
    runtime_evidence = $runtimeEvidence
    kagura_commit = $toolchain.kagura_commit
    llvm_version = $toolchain.llvm_version
    seed = $Seed
    target = $toolchain.target
    executable = $executable
    executable_sha256 = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash.ToLowerInvariant()
    before_ir = $beforeIR
    after_ir = $afterIR
    checks = $(if ($Protection -eq 'layered') { @('target-wrapper-calls-vm', 'nonempty-bytecode-global', 'core-pre-vm-fla-sub-co-IR-evidence', 'runtime-dispatcher-fla-sub-co-IR-evidence') } elseif ($Protection -eq 'vm') { @('target-wrapper-calls-vm', 'nonempty-bytecode-global') } else { @('baseline-has-no-vm') })
    scope = 'Coverage evidence only; functional equivalence and attack evaluation are separate mandatory gates.'
}
[IO.File]::WriteAllText((Join-Path $OutputDir 'coverage.json'), ($coverage | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
Write-Host "Built $Protection sample: $executable"
