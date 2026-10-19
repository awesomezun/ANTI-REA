[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SourceDir,
    [Parameter(Mandatory = $true)][string]$OutputDir,
    [Parameter(Mandatory = $true)][string]$ConfigInclude,
    [ValidateSet('none', 'core', 'expanded')][string]$Protection = 'expanded',
    [ValidateRange(1, 2147483647)][int]$Seed = 1729,
    [string]$Workspace = ''
)

$ErrorActionPreference = 'Stop'
if (-not $Workspace) { $Workspace = Split-Path -Parent $PSScriptRoot }
$Workspace = [IO.Path]::GetFullPath($Workspace)
$SourceDir = [IO.Path]::GetFullPath($SourceDir)
$OutputDir = [IO.Path]::GetFullPath($OutputDir)
$ConfigInclude = [IO.Path]::GetFullPath($ConfigInclude)
$python = (Get-Command python).Source
$toolchain = Get-Content -LiteralPath (Join-Path $Workspace '.tools\kagura-toolchain.json') -Raw | ConvertFrom-Json
& $toolchain.developer_shell -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null
foreach ($path in @((Join-Path $SourceDir 'core.cpp'), (Join-Path $SourceDir 'main.cpp'),
                   (Join-Path $SourceDir 'protection-policy.json'), (Join-Path $ConfigInclude 'generated_config.h'))) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Input missing: $path" }
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$commands = [Collections.Generic.List[object]]::new()
function Write-Json([string]$Path, $Value) {
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
}
function Invoke-Recorded([string]$Program, [string[]]$Arguments) {
    $record = [ordered]@{program=$Program; arguments=$Arguments; exit_code=$null}
    $commands.Add($record)
    Write-Host ('> ' + $Program + ' ' + ($Arguments -join ' '))
    & $Program @Arguments
    $exitCode = $LASTEXITCODE
    $record.exit_code = $exitCode
    Write-Json (Join-Path $OutputDir 'build-commands.json') $commands
    if ($exitCode -ne 0) { throw "$Program failed with exit code $exitCode" }
}
function Get-FunctionBody([string]$IR, [string]$Name) {
    $escaped = [regex]::Escape($Name)
    $found = [regex]::Match($IR, "(?ms)^define\s+[^\r\n]*@$escaped\([^\r\n]*\)[^\r\n]*\{\r?\n(?<body>.*?)^\}")
    if (-not $found.Success) { throw "Required function is absent from output IR: $Name" }
    return $found.Groups['body'].Value
}

$beforeIR = Join-Path $OutputDir 'core.before.ll'
$afterIR = Join-Path $OutputDir 'core.after.ll'
$scopePath = Join-Path $OutputDir 'scope.json'
$policyPath = Join-Path $SourceDir 'protection-policy.json'
$baseFlags = @('-std=c++17','-O1','-fno-inline','-fno-exceptions','-fno-rtti','-I',$ConfigInclude)
Invoke-Recorded $toolchain.clangxx ($baseFlags + @('-S','-emit-llvm',(Join-Path $SourceDir 'core.cpp'),'-o',$beforeIR))
$scopeMode = if ($Protection -eq 'core') { 'core' } else { 'expanded' }
Push-Location $Workspace
try {
    Invoke-Recorded $python @('-m','antirea.scope','--ir',$beforeIR,'--policy',$policyPath,'--mode',$scopeMode,'--output',$scopePath)
} finally { Pop-Location }
$scope = Get-Content -LiteralPath $scopePath -Raw | ConvertFrom-Json
if ($scope.status -ne 'ready') {
    throw "Scope analysis is not ready: $($scope.status). See $scopePath"
}
$selected = @($scope.selected_functions)
if ($selected.Count -eq 0) { throw 'Scope analysis selected no functions.' }
foreach ($name in $selected) {
    if ($name -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') { throw "Unsupported exact allowlist symbol: $name" }
}
$policy = Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json
# Trust only reviewed boundaries in the ready plan. An explicit sensitive/core
# designation can override a presentation label, so those selected functions
# must receive protection instead of being rejected as UI by this adapter.
$publicFunctions = @($scope.boundary_functions.PSObject.Properties.Name | Where-Object { $selected -notcontains $_ })
$optimizerArgs = @('-O1')
if ($Protection -ne 'none') {
    $optimizerArgs += @('-kagura-vm', "-kagura-seed=$Seed", "-kagura-allow=$($selected -join ',')")
}
Invoke-Recorded $toolchain.optimizer ($optimizerArgs + @('-S',$beforeIR,'-o',$afterIR))
$ir = Get-Content -LiteralPath $afterIR -Raw
$originalIR = Get-Content -LiteralPath $beforeIR -Raw
$functionCoverage = [ordered]@{}
foreach ($name in $selected) {
    $body = Get-FunctionBody $ir $name
    $call = [regex]::Match($body, 'call\s+i64\s+@kagura_vm_execute\(ptr\s+@(?<blob>kagura_vm_bc_[A-Za-z0-9_]+),\s+i32\s+(?<size>\d+)')
    $virtualized = $call.Success
    $size = if ($virtualized) { [int]$call.Groups['size'].Value } else { 0 }
    $blob = if ($virtualized) { $call.Groups['blob'].Value } else { $null }
    $blobFound = $false
    if ($virtualized) {
        $blobPattern = '(?m)^@' + [regex]::Escape($blob) + '\s*=\s*private constant\s+\[' + $size + ' x i8\]'
        $blobFound = [regex]::IsMatch($ir, $blobPattern)
    }
    if ($Protection -ne 'none' -and (-not $virtualized -or $size -le 0 -or -not $blobFound)) {
        throw "Selected function was not actually virtualized with nonempty bytecode: $name"
    }
    if ($Protection -eq 'none' -and $virtualized) { throw "Baseline unexpectedly virtualized: $name" }
    $functionCoverage[$name] = [ordered]@{virtualized=$virtualized; bytecode_global=$blob; bytecode_size=$size; nonempty_blob_verified=$blobFound}
}
$publicCoverage = @()
foreach ($name in $publicFunctions) {
    $body = Get-FunctionBody $ir $name
    if ($body.Contains('@kagura_vm_execute(')) { throw "Public presentation function was virtualized: $name" }
    $originalBody = Get-FunctionBody $originalIR $name
    $normalizedBody = (($body -replace '#\d+', '') -replace '\s+', ' ').Trim()
    $normalizedOriginal = (($originalBody -replace '#\d+', '') -replace '\s+', ' ').Trim()
    $unchanged = $normalizedBody -eq $normalizedOriginal
    if (-not $unchanged) { throw "Public presentation body unexpectedly changed (excluding attribute IDs): $name" }
    $publicCoverage += [ordered]@{function=$name; virtualized=$false; body_unchanged_ignoring_attribute_ids=$unchanged; review_reason=$scope.boundary_functions.$name.reason}
    $functionCoverage[$name] = [ordered]@{virtualized=$false; public_boundary=$true; body_unchanged_ignoring_attribute_ids=$unchanged; review_reason=$scope.boundary_functions.$name.reason}
}
$vmCallCount = [regex]::Matches($ir, 'call\s+i64\s+@kagura_vm_execute\(').Count
$expectedCount = if ($Protection -eq 'none') { 0 } else { $selected.Count }
if ($vmCallCount -ne $expectedCount) { throw "VM coverage mismatch: expected $expectedCount, found $vmCallCount" }
if (-not $functionCoverage.Contains('antirea_mix')) { throw 'Scope plan omitted the designated core root antirea_mix.' }

$coreObject = Join-Path $OutputDir 'core.obj'
$mainObject = Join-Path $OutputDir 'main.obj'
$executable = Join-Path $OutputDir 'app.exe'
Invoke-Recorded $toolchain.clangxx @('-O1','-c',$afterIR,'-o',$coreObject)
Invoke-Recorded $toolchain.clangxx ($baseFlags + @('-c',(Join-Path $SourceDir 'main.cpp'),'-o',$mainObject))
$linkArgs = @('-fuse-ld=lld',$mainObject,$coreObject,'-o',$executable,'-Wl,/DEBUG:NONE','-Wl,/INCREMENTAL:NO')
if ($Protection -ne 'none') { $linkArgs += $toolchain.runtime }
Invoke-Recorded $toolchain.clangxx $linkArgs
$coverage = [ordered]@{
    schema_version=1; protection=$Protection; target_function='antirea_mix'
    target_virtualized=$functionCoverage['antirea_mix'].virtualized; vm_call_count=$vmCallCount
    bytecode_blob_count=([regex]::Matches($ir,'(?m)^@kagura_vm_bc_[^\r\n]*constant\s+\[').Count)
    selected_functions=@(if ($Protection -ne 'none') { $selected }); function_coverage=$functionCoverage
    scope_plan=$scope; public_boundaries_unvirtualized=$true
    public_presentation_coverage=$publicCoverage; scope_manifest=$scopePath
    scope_mode=$scopeMode; scope_status=$scope.status
    requested_core_passes=@(if ($Protection -ne 'none') { 'vm' })
    kagura_commit=$toolchain.kagura_commit; llvm_version=$toolchain.llvm_version
    seed=$Seed; target=$toolchain.target; executable=$executable
    executable_sha256=(Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash.ToLowerInvariant()
    before_ir=$beforeIR; after_ir=$afterIR
    analyzed_modules=@('core.cpp'); excluded_modules=@([ordered]@{module='main.cpp';reason='Reviewed public CLI parsing/output adapter; standard library is outside analysis'})
    data_protection='Constants are immediate operands inside business functions. Only selected functions receive VM treatment; core-only intentionally leaves neighboring functions and their constants native. No global or string encryption is claimed.'
    scope='Per-function VM coverage only. Functional equivalence and REA evaluation remain mandatory independent gates.'
}
Write-Json (Join-Path $OutputDir 'coverage.json') $coverage
Write-Host "Built $Protection context sample: $executable"
