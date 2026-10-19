[CmdletBinding()]
param(
    [string]$Workspace = '',
    [ValidateRange(1, 32)][int]$Jobs = 4,
    [switch]$SkipDownload
)

# All downloads/builds are local to this checkout. Existing Visual Studio C++
# tools and the Windows SDK are prerequisites; this script does not install them.
$ErrorActionPreference = 'Stop'
if (-not $Workspace) { $Workspace = Split-Path -Parent $PSScriptRoot }
$Workspace = [IO.Path]::GetFullPath($Workspace)
$toolsDir = Join-Path $Workspace '.tools'
$downloadDir = Join-Path $toolsDir 'downloads'
$sourceDir = Join-Path $toolsDir 'kagura'
$buildDir = Join-Path $toolsDir 'kagura-build'
$llvmVersion = '22.1.0'
$kaguraCommit = 'ac2136ee0408677cf7cdee55307e9b16edd5f4d5'
$archiveName = "clang+llvm-$llvmVersion-x86_64-pc-windows-msvc.tar.xz"
$llvmRoot = Join-Path $toolsDir "clang+llvm-$llvmVersion-x86_64-pc-windows-msvc"
$archive = Join-Path $downloadDir $archiveName
$archiveHash = '2dd6a6c990865f98766dec58cce1cbfba48e5affc0098e5b1fff96c2f1d23e81'
$archiveUrl = "https://github.com/llvm/llvm-project/releases/download/llvmorg-$llvmVersion/clang%2Bllvm-$llvmVersion-x86_64-pc-windows-msvc.tar.xz"

function Invoke-Checked([string]$Program, [string[]]$Arguments) {
    Write-Host ('> ' + $Program + ' ' + ($Arguments -join ' '))
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) {
    throw 'Visual Studio with C++ build tools and a Windows SDK is required.'
}
$vsPath = (& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1)
if (-not $vsPath) { throw 'No Visual Studio C++ tools installation was found.' }
$devShell = Join-Path $vsPath 'Common7\Tools\Launch-VsDevShell.ps1'
& $devShell -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null
$cmake = Join-Path $vsPath 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
$ninja = Join-Path $vsPath 'Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe'
foreach ($required in @($cmake, $ninja)) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Required VS CMake tool missing: $required" }
}
New-Item -ItemType Directory -Force -Path $toolsDir, $downloadDir | Out-Null

if (-not (Test-Path -LiteralPath (Join-Path $llvmRoot 'lib\cmake\llvm\LLVMConfig.cmake'))) {
    if (-not (Test-Path -LiteralPath $archive)) {
        if ($SkipDownload) { throw "Missing LLVM archive: $archive" }
        Invoke-Checked 'curl.exe' @('--fail', '--location', '--retry', '3', '--output', $archive, $archiveUrl)
    }
    $actualHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $archiveHash) {
        throw "LLVM archive checksum mismatch. Expected $archiveHash, got $actualHash. Archive was left in place."
    }
    Invoke-Checked 'tar.exe' @('-xf', $archive, '-C', $toolsDir)
}
foreach ($required in @('lib\cmake\llvm\LLVMConfig.cmake', 'lib\LLVMCore.lib', 'bin\clang-cl.exe')) {
    if (-not (Test-Path -LiteralPath (Join-Path $llvmRoot $required))) { throw "Incomplete LLVM dev archive: $required" }
}

if (-not (Test-Path -LiteralPath $sourceDir)) {
    if ($SkipDownload) { throw "Missing pinned Kagura checkout: $sourceDir" }
    Invoke-Checked 'git' @('clone', '--no-checkout', '--filter=blob:none', 'https://github.com/qusamulab/kagura.git', $sourceDir)
    Invoke-Checked 'git' @('-C', $sourceDir, 'checkout', '--detach', $kaguraCommit)
}
$actualCommit = (& git -C $sourceDir rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $actualCommit -ne $kaguraCommit) {
    throw "Kagura checkout must be at $kaguraCommit; refusing to replace existing content."
}
$dirty = @(& git -C $sourceDir status --porcelain --untracked-files=no)
if ($dirty.Count -gt 0) { throw 'Kagura checkout has tracked modifications; refusing to use it as pinned upstream.' }

$clangCL = Join-Path $llvmRoot 'bin\clang-cl.exe'
Invoke-Checked $cmake @(
    '-S', $sourceDir, '-B', $buildDir, '-G', 'Ninja',
    '-DCMAKE_BUILD_TYPE=Release', "-DCMAKE_MAKE_PROGRAM=$ninja",
    "-DLLVM_DIR=$(Join-Path $llvmRoot 'lib\cmake\llvm')",
    "-DCMAKE_C_COMPILER=$clangCL", "-DCMAKE_CXX_COMPILER=$clangCL",
    '-DKAGURA_BITCODE_TOOLS=ON', '-DKAGURA_BUILD_TESTS=OFF',
    '-DKAGURA_FORCE_STATIC_PLUGIN=ON', '-DKAGURA_USE_CACHE=OFF'
)
Invoke-Checked $cmake @('--build', $buildDir, '--parallel', "$Jobs", '--target', 'kagura-opt', 'kagura_runtime')

$optimizer = Join-Path $buildDir 'bin\kagura-opt.exe'
$runtime = Join-Path $buildDir 'runtime\kagura_runtime.lib'
foreach ($required in @($optimizer, $runtime)) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Build output missing: $required" }
}
$manifest = [ordered]@{
    schema_version = 1
    target = 'x86_64-pc-windows-msvc'
    llvm_version = $llvmVersion
    llvm_archive_url = $archiveUrl
    llvm_archive_sha256 = $archiveHash
    kagura_commit = $kaguraCommit
    llvm_root = $llvmRoot
    kagura_source = $sourceDir
    kagura_build = $buildDir
    clang = (Join-Path $llvmRoot 'bin\clang.exe')
    clangxx = (Join-Path $llvmRoot 'bin\clang++.exe')
    optimizer = $optimizer
    optimizer_sha256 = (Get-FileHash -LiteralPath $optimizer -Algorithm SHA256).Hash.ToLowerInvariant()
    runtime = $runtime
    runtime_sha256 = (Get-FileHash -LiteralPath $runtime -Algorithm SHA256).Hash.ToLowerInvariant()
    visual_studio = $vsPath
    developer_shell = $devShell
    cmake = $cmake
}
$manifestPath = Join-Path $toolsDir 'kagura-toolchain.json'
[IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
Write-Host "Kagura toolchain ready: $manifestPath"
