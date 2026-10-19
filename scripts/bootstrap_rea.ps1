param(
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$JavaHome = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$ProjectRoot = [IO.Path]::GetFullPath($ProjectRoot)
$reaRoot = Join-Path $ProjectRoot ".tools\rea"
$ghidraRoot = Join-Path $ProjectRoot ".tools\ghidra"
$downloads = Join-Path $reaRoot "downloads"
New-Item -ItemType Directory -Force -Path $reaRoot, $ghidraRoot, $downloads | Out-Null

# Pin the published package, its matching source, and the provider artifacts.
$reaVersion = "6.5.0"
$reaCommit = "3b79af28e80785afce9f5998d8f03289402a1847"
$nodeVersion = "22.19.0"
$nodeName = "node-v$nodeVersion-win-x64.zip"
$nodeSha256 = "ea3fad0e67a991d8477d8c01344b56e69c676ccb733f065b22436994b1253f86"
$ghidraName = "ghidra_12.1.4_PUBLIC_20260921.zip"
$ghidraSha256 = "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db"

function Get-VerifiedArchive([string]$Url, [string]$Destination, [string]$Sha256) {
    if (-not (Test-Path -LiteralPath $Destination)) {
        Write-Host "Downloading $Url"
        & curl.exe --fail --location --retry 3 --output $Destination $Url
        if ($LASTEXITCODE -ne 0) { throw "Download failed: $Url (partial file retained for inspection)." }
    }
    $actual = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Sha256) { throw "SHA256 mismatch for $Destination; refusing to extract." }
}

$nodeArchive = Join-Path $downloads $nodeName
Get-VerifiedArchive "https://nodejs.org/dist/v$nodeVersion/$nodeName" $nodeArchive $nodeSha256
$nodeDir = Join-Path $reaRoot "node-v$nodeVersion-win-x64"
if (-not (Test-Path -LiteralPath (Join-Path $nodeDir "node.exe"))) {
    Expand-Archive -LiteralPath $nodeArchive -DestinationPath $reaRoot
}
$node = Join-Path $nodeDir "node.exe"
$npm = Join-Path $nodeDir "node_modules\npm\bin\npm-cli.js"

$source = Join-Path $reaRoot "source"
if (-not (Test-Path -LiteralPath $source)) {
    & git clone --depth 1 --branch "rea-agents-$reaVersion" https://github.com/morluto/rea.git $source
    if ($LASTEXITCODE -ne 0) { throw "REA source checkout failed." }
}
$actualCommit = (& git -C $source rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $actualCommit -ne $reaCommit) {
    throw "REA source is not pinned at $reaCommit; preserving existing checkout."
}

$runtime = Join-Path $reaRoot "runtime"
$entry = Join-Path $runtime "node_modules\rea-agents\scripts\rea.mjs"
$package = Join-Path $runtime "node_modules\rea-agents\package.json"
New-Item -ItemType Directory -Force -Path $runtime | Out-Null
$oldPath = $env:PATH
try {
    $env:PATH = "$nodeDir;$oldPath"
    if (-not (Test-Path -LiteralPath $entry)) {
        # The published package includes its Windows native authority addon.
        # Lifecycle scripts are unnecessary for this read-only Ghidra path.
        & $node $npm install --prefix $runtime --cache (Join-Path $reaRoot "npm-cache") --ignore-scripts --omit=dev --no-audit --no-fund --save-exact "rea-agents@$reaVersion"
        if ($LASTEXITCODE -ne 0) { throw "Local REA dependency installation failed." }
    }
} finally { $env:PATH = $oldPath }
if ((Get-Content -LiteralPath $package -Raw | ConvertFrom-Json).version -ne $reaVersion) {
    throw "REA runtime version does not match the pinned version; preserving existing files."
}

$ghidraArchive = Join-Path $downloads $ghidraName
Get-VerifiedArchive "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/$ghidraName" $ghidraArchive $ghidraSha256
$ghidra = Join-Path $ghidraRoot "ghidra_12.1.4_PUBLIC"
if (-not (Test-Path -LiteralPath (Join-Path $ghidra "support\analyzeHeadless.bat"))) {
    Write-Host "Extracting verified Ghidra archive."
    Expand-Archive -LiteralPath $ghidraArchive -DestinationPath $ghidraRoot
}

if (-not $JavaHome) { $JavaHome = $env:JAVA_HOME }
if (-not $JavaHome) {
    $javaCommand = Get-Command java.exe -ErrorAction Stop
    $JavaHome = Split-Path -Parent (Split-Path -Parent $javaCommand.Source)
}
$JavaHome = [IO.Path]::GetFullPath($JavaHome)
if (-not (Test-Path -LiteralPath (Join-Path $JavaHome "bin\javac.exe"))) {
    throw "Pass -JavaHome pointing at a full 64-bit JDK 21 or newer. No global JDK installation will be made."
}
$runtimeConfig = [ordered]@{
    schema_version = 1
    rea_version = $reaVersion
    rea_commit = $reaCommit
    rea_source = $source
    node = $node
    entry = $entry
    ghidra_install_dir = $ghidra
    java_home = $JavaHome
    archives = @(
        @{ name = $nodeName; sha256 = $nodeSha256 },
        @{ name = $ghidraName; sha256 = $ghidraSha256 }
    )
}
$configPath = Join-Path $reaRoot "environment.json"
$runtimeConfig | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $configPath -Encoding UTF8
Write-Host "REA environment ready: $configPath"
Write-Host "No global installs or agent registrations were changed."
