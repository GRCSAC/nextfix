# Authenticode-sign one Windows artifact with Azure Artifact Signing (Trusted Signing), then
# prove the signature is the one we meant to apply.
#
#   powershell -File packaging\windows\sign.ps1 -Path dist-bin\win32-x64\nextfix.exe
#   powershell -File packaging\windows\sign.ps1 -Path dist-bin\NextFix-Setup-1.0.0.exe -VerifyOnly
#
# ONE file per invocation, deliberately. `powershell -File x.ps1 -Paths a.exe b.exe` binds a.exe
# to -Paths and b.exe to the next positional parameter, so an array parameter silently misbinds;
# a single scalar path cannot. release.ps1 loops.
#
# Never in CI. This certificate can sign ANY binary as GRCSAC. If a workflow could reach it,
# write access to the repository would be enough to sign malware with our name on it, so the
# script refuses when a CI environment variable is set and signing is done by a person, on a
# machine they control, with an interactive Azure login.
#
# One-time prerequisites on the signing machine (the account owner's):
#   1. winget install -e --id Microsoft.Azure.ArtifactSigningClientTools
#      One package: a supported SignTool (Windows SDK, >= 10.0.2261.755, not 10.0.20348), the
#      .NET 8 runtime, the VC++ redistributable and Azure.CodeSigning.Dlib.dll. It installs flat
#      under %LOCALAPPDATA%\Microsoft\MicrosoftArtifactSigningClientTools\ with no x64 folder,
#      and `winget list` shows the row as "Microsoft Azure CLI (64-bit)"; check for the dll.
#   2. Azure CLI, signed in as the owner of the signing account:
#        az login --tenant paulgrcsac.onmicrosoft.com
#      Authentication goes through DefaultAzureCredential, so the login session is enough and
#      no secret is stored anywhere. The signing identity needs the "Artifact Signing
#      Certificate Profile Signer" role on the account (Owner is not enough; signing is a
#      data-plane operation; a newly granted role takes ~15 minutes to propagate).
#   3. tools\signing-metadata.json: endpoint, account and certificate profile, in the exact
#      schema SignTool's /dmdf flag reads. The account is NetVane's for now; a NextFix account
#      on the same tenant can replace it by editing that file alone.
# NetVane keeps the long-form notes on this toolchain in its repository at docs/SIGNING.md and
# the Setup section of RELEASE.md; the layout and the traps are the same here.
#
# Artifact Signing certificates are valid for THREE DAYS. Every signature must carry an RFC 3161
# timestamp (http://timestamp.acs.microsoft.com) or it stops validating later the same week, so
# an untimestamped signature is a release-blocking defect and the verify step treats it as one.
param(
  [Parameter(Mandatory = $true)]
  [string]$Path,
  [switch]$VerifyOnly,
  # Resolved in the body: $PSScriptRoot is empty inside a param() default when the script is
  # launched as `powershell -File packaging\windows\sign.ps1` with a relative path.
  [string]$Metadata,
  # The subject the certificate profile issues (Azure portal -> Certificate profiles ->
  # GrcsacPublicTrust). Verified after every sign, so a misconfigured profile, or somebody else's
  # certificate, cannot pass silently. This is also the publisher name Windows shows in the
  # SmartScreen and UAC prompts, and the AppPublisher in nextfix.iss matches it on purpose.
  [string]$ExpectedCN = "GRCSAC",
  [string]$TimestampUrl = "http://timestamp.acs.microsoft.com"
)
$ErrorActionPreference = "Stop"

$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $Metadata) { $Metadata = Join-Path $ScriptDir "..\..\tools\signing-metadata.json" }

function Fail($m) { Write-Host "  [FAIL] $m"; exit 1 }
function Note($m) { Write-Host "  $m" }

# --- never in CI -----------------------------------------------------------------------------
foreach ($v in @("GITHUB_ACTIONS", "CI", "TF_BUILD", "JENKINS_URL", "GITLAB_CI")) {
  if ([Environment]::GetEnvironmentVariable($v)) {
    Write-Host "REFUSING TO SIGN: $v is set, so this looks like an automated build."
    Write-Host "Artifact Signing can sign ANY binary as $ExpectedCN. Sign on a machine a person controls."
    exit 1
  }
}

# --- locate the toolchain --------------------------------------------------------------------
# Searched rather than hardcoded: the client tools MSI and the Windows SDK land in different
# places depending on how each was installed (winget, the SDK installer, Visual Studio, a NuGet
# extract), and a wrong hardcoded path surfaces as a confusing "file not found" at release time.
function Get-SdkVersion($file) {
  # The SDK version is in the install path (...\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe).
  # VersionInfo.FileVersion is useless for this: every signtool.exe reports "4.00".
  if ($file.FullName -match '\\bin\\(\d+\.\d+\.\d+(?:\.\d+)?)\\') {
    $v = $null
    if ([version]::TryParse($Matches[1], [ref]$v)) { return $v }
  }
  return $null
}

function Find-SignTool {
  $cands = @()
  $cands += Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe `
              -ErrorAction SilentlyContinue | Where-Object { $_.DirectoryName -match '\\x64$' }
  $cands += Get-ChildItem "$env:ProgramFiles\Windows Kits\10\bin" -Recurse -Filter signtool.exe `
              -ErrorAction SilentlyContinue | Where-Object { $_.DirectoryName -match '\\x64$' }
  $onPath = Get-Command signtool.exe -ErrorAction SilentlyContinue
  if ($onPath) { $cands += Get-Item $onPath.Source }
  # 10.0.20348 is explicitly unsupported by the dlib, and it is a version people commonly have.
  $ok = $cands | Where-Object { $_.FullName -notmatch '10\.0\.20348' } |
        Sort-Object -Property @{ Expression = {
          $v = Get-SdkVersion $_
          if ($v) { $v } else { [version]"0.0.0.0" }
        } } -Descending
  return ($ok | Select-Object -First 1)
}

function Find-Dlib {
  # The MSI installs flat under %LOCALAPPDATA% with no x64 subdirectory; a NuGet extract of
  # Microsoft.ArtifactSigning.Client uses bin\x64\. Both shapes work; x64 is preferred when present.
  $roots = @(
    "$env:LOCALAPPDATA\Microsoft\MicrosoftArtifactSigningClientTools",
    "$env:ProgramFiles\Microsoft\Artifact Signing Client Tools",
    "${env:ProgramFiles(x86)}\Microsoft\Artifact Signing Client Tools",
    "$env:LOCALAPPDATA\Microsoft\MicrosoftTrustedSigningClientTools",
    "$env:LOCALAPPDATA\Microsoft\WinGet\Packages",
    (Join-Path $ScriptDir "..\..\.signing")
  )
  foreach ($r in $roots) {
    if (-not (Test-Path $r)) { continue }
    # Exact filename: Azure.CodeSigning.Dlib.Core.dll sits beside it and is not the dlib.
    $hits = Get-ChildItem $r -Recurse -Filter "Azure.CodeSigning.Dlib.dll" -ErrorAction SilentlyContinue
    if (-not $hits) { continue }
    $x64 = $hits | Where-Object { $_.DirectoryName -match '\\x64$' } | Select-Object -First 1
    if ($x64) { return $x64 }
    return ($hits | Select-Object -First 1)
  }
  return $null
}

$signtool = Find-SignTool
if (-not $signtool) {
  Fail @"
signtool.exe (x64, >= 10.0.2261.755, not 10.0.20348) not found. Install the client tools:
    winget install -e --id Microsoft.Azure.ArtifactSigningClientTools
"@
}
$sdk = Get-SdkVersion $signtool
$stVer = if ($sdk) { "SDK $sdk" } else { "SDK version undeterminable" }
if ($sdk -and $sdk -lt [version]"10.0.2261.755") {
  Fail @"
signtool comes from an SDK too old for the Artifact Signing dlib.
  found: $($signtool.FullName)
  SDK:   $sdk
  need:  >= 10.0.2261.755, and not 10.0.20348
    winget install -e --id Microsoft.Azure.ArtifactSigningClientTools
"@
}
if (-not $sdk) {
  Note "!! could not determine the SDK version of $($signtool.FullName) - proceeding; if the"
  Note "   dlib rejects it, install: winget install -e --id Microsoft.Azure.ArtifactSigningClientTools"
}

function Invoke-Verify([string]$file) {
  # A sign command that exits 0 is not proof: it can succeed against the wrong certificate
  # profile, or produce an untimestamped signature that expires in three days. Assert the
  # subject and the timestamp.
  #
  # signtool writes to stderr, and with $ErrorActionPreference = 'Stop' a native command's
  # stderr becomes a terminating error that would kill the script before the diagnosis prints.
  $prev = $ErrorActionPreference
  $ErrorActionPreference = 'SilentlyContinue'
  $out = & $signtool.FullName verify /pa /v $file 2>&1 | Out-String
  $ErrorActionPreference = $prev
  if ($LASTEXITCODE -ne 0) {
    Write-Host $out
    return "signature does not verify"
  }
  if ($out -notmatch [regex]::Escape($ExpectedCN)) {
    Write-Host $out
    return "signed, but the subject does not contain '$ExpectedCN' - wrong certificate profile?"
  }
  if ($out -notmatch "imestamp") {
    Write-Host $out
    return "signed but NOT timestamped - Artifact Signing certificates last 3 days, so this signature would stop validating this week"
  }
  return $null
}

$leaf = Split-Path $Path -Leaf
if (-not (Test-Path $Path)) { Fail "file not found: $Path" }

# --- verify-only mode ------------------------------------------------------------------------
if ($VerifyOnly) {
  Note "signtool: $($signtool.FullName) ($stVer)"
  $err = Invoke-Verify $Path
  if ($err) { Fail "$leaf : $err" }
  Write-Host "  [PASS] $leaf signed as $ExpectedCN, timestamped"
  exit 0
}

# --- sign ------------------------------------------------------------------------------------
if (-not (Test-Path $Metadata)) { Fail "signing metadata not found: $Metadata" }

$dlib = Find-Dlib
if (-not $dlib) {
  Fail @"
Azure.CodeSigning.Dlib.dll not found. Install the client tools:
    winget install -e --id Microsoft.Azure.ArtifactSigningClientTools
Or extract the NuGet package Microsoft.ArtifactSigning.Client into .signing\ at the repo root.
"@
}

$meta = Get-Content $Metadata -Raw | ConvertFrom-Json
Note "signtool: $($signtool.FullName) ($stVer)"
Note "dlib:     $($dlib.FullName)"
Note "profile:  $($meta.CertificateProfileName) @ $($meta.Endpoint) (account $($meta.CodeSigningAccountName))"

Note "signing $leaf ..."
$prevEap = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
& $signtool.FullName sign /v /fd SHA256 /tr $TimestampUrl /td SHA256 `
    /dlib $dlib.FullName /dmdf $Metadata $Path
$signRc = $LASTEXITCODE
$ErrorActionPreference = $prevEap
if ($signRc -ne 0) {
  Fail @"
signtool failed on $leaf (exit $signRc). Most common causes, in order:
  1. Not signed in to Azure, or the wrong tenant:  az login --tenant paulgrcsac.onmicrosoft.com
  2. Missing the 'Artifact Signing Certificate Profile Signer' role (Owner is not enough).
     A newly granted role can take ~15 min to propagate.
  3. Endpoint/region mismatch with the account, which surfaces as a bare 403 Forbidden.
"@
}
$err = Invoke-Verify $Path
if ($err) { Fail "$leaf : $err" }
Write-Host "  [PASS] $leaf signed as $ExpectedCN, timestamped"
