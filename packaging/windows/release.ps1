# NextFix Windows release helper: builds and stages the Windows artifacts and verifies them.
# It does not publish anything; attaching assets to the GitHub release and submitting the
# winget and Chocolatey manifests are the owner's steps in docs/INSTALL-WINDOWS.md.
#
#   powershell -File packaging\windows\release.ps1 -Build    # exe -> sign -> installer -> sign
#                                                            #   -> SHA256SUMS -> manifests -> -Check
#   powershell -File packaging\windows\release.ps1 -Check    # verify the staged artifacts
#
# The version comes from the root package.json and nowhere else.
#
# Order inside -Build, which is load-bearing:
#   1. build (or find) dist-bin\win32-x64\nextfix.exe and confirm `nextfix --version` prints
#      the package.json version, so a stale exe fails before it costs a signing round;
#   2. SIGN nextfix.exe, before anything copies or packages it: the installer is built FROM
#      this file, so signing later would ship a signed installer that drops an unsigned exe;
#   3. ISCC builds NextFix-Setup-<ver>.exe, a fresh PE with no signature of its own;
#   4. SIGN the installer: this is the file users download and SmartScreen judges;
#   5. write SHA256SUMS and the winget/Chocolatey manifests AFTER both signatures, because
#      signing rewrites the files and a hash taken earlier describes bytes nobody downloads.
param(
  [switch]$Build,
  [switch]$Check,
  # Throwaway builds only. -Build skips both signing steps and says so; -Check then reports the
  # unsigned artifacts as warnings instead of failures and labels the result NOT RELEASABLE.
  # A plain -Check (without -SkipSign) still goes red on an unsigned artifact, so a throwaway
  # build cannot pass the release gate by accident.
  [switch]$SkipSign,
  [string]$Iscc
)
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$fail = @()
$warn = @()
function Say($m) { Write-Host $m }
function Pass($m) { Write-Host "  [PASS] $m" }
function Warn($m) { Write-Host "  [WARN] $m"; $script:warn += $m }
function Fail($m) { Write-Host "  [FAIL] $m"; $script:fail += $m }

if (-not $Build -and -not $Check) {
  Say "usage: release.ps1 -Build [-SkipSign] | -Check [-SkipSign]"
  exit 2
}

# --- version: the root package.json is the single source -------------------------------------
$pkg = Get-Content (Join-Path $Root "package.json") -Raw | ConvertFrom-Json
$VER = [string]$pkg.version
if ($VER -notmatch '^(\d+\.\d+\.\d+)(-[\w.]+)?$') { throw "package.json version '$VER' is not semver" }
# VersionInfoVersion must be numeric; a prerelease tag stays in AppVersion and the file name.
$NUM = $Matches[1]
Say "=== NextFix Windows release helper :: v$VER ==="

$DistBin   = Join-Path $Root "dist-bin"
$Exe       = Join-Path $DistBin "win32-x64\nextfix.exe"
$Setup     = Join-Path $DistBin "NextFix-Setup-$VER.exe"
# Named apart from the release workflow's SHA256SUMS (every platform) so an upload never replaces it.
$Sums      = Join-Path $DistBin "SHA256SUMS.windows"
# The signed executable under the name the release attaches, so it replaces the unsigned asset.
$LooseExe  = Join-Path $DistBin "nextfix-$VER-win32-x64.exe"
$Iss       = Join-Path $PSScriptRoot "nextfix.iss"
$SignPs1   = Join-Path $PSScriptRoot "sign.ps1"
$Refresh   = Join-Path $PSScriptRoot "refresh-manifests.mjs"
$BuildSea  = Join-Path $Root "packaging\build-sea.mjs"

function Find-Iscc {
  if ($Iscc) { return $Iscc }
  foreach ($p in @("$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
                   "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
                   "$env:ProgramFiles\Inno Setup 6\ISCC.exe")) {
    if (Test-Path $p) { return $p }
  }
  $c = Get-Command ISCC.exe -ErrorAction SilentlyContinue
  if ($c) { return $c.Source }
  throw "ISCC.exe (Inno Setup 6) not found. Install it: winget install -e --id JRSoftware.InnoSetup"
}

function Invoke-Sign([string]$Path) {
  # Fails the build. An unsigned release that looks fine is the failure this script exists to
  # prevent, and nothing downstream would notice.
  if ($SkipSign) {
    Say "  !! -SkipSign: NOT signing $(Split-Path $Path -Leaf). This build MUST NOT be released."
    return
  }
  # One file per invocation: `powershell -File` binds each extra token to the next positional
  # parameter, so an array parameter would misbind.
  & powershell -NoProfile -ExecutionPolicy Bypass -File $SignPs1 -Path $Path
  if ($LASTEXITCODE -ne 0) { throw "Authenticode signing failed on $Path - refusing to continue" }
}

function Get-ReportedVersion([string]$ExePath) {
  # `nextfix --version` prints the version from the package.json compiled into the executable.
  $prev = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  $out = (& $ExePath --version 2>&1 | Out-String).Trim()
  $rc = $LASTEXITCODE
  $ErrorActionPreference = $prev
  if ($rc -ne 0) { return "exit $rc : $out" }
  return $out
}

function Write-Sha256Sums {
  # sha256sum format (lowercase hex, two spaces, path relative to dist-bin with forward
  # slashes) so `sha256sum -c SHA256SUMS` works for anyone verifying a download. No BOM: a
  # BOM is a silent way to make every checksum tool reject the file.
  $lines = @()
  foreach ($f in @($Setup, $Exe, $LooseExe)) {
    $rel = $f.Substring($DistBin.Length + 1).Replace('\', '/')
    $h = (Get-FileHash $f -Algorithm SHA256).Hash.ToLower()
    $lines += "$h  $rel"
  }
  [IO.File]::WriteAllText($Sums, ($lines -join "`n") + "`n", (New-Object Text.UTF8Encoding($false)))
  Say "  wrote $Sums"
}

function Invoke-Build {
  New-Item -ItemType Directory -Force (Split-Path $Exe) | Out-Null
  if (Test-Path $BuildSea) {
    Say "--- single executable (packaging\build-sea.mjs) ---"
    Push-Location $Root
    try {
      & node $BuildSea --platform win32
      $rc = $LASTEXITCODE
    } finally { Pop-Location }
    if ($rc -ne 0) { throw "build-sea.mjs failed (exit $rc) - refusing to continue; everything after this point would sign and package a stale exe" }
  } else {
    Say "--- single executable: packaging\build-sea.mjs not present, using the staged exe ---"
  }
  if (-not (Test-Path $Exe)) { throw "missing $Exe (run packaging\build-sea.mjs --platform win32 first)" }
  $reported = Get-ReportedVersion $Exe
  if ($reported -ne $VER) { throw "dist-bin\win32-x64\nextfix.exe reports '$reported', package.json says $VER - stale build, refusing to sign it" }
  Say "  nextfix.exe --version -> $reported"

  Say "--- sign nextfix.exe (before the installer is built from it) ---"
  Invoke-Sign $Exe
  # A byte copy keeps the signature: this is the loose download, under the release's asset name.
  Copy-Item $Exe $LooseExe -Force
  Say "  copied signed exe to $LooseExe"

  Say "--- installer (Inno Setup) ---"
  $iscc = Find-Iscc
  if (Test-Path $Setup) { Remove-Item $Setup -Force }
  & $iscc "/DAppVersion=$VER" "/DFileVersion=$NUM" "/Q" $Iss
  if ($LASTEXITCODE -ne 0) { throw "ISCC failed (exit $LASTEXITCODE)" }
  if (-not (Test-Path $Setup)) { throw "ISCC exited 0 but $Setup is missing" }
  Say "  wrote $Setup"

  Say "--- sign the installer ---"
  Invoke-Sign $Setup

  Say "--- checksums and package-manager manifests (after signing) ---"
  Write-Sha256Sums
  Push-Location $Root
  try {
    & node $Refresh
    $rc = $LASTEXITCODE
  } finally { Pop-Location }
  if ($rc -ne 0) { throw "refresh-manifests.mjs failed (exit $rc)" }
}

function Invoke-Check {
  Say "--- staged artifacts ---"
  if (Test-Path $Exe) { Pass "dist-bin\win32-x64\nextfix.exe present" } else { Fail "dist-bin\win32-x64\nextfix.exe missing" }
  if (Test-Path $Setup) { Pass "dist-bin\NextFix-Setup-$VER.exe present" } else { Fail "dist-bin\NextFix-Setup-$VER.exe missing (run -Build)" }
  if ($fail.Count -gt 0) { return }

  Say "--- versions ---"
  $reported = Get-ReportedVersion $Exe
  if ($reported -eq $VER) { Pass "nextfix.exe --version prints $VER" }
  else { Fail "nextfix.exe --version prints '$reported', package.json says $VER (stale exe)" }

  # Inno pads the version-resource strings with spaces; compare the trimmed values.
  $vi = (Get-Item $Setup).VersionInfo
  $productVersion = ([string]$vi.ProductVersion).Trim()
  $fileVersion    = ([string]$vi.FileVersion).Trim()
  $company        = ([string]$vi.CompanyName).Trim()
  $product        = ([string]$vi.ProductName).Trim()
  if ($productVersion -eq $VER) { Pass "installer VersionInfo ProductVersion = $VER" }
  else { Fail "installer VersionInfo ProductVersion = '$productVersion', expected $VER (ISCC ran with the wrong /DAppVersion?)" }
  if ($fileVersion -match ('^' + [regex]::Escape($NUM) + '(\.0)?$')) { Pass "installer VersionInfo FileVersion = $fileVersion" }
  else { Fail "installer VersionInfo FileVersion = '$fileVersion', expected $NUM" }
  if ($company -eq "GRCSAC") { Pass "installer VersionInfo CompanyName = GRCSAC (matches the certificate subject)" }
  else { Fail "installer VersionInfo CompanyName = '$company', expected GRCSAC" }
  if ($product -eq "NextFix") { Pass "installer VersionInfo ProductName = NextFix" }
  else { Fail "installer VersionInfo ProductName = '$product', expected NextFix" }

  # The installer is built from the exe, so an installer older than the exe packages a
  # previous build. Cheap, and it catches a re-run of build-sea.mjs without a re-run of ISCC.
  if ((Get-Item $Setup).LastWriteTimeUtc -ge (Get-Item $Exe).LastWriteTimeUtc) { Pass "installer is newer than nextfix.exe" }
  else { Fail "installer is OLDER than nextfix.exe - it packages a previous build. Re-run -Build." }

  # Checked here independently of -Build: a build that printed "signed" is not evidence, and
  # -SkipSign exists.
  Say "--- Authenticode signatures ---"
  foreach ($p in @($Exe, $Setup)) {
    & powershell -NoProfile -ExecutionPolicy Bypass -File $SignPs1 -Path $p -VerifyOnly
    if ($LASTEXITCODE -ne 0) {
      $leaf = Split-Path $p -Leaf
      if ($SkipSign) { Warn "$leaf is not signed (throwaway build; NOT releasable)" }
      else { Fail "$leaf is not correctly signed (see above) - do not release" }
    }
  }

  Say "--- SHA256SUMS.windows ---"
  if (-not (Test-Path $Sums)) { Fail "dist-bin\SHA256SUMS missing (run -Build)" }
  else {
    $bytes = [IO.File]::ReadAllBytes($Sums)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { Fail "SHA256SUMS.windows has a UTF-8 BOM; checksum tools reject it" }
    $listed = @{}
    foreach ($line in (Get-Content $Sums)) {
      if ($line -match '^([0-9a-f]{64})  (.+)$') { $listed[$Matches[2]] = $Matches[1] }
    }
    foreach ($f in @($Setup, $Exe, $LooseExe)) {
      $rel = $f.Substring($DistBin.Length + 1).Replace('\', '/')
      $h = (Get-FileHash $f -Algorithm SHA256).Hash.ToLower()
      if (-not $listed.ContainsKey($rel)) { Fail "SHA256SUMS.windows has no entry for $rel" }
      elseif ($listed[$rel] -ne $h) { Fail "SHA256SUMS.windows entry for $rel does not match the file on disk (hash taken before signing?). Re-run -Build." }
      else { Pass "SHA256SUMS matches $rel" }
    }
  }

  Say "--- winget and Chocolatey manifests ---"
  Push-Location $Root
  try {
    & node $Refresh --check
    $rc = $LASTEXITCODE
  } finally { Pop-Location }
  if ($rc -eq 0) { Pass "manifests carry v$VER, the release URL and the installer's SHA256" }
  else { Fail "manifests are stale or missing (see above). Re-run -Build, or node packaging\windows\refresh-manifests.mjs" }
}

if ($Build) { Invoke-Build }
Invoke-Check

Say ""
if ($fail.Count -gt 0) {
  Say "CHECK FAILED: $($fail.Count) problem(s)"
  foreach ($f in $fail) { Say "  - $f" }
  exit 1
}
if ($warn.Count -gt 0) {
  Say "CHECK PASSED WITH WARNINGS: NOT RELEASABLE ($($warn.Count) unsigned artifact(s); rebuild without -SkipSign)"
  exit 0
}
Say "CHECK PASSED: dist-bin\NextFix-Setup-$VER.exe is signed, verified and described by SHA256SUMS.windows and the manifests"
exit 0
