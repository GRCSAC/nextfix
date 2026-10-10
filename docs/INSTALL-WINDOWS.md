# Windows installer

How NextFix is installed on Windows, how a signed release is built, and how it reaches
winget and Chocolatey. The single executable, the Docker image and the release workflow are
documented alongside the build script in `packaging/`; this page covers only what sits on top
of `dist-bin/win32-x64/nextfix.exe`.

## For users

Three ways to install, all per-user (no administrator rights, no UAC prompt), all the same
signed files:

```powershell
winget install GRCSAC.NextFix
choco install nextfix
# or download NextFix-Setup-<version>.exe from https://github.com/GRCSAC/nextfix/releases
```

The installer puts `nextfix.exe` in `%LOCALAPPDATA%\Programs\NextFix`, adds that folder to the
user's `PATH` (open a new shell afterwards), and creates a Start Menu entry **NextFix
dashboards** that runs `nextfix serve`. Upgrades install over the previous version in place,
stopping a running `nextfix serve` first. Uninstall from Settings > Apps, or:

```powershell
"$env:LOCALAPPDATA\Programs\NextFix\unins000.exe"
```

Scan history, accounts, settings and the advisory cache live in `%USERPROFILE%\.nextfix`,
outside the install folder. An interactive uninstall asks whether to delete that folder and
defaults to keeping it; a silent uninstall (winget, Chocolatey, scripts) always keeps it.

Verify a download before running it: the SHA256 is in the `SHA256SUMS` file attached to the
same release, and the publisher is in the signature:

```powershell
Get-FileHash .\NextFix-Setup-<version>.exe -Algorithm SHA256
Get-AuthenticodeSignature .\NextFix-Setup-<version>.exe | Format-List Status, SignerCertificate
# Status: Valid    Subject: CN=GRCSAC, O=GRCSAC, L=Union Beach, S=New Jersey, C=US
```

Requirements: Windows 10 or 11, 64-bit.

## What is in `packaging/`

| Path | Role |
|---|---|
| `packaging/windows/release.ps1` | Builds and verifies the Windows artifacts. `-Build` then `-Check`; never publishes. |
| `packaging/windows/sign.ps1` | Authenticode-signs one file through Azure Artifact Signing (Trusted Signing) and verifies the result. Refuses to run in CI. |
| `packaging/windows/nextfix.iss` | Inno Setup script. Per-user, stable AppId, PATH handling, Start Menu entry, VersionInfo. |
| `packaging/windows/refresh-manifests.mjs` | Fills the winget and Chocolatey manifests from the staged, signed installer. |
| `packaging/windows/manifests/templates/` | The manifest templates (`__VERSION__`, `__URL__`, `__SHA256__`, `__DATE__`, `__PRODUCT_CODE__`). |
| `packaging/windows/manifests/winget/g/GRCSAC/NextFix/<version>/` | Generated: the folder submitted to `microsoft/winget-pkgs`. |
| `packaging/windows/manifests/chocolatey/` | Generated: the folder `choco pack` runs in. |
| `packaging/icons/make-icons.mjs` | Renders `nextfix.ico` (16 to 256 px) and `nextfix-256.png` from the brand mark with no dependencies. |
| `tools/signing-metadata.json` | Endpoint, account and certificate profile for SignTool's `/dmdf`. No secrets. |

The version comes from the root `package.json` and nowhere else: `release.ps1` reads it, passes
it to ISCC as `/DAppVersion`, checks that `nextfix.exe --version` prints the same string before
signing, and `refresh-manifests.mjs` stamps it into every manifest.

## Building a signed release (account owner)

Signing needs an interactive Azure login held by the owner of the signing account, so this runs
on the owner's machine, never in CI. The GitHub workflow builds the unsigned executable for the
other platforms; the Windows installer is built and signed here and attached to the release by
hand.

```powershell
az login --tenant paulgrcsac.onmicrosoft.com          # once per session (owner's identity)
cd C:\path\to\nextfix
npm ci
powershell -File packaging\windows\release.ps1 -Build  # exe -> sign -> installer -> sign -> SHA256SUMS -> manifests -> -Check
powershell -File packaging\windows\release.ps1 -Check  # re-run any time; must end "CHECK PASSED"
```

`-Build` runs, in this order and for these reasons:

1. `node packaging/build-sea.mjs --platform win32`, then confirms `dist-bin\win32-x64\nextfix.exe --version`
   prints the `package.json` version. A stale exe fails here, before it costs a signing round.
2. Signs `nextfix.exe`. This must happen before the installer is built, because the installer
   is built from this file; signing later would ship a signed installer that drops an unsigned
   exe on the user's disk.
3. `ISCC.exe /DAppVersion=<version> packaging\windows\nextfix.iss` writes
   `dist-bin\NextFix-Setup-<version>.exe`.
4. Signs the installer: the file users download and SmartScreen judges.
5. Writes `dist-bin\SHA256SUMS` and runs `refresh-manifests.mjs`. Both come after signing,
   because signing rewrites the files and a hash taken earlier describes bytes nobody downloads.
6. Runs `-Check`.

`-Check` verifies independently of the build: both artifacts exist; `nextfix.exe --version`
and the installer's VersionInfo (ProductVersion, FileVersion, CompanyName `GRCSAC`, ProductName)
match `package.json`; the installer is newer than the exe; both signatures validate with subject
`GRCSAC` and a timestamp; `SHA256SUMS` matches the files on disk and has no BOM; the winget and
Chocolatey manifests carry the current version, URL and SHA256. Any mismatch is a `[FAIL]` and
exit code 1.

`-SkipSign` exists for throwaway local builds. `-Build -SkipSign` skips both signing steps and
says so; `-Check -SkipSign` reports the unsigned artifacts as warnings and labels the result
`NOT RELEASABLE`. A plain `-Check` still fails on an unsigned artifact, so a throwaway build
cannot pass the gate by accident.

Then publish (owner):

```powershell
gh release upload v<version> dist-bin\NextFix-Setup-<version>.exe dist-bin\SHA256SUMS --clobber
```

and commit the generated manifests under `packaging/windows/manifests/` with the release.

### One-time prerequisites on the signing machine

1. **Inno Setup 6**: `winget install -e --id JRSoftware.InnoSetup`. `release.ps1` finds
   `ISCC.exe` under `%LOCALAPPDATA%\Programs\Inno Setup 6`, Program Files, or the PATH.
2. **Artifact Signing client tools**: `winget install -e --id Microsoft.Azure.ArtifactSigningClientTools`.
   One package brings a supported SignTool (Windows SDK 10.0.2261.755 or later; the 10.0.20348
   SDK is unsupported), the .NET 8 runtime, the VC++ redistributable and
   `Azure.CodeSigning.Dlib.dll`. It installs flat under
   `%LOCALAPPDATA%\Microsoft\MicrosoftArtifactSigningClientTools\` with no `x64` folder, and
   `winget list` shows the row as "Microsoft Azure CLI (64-bit)"; the dll is the real check.
3. **Azure CLI** signed in as the owner of the signing account:
   `az login --tenant paulgrcsac.onmicrosoft.com`. Authentication goes through
   `DefaultAzureCredential`, so the login session is enough and no secret is stored. The
   identity needs the **Artifact Signing Certificate Profile Signer** role on the account
   (Owner is not enough; a newly granted role takes about 15 minutes to propagate).
4. **`tools/signing-metadata.json`**: endpoint `https://eus.codesigning.azure.net`, account
   `NetVane`, certificate profile `GrcsacPublicTrust`, which issues `CN=GRCSAC`. The account
   is NetVane's; a NextFix account on the same tenant can replace it by editing that one file.
   `sign.ps1` verifies the subject after every signature, so a wrong profile cannot pass.

NetVane's repository keeps the long-form notes on this toolchain (`docs/SIGNING.md` and the
Setup section of `RELEASE.md` there); the layout and the traps are the same.

Trusted Signing certificates are valid for three days. Every signature carries an RFC 3161
timestamp from `http://timestamp.acs.microsoft.com`, so it keeps validating after the
certificate expires; `sign.ps1` refuses an untimestamped result.

## Package managers

Both channels download the installer from its GitHub release URL and pin its SHA256. Nothing
in the build reads those manifests, so `refresh-manifests.mjs` copies the values from the
staged installer and `-Check` fails if they drift. Submit only after the release assets are
live: both validators download the URL and compare the hash.

### winget (`GRCSAC.NextFix`)

The generated folder `packaging/windows/manifests/winget/g/GRCSAC/NextFix/<version>/` mirrors
the `microsoft/winget-pkgs` layout exactly.

```powershell
winget validate --manifest packaging\windows\manifests\winget\g\GRCSAC\NextFix\<version>
# Optional local install test (needs an elevated shell once to allow local manifests):
winget settings --enable LocalManifestFiles
winget install --manifest packaging\windows\manifests\winget\g\GRCSAC\NextFix\<version> --silent
winget uninstall GRCSAC.NextFix
```

Submit with `wingetcreate` (`winget install -e --id Microsoft.WingetCreate`), which forks
`microsoft/winget-pkgs` under the signed-in GitHub account and opens the pull request:

```powershell
wingetcreate submit --token <github-token> packaging\windows\manifests\winget\g\GRCSAC\NextFix\<version>
```

The first submission creates the package (`New package: GRCSAC.NextFix version <version>`);
later ones are updates. Their automation downloads the installer, verifies the hash, scans
the binary and runs a sandboxed install and uninstall; the Authenticode signature matters
here. The ARP entry the installer writes (`DisplayName NextFix`, `Publisher GRCSAC`,
`ProductCode {AppId}_is1`) is what winget correlates on, and it is pinned in `nextfix.iss`.
Published manifests are immutable; a mistake ships as a new version.

Needs the account owner: the GitHub token (a PR is opened under their account).

### Chocolatey (`nextfix`)

The generated folder `packaging/windows/manifests/chocolatey/` holds the nuspec,
`chocolateyinstall.ps1` (URL, SHA256, Inno silent switches), `chocolateyuninstall.ps1`
(deliberately delegates to AutoUninstaller) and `VERIFICATION.txt` with `LICENSE.txt`.

```powershell
cd packaging\windows\manifests\chocolatey
choco pack                                                # -> nextfix.<version>.nupkg
choco install nextfix --source "<absolute path to this folder>" --yes   # elevated; local test
choco uninstall nextfix --yes
choco apikey --key <api-key> --source https://push.chocolatey.org/      # once per machine
choco push nextfix.<version>.nupkg --source https://push.chocolatey.org/
```

Pass an absolute `--source` path: an elevated PowerShell opens in `System32`, where `.`
silently means the wrong directory. After the push, post in the **review comments** box on the
package page the same day: no moderator sees a package until automated checks pass or the
maintainer comments there, and a `403` on a later push usually means an earlier version is
still unapproved rather than that the key is wrong. Published versions are immutable.

Needs the account owner: the chocolatey.org API key, and the review-comment post.

## Behaviour pinned in `nextfix.iss`

- `AppId` is a fixed GUID (also the winget `ProductCode` as `{AppId}_is1`); never change it.
- `AppPublisher` is `GRCSAC`, matching the certificate subject Windows displays; `GRCSAC LLC`
  appears only in the copyright line.
- `PrivilegesRequired=lowest`, `DefaultDirName={localappdata}\Programs\NextFix`.
- The install folder is appended to `HKCU\Environment\Path` on install and removed on
  uninstall, with `WM_SETTINGCHANGE` broadcast both times.
- `CloseApplications=yes` plus an explicit `taskkill` of `nextfix.exe` before install and
  before uninstall, with the exit code logged (128 means nothing was running).
- `VersionInfoVersion` takes `/DFileVersion` (numeric) so a prerelease tag in `AppVersion`
  does not break the resource; `release.ps1` passes both.
- The icon is installed as `nextfix.ico` beside the exe and used for the Start Menu entry and
  the uninstall entry, so it does not depend on the executable carrying an icon resource.
- `LICENSE.txt` and `NOTICE.txt` are installed beside the exe (Apache-2.0).
