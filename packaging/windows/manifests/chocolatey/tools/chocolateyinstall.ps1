$ErrorActionPreference = 'Stop'

# Downloads the signed installer from the GitHub release rather than embedding it. The checksum
# is the SHA256 of the signed NextFix-Setup-1.1.0.exe, the same value published in the
# release's SHA256SUMS, filled in by packaging/windows/refresh-manifests.mjs from the staged
# file so the package and the published asset agree by construction.

$packageArgs = @{
  packageName    = 'nextfix'
  fileType       = 'exe'
  url64bit       = 'https://github.com/GRCSAC/nextfix/releases/download/v1.1.0/NextFix-Setup-1.1.0.exe'
  checksum64     = '68647AC97274D662DD5C0C78B0B6F25FB6C6190A167CDC6053ABBDBF0AEEF7C2'
  checksumType64 = 'sha256'

  # Inno Setup. /SP- suppresses the "This will install..." prompt that /VERYSILENT does not.
  silentArgs     = '/VERYSILENT /SP- /SUPPRESSMSGBOXES /NORESTART'
  validExitCodes = @(0)

  softwareName   = 'NextFix*'
}

Install-ChocolateyPackage @packageArgs

# The installer is per-user by design (PrivilegesRequired=lowest, no UAC). Under an elevated
# Chocolatey shell that means the administrator's profile receives the app. Say so now rather
# than leaving it to be discovered from an empty Start menu on the normal account.
Write-Host ''
Write-Host "NextFix is installed per-user, for the account running this command ($env:USERNAME)," -ForegroundColor Cyan
Write-Host 'into %LOCALAPPDATA%\Programs\NextFix, which is now on that account''s PATH.' -ForegroundColor Cyan
Write-Host 'Open a new shell and run `nextfix scan <folder>`, or `nextfix serve` for the dashboards.' -ForegroundColor Cyan
