$ErrorActionPreference = 'Stop'

# Chocolatey's AutoUninstaller handles the removal: the Inno installer registers a normal
# Add/Remove Programs entry ({AppId}_is1) with a working UninstallString, which AutoUninstaller
# finds and runs as `unins000.exe /SILENT`. Duplicating that here would risk running it twice.
# This file exists to say so; an absent chocolateyuninstall.ps1 is indistinguishable from a
# forgotten one during moderation.
#
# A silent uninstall never deletes user data (packaging/windows/nextfix.iss skips the prompt
# when UninstallSilent is true), so a Chocolatey user is never offered the purge. This notice is
# the only place they learn where the data is. Chocolatey runs this script before the
# AutoUninstaller, hence the future tense.

Write-Host 'NextFix is removed by its own uninstaller via Chocolatey AutoUninstaller.'
Write-Host ''
Write-Host 'Your NextFix data will be KEPT. A silent uninstall never deletes it, so scan history,' -ForegroundColor Cyan
Write-Host 'accounts and settings remain in:' -ForegroundColor Cyan
Write-Host "  $env:USERPROFILE\.nextfix" -ForegroundColor Cyan
Write-Host 'Reinstalling picks up where you left off. To remove it, delete that folder.' -ForegroundColor Cyan
