; NextFix - Windows installer (Inno Setup 6).
; Per-user install, no administrator rights and no UAC prompt. A newer version installs over
; the previous one in place (same AppId), so only one copy is ever on the machine.
;
; Build:  ISCC.exe /DAppVersion=<ver> packaging\windows\nextfix.iss
;         release.ps1 reads <ver> from the root package.json, the single source of the version,
;         so the installer, its VersionInfo and `nextfix --version` cannot disagree.
;         /DAppVersion is required; a hardcoded fallback could stamp a stale version silently.
;         /DFileVersion=<a.b.c> is the numeric form for VersionInfoVersion when AppVersion
;         carries a prerelease tag (1.0.0-rc.1); it defaults to AppVersion.
; Output: dist-bin\NextFix-Setup-<AppVersion>.exe  (packages dist-bin\win32-x64\nextfix.exe)
;
; Signing order (release.ps1): nextfix.exe is signed BEFORE this script packages it, and the
; installer is signed after ISCC writes it. Signing the exe later would ship a signed installer
; that drops an unsigned nextfix.exe on the user's disk.

#define AppName "NextFix"
#ifndef AppVersion
  #error AppVersion is required: build with ISCC.exe /DAppVersion=<ver> (release.ps1 reads it from package.json)
#endif
#ifndef FileVersion
  #define FileVersion AppVersion
#endif
; Must match the Authenticode certificate subject (CN=GRCSAC): Windows shows what the
; certificate says in the SmartScreen and UAC prompts, and an installer naming a different
; publisher than its signature is a mismatch a careful user cannot resolve. GRCSAC LLC, the
; legal entity, belongs in the copyright line only.
#define AppPublisher "GRCSAC"
#define AppURL "https://nextfix.grcsac.com"
#define RepoURL "https://github.com/GRCSAC/nextfix"
#define AppExe "nextfix.exe"
; Stable product GUID. Never change it between versions: it drives upgrade and uninstall
; detection here and is the ProductCode ({AppId}_is1) in the winget manifest.
#define AppGuid "6E2B7C41-9F3D-4A58-B1C6-2D7E8F9A0B13"
#ifndef SourceExe
  #define SourceExe "..\..\dist-bin\win32-x64\" + AppExe
#endif
#ifndef OutputDirectory
  #define OutputDirectory "..\..\dist-bin"
#endif

[Setup]
AppId={{{#AppGuid}}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#RepoURL}/releases
AppComments=Reachability- and exposure-aware vulnerability prioritization. Scanners find. NextFix decides.
DefaultDirName={localappdata}\Programs\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
DisableDirPage=auto
PrivilegesRequired=lowest
OutputDir={#OutputDirectory}
OutputBaseFilename=NextFix-Setup-{#AppVersion}
SetupIconFile=..\icons\nextfix.ico
; The icon ships as a file beside the exe so the uninstall entry and the Start Menu shortcut
; show the NextFix mark whether or not the executable carries an icon resource of its own.
UninstallDisplayIcon={app}\nextfix.ico
UninstallDisplayName={#AppName}
WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
VersionInfoVersion={#FileVersion}
VersionInfoProductName={#AppName}
VersionInfoProductVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription={#AppName} installer
VersionInfoCopyright=Copyright (c) {#GetDateTimeString('yyyy', '', '')} GRCSAC LLC
; The install directory goes on the user's PATH ([Code] below); this makes Setup broadcast
; WM_SETTINGCHANGE so shells opened afterwards see it without a sign-out.
ChangesEnvironment=yes
; A running `nextfix serve` holds the exe open. Restart Manager closes it for an upgrade;
; PrepareToInstall below stops it explicitly first, with the result logged.
CloseApplications=yes
CloseApplicationsFilter={#AppExe}
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#SourceExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\icons\nextfix.ico"; DestDir: "{app}"; Flags: ignoreversion
; Apache-2.0 requires the licence and the NOTICE file to travel with the distribution.
Source: "..\..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion
Source: "..\..\NOTICE"; DestDir: "{app}"; DestName: "NOTICE.txt"; Flags: ignoreversion

[Icons]
; `nextfix serve` builds nothing at runtime: the single executable already contains the UI.
; It opens the dashboards in the default browser and keeps the console window as the server.
Name: "{group}\NextFix dashboards"; Filename: "{app}\{#AppExe}"; Parameters: "serve"; WorkingDir: "{%USERPROFILE}"; IconFilename: "{app}\nextfix.ico"; Comment: "Start the NextFix server and open the dashboards"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"

[Run]
Filename: "{app}\{#AppExe}"; Parameters: "serve"; WorkingDir: "{%USERPROFILE}"; Description: "Open the NextFix dashboards"; Flags: nowait postinstall skipifsilent

[Code]
{ --- user PATH ----------------------------------------------------------------------------
  The install directory is appended to HKCU\Environment\Path so `nextfix scan .` works from any
  shell, and removed again on uninstall. Done in code rather than a [Registry] entry so a
  missing or empty Path value does not gain a leading semicolon, and so removal can take the
  entry out of the middle of the list. }

const
  EnvKey = 'Environment';

function SplitPath(const Value: String): TArrayOfString;
var
  rest: String;
  p, n: Integer;
begin
  SetArrayLength(Result, 0);
  rest := Value;
  n := 0;
  while rest <> '' do
  begin
    p := Pos(';', rest);
    if p = 0 then
    begin
      SetArrayLength(Result, n + 1);
      Result[n] := rest;
      rest := '';
    end
    else
    begin
      SetArrayLength(Result, n + 1);
      Result[n] := Copy(rest, 1, p - 1);
      rest := Copy(rest, p + 1, Length(rest));
    end;
    n := n + 1;
  end;
end;

function SameDir(const A, B: String): Boolean;
begin
  Result := CompareText(RemoveBackslashUnlessRoot(Trim(A)), RemoveBackslashUnlessRoot(Trim(B))) = 0;
end;

procedure AddToUserPath(const Dir: String);
var
  current: String;
  parts: TArrayOfString;
  i: Integer;
begin
  current := '';
  RegQueryStringValue(HKEY_CURRENT_USER, EnvKey, 'Path', current);
  parts := SplitPath(current);
  for i := 0 to GetArrayLength(parts) - 1 do
    if SameDir(parts[i], Dir) then
    begin
      Log('PATH already contains ' + Dir);
      exit;
    end;
  if (current <> '') and (current[Length(current)] <> ';') then
    current := current + ';';
  current := current + Dir;
  if RegWriteExpandStringValue(HKEY_CURRENT_USER, EnvKey, 'Path', current) then
    Log('PATH: added ' + Dir)
  else
    Log('PATH: could not write HKCU\Environment\Path');
end;

procedure RemoveFromUserPath(const Dir: String);
var
  current, rebuilt: String;
  parts: TArrayOfString;
  i: Integer;
  changed: Boolean;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, EnvKey, 'Path', current) then
    exit;
  parts := SplitPath(current);
  rebuilt := '';
  changed := False;
  for i := 0 to GetArrayLength(parts) - 1 do
  begin
    if SameDir(parts[i], Dir) then
    begin
      changed := True;
      continue;
    end;
    if parts[i] = '' then
      continue;
    if rebuilt <> '' then
      rebuilt := rebuilt + ';';
    rebuilt := rebuilt + parts[i];
  end;
  if not changed then
    exit;
  if RegWriteExpandStringValue(HKEY_CURRENT_USER, EnvKey, 'Path', rebuilt) then
    Log('PATH: removed ' + Dir)
  else
    Log('PATH: could not rewrite HKCU\Environment\Path');
end;

{ Setup broadcasts WM_SETTINGCHANGE itself (ChangesEnvironment=yes); the uninstaller does not,
  so the removal is announced here or every open shell keeps the stale entry until sign-out. }
function SendMessageTimeout(hWnd: HWND; Msg: Cardinal; wParam: Longint; lParam: String;
  fuFlags: Cardinal; uTimeout: Cardinal; var lpdwResult: DWORD): Longint;
  external 'SendMessageTimeoutW@user32.dll stdcall';

procedure BroadcastEnvironmentChange;
var
  r: DWORD;
begin
  { HWND_BROADCAST, WM_SETTINGCHANGE, SMTO_ABORTIFHUNG, 5 s }
  SendMessageTimeout($FFFF, $001A, 0, 'Environment', $0002, 5000, r);
end;

{ --- running server ------------------------------------------------------------------------
  `nextfix serve` is a console process holding nextfix.exe open. Stop it before the copy so
  the upgrade does not stall on a locked file, and log the outcome: taskkill returns 128 when
  there was nothing to stop, which is the ordinary case. CloseApplications=yes remains as the
  second net. }
function StopRunningServer(const Stage: String): Integer;
var
  code: Integer;
begin
  Exec(ExpandConstant('{cmd}'), '/C taskkill /IM {#AppExe} /F /T', '', SW_HIDE, ewWaitUntilTerminated, code);
  Log(Format('%s: taskkill {#AppExe} exit code %d (128 = nothing running)', [Stage, code]));
  Result := code;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if StopRunningServer('pre-install') = 0 then
    Sleep(800);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    AddToUserPath(ExpandConstant('{app}'));
end;

{ --- uninstall -------------------------------------------------------------------------------
  Data (scan history, accounts, settings, the advisory cache) lives in %USERPROFILE%\.nextfix,
  outside the install directory, and is never removed by the installer. An interactive uninstall offers to
  delete it and defaults to keeping it; a silent uninstall (winget, Chocolatey, scripts) keeps
  it without asking, because an unattended removal is not a request to erase history. }
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  dataDir: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    if StopRunningServer('pre-uninstall') = 0 then
      Sleep(1200);
    exit;
  end;
  if CurUninstallStep <> usPostUninstall then
    exit;
  RemoveFromUserPath(ExpandConstant('{app}'));
  BroadcastEnvironmentChange;
  dataDir := ExpandConstant('{%USERPROFILE}\.nextfix');
  if (not DirExists(dataDir)) or UninstallSilent then
    exit;
  { Lines inside [Code] must not start with '#': the preprocessor would read it as a directive. }
  if MsgBox('Also delete your NextFix data?' + #13#10#13#10 +
            'This removes scan history, accounts, settings and the cached advisory data in:' + #13#10 +
            dataDir + #13#10#13#10 +
            'Choose No to keep it. Reinstalling NextFix later picks up where you left off; ' +
            'deleted history cannot be recovered.',
            mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
    DelTree(dataDir, True, True, True);
end;
