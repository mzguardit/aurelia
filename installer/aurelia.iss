; Aurelia VPN - Inno Setup Script
#define MyAppName "Aurelia VPN"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "mzguardit"
#define MyAppURL "https://github.com/mzguardit/aurelia"
#define MyAppExeName "aurelia.exe"

[Setup]
AppId={{8B3F2E4A-9A4B-4E3F-8C7F-1E2D3C4B5A6F}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases
DefaultDirName={autopf}\Aurelia
DefaultGroupName={#MyAppName}
LicenseFile=..\LICENSE
SetupIconFile=..\src\aurelia.ico
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
OutputDir=..\dist
OutputBaseFilename=Aurelia-Setup-v1.0.0
UninstallDisplayIcon={app}\{#MyAppExeName}
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "italian"; MessagesFile: "compiler:Languages\Italian.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "..\build\Release\aurelia.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\build\Release\aurelia-net.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\build\Release\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\build\Release\hev-socks5-tunnel.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\build\Release\Tor\*"; DestDir: "{app}\Tor"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
