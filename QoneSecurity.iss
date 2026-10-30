; Qone Security 安装脚本
; 用 Inno Setup 6 编译：ISCC.exe QoneSecurity.iss

#define AppName "Qone Security"
#define AppVersion "1.4.0.0"
#define AppPublisher "Sun2530"
#define AppExeName "Qone Security.exe"
#define AppURL "https://github.com/Sun2530/Qone-Security"

[Setup]
AppId={{8C7A3D2E-5F4B-4A1E-9B2C-6D0E7F8A9B1C}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
; 输出到 dist，文件名带版本号
OutputDir=dist
OutputBaseFilename=Qone-Security-Setup-{#AppVersion}
; 安装包图标
SetupIconFile=assets\icon.ico
; 安装包压缩
Compression=lzma2/max
SolidCompression=yes
; 卸载器也带图标
UninstallDisplayIcon={app}\{#AppExeName}
; 权限与平台
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; 显示中文语言
LicenseFile=LICENSE
; 版本信息
VersionInfoVersion={#AppVersion}
VersionInfoDescription={#AppName} 安装程序
VersionInfoCompany={#AppPublisher}
VersionInfoCopyright=© 2026 Sun2530

[Languages]
Name: "chinesesimp"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加任务："

[Files]
Source: "dist\Qone Security.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "assets\legal\LICENSE.txt"; DestDir: "{app}\licenses"; Flags: ignoreversion
Source: "assets\legal\THIRD-PARTY-NOTICES.txt"; DestDir: "{app}\licenses"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{group}\卸载 {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExeName}"; Description: "立即运行 {#AppName}"; Flags: nowait postinstall skipifsilent

[Code]
// WebView2 Runtime 检测：Win11 自带，Win10 缺失则提示安装
function InitializeSetup(): Boolean;
var
  WebView2Ver: string;
  ErrCode: Integer;
begin
  Result := True;
  if not IsWin64 then
  begin
    MsgBox('{#AppName} 需要 64 位 Windows。', mbError, MB_OK);
    Result := False;
  end;
  // 检测 WebView2：HKLM 或 HKCU 任一存在即视为已装
  if (not RegQueryStringValue(HKLM64,
      'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}',
      'pv', WebView2Ver)) and
     (not RegQueryStringValue(HKCU,
      'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}',
      'pv', WebView2Ver)) then
  begin
    if MsgBox('未检测到 Microsoft Edge WebView2 Runtime，界面将无法显示。' + #13#10 +
              '是否现在前往微软官网下载安装？', mbConfirmation, MB_YESNO) = IDYES then
      ShellExec('open', 'https://developer.microsoft.com/microsoft-edge/webview2/', '',
        '', SW_SHOWNORMAL, ewNoWait, ErrCode);
  end;
end;
