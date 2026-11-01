; PrivateVPN Windows installer (NSIS 3), built by make-installer.sh:
;   makensis -DARCH=amd64|arm64 -DVERSION=1.2.3 -DSRCDIR=<dir> -DOUTFILE=<setup.exe> installer.nsi
; SRCDIR holds privatevpn.exe, wintun.dll, WINTUN-LICENSE.txt and LICENSE.
;
; Installs per machine into Program Files: the elevated tunnel helper runs
; this executable, so it must live where only administrators can write.
; The installer adds the Windows Firewall rules once (it is elevated anyway)
; and starts PrivateVPN as the logged-in user, never as administrator.

!ifndef ARCH
  !error "ARCH is required (amd64 or arm64)"
!endif
!ifndef VERSION
  !error "VERSION is required (e.g. 1.2.3)"
!endif
!ifndef SRCDIR
  !error "SRCDIR is required"
!endif
!ifndef OUTFILE
  !error "OUTFILE is required"
!endif

Unicode true
ManifestDPIAware true
SetCompressor /SOLID lzma
RequestExecutionLevel admin

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"
!include "WinVer.nsh"
!include "FileFunc.nsh"

!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\PrivateVPN"
!define RUN_KEY "Software\Microsoft\Windows\CurrentVersion\Run"

Name "PrivateVPN"
OutFile "${OUTFILE}"
InstallDir "$PROGRAMFILES64\PrivateVPN"
BrandingText "PrivateVPN ${VERSION}"

!define MUI_ICON "icon.ico"
!define MUI_UNICON "icon.ico"
!define MUI_ABORTWARNING

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "Start PrivateVPN"
!define MUI_FINISHPAGE_RUN_FUNCTION StartApp
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "PrivateVPN"
VIAddVersionKey "FileDescription" "PrivateVPN Setup"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "Copyright (c) 2026 PrivateVPN contributors"

!macro CheckPlatform
  ${IfNot} ${AtLeastWin10}
    MessageBox MB_ICONSTOP "PrivateVPN needs Windows 10 or later." /SD IDOK
    Abort
  ${EndIf}
  !if "${ARCH}" == "arm64"
    ${IfNot} ${IsNativeARM64}
      MessageBox MB_ICONSTOP "This installer is for Windows on Arm. Download the amd64 installer for Intel/AMD PCs." /SD IDOK
      Abort
    ${EndIf}
  !else
    ${IfNot} ${IsNativeAMD64}
      MessageBox MB_ICONSTOP "This installer is for 64-bit Intel/AMD Windows. Download the arm64 installer for Windows on Arm." /SD IDOK
      Abort
    ${EndIf}
  !endif
  SetRegView 64
!macroend

; Stop every running PrivateVPN so its files can be replaced or removed.
; A connected client stays protected: the kill switch keeps blocking until
; PrivateVPN starts again and reconnects.
!macro StopApp
  nsExec::Exec '"$SYSDIR\taskkill.exe" /F /IM privatevpn.exe'
  Pop $0
  Sleep 1000
!macroend

Function .onInit
  !insertmacro CheckPlatform
FunctionEnd

Function un.onInit
  !insertmacro CheckPlatform
FunctionEnd

Section "PrivateVPN"
  SetShellVarContext all
  !insertmacro StopApp

  SetOutPath "$INSTDIR"
  File "${SRCDIR}/privatevpn.exe"
  File "${SRCDIR}/wintun.dll"
  File "${SRCDIR}/WINTUN-LICENSE.txt"
  File "/oname=LICENSE.txt" "${SRCDIR}/LICENSE"
  WriteUninstaller "$INSTDIR\uninstall.exe"
  CreateShortcut "$SMPROGRAMS\PrivateVPN.lnk" "$INSTDIR\privatevpn.exe"

  ; Inbound UDP rules for gateway mode and discovery (on Public networks
  ; only the local subnet is admitted), so no separate prompt is needed.
  nsExec::Exec '"$INSTDIR\privatevpn.exe" firewall add'
  Pop $0
  ${If} $0 != 0
    DetailPrint "Windows Firewall rule not added (exit $0); PrivateVPN offers to add it later."
  ${EndIf}

  ; Login autostart that was on for a previously used copy (e.g. the
  ; portable zip) now starts this one.
  ClearErrors
  ReadRegStr $0 HKCU "${RUN_KEY}" "PrivateVPN"
  ${IfNot} ${Errors}
    WriteRegStr HKCU "${RUN_KEY}" "PrivateVPN" '"$INSTDIR\privatevpn.exe" --autostart'
  ${EndIf}

  WriteRegStr HKLM "${UNINST_KEY}" "DisplayName" "PrivateVPN"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINST_KEY}" "Publisher" "PrivateVPN"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\privatevpn.exe"
  WriteRegStr HKLM "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINST_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "${UNINST_KEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegStr HKLM "${UNINST_KEY}" "URLInfoAbout" "https://github.com/cyberkyd01/privatevpn"
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD HKLM "${UNINST_KEY}" "EstimatedSize" "$0"
SectionEnd

; The installer runs elevated: start PrivateVPN through Explorer so it runs
; with the logged-in user's normal rights.
Function StartApp
  Exec '"$WINDIR\explorer.exe" "$INSTDIR\privatevpn.exe"'
FunctionEnd

Section "Uninstall"
  SetShellVarContext all
  !insertmacro StopApp

  ; Remove the kill-switch block and its boot-time pieces, so direct
  ; Internet access works once PrivateVPN is gone.
  nsExec::Exec '"$INSTDIR\privatevpn.exe" unblock'
  Pop $1
  nsExec::Exec '"$INSTDIR\privatevpn.exe" firewall remove'
  Pop $0
  DeleteRegValue HKCU "${RUN_KEY}" "PrivateVPN"

  Delete "$SMPROGRAMS\PrivateVPN.lnk"
  Delete "$INSTDIR\uninstall.exe"
  Delete "$INSTDIR\LICENSE.txt"
  Delete "$INSTDIR\WINTUN-LICENSE.txt"
  ${If} $1 == 0
    Delete "$INSTDIR\privatevpn.exe"
    Delete "$INSTDIR\wintun.dll"
    RMDir "$INSTDIR\recovery"
  ${Else}
    ; Keep the program: it is what removes the block by hand.
    MessageBox MB_ICONEXCLAMATION "The PrivateVPN kill switch could not be removed, so Internet access may stay blocked. Run this in an Administrator Command Prompt (restart Windows first if it fails again):$\r$\n$\r$\n$\"$INSTDIR\privatevpn.exe$\" unblock" /SD IDOK
  ${EndIf}
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "${UNINST_KEY}"

  SetShellVarContext current
  MessageBox MB_YESNO|MB_DEFBUTTON2 "Also delete your PrivateVPN settings and network keys?" /SD IDNO IDNO keep
  RMDir /r "$LOCALAPPDATA\PrivateVPN"
  keep:
SectionEnd
