; DockVault installer hooks, included by electron-builder's NSIS template.
;
; The app registers itself to start at login through the per-user Run key, under the value name
; "io.dockvault.desktop": the application id, which is what Electron files a login item under (see
; src/main/app-identity.js and the test that keeps this file in step with it). The generated
; uninstaller knows nothing about that entry, so it is removed here, together with the "startup apps"
; approval flag Windows keeps for it; otherwise Windows would keep trying to start a program that is gone.
;
; The app's data folder (encrypted session, device identity, sync state) is deliberately left in
; place: removing it would silently orphan this computer's registration on the server. Deleting it
; is a separate, explicit choice for the person, not a side effect of uninstalling, and the
; uninstaller says so (except when run silently; the note shows before the files go).

!macro customUnInstall
  ; An install over an existing one runs this uninstaller first with the updated flag: the login item must
  ; survive that (the install path is stable, so it still points at the new executable), or every update
  ; would silently turn start-at-login off. Only a real uninstall removes it.
  ${ifNot} ${isUpdated}
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "io.dockvault.desktop"
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" "io.dockvault.desktop"
  ; Electron registers a per-profile notification activator class under the user's registry the first
  ; time it shows a toast (HKCU\Software\Classes\CLSID\{...}\LocalServer32 = this executable). Nothing
  ; else removes it, so every class whose server is the executable being uninstalled goes with it,
  ; matched by path and never by a fixed id, because the id is minted per data folder.
  StrCpy $R7 0
  ${Do}
    EnumRegKey $R8 HKCU "Software\Classes\CLSID" $R7
    ${If} $R8 == ""
      ${ExitDo}
    ${EndIf}
    ReadRegStr $R9 HKCU "Software\Classes\CLSID\$R8\LocalServer32" ""
    ${If} $R9 == "$INSTDIR\${APP_EXECUTABLE_FILENAME}"
    ${OrIf} $R9 == '"$INSTDIR\${APP_EXECUTABLE_FILENAME}"'
      DeleteRegKey HKCU "Software\Classes\CLSID\$R8"
    ${Else}
      IntOp $R7 $R7 + 1
    ${EndIf}
  ${Loop}
  ${endIf}
  IfSilent +2
  MessageBox MB_OK|MB_ICONINFORMATION "DockVault is being removed. Your synced files stay in their folders, and the app's data stays in $APPDATA\dockvault-desktop so this computer keeps its registration if you reinstall. Delete that folder yourself if you want it gone."
!macroend
