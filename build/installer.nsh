; DockVault installer hooks, included by electron-builder's NSIS template.
;
; The app registers itself to start at login through the per-user Run key, under the value name
; "io.dockvault.desktop": the application id, which is what Electron files a login item under (see
; src/main/app-identity.js and the test that keeps this file in step with it). The generated
; uninstaller knows nothing about that entry, so it is removed here, together with the "startup apps"
; approval flag Windows keeps for it; otherwise Windows would keep trying to start a program that is gone.
;
; The app's data folder (encrypted session, device identity, sync state) is KEPT BY DEFAULT: removing
; it silently orphans this computer's registration on the server, and an upgrade must never lose it.
; Deleting it is the person's own explicit choice, offered as an unticked box on the uninstaller (see
; customUnInstallSection at the bottom), never a side effect of uninstalling.
;
; ON UPGRADING IN PLACE. Installing over an existing DockVault replaces it where it already is rather
; than standing a second copy beside it, and that is the generated installer's own doing, not ours:
; it reads the previous location from InstallLocation under HKCU\Software\<app guid> and installs
; there, its Add/Remove entry is keyed by that same guid so a re-install rewrites the one entry, and
; it closes a running DockVault first (prompting, unless it is an update). What this file adds is the
; one thing that was missing: the location is written into the Add/Remove entry too, so Windows and
; anything reading that entry can say where the app actually is. See customInstall.

; The box's label, in one place, because two things have to agree on it exactly: the section that
; declares it and the walk that identifies that section by it.
;
; It carries more than a name because it is ALL the person gets. The components page has no
; description pane (the template defines MUI_COMPONENTSPAGE_NODESC), so there is nowhere else on
; that page for a caveat to live, and the choice is spent by the time any message appears. Two
; things therefore have to be in the label itself: what is actually destroyed — this computer's
; registration with the server, not some replaceable preferences file, which is why the plainer
; "sync state" was not enough — and what is NOT, because "delete ... sync" read cold is easily
; heard as "delete my synced files", which is the one thing this never touches.
!define DV_APPDATA_LABEL "Also delete DockVault's settings and this computer's sync registration (your synced files are not touched)"

; The page's own words. Left to MUI, it opens "Choose which features of DockVault you want to
; uninstall" over a greyed, un-untickable "Uninstall" row and the new box — which frames deleting
; someone's device registration as picking features off a list, and invites reading the two rows as
; the same kind of thing. They are not: one is what is about to happen, the other is a choice.
!define MUI_UNTEXT_COMPONENTS_SUBTITLE "DockVault is about to be removed. Choose what happens to its data."
!define MUI_UNINNERTEXT_COMPONENTS_TOP "DockVault will be removed from this computer. Your synced files are never deleted and stay in their folders. The one choice below is optional and is off by default."
; How far to walk looking for it. There are two uninstaller sections and there is no reason for a
; third, so this is a runaway guard rather than a limit anything is expected to approach.
!define DV_MAX_SECTIONS 32
; ${SF_SELECTED}, the selected bit of a section's flags, is NOT defined here. This file is included
; ahead of Sections.nsh, which defines it, and defining it first makes that include fail outright —
; it does a plain !define and NSIS refuses the redefinition. It does not need to be: the only use is
; inside a macro body, and a macro body is expanded where it is inserted, long after Sections.nsh.
; Whether the data was actually removed, for the note at the end. Declared at the top level, which
; this file is: it is included into the script header, ahead of the templates that use it. Only for
; the uninstaller's compile — this same file is compiled into the installer too, where nothing reads
; it, and makensis runs with -WX, where an unused variable is a warning and a warning is a failure.
!ifdef BUILD_UNINSTALLER
  Var /GLOBAL dvRemovedAppData
!endif

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

  ; THE BOX, ACTED ON. This runs inside the uninstall section, which is the only place it can: a
  ; one-click uninstall section ends in Quit, so the section the box belongs to never executes. What
  ; makes reading it here correct is that the components page is drawn BEFORE any section runs, so by
  ; now the person's answer is already sitting in that section's flags. The box is read, not run.
  ;
  ; It is found BY ITS LABEL, not by a remembered position. Its name is not a symbol until it is
  ; declared, which happens after this point (a forward reference is warning 6000 and then a hard
  ; compile abort, so it cannot be used and cannot silently misread either). The obvious substitute
  ; is the index it happens to sit at — but then the box quietly becomes decoration the day anything
  ; is declared before it, and nothing would say so. So the sections are walked and the one carrying
  ; the label is the one that is read. Nothing here depends on an ordering.
  ;
  ; $APPDATA has to mean the PERSON'S roaming folder for all of it. Electron keeps this app's data
  ; per user always, but SetShellVarContext all remaps $APPDATA to ProgramData, and the deletion
  ; would then quietly remove nothing while the note named a folder nobody has. It cannot happen
  ; today ($installMode is CurrentUser while the installer is one-click and per-user, and a test pins
  ; those settings) — but the template guards its own copy of this deletion the same way, and the
  ; guard costs two lines. Restored after, so nothing later in the uninstall sees a changed context.
  ;
  ; Every way of being wrong — label not found, unticked, an update, a silent run — keeps the data.
  ${if} $installMode == "all"
    SetShellVarContext current
  ${endif}
  StrCpy $dvRemovedAppData "0"
  ${IfNot} ${isUpdated}
    StrCpy $R4 0        ; the section being looked at
    StrCpy $R5 ""       ; the flags of the box, once it is found
    ${Do}
      ; An index past the last section sets the error flag and leaves the output UNTOUCHED, so the
      ; output is cleared first: read back on its own it would otherwise still hold the previous
      ; section's label, and the walk would match a section that is no longer there.
      ClearErrors
      StrCpy $R6 ""
      SectionGetText $R4 $R6
      ${If} ${Errors}
        ${ExitDo}
      ${EndIf}
      ; The un. spelling is belt-and-braces, not load-bearing: NSIS strips that prefix from the
      ; stored name (checked in a built uninstaller), so it is the bare label that matches.
      ${If} $R6 == "${DV_APPDATA_LABEL}"
      ${OrIf} $R6 == "un.${DV_APPDATA_LABEL}"
        SectionGetFlags $R4 $R5
        ${ExitDo}
      ${EndIf}
      IntOp $R4 $R4 + 1
      ; A bound, so a malformed uninstaller cannot spin here forever.
      ${If} $R4 > ${DV_MAX_SECTIONS}
        ${ExitDo}
      ${EndIf}
    ${Loop}
    ; ...and the same answer given on the command line. The template has its own --delete-app-data
    ; handling that runs AFTER this macro, so without reading it here an uninstall passed that flag
    ; would draw the box UNTICKED, be told by the note that its data was kept, and then have the
    ; template delete it anyway: the page and the sentence both false in the same run. Passing the
    ; flag IS the choice this box exists to offer, so it is treated as the box being ticked, and
    ; whichever one deletes first leaves nothing for the other to do.
    StrCpy $R3 ""
    ClearErrors
    ${GetParameters} $R2
    ${GetOptions} $R2 "--delete-app-data" $R1
    ${IfNot} ${Errors}
      StrCpy $R3 "asked"
    ${EndIf}
    ClearErrors
    ${If} $R5 != ""
      IntOp $R5 $R5 & ${SF_SELECTED}
    ${Else}
      StrCpy $R5 0
    ${EndIf}
    ${If} $R5 == ${SF_SELECTED}
    ${OrIf} $R3 == "asked"
      ; Exactly the folder Electron keeps this app's data in, which follows the package name. Named
      ; precisely rather than swept for: the app's other names are folders it does not own, and an
      ; uninstaller must not delete on a guess.
      RMDir /r "$APPDATA\${APP_PACKAGE_NAME}"
      ; The folder itself, once it is empty. Without this a directory that survived its contents
      ; — a handle held on it by a search indexer, a virus scanner, an open Explorer window — reads
      ; as "still there" below, and the note would then tell the person their settings were kept
      ; when every one of them had just been deleted. That is the same untruth as a box that does
      ; nothing, only inverted, so the emptied folder is removed and the check made exact.
      RMDir "$APPDATA\${APP_PACKAGE_NAME}"
      ; THREE outcomes, because there are three. RMDir /r deletes what it can and does NOT fail
      ; loudly on a file something else has open, so "asked to delete" and "deleted" are not the
      ; same event. The realistic partial is the WORST one to get wrong: the small files go first,
      ; so this computer's identity is gone while one cache file a search indexer had open keeps
      ; the folder alive. Read as two outcomes that lands in "kept", and the person is told their
      ; registration is intact and reusable at the exact moment it stopped existing — they would
      ; reinstall, expect to pick up where they left off, and find a computer the server no longer
      ; recognises. So a delete that was ASKED FOR never reaches the kept wording, whatever happened.
      IfFileExists "$APPDATA\${APP_PACKAGE_NAME}" dvSomeLeft
      StrCpy $dvRemovedAppData "gone"
      Goto dvRemovalDone
      dvSomeLeft:
      StrCpy $dvRemovedAppData "partial"
      dvRemovalDone:
    ${EndIf}
  ${EndIf}

  ; What actually happened, in the words for what actually happened. This used to be one message that
  ; asserted the data was kept, which a box makes false half the time — and it never appeared at all,
  ; because a one-click uninstaller silences itself before any section runs and the IfSilent guard was
  ; therefore always true. It appears now because customUnInit un-silences an uninstall a person
  ; started; a silent one still says nothing, which is what a silent run is for.
  IfSilent dvNoteDone
  ${If} $dvRemovedAppData == "gone"
    MessageBox MB_OK|MB_ICONINFORMATION "DockVault is being removed, along with its settings and this computer's sync registration. Your synced files stay where they are, in their folders. If you install DockVault again, this computer will set itself up from scratch."
  ${ElseIf} $dvRemovedAppData == "partial"
    MessageBox MB_OK|MB_ICONEXCLAMATION "DockVault is being removed, but some of its files were in use and could not be deleted. Treat this computer's sync registration as gone: if you install DockVault again, set this computer up from scratch rather than expecting it to pick up where it left off. Your synced files stay where they are, in their folders. Whatever is left is in $APPDATA\${APP_PACKAGE_NAME} — close anything using that folder and delete it yourself if you want it gone."
  ${Else}
    MessageBox MB_OK|MB_ICONINFORMATION "DockVault is being removed. Your synced files stay in their folders, and the app's settings and sync registration stay in $APPDATA\${APP_PACKAGE_NAME}, so this computer picks up where it left off if you install it again."
  ${EndIf}
  dvNoteDone:
  ${if} $installMode == "all"
    SetShellVarContext all
  ${endif}
  ; The error flag is not ours to hand back set: SectionGetText raises it at the end of the walk
  ; and RMDir raises it on a locked file. Nothing between here and the template's own ClearErrors
  ; reads it today — which is a fact about their code, not a promise they made us.
  ClearErrors
!macroend

; Where the app is installed, written into the Add/Remove Programs entry as well as into the app's
; own key. The generated installer only writes InstallLocation under HKCU\Software\<app guid>, which
; is where a re-install reads it from to upgrade in place; the Add/Remove entry it writes beside that
; leaves the value empty, so Windows shows the app with no location and anything reading that entry
; to find the install has to guess. Same value, same moment, written where a person looking at the
; installed-programs list can see it. Nothing depends on it, which is why it was never noticed.
!macro customInstall
  WriteRegStr SHELL_CONTEXT "${UNINSTALL_REGISTRY_KEY}" "InstallLocation" "$INSTDIR"
  !ifdef UNINSTALL_REGISTRY_KEY_2
    WriteRegStr SHELL_CONTEXT "${UNINSTALL_REGISTRY_KEY_2}" "InstallLocation" "$INSTDIR"
  !endif
!macroend

; ------------------------------------------------------------------------------------------------
; The choice about the app's data, as a box the person ticks.
;
; WHY A SECTION AND NOT A DIALOG. Defining customUnInstallSection is what makes the generated
; uninstaller carry a components page at all (installer.nsi asks !ifmacrodef for exactly this name,
; outside its one-click guard), so an optional section declared /o IS an unticked checkbox on a real
; page, and an unticked section simply never runs. That keeps the INSTALLER one-click, which was a
; deliberate choice: the assisted installer opens on an "anyone who uses this computer / only me"
; page whose first option dead-ends without administrator rights.
;
; WHY THE UNINSTALLER HAS TO BE UN-SILENCED. A one-click uninstaller sets itself silent in un.onInit
; (see the template), and a silent run draws no pages, so the box would never be seen. customUnInit
; turns that back off — but ONLY for an uninstall a person started. An upgrade runs the old
; uninstaller with /S --updated, and putting a page in front of someone mid-upgrade would be a bug;
; a scripted /S uninstall must stay scripted for the same reason. Both keep today's behaviour exactly:
; silent, box untouched, data kept.
!macro customUnInit
  ClearErrors
  ${GetParameters} $R0
  ${GetOptions} $R0 "/S" $R1
  ${If} ${Errors}
    ${IfNot} ${isUpdated}
      SetSilent normal
    ${EndIf}
  ${EndIf}
  ClearErrors
!macroend

; The box itself is DECLARED here and does nothing when it runs. Everything it means is carried out
; in customUnInstall above, which is inside the uninstall section — because a one-click uninstall
; section ends in quitSuccess (SetErrorLevel 0, then Quit), and Quit ends the run, so NOTHING
; declared after that section ever executes. A first version of this put the deletion in the section
; body, where it was drawn, ticked, and silently ignored: the box made a promise the uninstaller did
; not keep. Defining this macro is still what gives the uninstaller its components page at all
; (installer.nsi asks !ifmacrodef for exactly this name, outside its one-click guard), so the section
; still has to exist — it just has to be read rather than run.
!macro customUnInstallSection
  ; Unticked (/o). The wording names both of the things in there, because "settings" alone reads as
  ; something replaceable and the sync state is not: it is this computer's registration with the
  ; server, and removing it is what leaves the server holding a computer that no longer exists.
  Section /o "un.${DV_APPDATA_LABEL}" dvSecRemoveAppData
    ; Deliberately empty. See above: this body is unreachable in a one-click build.
  SectionEnd
!macroend
