'use strict';

/*
 * WHERE A PORTABLE RUN KEEPS ITS DATA — and why it must not be where the installed app keeps its.
 *
 * A portable build is one downloaded .exe that runs with nothing installed, so a person can try a
 * specific build with no install, no uninstall, and no doubt about which one they are looking at.
 * That is the whole point of it, and it has two ways to go badly wrong.
 *
 * THE FIRST HAZARD: SHARING. Electron derives an app's data folder from its name, not from how it
 * was launched, so a portable build sitting in a Downloads folder would by default open the SAME
 * %APPDATA% folder the installed DockVault uses: the same device identity, session, sync state and
 * database, possibly while the installed app is running against them. So a portable run gets its own
 * folder, beside the executable the person launched — the build and everything it knows travel
 * together, and deleting what you downloaded leaves nothing behind. The launcher unpacks the app into
 * a temporary directory and runs it from there, so the app cannot see its own origin;
 * PORTABLE_EXECUTABLE_DIR is the launcher telling it where the real .exe lives.
 *
 * THE SECOND HAZARD: BEING TOLD. That variable is just an environment variable, and an INSTALLED app
 * reads the same code. Anything able to set a variable — a shortcut, a shell, a value under
 * HKCU\Environment — could otherwise point the installed app's data somewhere else: at a fresh empty
 * profile, so it forgets who it is and asks to be set up again against whatever server it is then
 * told; or at a network share, so a device identity and an encrypted session are written somewhere
 * they were never meant to go. Electron accepts a UNC path for that without complaint. Elsewhere this
 * codebase only honours environment overrides in a development run for exactly this reason.
 *
 * So the variable is not believed, it is CHECKED — and the question asked is deliberately the negative
 * one. Not "does this look like a portable launch?", because everything that makes a launch look
 * portable is a variable, and whoever set the first can set the rest. The question is "IS THIS THE
 * INSTALLED APP?", which they cannot answer for us: the installer writes its uninstaller into the
 * program directory, that file is not part of the packaged app, and the portable launcher never writes
 * one. It is a fact about the disk rather than about the environment, and it is true of every install
 * the installer makes rather than of one location we guessed at.
 *
 * Two earlier versions of this check asked positive questions and both failed in BOTH directions. One
 * asked whether the running program was somewhere other than the launcher's directory — free for an
 * attacker to satisfy, and false for a genuine launch downloaded into a folder containing temp. The
 * next asked whether it was inside the temp folder, and called that something nobody else could
 * arrange; but the caller derives temp from os.tmpdir(), which on Windows reads TEMP, so it was a third
 * environment variable standing next to the two being refused. Both are worth remembering as the same
 * mistake: checking an operand chosen carefully without asking who owns the other one.
 *
 * A run that fails the check is simply an ordinary run: the variable is ignored and the installed app
 * opens its own data exactly as it always did. Failing towards "ordinary" is the whole point, which is
 * also why a directory this program cannot read counts against it rather than for it.
 *
 * ...AND WHERE IT MAY NOT GO. Even a genuine portable launch may not put its folder inside the
 * installed app's, which is reachable in a way plain equality is not: an .exe run from inside
 * %APPDATA%\dockvault-desktop would otherwise nest its profile there, where an uninstall that removes
 * that folder would delete it. Containment is checked both ways, through the real paths on disk
 * rather than through the spelling of them — on Windows one directory has many spellings (8.3 short
 * names, \\?\ forms, a UNC route to a local disk) and comparing text answers the wrong question.
 *
 * WHEN NO FOLDER IS POSSIBLE — a read-only stick, a folder that is not the person's — the fallback is
 * a clearly separate per-user folder, NEVER the installed app's, and when even that is impossible the
 * run refuses. It is returned as a value rather than thrown, so the caller decides how to say it.
 *
 * The decisions are pure and take their inputs as arguments, so they can be tested without an app, a
 * portable launcher, or a machine that has DockVault installed.
 */

const path = require('node:path');
const crypto = require('node:crypto');

// Set by electron-builder's portable launcher to the directory holding the .exe the person ran, and
// to that .exe itself. Both, because one of them can be checked against the other.
const PORTABLE_ENV = 'PORTABLE_EXECUTABLE_DIR';
const PORTABLE_FILE_ENV = 'PORTABLE_EXECUTABLE_FILE';
// The launcher also names the executable it unpacked and started, which is what lets the running
// program be matched against the launch rather than merely be somewhere else.
const PORTABLE_APP_ENV = 'PORTABLE_EXECUTABLE_APP_FILENAME';
// The folder made BESIDE the executable, and named AFTER it. Electron keys its single-instance lock on the
// data folder, so a fixed name would give two portable builds downloaded into one Downloads folder the same
// path — and the second would not merely share a profile, it would find the lock held, hand over to the first,
// and NEVER OPEN. The person is then looking at build A believing it is build B, which is exactly the
// confusion a portable build exists to remove, arriving by the back door. Comparing two builds side by side
// is the use this feature is for, not an edge case.
//
// `DockVault-0.2.0-portable.exe` keeps its data in `DockVault-0.2.0-portable-data`, so the pair is obvious to
// anyone looking at the folder. The wart, stated because it is the sort of thing that surprises someone
// months later: this ties the data to the FILE NAME. Renaming the .exe starts it fresh, and renaming it back
// finds the old data again. The fallback below already makes that same trade, and the alternative is the bug.
const DATA_DIR_NAME = 'DockVault-data';   // only when the launcher did not name the executable
function besideDirName(exeFile) {
  const base = path.basename(String(exeFile || ''), '.exe').trim();
  return base ? `${base}-data` : DATA_DIR_NAME;
}

// Where a portable run keeps its data when it cannot write beside the executable — a read-only stick, a folder
// that is not the person's, or a network share. Deliberately NOT the installed app's folder, and named so that
// finding it later answers how it got there. Per executable for the same reason as above; the suffix comes
// from the PATH of the .exe, so two copies of one file name in different folders still differ.
const FALLBACK_DIR_NAME = 'dockvault-portable-data';
function fallbackDirName(exeFile, fs) {
  const key = canonical(exeFile, fs) || String(exeFile || '');
  const tag = crypto.createHash('sha256').update(key.toLowerCase()).digest('hex').slice(0, 8);
  return `${FALLBACK_DIR_NAME}-${tag}`;
}

const str = (v) => (typeof v === 'string' ? v.trim() : '');

// The same directory can be written many ways on Windows, so compare what the filesystem says a path
// IS, not how it was spelled. realpath only works on something that exists, so this walks up to the
// nearest existing ancestor and re-attaches the rest — enough to see through short names and \\?\
// prefixes on the part that is real.
function canonical(p, fs) {
  if (typeof p !== 'string' || p === '') return null;
  let cur = path.resolve(p);
  const tail = [];
  for (let i = 0; i < 64; i += 1) {
    try { return path.join(fs.realpathSync.native(cur), ...tail.reverse()); } catch { /* keep walking up */ }
    const parent = path.dirname(cur);
    if (parent === cur) return path.resolve(p);
    tail.push(path.basename(cur));
    cur = parent;
  }
  return path.resolve(p);
}

const sameDir = (a, b, fs) => {
  const ca = canonical(a, fs); const cb = canonical(b, fs);
  return !!ca && !!cb && ca.toLowerCase() === cb.toLowerCase();
};

// Is `child` the same directory as `parent`, or inside it? Compared on canonical paths, and on whole
// segments so that `...\dockvault-desktop-other` is not read as being inside `...\dockvault-desktop`.
function insideOrSame(child, parent, fs) {
  const c = canonical(child, fs); const p = canonical(parent, fs);
  if (!c || !p) return false;
  const cl = c.toLowerCase(); const pl = p.toLowerCase();
  if (cl === pl) return true;
  return cl.startsWith(pl.endsWith(path.sep) ? pl : pl + path.sep);
}

// Does an INSTALLER'S uninstaller sit beside this program? That is the one fact about being installed
// which does not come from the environment, and it is why this check exists at all.
//
// The installer writes its uninstaller into the program directory at install time (NSIS
// `WriteUninstaller`, copied to $INSTDIR under the configured name). It is not one of the packaged
// application files, so it is not in the portable payload, and the portable launcher never writes one:
// its script has no uninstaller in it anywhere. Both a per-user and a per-machine install go through
// that same installer script, which is what makes this independent of WHERE the app was installed —
// the previous attempt at this derived one known install location and missed every other.
//
// Matched by shape, not by an exact name, because the name is a build setting. Over-matching is free:
// the unpack directory holds only the packaged payload, which by construction contains no uninstaller
// of any name, so a broad pattern costs a portable launch nothing and survives a productName change or
// a future UNINSTALL_FILENAME. It also covers the `unins000.exe` shape other installers use.
const UNINSTALLER = /^unins.*\.exe$/i;

// AN ACCEPTED RESIDUAL, written down because every trap this code has sprung came from a belief nobody wrote
// down. ANY copy of the program directory that lacks an uninstaller reads as not-installed. That covers a
// developer's `win-unpacked` build, and equally a copy someone made with xcopy or a hard link from a real
// install - no elevation needed, the binary still genuinely signed, asar integrity intact.
//
// It is accepted rather than fixed because the actor is the same one the note above concedes: someone already
// running as this user, who can write to the program directory. Such a copy is treated as portable, so it
// keeps its data separately instead of sharing the installed copy's - which is the safer of the two wrong
// answers. `isPackaged` does not exclude it, because a copied install IS packaged.
function looksInstalled(runDir, fs) {
  let names;
  try {
    names = fs.readdirSync(runDir);
  } catch {
    // We cannot read the directory we are running from. That is not evidence of being portable, and
    // this is the check the isolation now rests on, so it fails CLOSED: unknown is treated as
    // installed. The module's whole posture is that a run it cannot vouch for is an ordinary run.
    return 'unknown';
  }
  return names.some((name) => UNINSTALLER.test(name)) ? 'installed' : 'no';
}

// THERE IS DELIBERATELY NO TEMP FOLDER CHECK HERE, and it must not be added back.
//
// Every version of this decision that failed — three of them — anchored on a path the environment
// supplies, and so handed the anchor to whoever set the variables. First "the running program is not
// inside PORTABLE_EXECUTABLE_DIR": they name that directory. Then "the running program is inside the
// temp folder": os.tmpdir() is TEMP || TMP || SystemRoot\temp, so they name that too.
//
// An AND-ed temp check can only ever produce FALSE NEGATIVES — a genuine launch refused — because it
// only removes launches from the portable set. And a false negative here is the severe direction: the
// portable build silently opens the installed app's identity, session and database. That is not
// hypothetical; it happened. Meanwhile it defends against nothing the uninstaller check below does not
// already refuse. Depth bought at the price of the failure mode that actually bit is a bad trade.
//
// There is also a comparison here that cannot be made correct in principle. The launcher computes temp
// with Windows' GetTempPathW (TMP, then TEMP, then USERPROFILE, then the Windows directory); this
// process would compute it with Node's os.tmpdir() (TEMP, then TMP, then the Windows temp folder).
// Different first choice AND different fallback. Code that compares those two is betting on a
// coincidence neither project promises, and on the machines where the bet loses it loses silently.

/**
 * Is this process REALLY a portable launch? Not "was a variable set" — see the header.
 *
 * @returns {{portable: boolean, exeDir: string|null, why: string|null}} `why` names the check that
 *          failed, for a log line; a failure means "treat this as an ordinary run", never an error.
 */
function portableLaunch({ env, fs, execPath, platform, appName, isPackaged = true }) {
  const dir = str(env && env[PORTABLE_ENV]);
  if (dir === '') return { portable: false, exeDir: null, why: null }; // the ordinary case: not set
  const fail = (why) => ({ portable: false, exeDir: null, why });
  // The portable target is Windows-only. Anywhere else the variable means nothing and is refused
  // rather than acted on, which also keeps a stray variable from stopping the app on mac or Linux.
  if (platform !== 'win32') return fail('portable builds are a Windows target');
  // A development run is never a portable launch, whatever the environment says. Cheap, and it keeps a
  // stray variable in a developer's shell from moving their own data.
  if (!isPackaged) return fail('this is a development run, not a packaged program');
  if (!path.isAbsolute(dir)) return fail('the launcher directory is not an absolute path');

  // THE CHECK THAT DECIDES. There is exactly one, deliberately — see the note above `looksInstalled`
  // for why an extra temp-folder check was removed rather than kept alongside it.
  //
  // The question is NOT "does this look like a portable launch?" - everything that makes a launch look
  // portable can be stated by whoever set the variables. It is "is this the INSTALLED app?", which is
  // answered by a file on disk rather than by the environment.
  //
  // WHAT THIS IS AND IS NOT WORTH, stated exactly, because an earlier version of this comment claimed more.
  // It said "neither is what that directory holds", and that is false for the configuration actually
  // shipped: the installer is per-user (oneClick, not perMachine), so the program directory lives under
  // %LOCALAPPDATA% and the user has full control of it. Anything already running as that user can delete
  // the uninstaller and beat this check. There is no fix for that, and no discriminator can have one: every
  // signal that could say "I am installed" lives somewhere the same user can write.
  //
  // What it DOES do is raise the cost from "set an environment variable" - which needs no file, no
  // privilege, and leaves nothing behind - to "write into the program directory". That is a far louder act
  // and a different class of attacker. The corroboration below is required rather than optional for the
  // same reason, and the damage is bounded separately by refusing to put a device identity on a network
  // location. Depth, not a boundary.
  const runDir = typeof execPath === 'string' && execPath ? path.dirname(execPath) : '';
  if (!runDir) return fail('there is no way to tell where this program is running from');
  const installed = looksInstalled(runDir, fs);
  if (installed === 'installed') return fail('this program is the installed app, not a portable copy');
  if (installed === 'unknown') return fail('this program cannot see where it is running from');

  // Corroboration — REQUIRED, not optional, and that distinction is the whole point of this block.
  //
  // Both of these used to be skipped when their own variable was unset ("if it is set, check it"), which
  // let whoever set the first variable DECLINE the remaining checks simply by not setting them. The
  // attack needed one variable and no file anywhere on disk. The real launcher sets all three of these
  // unconditionally on every launch, so demanding them costs a genuine run nothing and costs a forged
  // one an actual file in the directory it names.
  const appFile = str(env && env[PORTABLE_APP_ENV]);
  if (appFile === '') return fail('the launcher did not name the program it started');
  // The app's NAME (the one the data folder is named for), not the executable's file name — they
  // differ, and comparing against the wrong one once rejected every real launch.
  if (!appName) return fail('this program does not know its own name');
  if (appFile.toLowerCase() !== String(appName).toLowerCase()) {
    return fail('the launcher names a different program than the one running');
  }
  const file = str(env && env[PORTABLE_FILE_ENV]);
  if (file === '') return fail('the launcher did not name the executable that was run');
  try { if (!fs.statSync(file).isFile()) return fail('the launcher executable is not a file'); }
  catch { return fail('the launcher executable does not exist'); }
  if (!sameDir(path.dirname(file), dir, fs)) return fail('the launcher executable is not in the directory it names');
  return { portable: true, exeDir: dir, why: null };
}

/**
 * Decide where a portable run's data goes.
 *
 * @param {object} o
 * @param {string} o.exeDir        the launcher's directory, already checked by portableLaunch.
 * @param {string} o.installedDir  the folder an ORDINARY run would use. Used only to stay out of it.
 * @param {string} [o.localAppData] per-user local data root, for the fallback.
 * @param {object} o.fs            for canonicalising paths.
 * @param {(dir: string) => boolean} [o.canWrite]
 * @returns {{dir: string|null, where: 'beside-exe'|'fallback'|null, refused: string|null}}
 */
// A device identity and an encrypted session do not leave this machine. `\\server\share` and
// `\\?\UNC\...` are what an attacker reaches for once they have the launch decision, and the module
// header names exactly that as the harm — but nothing here ever looked.
//
// This is a BOUND ON THE DAMAGE rather than another attempt at the decision, and the difference matters:
// the decision rests on one file in a directory the user can write to, so a determined attacker who is
// already running as the user can beat it. What they must not also get is the identity leaving the
// machine. A refusal here costs a genuine portable run nothing that matters — it falls through to a
// per-executable local folder and still never touches the installed profile — so the two failure
// directions are not symmetric here the way they are in the launch decision.
function isRemote(dir) {
  const p = String(dir || '');
  if (p.startsWith('\\\\?\\UNC\\') || p.startsWith('//?/UNC/')) return true;
  // A UNC root, but not the \\?\ local-device prefix, which is a long-path spelling of a local path.
  if (/^[\\/]{2}/.test(p)) return !/^[\\/]{2}[?.][\\/]/.test(p);
  return false;
}

function chooseDataDir({ exeDir, exeFile, installedDir, localAppData, fs, canWrite = () => true }) {
  // NAMED AFTER THE EXECUTABLE, not a fixed "DockVault-data", for the reason the fallback is: Electron keys
  // its single-instance lock on the data folder. Two portable builds downloaded into one Downloads folder —
  // the ordinary way of comparing two builds, and the use this feature exists for — would otherwise get the
  // same path, and the second would not merely share a profile: it would find the lock held, hand over to the
  // first, and NEVER OPEN. The person is then looking at build A believing it is build B, which is exactly
  // the confusion a portable build exists to remove, arriving by the back door.
  const beside = isRemote(exeDir) ? null : path.join(exeDir, besideDirName(exeFile));
  // Not merely "is not the installed folder" — not INSIDE it either, and not a parent of it. An .exe run from
  // within the installed profile would otherwise nest its data where an uninstall's opt-in data removal would
  // take it with the rest.
  const clear = (candidate) => !!installedDir
    && !insideOrSame(candidate, installedDir, fs)
    && !insideOrSame(installedDir, candidate, fs);
  // AND NEVER INSIDE THE PROGRAM DIRECTORY, which is a different folder from the profile above and is
  // destroyed on a far commoner event. The uninstaller does `RMDir /r $INSTDIR` on every uninstall AND on
  // every in-place upgrade, unconditionally — where deleting the roaming profile is an unticked box the person
  // has to choose. So a portable copy sitting in the install directory would have its data taken by the next
  // routine upgrade, silently, with no one having asked for anything to be deleted.
  const inProgramDir = looksInstalled(exeDir, fs) === 'installed';
  if (beside && !inProgramDir && clear(beside) && canWrite(beside)) return { dir: beside, where: 'beside-exe', refused: null };
  const fallback = localAppData && !isRemote(localAppData)
    ? path.join(localAppData, fallbackDirName(exeFile || exeDir, fs))
    : null;
  if (fallback && clear(fallback) && canWrite(fallback)) return { dir: fallback, where: 'fallback', refused: null };
  return {
    dir: null,
    where: null,
    refused: 'no writable folder of its own; a portable run will not share the installed app\'s data',
  };
}

/**
 * Point the app at that folder. Must run BEFORE anything reads the data path — including Electron's
 * single-instance lock, which is keyed on it, and which is what lets a portable run and an installed
 * one be open at once instead of one handing over to the other.
 *
 * The installed folder is WORKED OUT rather than asked for: Electron creates that directory when
 * asked for it, so asking would mean every portable run made the installed app's folder on its way
 * past it, and left one behind on a machine with no DockVault at all. It is the app's name under the
 * roaming folder, which is exactly how Electron derives it.
 *
 * Never throws: a portable run that cannot be isolated is reported, not crashed.
 */
function applyDataDir(app, { env, fs, localAppData, appName, roamingDir, platform, isPackaged, execPath = process.execPath }) {
  const nothing = { portable: false, dir: null, where: null, refused: null, applied: false, why: null };
  const launch = portableLaunch({ env, fs, execPath, platform, appName, isPackaged });
  if (!launch.portable) return { ...nothing, why: launch.why };
  const installedDir = appName && roamingDir ? path.join(roamingDir, appName) : '';
  const canWrite = (dir) => {
    try { fs.mkdirSync(dir, { recursive: true }); fs.accessSync(dir, fs.constants.W_OK); return true; }
    catch { return false; }
  };
  const decision = chooseDataDir({ exeDir: launch.exeDir, exeFile: str(env && env[PORTABLE_FILE_ENV]), installedDir, localAppData, fs, canWrite });
  if (!decision.dir) return { ...decision, portable: true, applied: false, why: null };
  try { app.setPath('userData', decision.dir); } catch { return { ...decision, portable: true, applied: false, why: null }; }
  return { ...decision, portable: true, applied: true, why: null };
}

/**
 * What, if anything, this run should say about the decision that was made.
 *
 * A DEMOTION is the case that matters: the launcher variables were set and the answer was no, so the
 * app is about to open the installed profile. Both isolation defects found in review landed as complete
 * silence, because the reason was computed and never read. An ordinary run (no variable) and a
 * successful portable launch have nothing to report — a line on every start would be noise, and noise
 * is how the interesting line gets missed.
 *
 * Separate from the caller so it can be ASKED rather than inspected: a source-text test of the wiring
 * could not tell a reachable branch from an unreachable one, and did not.
 *
 * @param {{portable: boolean, why: string|null}} result
 * @returns {string|null}
 */
function notice(result) {
  const why = result && typeof result.why === 'string' ? result.why.trim() : '';
  if (!why || (result && result.portable)) return null;
  return `the launcher variable was set but this is not a portable launch: ${why}`;
}

/**
 * Say it, if there is anything to say. Returns whether it did.
 *
 * The REPORTING lives here rather than in the caller so that "does a demotion actually get reported?" can be
 * asked instead of read. A test over the shell's source could only see that the reason was READ somewhere —
 * which passes just as well when the value is computed and dropped, and a report nobody makes is exactly the
 * silence that let two isolation defects through two reviews.
 *
 * @param {{portable: boolean, why: string|null}} result
 * @param {(line: string) => void} warn
 * @returns {boolean} true when something was reported
 */
function reportDemotion(result, warn) {
  const line = notice(result);
  if (!line) return false;
  try { warn(`[portable] ${line}`); } catch { /* a log that throws must not stop the launch */ }
  return true;
}

module.exports = {
  portableLaunch, chooseDataDir, applyDataDir, insideOrSame, canonical,
  fallbackDirName, besideDirName, notice, reportDemotion, isRemote,
  PORTABLE_ENV, PORTABLE_FILE_ENV, PORTABLE_APP_ENV, DATA_DIR_NAME, FALLBACK_DIR_NAME,
};
