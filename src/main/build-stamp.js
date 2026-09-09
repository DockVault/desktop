'use strict';

/*
 * WHICH build is this? — the app's visible build identity.
 *
 * Every release so far reported the same `0.1.0` and nothing else, so two installers built weeks
 * apart were indistinguishable once installed: neither the person running one nor the person reading
 * their report could say which code was actually on the machine. This module is the answer to that
 * question, and the ONE place the answer is composed.
 *
 * WHERE THE ANSWER COMES FROM. The build bakes it in: electron-builder's `extraMetadata` writes
 * `buildCommit` / `buildDate` into the package.json that ships inside the app archive, fed from the
 * environment of the build (the CI passes the commit it checked out and the day it ran). Nothing is
 * computed at run time and nothing is read from disk beside the app — a build's identity is fixed
 * when the build is made, which is the only moment it is actually known.
 *
 * WHY THE SHAPE IS CHECKED. `extraMetadata` is an environment-fed path into a string this app then
 * SHOWS a person, so what arrives is treated as untrusted input, not as a label to print: a commit
 * must be hex of a commit's length, a date must be a real calendar date in ISO order, a version must
 * be digits and dots. Anything else is not "shown oddly" — it is absent, and the app says the build
 * is not stamped. So a broken or hostile build environment can put no sentence of its own in front of
 * a person: no URL, no phone number, no instruction, nothing but a short hex string and a date.
 *
 * WHAT A STAMP IS NOT. It is a SELF-REPORT, checked for shape and not for truth. Anyone who can run a
 * build can set the variable, so a stamp naming a commit is not evidence the artifact was built from
 * it, and this module must never be read as proving provenance — the code signature does that (see
 * the release gate in .github/workflows/build-installers.yml, which refuses to publish unsigned
 * installers). What the stamp is for is the ordinary case: telling two honest builds apart, so a
 * person can say which one they are running and the owner can look at the same code they are.
 *
 * WHY AN UNSTAMPED BUILD SAYS SO. A build made without those variables is given no stamp, and this
 * says exactly that rather than inventing one from the working tree — a working tree can be dirty, so
 * a commit read from it would name code the build does not contain. What the app can then honestly
 * say is only "this copy does not record which commit it came from", NOT "this did not come from the
 * pipeline": the app sees a missing field, not a provenance. The pipeline's side of that is enforced
 * where it can be — the workflow refuses to build at all if it cannot stamp — so a missing stamp is
 * in practice informative without the app having to claim more than it knows.
 *
 * Leak posture: a short commit and a date, both public facts about a public repository. No path, no
 * host, no branch name, no build machine — nothing here would say anything about where it was built.
 */

// A commit as git writes it: hex, and between an abbreviation and a full object id.
const COMMIT = /^[0-9a-f]{7,40}$/;
// A date in ISO order only, so it reads the same to every reader; the value is checked against the
// calendar below, because this pattern also admits a 13th month.
const DATE = /^(\d{4})-(\d{2})-(\d{2})$/;
// A version has to LOOK LIKE ONE, not merely be made of a version's characters. This is shown to a
// person beside the commit, so a shape check alone is not enough: a permissive class would accept
// `1-800-555-0199`, which is every character a version may contain and is not a version. Numbered
// parts, dots between them, and at most a pre-release and a build tail.
const VERSION = /^\d{1,6}\.\d{1,6}(\.\d{1,6})?(-[0-9A-Za-z][0-9A-Za-z.-]{0,23})?(\+[0-9A-Za-z][0-9A-Za-z.-]{0,23})?$/;
// How much of the commit a person is shown. Enough to name one commit in this repository, short
// enough to read back over a call or paste into a report — and the length `git show` accepts.
const SHORT = 7;

// Is this a date that exists? `2026-02-31` passes the pattern and no calendar.
function isRealDate(y, m, d) {
  const t = new Date(Date.UTC(y, m - 1, d));
  return t.getUTCFullYear() === y && t.getUTCMonth() === m - 1 && t.getUTCDate() === d;
}

/**
 * Read the build's identity out of the metadata the build baked in.
 *
 * @param {object} meta  the app's package metadata (`version`, and `buildCommit`/`buildDate` when a
 *                       build stamped it). Anything malformed is treated as absent.
 * @returns {{version: string|null, commit: string|null, date: string|null, stamped: boolean}}
 *          `commit` is the SHORT commit, ready to show. `stamped` is whether this build says which
 *          commit it is — the question the whole module exists to answer.
 */
function readStamp(meta) {
  const m = meta && typeof meta === 'object' ? meta : {};
  const rawVersion = typeof m.version === 'string' ? m.version.trim() : '';
  const rawCommit = typeof m.buildCommit === 'string' ? m.buildCommit.trim().toLowerCase() : '';
  const rawDate = typeof m.buildDate === 'string' ? m.buildDate.trim() : '';
  const dateParts = DATE.exec(rawDate);
  return {
    version: VERSION.test(rawVersion) ? rawVersion : null,
    commit: COMMIT.test(rawCommit) ? rawCommit.slice(0, SHORT) : null,
    date: dateParts && isRealDate(Number(dateParts[1]), Number(dateParts[2]), Number(dateParts[3])) ? rawDate : null,
    // The COMMIT is what identifies a build; the date is a convenience beside it. A build that named
    // its commit is stamped even if its date did not survive the shape check.
    stamped: COMMIT.test(rawCommit),
  };
}

// Does this stamp name a build? ONE definition, so the line and the sentence beside it can never
// disagree — a footer reading "build not stamped" under an About box that explains nothing, or the
// reverse, would be the label and the payload contradicting each other on one screen. readStamp keeps
// `stamped` and a present `commit` in step; this holds for any stamp object, however it was composed.
const isStamped = (s) => !!(s && typeof s.commit === 'string' && s.commit);

/**
 * The one line that identifies this build, for anywhere a person reads it — a window footer, an
 * About box, a sentence pasted into a report. Never partial and never blank: an unstamped build gets
 * a line that says it is unstamped, because a missing line reads as a page that failed to load.
 */
function stampLine(stamp) {
  const s = stamp && typeof stamp === 'object' ? stamp : {};
  const parts = ['DockVault'];
  if (s.version) parts.push(s.version);
  const tail = isStamped(s)
    ? (s.date ? `build ${s.commit} · ${s.date}` : `build ${s.commit}`)
    : 'build not stamped';
  return `${parts.join(' ')} · ${tail}`;
}

/**
 * What "not stamped" MEANS, in a sentence, for the surfaces that show the line without room to
 * explain it (the Computers window puts it on the footer's hover) and for the About box, which says
 * it outright. One wording, one place, so the two can never explain it differently.
 *
 * It states what the app actually knows — this copy carries no commit — and nothing about where the
 * copy came from, which the app cannot see. The second sentence is a fact about the PIPELINE, not a
 * claim about this copy: the workflow refuses to build without a commit to stamp, so a copy with no
 * stamp did not come out of it. Null for a stamped build, which needs no explaining.
 */
function stampNote(stamp) {
  if (isStamped(stamp)) return null;
  return 'This copy does not record which commit it was built from, so it cannot be matched to one. A build from the release pipeline always records it.';
}

/**
 * The About box: what the app says about itself when asked directly. The build line, then the facts
 * a person is asked for when they report something — the platform and architecture this build runs
 * on, and the Electron it is built against. All non-secret, all about the software rather than the
 * machine: no host name, no user, no path.
 *
 * `copyText` is the whole thing as one block, because the reason someone opens an About box is
 * almost always to put its contents somewhere else.
 */
function aboutDialog(stamp, env) {
  const e = env && typeof env === 'object' ? env : {};
  const lines = [stampLine(stamp)];
  const platform = typeof e.platform === 'string' && e.platform ? e.platform : null;
  const arch = typeof e.arch === 'string' && e.arch ? e.arch : null;
  if (platform || arch) lines.push(`Platform: ${[platform, arch].filter(Boolean).join(' ')}`);
  if (typeof e.electron === 'string' && e.electron) lines.push(`Electron: ${e.electron}`);
  // Said in the box, not only implied by the line above it: a report about this copy can only ever be
  // approximate. Better known than discovered later.
  const note = stampNote(stamp);
  if (note) lines.push(note);
  const detail = lines.join('\n');
  return {
    title: 'About DockVault',
    message: 'DockVault',
    detail,
    buttons: ['Copy details', 'Close'],
    copyIndex: 0,
    // Closing is the DEFAULT, so dismissing the box with the keyboard does not silently replace what
    // the person had on their clipboard. Copying is worth a deliberate click; a clipboard someone did
    // not ask to lose is not worth saving them one.
    closeIndex: 1,
    defaultIndex: 1,
    copyText: detail,
  };
}

/**
 * The other end of the same rules: what a BUILD may bake in. electron-builder.js calls this with the
 * environment it was given and puts the result in `extraMetadata`, so the check that decides what is
 * written into a shipped artifact IS the check that decides what is read back out of one — not a
 * second copy of it, free to drift. (A copy did drift: it admitted 2026-02-31, which the reader then
 * refused, so the artifact would have carried a date no one could ever be shown.)
 *
 * The COMMIT is stored WHOLE. Only the display is shortened, and shortening is the reader's job: an
 * artifact that recorded only seven characters could never be checked against a longer one later.
 *
 * @param {{commit?: string, date?: string}} values  what the build was told, in whatever state.
 * @returns {{buildCommit?: string, buildDate?: string}}  only the fields that survived. One that did
 *          not is ABSENT rather than empty, so nothing downstream has to defend against a blank.
 */
function stampMetadata(values) {
  const v = values && typeof values === 'object' ? values : {};
  const commit = typeof v.commit === 'string' ? v.commit.trim().toLowerCase() : '';
  const date = typeof v.date === 'string' ? v.date.trim() : '';
  const meta = {};
  if (COMMIT.test(commit)) meta.buildCommit = commit;
  // Asked through the reader itself, calendar check and all, rather than re-stating its pattern here.
  if (readStamp({ buildDate: date }).date) meta.buildDate = date;
  return meta;
}

module.exports = { readStamp, stampLine, stampNote, stampMetadata, aboutDialog, SHORT };
