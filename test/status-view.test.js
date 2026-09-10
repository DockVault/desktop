'use strict';

// THE MODEL BEHIND THE DEDICATED SYNC-STATUS WINDOW.
//
// The three properties that decide whether this window is worth having, each of which a plausible
// implementation gets wrong:
//
//   - it says the SAME thing about a vault as the Computers card does, because it reads that card's own
//     sentence rather than composing a second one;
//   - it never shows a progress bar it cannot honestly fill, and never invents a fraction from a total that
//     is not one;
//   - it works when the session and the server do not, because the person watching a sync misbehave is often
//     the person whose session is the problem.

const test = require('node:test');
const assert = require('node:assert/strict');

const { createStatusView, transferOf } = require('../src/main/status-view');

const V1 = '11111111-1111-1111-1111-111111111111';
const V2 = '22222222-2222-2222-2222-222222222222';

function io(over = {}) {
  const calls = { reasonText: 0 };
  return {
    calls,
    io: {
      configured: over.configured || (() => [{ vaultId: V1, vaultName: 'Photos', localFolder: 'C:\\Users\\a\\Photos', enabled: true }]),
      liveStatus: over.liveStatus || (() => ({ state: 'up-to-date', label: 'Up to date', vaults: [{ vault: V1, state: 'up-to-date', reason: null, running: false, lastSyncedAt: 1000 }] })),
      reasonText: over.reasonText || ((live, name) => { calls.reasonText += 1; return `${name}: ${live.reason || 'no reason'}`; }),
      lastSyncedLabel: over.lastSyncedLabel || (() => '2 minutes ago'),
    },
  };
}

test('one row per synced folder, carrying its state, its folder and when it last finished', () => {
  const { io: i } = io();
  const m = createStatusView(i).model();
  assert.equal(m.items.length, 1);
  const [row] = m.items;
  assert.equal(row.name, 'Photos');
  assert.equal(row.folder, 'C:\\Users\\a\\Photos');
  assert.equal(row.state, 'up-to-date');
  assert.equal(row.lastSynced, '2 minutes ago');
  assert.equal(m.headline, 'Up to date');
  assert.equal(m.empty, false);
});

// The failure this window exists to remove is two surfaces telling one person two stories. The way to not
// have that is one source, not two careful ones — so the sentence comes from the Computers card's own.
test('the sentence is the Computers card\'s own, not a second copy of the same logic', () => {
  const { io: i, calls } = io({
    liveStatus: () => ({ state: 'sync-problem', label: 'Problem', vaults: [{ vault: V1, state: 'sync-problem', reason: 'vault-full', running: false }] }),
    reasonText: () => 'Photos is out of room on the server.',
  });
  const m = createStatusView(i).model();
  assert.equal(m.items[0].note, 'Photos is out of room on the server.');
  assert.equal(calls.reasonText, 0, 'the injected one was used (the default counter was replaced)');
});

test('a state that explains itself carries no note, rather than a restatement', () => {
  const { io: i } = io({ reasonText: () => null });
  assert.equal(createStatusView(i).model().items[0].note, null);
});

// A vault whose sync is switched off is OFF. Reporting it as "waiting to start" would be the calm-sounding
// lie this window is meant to remove, and it is the shape a naive implementation produces for free.
test('a vault with sync switched off says so, and is not reported as waiting', () => {
  const { io: i } = io({
    configured: () => [{ vaultId: V1, vaultName: 'Photos', localFolder: 'C:\\p', enabled: false }],
    liveStatus: () => ({ state: 'waiting', label: 'Waiting', vaults: [{ vault: V1, state: 'waiting', running: false }] }),
  });
  const row = createStatusView(i).model().items[0];
  assert.equal(row.enabled, false);
  assert.equal(row.state, 'off');
  assert.notEqual(row.state, 'waiting');
  assert.equal(row.note, null, 'and it is not given a reason for a run it is not attempting');
  assert.equal(row.transfer, null);
});

test('a configured vault the scheduler has never reported is shown, not dropped', () => {
  const { io: i } = io({
    configured: () => [{ vaultId: V1, vaultName: 'Photos', localFolder: 'C:\\p', enabled: true }],
    liveStatus: () => ({ state: 'waiting', label: 'Waiting', vaults: [] }),
  });
  const m = createStatusView(i).model();
  assert.equal(m.items.length, 1, 'a folder that is set up must appear even before its first run');
  assert.equal(m.items[0].state, null);
});

test('nothing configured says so, rather than rendering a blank panel', () => {
  const { io: i } = io({ configured: () => [], liveStatus: () => ({ state: 'idle', label: 'Nothing set up', vaults: [] }) });
  const m = createStatusView(i).model();
  assert.equal(m.empty, true);
  assert.deepEqual(m.items, []);
});

// ---------------------------------------------------------------------------------------------
// The progress bar. A bar that lies is worse than no bar.
// ---------------------------------------------------------------------------------------------

test('a bar is filled only from a real fraction, and never from a total that is not one', () => {
  assert.equal(transferOf({ percent: 42 }).fraction, 0.42, 'a stated percentage is used as stated');
  assert.equal(transferOf({ bytes: 50, bytesTotal: 200 }).fraction, 0.25, 'else bytes of bytes');
  assert.equal(transferOf({ files: 1, filesTotal: 4 }).fraction, 0.25, 'else files of files');

  // A count with no total cannot fill a bar — but it is still worth reporting as a number.
  const noTotal = transferOf({ files: 3 });
  assert.equal(noTotal.fraction, null);
  assert.equal(noTotal.files, 3);
  // A zero total is not a total.
  assert.equal(transferOf({ files: 3, filesTotal: 0 }).fraction, null);
  assert.equal(transferOf({ bytes: 10, bytesTotal: 0 }).fraction, null);
  // Nothing at all is no transfer, not an empty bar at 0%.
  for (const nothing of [null, undefined, {}, 'x', 5]) assert.equal(transferOf(nothing), null, String(nothing));
});

test('a malformed number is dropped rather than shown', () => {
  // Every number unusable: there is no transfer to report at all, which is not the same as a transfer
  // reporting zero. A 0% bar would claim a run is under way and getting nowhere.
  assert.equal(transferOf({ percent: 140, bytes: -5, files: 2.5, bytesTotal: NaN }), null);

  // A PARTIALLY malformed one is the interesting case: the bad numbers go, the good ones stay, and the bar
  // falls back to whatever is still trustworthy rather than to the first thing offered.
  const t = transferOf({ percent: 140, bytes: -5, files: 1, filesTotal: 4 });
  assert.equal(t.percent, null, 'a percentage out of range is not a percentage');
  assert.equal(t.bytes, null, 'a negative byte count is not a byte count');
  assert.equal(t.files, 1);
  assert.equal(t.fraction, 0.25, 'so the bar comes from the files, not from the rejected percentage');
});

test('a fraction never exceeds a full bar, even when the helper overshoots its own total', () => {
  assert.equal(transferOf({ bytes: 300, bytesTotal: 200 }).fraction, 1);
  assert.equal(transferOf({ files: 9, filesTotal: 4 }).fraction, 1);
});

test('a transfer is shown only while a run is actually in flight', () => {
  const progress = { percent: 50 };
  const notRunning = io({
    liveStatus: () => ({ state: 'paused', label: 'Paused', vaults: [{ vault: V1, state: 'paused', running: false, progress }] }),
  });
  assert.equal(createStatusView(notRunning.io).model().items[0].transfer, null, 'a stale percentage is not progress');

  const running = io({
    liveStatus: () => ({ state: 'syncing', label: 'Syncing', vaults: [{ vault: V1, state: 'syncing', running: true, progress }] }),
  });
  assert.equal(createStatusView(running.io).model().items[0].transfer.fraction, 0.5);
});

// ---------------------------------------------------------------------------------------------
// It has to work when the rest of the app does not — that is when it is read.
// ---------------------------------------------------------------------------------------------

test('it survives every injected piece failing, and still lists what is configured', () => {
  const i = {
    configured: () => [{ vaultId: V1, vaultName: 'Photos', localFolder: 'C:\\p', enabled: true }],
    liveStatus: () => { throw new Error('the scheduler is not up'); },
    reasonText: () => { throw new Error('no'); },
    lastSyncedLabel: () => { throw new Error('no'); },
  };
  const m = createStatusView(i).model();
  assert.equal(m.items.length, 1, 'the folder is still named');
  assert.equal(m.items[0].state, null, 'with an honest unknown state rather than an invented one');
  assert.equal(m.items[0].note, null);
  assert.equal(m.headline, null);
});

test('a live entry for a vault that is no longer configured is ignored, not shown', () => {
  const { io: i } = io({
    configured: () => [{ vaultId: V1, vaultName: 'Photos', localFolder: 'C:\\p', enabled: true }],
    liveStatus: () => ({
      state: 'syncing', label: 'Syncing',
      vaults: [{ vault: V2, state: 'syncing', running: true }, { vault: V1, state: 'up-to-date', running: false }],
    }),
  });
  const m = createStatusView(i).model();
  assert.equal(m.items.length, 1);
  assert.equal(m.items[0].vaultId, V1, 'configuration decides what is listed, not the scheduler');
});

test('vault ids are matched regardless of case, so a row is never silently stateless', () => {
  // An id with LETTERS in it. The first version of this used a digits-only uuid, whose upper-case form is
  // identical to its lower-case one — so it exercised nothing, and a mutation making the match
  // case-sensitive kept it green. Found by mutating, not by reading it back.
  const MIXED = 'aabbccdd-eeff-4a1b-9c2d-3e4f5a6b7c8d';
  const { io: i } = io({
    configured: () => [{ vaultId: MIXED.toUpperCase(), vaultName: 'Photos', localFolder: 'C:\\p', enabled: true }],
    liveStatus: () => ({ state: 'syncing', label: 'Syncing', vaults: [{ vault: MIXED, state: 'syncing', running: true, progress: { percent: 10 } }] }),
  });
  const row = createStatusView(i).model().items[0];
  assert.equal(row.state, 'syncing');
  assert.equal(row.transfer.fraction, 0.1);
});

// ---------------------------------------------------------------------------------------------
// THE WIRING. Source text for the parts that run before an app is ready and cannot be driven from here —
// aimed at the properties that would actually cost something if they regressed, not at the shape of the code.
// ---------------------------------------------------------------------------------------------

const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const main = fs.readFileSync(path.join(root, 'src', 'main', 'index.js'), 'utf8');
const preload = fs.readFileSync(path.join(root, 'src', 'preload', 'index.js'), 'utf8');

test('the status channel is gated to its own window and its own page, like every other first-party page', () => {
  // The shared preload is NOT what keeps the vault's own web interface out of these channels — this
  // per-page sender check is. Every first-party page here has one; a new page without one would be a hole
  // that looks exactly like the others from the preload side.
  assert.match(main, /const fromStatusPage = \(e\) => serverSetupMod\.isTrustedSetupSender\(/);
  const gate = main.slice(main.indexOf('const fromStatusPage'), main.indexOf('ipcMain.handle(\'dockvault:status.model\''));
  assert.match(gate, /webContents: \(statusWindow && !statusWindow\.isDestroyed\(\)\)/, 'bound to the status window');
  assert.match(gate, /pagePath: schemeMod\.SHELL_PATH \+ STATUS_PAGE/, 'and to the status page');
  // The handler actually consults it, rather than merely having one defined nearby.
  assert.match(main, /ipcMain\.handle\('dockvault:status\.model', \(e\) => \(fromStatusPage\(e\) \? statusModel\(\) : null\)\)/);
});

test('the status view can only be read from, never acted through', () => {
  const handlers = [...main.matchAll(/ipcMain\.handle\('(dockvault:status\.[a-z.-]+)'/g)].map((m) => m[1]);
  assert.deepEqual(handlers, ['dockvault:status.model'], `read-only: ${handlers}`);
  const exposed = [...preload.matchAll(/ipcRenderer\.invoke\('(dockvault:status\.[a-z.-]+)'\)/g)].map((m) => m[1]);
  assert.deepEqual(exposed, ['dockvault:status.model'], `and nothing else is exposed: ${exposed}`);
});

test('the composed sentence never travels on the channel the vault\'s own web interface can reach', () => {
  // publicStatus() is what sync.status() hands to any renderer, and it strips each vault's outcome detail
  // because that channel is reachable from the main window. If the status model's reason text were added
  // there, file names would reach the one window that is not ours. It must stay on the gated channel.
  const model = fs.readFileSync(path.join(root, 'src', 'main', 'sync-status-model.js'), 'utf8');
  const pub = model.slice(model.indexOf('function publicStatus('), model.indexOf('module.exports'));
  assert.match(pub, /const \{ detail, \.\.\.rest \} = model;/, 'the model-level detail is still stripped');
  assert.match(pub, /map\(\(\{ detail: _d, \.\.\.v \}\) => v\)/, 'and so is every vault\'s');
  assert.ok(!/reasonText|note|sentence/i.test(pub), 'and no composed sentence was added to it');
});

test('the status window is opened with the same hardening every other first-party window uses', () => {
  const open = main.slice(main.indexOf('async function openStatusView()'), main.indexOf('async function openManageView()'));
  assert.ok(open.length > 0, 'the opener exists');
  for (const must of [/contextIsolation: true/, /sandbox: true/, /nodeIntegration: false/, /webSecurity: true/]) {
    assert.match(open, must, `status window sets ${must}`);
  }
  assert.match(open, /setWindowOpenHandler\(\(\) => \(\{ action: 'deny' \}\)\)/, 'it opens no windows of its own');
  assert.match(open, /on\('will-navigate', \(e\) => e\.preventDefault\(\)\)/, 'and navigates nowhere');
});

test('it is reachable from the app itself, not only from the tray', () => {
  // The acceptance is explicit that the tray must not be the only door: a person looking at the Computers
  // cards for a problem should not have to know the tray exists to see the detail.
  assert.match(main, /ipcMain\.handle\('dockvault:manage\.open-status'/, 'the Computers window can open it');
  const page = fs.readFileSync(path.join(root, 'src', 'renderer', 'manage.html'), 'utf8');
  assert.match(page, /id="status"/, 'and there is a button on that page to do it');
  const js = fs.readFileSync(path.join(root, 'src', 'renderer', 'manage.js'), 'utf8');
  assert.match(js, /btnStatus\.addEventListener\('click'/, 'that is actually wired');
  // And from the tray as well, for the person who never opens a window.
  assert.match(main, /label: 'Sync status\u2026', click: \(\) => \{ void openStatusView\(\); \}/);
});

// ---------------------------------------------------------------------------------------------
// WHETHER A FOLDER IS BEING WATCHED. A watcher the operating system drops turns near-live sync off for that
// folder and says so nowhere — the sync still happens, just up to five minutes later, so nothing breaks and
// nothing complains. "Why did my edit take five minutes to appear" was unanswerable anywhere in the app.
// ---------------------------------------------------------------------------------------------

test('a folder that is watched, and one that is not, are told apart', () => {
  const { io: i } = io({
    configured: () => [
      { vaultId: V1, vaultName: 'Photos', localFolder: 'C:\p', enabled: true },
      { vaultId: V2, vaultName: 'Invoices', localFolder: 'C:\i', enabled: true },
    ],
    liveStatus: () => ({ state: 'up-to-date', label: 'Up to date', vaults: [] }),
  });
  i.watchedLive = () => [V1];
  const rows = createStatusView(i).model().items;
  assert.equal(rows[0].live, true, 'watched: changes are picked up in seconds');
  assert.equal(rows[1].live, false, 'not watched: it still syncs, just on the next check');
});

// Not knowing and being degraded are different, and only one of them is worth telling anyone about.
test('with no watcher running at all, no row claims to be degraded', () => {
  const { io: i } = io();
  i.watchedLive = () => null;
  assert.equal(createStatusView(i).model().items[0].live, null);

  const { io: j } = io();          // no accessor at all
  assert.equal(createStatusView(j).model().items[0].live, null);

  const { io: k } = io();
  k.watchedLive = () => { throw new Error('gone'); };
  assert.equal(createStatusView(k).model().items[0].live, null, 'a failing accessor is not a fault report');
});

test('a vault with sync switched off is not reported as unwatched', () => {
  const { io: i } = io({
    configured: () => [{ vaultId: V1, vaultName: 'Photos', localFolder: 'C:\p', enabled: false }],
    liveStatus: () => ({ state: 'off', label: 'Off', vaults: [] }),
  });
  i.watchedLive = () => [];
  const row = createStatusView(i).model().items[0];
  assert.equal(row.live, null, 'nothing is watching it because nothing is syncing it — that is not a fault');
});

test('the id is matched however it is cased, so a watched folder is never reported as unwatched', () => {
  const MIXED = 'aabbccdd-eeff-4a1b-9c2d-3e4f5a6b7c8d';
  const { io: i } = io({
    configured: () => [{ vaultId: MIXED.toUpperCase(), vaultName: 'Photos', localFolder: 'C:\p', enabled: true }],
    liveStatus: () => ({ state: 'up-to-date', label: 'Up to date', vaults: [] }),
  });
  // The two sides are spelled DIFFERENTLY on purpose. An earlier version had the config upper-cased and the
  // watcher lower-cased, which is what the code already normalises to — so it matched either way and a
  // mutation dropping the normalisation kept it green.
  i.watchedLive = () => [MIXED.toUpperCase()];
  assert.equal(createStatusView(i).model().items[0].live, true);
});

test('the page says it, and only when the answer is actually "not watched"', () => {
  const js = fs.readFileSync(path.join(root, 'src', 'renderer', 'status.js'), 'utf8');
  assert.match(js, /item\.live === false/, 'strictly false — null means unknown and must say nothing');
  assert.match(js, /next check rather than straight away/);
  const main2 = fs.readFileSync(path.join(root, 'src', 'main', 'index.js'), 'utf8');
  assert.match(main2, /watchedLive: \(\) => \(folderWatch \? folderWatch\.watching\(\) : null\)/,
    'and it reports what the watcher really has, not a hardcoded answer');
});

// THE LIVE PUSH HAS TO REACH THIS WINDOW. It subscribes to the same event the Computers view does, and main
// sent that event to the Computers window ONLY — so this page was carried entirely by its five-second poll
// while its own comment said it was pushed to. The poll meant nothing looked broken, which is precisely why
// it went unnoticed: a window that claims to be live and is not is worse than one that says it polls,
// because the claim is what stops anyone checking.
test('a change reaches the status window, not only the Computers window', () => {
  const main3 = fs.readFileSync(path.join(root, 'src', 'main', 'index.js'), 'utf8');
  const fn = main3.slice(main3.indexOf('function notifyManageChanged()'), main3.indexOf('\n}', main3.indexOf('function notifyManageChanged()')));
  assert.ok(fn.length > 0, 'the notifier exists');
  assert.match(fn, /manageWindow/, 'the Computers window still gets it');
  assert.match(fn, /statusWindow/, 'and so does the status window');
  // Both are sent the same channel the page subscribes to.
  assert.match(fn, /'dockvault:evt:manage'/);
  const page = fs.readFileSync(path.join(root, 'src', 'renderer', 'status.js'), 'utf8');
  assert.match(page, /api\.onChanged\(/, 'the page really does subscribe');
  // And the page no longer claims the poll is a backstop while being the only mechanism.
  assert.ok(!/the push is the same one the tray listens to/.test(page), 'the untrue claim is gone');
});
