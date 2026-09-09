'use strict';

/*
 * The preload is the primary control on how far a renderer compromise can reach, so its surface is
 * tested by static analysis (the file cannot be required outside Electron). These assertions encode
 * the surface rules: no secret-returning method, no generic IO, contextBridge with enumerated
 * channels. If a future change adds a forbidden capability, this test fails before it ships.
 *
 * The forbidden-token scan runs on a comment-stripped copy, so the preload's own documentation of
 * the forbidden list does not trip the scan — only real code should.
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const RAW = fs.readFileSync(path.join(__dirname, '..', 'src', 'preload', 'index.js'), 'utf8');
const CODE = RAW
  .replace(/\/\*[\s\S]*?\*\//g, ' ')   // strip block comments
  .replace(/\/\/[^\n]*/g, ' ');        // strip line comments

test('exposes via contextBridge, not a raw window global', () => {
  assert.match(CODE, /contextBridge\.exposeInMainWorld\(\s*['"]dockvault['"]/);
});

test('no generic-IO or secret-returning capability usage', () => {
  const forbidden = [
    /\breadFile\b/, /\bwriteFile\b/, /\breaddir\b/, /\bunlink\b/,
    /\bexec\b/, /\bspawn\b/, /\bexecFile\b/,
    /\bgetSecret\b/, /\bgetToken\b/, /\bgetKey\b/, /\bgetPassphrase\b/, /\bgetEnvelope\b/,
    /openExternal/, /\beval\b/, /child_process/,
  ];
  for (const re of forbidden) assert.ok(!re.test(CODE), `forbidden token present in code: ${re}`);
});

test('no generic fetch/request passthrough is exposed', () => {
  assert.ok(!/\bfetch\s*:/.test(CODE), 'no fetch: capability');
  assert.ok(!/\brequest\s*:/.test(CODE), 'no request: capability');
});

test('the sync surface is OBSERVE-ONLY: status query + status event, and NO initiator/list/control', () => {
  assert.match(CODE, /EVENT_CHANNELS\s*=\s*Object\.freeze\(\[[^\]]*['"]syncstatus['"]/, 'syncstatus is an allowlisted event channel');
  assert.match(CODE, /ipcRenderer\.invoke\(\s*['"]dockvault:sync\.status['"]\s*\)/, 'a cred-free status query is exposed');
  // The plain sync surface has NO start/stop/list method. Setting sync up and ending it exist only on the two
  // shell-owned pages (the wizard and the Computers view), each behind a sender gate bound to its own window,
  // and neither lets a page name a folder or a config (asserted below).
  assert.ok(!/dockvault:sync\.setup/.test(CODE), 'no renderer sync.setup initiator');
  assert.ok(!/dockvault:sync\.list/.test(CODE), 'no renderer sync.list capability');
  for (const verb of [/\bstartSync\b/, /\bstopSync\b/, /\brunSync\b/, /\bconfigureSync\b/, /\bsync\.run\b/, /\bsync\.start\b/, /\bsync\.setup\b/, /\bsync\.list\b/]) {
    assert.ok(!verb.test(CODE), `no renderer sync-control verb: ${verb}`);
  }
});

test('the Computers surface hands over a kind and two ids, nothing that names a URL, a path, or a folder; the wizard surface an id and a choice', () => {
  const actCall = CODE.match(/dockvault:manage\.act['"].*/)[0];
  assert.ok(!/url|path|folder|file|method|header/i.test(actCall), `manage.act passes only kind + ids: ${actCall}`);
  assert.match(actCall, /kind/); assert.match(actCall, /deviceId/); assert.match(actCall, /vaultId/);
  const answerCall = CODE.match(/dockvault:wizard\.answer['"].*/)[0];
  assert.ok(!/url|path|folder|file/i.test(answerCall), `wizard.answer passes only an id and a value: ${answerCall}`);
  // The Troubleshoot surface names a check by id only: no address, host, or port ever travels from the page.
  for (const call of [CODE.match(/dockvault:troubleshoot\.describe['"].*/)[0], CODE.match(/dockvault:troubleshoot\.probe['"].*/)[0]]) {
    assert.ok(!/url|host|port|address|path|folder|file/i.test(call), `troubleshoot passes only a check id: ${call}`);
    assert.match(call, /id: String\(id\)/);
  }
  // The only sync-controlling channels are the gated pages' own; nothing generic. The namespace list is an
  // ALLOWLIST on purpose: a new one cannot appear without someone deciding it should, which is what caught
  // `status` being added and made this line the place to say what it is.
  //
  // `status.` is the dedicated sync-status view, and it is READ-ONLY — one `model` call and no companion
  // action channel. It exists separately from `sync.` because the sentence it carries is composed from a
  // vault's outcome detail, which `sync.status()` deliberately strips before any renderer sees it: that one
  // is reachable from the window hosting the vault's own web interface, and this one is gated to its page.
  const channels = [...CODE.matchAll(/ipcRenderer\.invoke\(\s*['"](dockvault:[a-z.-]+)['"]/g)].map((m) => m[1]);
  for (const ch of channels) assert.match(ch, /^dockvault:(app|server|sync|wizard|manage|troubleshoot|status)\./, ch);
  // And it really is read-only: no channel in that namespace does anything but fetch the model.
  const statusChannels = channels.filter((c) => c.startsWith('dockvault:status.'));
  assert.deepEqual(statusChannels, ['dockvault:status.model'], `the status page reads and nothing else: ${statusChannels}`);
  assert.ok(!channels.includes('dockvault:sync.setup') && !channels.includes('dockvault:sync.list'));
});

test('IPC is invoke/on only — no send/sendSync, event channels are allowlisted', () => {
  assert.ok(!/ipcRenderer\.send\b/.test(CODE), 'no fire-and-forget send');
  assert.ok(!/ipcRenderer\.sendSync\b/.test(CODE), 'no sendSync');
  assert.match(CODE, /EVENT_CHANNELS/, 'event channels are enumerated via an allowlist');
  const invokes = CODE.match(/ipcRenderer\.invoke\(([^)]*)/g) || [];
  for (const call of invokes) {
    assert.match(call, /ipcRenderer\.invoke\(\s*['"]dockvault:/, `non-literal invoke channel: ${call}`);
  }
});

test('the server surface is one narrow intent: a state read and a typed-address hand-off, never a URL to fetch', () => {
  assert.match(CODE, /ipcRenderer\.invoke\(\s*['"]dockvault:server\.state['"]\s*\)/, 'a state query is exposed');
  assert.match(CODE, /ipcRenderer\.invoke\(\s*['"]dockvault:server\.connect['"]/, 'a connect hand-off is exposed');
  // The renderer hands over what the person typed and a boolean; main decides the route (/health), the
  // normalisation, and the write. No way to name a URL, a method, headers, or a file.
  const connectCall = CODE.match(/dockvault:server\.connect['"][^)]*\)/)[0];
  assert.ok(!/url|method|headers|path|file/i.test(connectCall), `connect passes only the typed input and a flag: ${connectCall}`);
  assert.ok(!/dockvault:server\.(write|read|save|delete|open)/.test(CODE), 'no renderer file-level verb on the server setting');
});
