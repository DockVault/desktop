'use strict';

/*
 * Functional check (run under Electron, not part of `npm test`): the main process forks the sync
 * daemon, brokers the database key once over the private channel, the daemon opens the encrypted
 * state DB and reports ready, a health ping round-trips, and the DB exists encrypted at rest.
 * Writes .local/daemon-check.json (no key material).
 *
 *   node_modules/electron/dist/electron.exe test/daemon-check.js
 */

const { app } = require('electron');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const RESULT = path.join(__dirname, '..', '.local', 'daemon-check.json');
const out = {};
const watchdog = setTimeout(() => { dump(); app.exit(3); }, 30000);
function dump() { try { fs.mkdirSync(path.dirname(RESULT), { recursive: true }); fs.writeFileSync(RESULT, JSON.stringify(out, null, 2)); } catch {} }

app.whenReady().then(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-daemon-'));
  const { DaemonManager } = require('../src/main/daemon-manager');
  const mgr = new DaemonManager(dir);

  const ready = new Promise((resolve) => mgr.on('ready', resolve));
  mgr.start();
  out.ready = await Promise.race([ready, new Promise((r) => setTimeout(() => r({ type: 'timeout' }), 8000))]);
  out.pong = await mgr.ping(3000);
  out.zkLockAck = await mgr.zkLock(3000); // the atomic dual-key purge hook acks over the private channel

  const dbFile = path.join(dir, 'state.db');
  out.dbExists = fs.existsSync(dbFile);
  if (out.dbExists) {
    const raw = fs.readFileSync(dbFile);
    out.dbEncrypted = !raw.subarray(0, 16).toString('latin1').startsWith('SQLite format 3');
  }
  const dbkExists = fs.existsSync(path.join(dir, 'state-dbk.bin'));

  mgr.stop();
  await new Promise((r) => setTimeout(r, 400));

  out.ok = !!(out.ready && out.ready.type === 'ready' && out.ready.encrypted === true
    && out.pong === true && out.zkLockAck === true && out.dbExists && out.dbEncrypted && dbkExists);
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
  clearTimeout(watchdog);
  dump();
  app.quit();
}).catch((e) => { out.fatal = String((e && e.stack) || e); dump(); app.exit(2); });
