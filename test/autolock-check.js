'use strict';

/*
 * Functional check (run under Electron, not part of `npm test`): the automatic lock triggers work
 * against the REAL powerMonitor and REAL timers — the OS input-idle time reads as a number, the
 * visibility-independent idle poll fires a lock, and the unattended escalation destroys a still-locked
 * window. Uses a stand-in lock state + window (no real key material). Writes .local/autolock-check.json.
 *
 *   node_modules/electron/dist/electron.exe test/autolock-check.js
 */

const { app, powerMonitor } = require('electron');
const fs = require('node:fs');
const path = require('node:path');

const RESULT = path.join(__dirname, '..', '.local', 'autolock-check.json');
const out = {};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const watchdog = setTimeout(() => { dump(); app.exit(3); }, 15000);
function dump() { try { fs.mkdirSync(path.dirname(RESULT), { recursive: true }); fs.writeFileSync(RESULT, JSON.stringify(out, null, 2)); } catch {} }

app.whenReady().then(async () => {
  const { AutoLock } = require('../src/main/auto-lock');

  out.idleTime = powerMonitor.getSystemIdleTime();
  out.idleIsNumber = typeof out.idleTime === 'number';

  const locks = [];
  let unlocked = true;
  const win = { destroyed: false, isDestroyed() { return this.destroyed; }, destroy() { this.destroyed = true; } };
  const al = new AutoLock({
    powerMonitor,
    lockState: { isUnlocked: () => unlocked, lock: (r) => { locks.push(r); unlocked = false; return Promise.resolve(true); } },
    getWindow: () => win,
    idleThresholdMs: 0,                         // any idle -> fires on the first real poll
    timers: { idlePollMs: 20, escalateAfterMs: 60 },
  });
  al.start();                                   // real setInterval poll against real getSystemIdleTime

  await sleep(120);
  out.idleLocked = locks.includes('idle');      // the visibility-independent poll fired a lock
  await sleep(150);
  out.escalated = win.destroyed;                // the unattended still-locked window was hard-purged
  al.stop();

  out.ok = !!(out.idleIsNumber && out.idleLocked && out.escalated);
  clearTimeout(watchdog);
  dump();
  app.quit();
}).catch((e) => { out.fatal = String((e && e.stack) || e); dump(); app.exit(2); });
