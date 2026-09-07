'use strict';

// The shell's own pages come over the app scheme from one flat directory: named files only, no
// traversal, no dotfiles, and the pages the app loads actually exist there.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { resolveShellFile, shellPageUrl, SHELL_PATH } = require('../src/main/scheme');

const root = path.resolve(__dirname, '..', 'src', 'renderer');

test('the shell pages and their scripts resolve to real files under src/renderer', () => {
  for (const name of ['server-setup.html', 'server-setup.js', 'sync-wizard.html', 'sync-wizard.js', 'selftest-fail.html']) {
    const file = resolveShellFile(`${SHELL_PATH}${name}`);
    assert.equal(file, path.join(root, name));
    assert.ok(fs.existsSync(file), `${name} exists`);
  }
  assert.equal(shellPageUrl('dockvault://app', 'server-setup.html'), 'dockvault://app/__dv_shell__/server-setup.html');
});

test('anything that is not a plain page name is refused', () => {
  for (const p of [`${SHELL_PATH}../index.js`, `${SHELL_PATH}..%2Fmain%2Findex.js`, `${SHELL_PATH}sub/x.html`, `${SHELL_PATH}.env`, `${SHELL_PATH}x.json`, `${SHELL_PATH}`, '/static/js/app.js', '/__dv_shell__x.html', `${SHELL_PATH}%ZZ.html`]) {
    assert.equal(resolveShellFile(p), null, p);
  }
  // A query string does not change the file.
  assert.equal(resolveShellFile(`${SHELL_PATH}server-setup.html?x=1`), path.join(root, 'server-setup.html'));
});

test('the setup page refers to its script by the bare name the route serves', () => {
  const html = fs.readFileSync(path.join(root, 'server-setup.html'), 'utf8');
  assert.match(html, /<script src="server-setup\.js"><\/script>/);
  assert.match(html, /script-src 'self'/);
  assert.match(html, /connect-src 'none'/, 'the page itself may not fetch anything');
});

test('the wizard page refers to its script by the bare name the route serves, and may fetch nothing itself', () => {
  const html = fs.readFileSync(path.join(root, 'sync-wizard.html'), 'utf8');
  assert.match(html, /<script src="sync-wizard\.js"><\/script>/);
  assert.match(html, /script-src 'self'/);
  assert.match(html, /connect-src 'none'/);
  // The page builds every element with textContent: no innerHTML anywhere in its script.
  const js = fs.readFileSync(path.join(root, 'sync-wizard.js'), 'utf8');
  assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write/.test(js), 'no markup from data');
});
