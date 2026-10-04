'use strict';

/*
 * THE BUNDLED WEB INTERFACE STILL FITS THE SHELL.
 *
 * The main window runs the vault's own web interface, taken from the pinned vendor/vault tree. Moving that
 * pin changes files the shell serves, the policy it has to mirror, and code the shell reaches into. These
 * tests read the pinned tree itself, so a pin that renames a file, adds a policy directive, drops the
 * sign-in form's early-submit guard or adds a key cache the lock does not clear fails here, inside
 * `npm test`, before anything is built.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const { contentType, isAssetPath } = require('../src/main/scheme');
const { buildCsp } = require('../src/main/csp');
const { RENDERER_PURGE_JS } = require('../src/main/lock-state');

const VAULT = path.resolve(__dirname, '..', 'vendor', 'vault');
const STATIC_ROOT = path.join(VAULT, 'static');
const INDEX_HTML = fs.readFileSync(path.join(STATIC_ROOT, 'index.html'), 'utf8');

// The file the scheme serves for an asset path: the query dropped, /static/ mapped onto the static root.
function servedFile(urlPath) {
  let p = urlPath.split('?')[0];
  if (p.startsWith('/static/')) p = p.slice('/static'.length);
  return path.join(STATIC_ROOT, p);
}

// The script sources and stylesheet links of the bundled index.html, in document order.
function referencedAssets(html) {
  const scripts = [...html.matchAll(/<script\b[^>]*\bsrc="([^"]+)"/g)].map((m) => m[1]);
  const styles = [...html.matchAll(/<link\b[^>]*\brel="stylesheet"[^>]*>/g)]
    .map((m) => (m[0].match(/\bhref="([^"]+)"/) || [])[1]).filter(Boolean);
  return { scripts, styles };
}

// The source of one top-level declaration in app.js, from its first line to its balanced closing brace.
// Exactly one such declaration must exist, or the test cannot say which one the shell meets.
function topLevelDeclaration(src, opener) {
  const at = [];
  let from = 0;
  for (;;) {
    const i = src.indexOf(`\n${opener}`, from);
    if (i < 0) break;
    at.push(i + 1);
    from = i + 1;
  }
  assert.equal(at.length, 1, `exactly one top-level "${opener}" in the bundled app.js (found ${at.length})`);
  const start = at[0];
  const open = src.indexOf('{', start);
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}' && --depth === 0) return src.slice(start, i + 1) + (src[i + 1] === ';' ? ';' : '');
  }
  throw new Error(`unbalanced "${opener}" in the bundled app.js`);
}

test('every script and stylesheet the bundled page loads is a served file with its own content type', () => {
  const { scripts, styles } = referencedAssets(INDEX_HTML);
  assert.ok(scripts.length >= 5, `the page loads its scripts (found ${scripts.length})`);
  assert.ok(styles.length >= 3, `the page loads its stylesheets (found ${styles.length})`);
  for (const ref of [...scripts, ...styles]) {
    const urlPath = ref.split('?')[0];
    assert.ok(isAssetPath(urlPath), `${ref} is served from the bundle, not forwarded to the server`);
    const file = servedFile(ref);
    assert.ok(fs.existsSync(file) && fs.statSync(file).isFile(), `${ref} exists in the pinned tree`);
  }
  for (const ref of scripts) assert.equal(contentType(servedFile(ref)), 'text/javascript; charset=utf-8', ref);
  for (const ref of styles) assert.equal(contentType(servedFile(ref)), 'text/css; charset=utf-8', ref);
  // The page's own scripts, in particular the crypto and the main script, are among them.
  for (const name of ['/static/js/ecc_crypto.js', '/static/js/app.js', '/static/js/auth-boot.js']) {
    assert.ok(scripts.some((s) => s.split('?')[0] === name), `${name} is loaded`);
  }
});

test('the early-submit guard loads in <head>, before the first form', () => {
  const head = INDEX_HTML.slice(0, INDEX_HTML.indexOf('</head>'));
  const guard = head.search(/<script\b[^>]*\bsrc="\/static\/js\/auth-boot\.js[?"]/);
  assert.ok(guard > 0, 'auth-boot.js is loaded in <head>');
  const firstForm = INDEX_HTML.search(/<form\b/);
  assert.ok(firstForm > 0 && guard < firstForm, 'and before the first <form>');
});

test('the guard stops the browser sending a form itself, in the capture phase, and nothing else', () => {
  const src = fs.readFileSync(path.join(STATIC_ROOT, 'js', 'auth-boot.js'), 'utf8');
  const listeners = [];
  const sandbox = {
    document: {
      addEventListener: (type, fn, capture) => listeners.push({ type, fn, capture }),
      documentElement: { setAttribute: () => {} },
    },
    location: { search: '' },
    localStorage: { getItem: () => null },
    sessionStorage: { getItem: () => null },
  };
  vm.runInNewContext(src, sandbox);
  const submits = listeners.filter((l) => l.type === 'submit');
  assert.equal(submits.length, 1, 'one submit listener');
  assert.equal(submits[0].capture, true, 'installed for the capture phase, so it runs before any form handler');
  let prevented = 0;
  let stopped = 0;
  submits[0].fn({ preventDefault: () => { prevented++; }, stopPropagation: () => { stopped++; }, stopImmediatePropagation: () => { stopped++; } });
  assert.equal(prevented, 1, 'the browser does not send the form');
  assert.equal(stopped, 0, "the forms' own handlers still run");
});

test('every form of the bundled page says method="post", so nothing is ever sent in an address', () => {
  const forms = [...INDEX_HTML.matchAll(/<form\b[^>]*>/g)].map((m) => m[0]);
  assert.ok(forms.length >= 3, `the page has its forms (found ${forms.length})`);
  for (const f of forms) assert.match(f, /\bmethod="post"/, f);
});

test('locking drops every zero-knowledge key the bundled interface caches, including the key-proof keys', () => {
  const app = fs.readFileSync(path.join(STATIC_ROOT, 'js', 'app.js'), 'utf8');
  const ctx = vm.createContext({});
  // The bundle's own key cache and its reset, as they are, with a stand-in for the page state the purge
  // also clears.
  vm.runInContext(topLevelDeclaration(app, 'const zkState = '), ctx);
  vm.runInContext(topLevelDeclaration(app, 'function zkResetKeys()'), ctx);
  vm.runInContext('var state = { vaultPassword: "pw", vaultPasswordTimestamp: 1 };', ctx);
  const fields = vm.runInContext('Object.keys(zkState)', ctx);
  assert.ok(fields.includes('privateKey') && fields.includes('keyProofKeys'), `the cache holds the identity and key-proof keys (${fields.join(', ')})`);
  // Fill every cache, then run the shell's purge exactly as it runs in the window.
  vm.runInContext('for (const k of Object.keys(zkState)) zkState[k] = { held: true };', ctx);
  assert.equal(vm.runInContext(RENDERER_PURGE_JS, ctx), true);
  for (const k of fields) {
    const v = vm.runInContext(`zkState[${JSON.stringify(k)}]`, ctx);
    assert.ok(v === null || (typeof v === 'object' && Object.keys(v).length === 0), `zkState.${k} is dropped`);
  }
  assert.equal(vm.runInContext('state.vaultPassword', ctx), null);
  assert.equal(vm.runInContext('state.vaultPasswordTimestamp', ctx), null);
});

test("the shell's policy keeps every directive the pinned server sends, tightening only connect-src", () => {
  const server = fs.readFileSync(path.join(VAULT, 'app', 'api', 'api_server.py'), 'utf8');
  const lists = [...server.matchAll(/csp_directives = \[([\s\S]*?)\n\s*\]/g)];
  assert.equal(lists.length, 1, 'the server builds its page policy in one place');
  const hosted = [...lists[0][1].matchAll(/^\s*"([^"]+)"/gm)].map((m) => m[1]);
  assert.ok(hosted.length >= 10, `the hosted policy was read (${hosted.length} directives)`);
  const parse = (s) => new Map(s.split(';').map((d) => d.trim()).filter(Boolean).map((d) => {
    const [name, ...v] = d.split(/\s+/);
    return [name, v.join(' ')];
  }));
  const hostedMap = parse(hosted.join('; '));
  for (const origins of [{}, { serverHttpsOrigin: 'https://vault.example.com', serverWssOrigin: 'wss://vault.example.com' }]) {
    const shell = parse(buildCsp(origins));
    assert.deepEqual([...shell.keys()].sort(), [...hostedMap.keys()].sort(), 'the same directives, no more and no fewer');
    for (const [name, value] of hostedMap) {
      if (name === 'connect-src') continue;
      assert.equal(shell.get(name), value, `${name} matches the server's`);
    }
    // connect-src names exact origins, never a bare scheme a page script could point anywhere.
    for (const source of shell.get('connect-src').split(' ')) assert.ok(!/^[a-z]+:$/.test(source), `connect-src ${source}`);
  }
});
