'use strict';

/*
 * DOES EACH PAGE ACTUALLY RENDER?
 *
 * A shipped Troubleshoot page threw `ReferenceError` on every render — a `const` declared inside an `if`
 * block and read after it closed — so no check drew its action button at all. Nothing saw it: the unit
 * suite never loads a renderer, and the functional harness that would have caught it in a second is run by
 * hand under Electron and had not been run.
 *
 * `node --check` cannot catch that class. It is syntactically valid; it fails only when the line executes.
 * So this loads each page's real source in a stub DOM and DRIVES ITS FIRST PAINT, which is the cheapest
 * thing that would have caught it — milliseconds, inside `npm test`, on every run.
 *
 * WHAT THIS IS NOT: it is not a test of what the pages draw. The stub DOM records nothing and asserts
 * nothing about structure; the functional harnesses do that properly, against a real browser, and they
 * remain the thing that proves the page works. This only asks the much smaller question those harnesses
 * were not around to ask: does the code run at all.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const RENDERER = path.join(path.resolve(__dirname, '..'), 'src', 'renderer');

// A DOM that says yes to everything. It exists to let real page code run, not to model a browser: every
// node accepts any property, every query returns something usable, and nothing here asserts.
function stubDom() {
  const makeNode = () => {
    const node = {
      children: [],
      style: {}, dataset: {}, classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
      textContent: '', innerText: '', value: '', disabled: false, hidden: false, type: '',
      appendChild(c) { this.children.push(c); this.firstChild = this.children[0]; return c; },
      removeChild(c) { this.children = this.children.filter((x) => x !== c); this.firstChild = this.children[0]; return c; },
      insertBefore(c) { this.children.unshift(c); this.firstChild = this.children[0]; return c; },
      replaceChildren(...c) { this.children = c; this.firstChild = this.children[0] || null; },
      append(...c) { this.children.push(...c); this.firstChild = this.children[0]; },
      prepend(...c) { this.children.unshift(...c); this.firstChild = this.children[0]; },
      setAttribute() {}, removeAttribute() {}, getAttribute: () => null, hasAttribute: () => false,
      addEventListener() {}, removeEventListener() {}, focus() {}, blur() {}, click() {}, remove() {},
      querySelector: () => makeNode(), querySelectorAll: () => [],
      closest: () => null, contains: () => false, scrollIntoView() {},
      get firstElementChild() { return this.children[0] || null; },
    };
    node.firstChild = null;
    return node;
  };
  const document = {
    getElementById: () => makeNode(),
    createElement: () => makeNode(),
    createTextNode: () => makeNode(),
    querySelector: () => makeNode(),
    querySelectorAll: () => [],
    addEventListener() {}, removeEventListener() {},
    body: makeNode(),
    documentElement: makeNode(),
    activeElement: makeNode(),
  };
  return document;
}

// Every preload surface, answering plausibly. A page that asks for something not here gets `undefined` and
// will fail loudly, which is the point.
function stubApi() {
  const checks = [{ id: 'server-connection', title: 'Cannot connect to the server' }];
  const picture = {
    id: 'server-connection', title: 'Cannot connect to the server', intro: 'x',
    facts: [{ label: 'Server address', value: 'vault.example.com:443', mono: true }],
    legs: [{ id: 'api', label: 'Server' }], canProbe: true, note: '',
    action: { kind: 'change-server', label: 'Change server…' },
  };
  const probe = {
    id: 'server-connection', ran: true,
    legs: [{ id: 'api', label: 'Server', state: 'ok', text: 'fine', detail: '' }],
    notes: [], verdict: { state: 'ok', text: 'fine' }, at: Date.now(),
  };
  const noop = async () => null;
  return {
    app: { info: async () => ({ version: '0.1.0' }), onDeepLink: () => () => {} },
    server: { state: async () => ({ status: 'ok', origin: 'https://vault.example.com' }), verify: noop, save: noop, close: noop },
    sync: { status: async () => ({ state: 'up-to-date', label: 'Up to date', vaults: [] }), onStatus: () => () => {} },
    wizard: { question: noop, answer: noop, cancel: noop, close: noop, openApp: noop, onQuestion: () => () => {} },
    manage: { model: async () => ({ kind: 'ok', computers: [], me: null }), act: noop, openSetup: noop, openStatus: noop, close: noop, onChanged: () => () => {} },
    troubleshoot: { checks: async () => checks, describe: async () => picture, probe: async () => probe, openServerSetup: noop, relocateFolder: noop, close: noop },
    status: { model: async () => ({ headline: 'Up to date', state: 'up-to-date', items: [], empty: true }), onChanged: () => () => {} },
  };
}

// Load one page's real source and let its first paint run to completion. Anything it throws — on load, or
// out of the async work it starts — is returned rather than swallowed.
async function firstPaint(file) {
  const src = fs.readFileSync(path.join(RENDERER, file), 'utf8');
  const thrown = [];
  const sandbox = {
    document: stubDom(),
    window: { dockvault: stubApi(), addEventListener() {}, removeEventListener() {}, close() {}, location: { href: '' } },
    console: { log() {}, warn() {}, error() {} },
    setTimeout: (fn, ms) => setTimeout(() => { try { fn(); } catch (e) { thrown.push(e); } }, Math.min(ms || 0, 1)),
    clearTimeout,
    setInterval: () => 0,     // a page's polling loop is not this test's business
    clearInterval: () => {},
    queueMicrotask,
    Promise, Date, Math, JSON, Object, Array, String, Number, Boolean, RegExp, Error, Map, Set, Intl,
    URL, encodeURIComponent, decodeURIComponent, isNaN, parseInt, parseFloat,
  };
  sandbox.globalThis = sandbox;
  sandbox.window.document = sandbox.document;

  const context = vm.createContext(sandbox);
  const onRejection = (e) => thrown.push(e);
  process.on('unhandledRejection', onRejection);
  try {
    vm.runInContext(src, context, { filename: file });
    // Let the page's own startup work — describe, model, the first render — run out.
    for (let i = 0; i < 40; i += 1) await new Promise((r) => setTimeout(r, 1));
  } catch (e) {
    thrown.push(e);
  } finally {
    process.off('unhandledRejection', onRejection);
  }
  return thrown;
}

const PAGES = ['troubleshoot.js', 'status.js', 'manage.js', 'sync-wizard.js', 'server-setup.js'];

for (const page of PAGES) {
  test(`${page} loads and paints without throwing`, async () => {
    const thrown = await firstPaint(page);
    const first = thrown[0];
    assert.equal(
      thrown.length, 0,
      first ? `${page} threw during its first paint: ${first && first.stack ? first.stack.split('\n').slice(0, 3).join(' | ') : first}` : '',
    );
  });
}

// The specific shape that shipped, kept as its own test so the reason this file exists stays legible: a
// block-scoped binding read after its block closes is valid syntax and a certain crash.
test('the Troubleshoot page renders its action section, which is where the shipped crash was', async () => {
  const src = fs.readFileSync(path.join(RENDERER, 'troubleshoot.js'), 'utf8');
  const decl = src.indexOf('const isRunning = state ===');
  const block = src.indexOf('if (picture.canProbe) {');
  const use = src.indexOf('!isRunning && result.action');
  assert.ok(decl !== -1 && block !== -1 && use !== -1, 'the three points still exist');
  assert.ok(decl < block, 'isRunning is declared before the block that used to own it');
  assert.ok(decl < use, 'and before the action section reads it');
  // And the page really does run, which is what the shape above only implies.
  assert.deepEqual(await firstPaint('troubleshoot.js'), []);
});
