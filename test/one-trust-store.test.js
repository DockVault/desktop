'use strict';

// One trust store for the whole app: every main-process request goes through Electron's network
// layer (the operating system's certificate store), never through Node's own roots.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const main = path.resolve(__dirname, '..', 'src', 'main');
const read = (f) => fs.readFileSync(path.join(main, f), 'utf8').replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/\/\/[^\n]*/g, ' ');

test('the request helper is built on Electron net and contains no Node http(s) client', () => {
  const src = read('http-json.js');
  assert.doesNotMatch(src, /require\(\s*['"]node:https?['"]\s*\)/);
  assert.doesNotMatch(src, /require\(\s*['"]https?['"]\s*\)/);
  assert.match(src, /net\.fetch\(/);
  assert.match(src, /credentials:\s*'omit'/, 'never the interface cookies or storage');
  assert.match(src, /redirect:\s*'error'/, 'the credential path refuses redirects');
  assert.match(src, /may not follow redirects/, 'and a request carrying a credential can never opt in to following them');
  assert.doesNotMatch(src, /redirect:\s*'follow'/, 'no path hands redirect-following to the network layer blind');
  assert.doesNotMatch(src, /headers\[\s*['"]Content-Length['"]\s*\]\s*=/, 'the network layer sets the length; a caller-set one is a restricted header');
  assert.match(src, /getReader\(\)/, 'the body is read as a stream so the cap can stop it early');
});

test('main binds the helper to Electron net once and passes it everywhere', () => {
  const src = read('index.js');
  assert.match(src, /createHttpJson\(net\)/);
  assert.doesNotMatch(src, /require\(\s*['"]\.\/http-json['"]\s*\)\.httpJson/);
});

test('no main-process module reaches for Node http(s) on its own', () => {
  const offenders = fs.readdirSync(main).filter((f) => f.endsWith('.js') && /require\(\s*['"](node:)?https?['"]\s*\)/.test(read(f)));
  assert.deepEqual(offenders, []);
});

test('no main-process module binds the retired httpJson export of the request helper', () => {
  const bind = /const\s*\{\s*httpJson\s*\}\s*=\s*require\(\s*['"]\.\/http-json['"]\s*\)/;
  const prop = /require\(\s*['"]\.\/http-json['"]\s*\)\.httpJson/;
  const offenders = fs.readdirSync(main).filter((f) => f.endsWith('.js') && (bind.test(read(f)) || prop.test(read(f))));
  assert.deepStrictEqual(offenders, [], 'the helper exports createHttpJson only; a module must build or be handed a client');
});
