'use strict';

/*
 * THE DOWNLOAD WORKER THE APP SERVES KEEPS A FINISHED DOWNLOAD UNTIL THE BROWSER ASKS FOR IT.
 *
 * The bundled interface writes a download into a slot of its download worker and then points a hidden
 * frame at the slot's address; the worker answers that request with the stream. The pinned worker drops
 * the slot as soon as the page says the download is complete. A small file is decrypted and written at
 * once, so the page says so before the frame's request has reached the worker, which then answers 404:
 * the hidden frame shows the 404 and no download starts, with no error anywhere. The app therefore
 * serves its own copy of the worker (src/web-ui/download-sw.js) in which a finished slot waits for its
 * request, and goes when that request takes it or when it expires.
 *
 * These tests hold three things:
 *   - the copy is the pinned worker plus exactly that change, so a new pin cannot leave it stale
 *     (when the pinned worker changes, the copy is made again from it, or dropped if the change is the fix);
 *   - the copy delivers a download finished before its request, in full, and still refuses a reload;
 *   - the same harness shows the pinned worker losing that download, so a pass here means something.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const PINNED = path.resolve(__dirname, '..', 'vendor', 'vault', 'static', 'js', 'download-sw.js');
const SERVED = path.resolve(__dirname, '..', 'src', 'web-ui', 'download-sw.js');

// The change, as edits to the pinned file. Each must apply exactly once.
const HEADER = [
  '/*',
  ' * DockVault Desktop: the download worker of the bundled web interface',
  ' * (vendor/vault/static/js/download-sw.js), served in its place with one change. The pinned worker',
  ' * removes a slot as soon as the page says the download is complete. For a small file the page says so',
  ' * before the browser\'s request for the slot has reached the worker, which then answers 404, and no',
  ' * download starts. Here a finished slot waits for that request. test/download-worker.test.js checks',
  ' * that this file is the pinned worker plus exactly this change.',
  ' */',
  '',
].join('\n');
const EDITS = [
  [
    '/** Slots handed out but not yet fetched, and slots currently streaming. */',
    '/** Slots handed out whose download the browser has not asked for yet. */',
  ],
  [
    '    port.onmessage = messageEvent => {\n',
    [
      '    // The page can finish before the browser has asked for the download: a small file is decrypted',
      '    // and written at once, while the hidden frame\'s request for the slot is still on its way. A closed',
      '    // stream keeps every byte written to it, so a finished slot stays until that request takes it, and',
      '    // goes when it expires if the request never comes.',
      '    const keepUntilAsked = () => {',
      '        const slot = PENDING.get(id);',
      '        setTimeout(() => { if (slot && PENDING.get(id) === slot) PENDING.delete(id); }, SLOT_TTL_MS);',
      '    };',
      '',
      '    port.onmessage = messageEvent => {',
      '',
    ].join('\n'),
  ],
  [
    "                controllerRef.close();\n                controllerRef = null;\n                PENDING.delete(id);\n",
    "                controllerRef.close();\n                controllerRef = null;\n                keepUntilAsked();\n",
  ],
  [
    "                controllerRef.error(new Error(message.reason || 'aborted'));\n                controllerRef = null;\n                PENDING.delete(id);\n",
    "                controllerRef.error(new Error(message.reason || 'aborted'));\n                controllerRef = null;\n                keepUntilAsked();\n",
  ],
  [
    "        event.respondWith(new Response('no such download', { status: 404 }));\n        return;\n    }\n",
    [
      "        event.respondWith(new Response('no such download', { status: 404 }));",
      '        return;',
      '    }',
      '',
      '    // A stream is read once, so this request spends the slot; another request for it is the reload above.',
      '    PENDING.delete(id);',
      '',
    ].join('\n'),
  ],
];

function derive(pinned) {
  let text = pinned;
  for (const [from, to] of EDITS) {
    assert.equal(text.split(from).length, 2, `the pinned worker has this exactly once: ${JSON.stringify(from.slice(0, 60))}`);
    text = text.replace(from, () => to);
  }
  return HEADER + text;
}

// A service worker global, enough to run the worker script: its listeners are captured, its timers are
// held so a test can run them, and Response, ReadableStream and MessageChannel are Node's own.
function loadWorker(file) {
  const listeners = {};
  const timers = [];
  const self = {
    // An http origin: Node's URL gives a custom scheme's address an opaque origin, which the app's
    // privileged scheme does not have; the worker only compares the two.
    location: { origin: 'https://app.example' },
    clients: { claim: () => Promise.resolve() },
    skipWaiting: () => Promise.resolve(),
    addEventListener: (type, fn) => { listeners[type] = fn; },
  };
  const context = vm.createContext({
    self, URL, Response, ReadableStream, Uint8Array, Map, Date, Number, String, Error,
    setTimeout: (fn, ms) => { timers.push({ fn, ms }); return timers.length; },
  });
  vm.runInContext(fs.readFileSync(file, 'utf8'), context, { filename: file });

  async function open(id, size) {
    const channel = new MessageChannel();
    const ready = new Promise((resolve) => { channel.port1.onmessage = (e) => resolve(e.data); });
    listeners.message({ data: { type: 'dv-sink-open', id, filename: 'f.bin', size, mime: 'application/octet-stream' }, ports: [channel.port2] });
    const reply = await ready;
    const port = channel.port1;
    openPorts.push(port);
    // One round trip after a post, so the worker has handled it before the test goes on.
    const settle = () => new Promise((r) => setTimeout(r, 20));
    return {
      url: reply.url,
      async write(bytes) { const copy = new Uint8Array(bytes); port.postMessage({ type: 'chunk', bytes: copy.buffer }, [copy.buffer]); await settle(); },
      async done() { port.postMessage({ type: 'done' }); await settle(); },
      async abort() { port.postMessage({ type: 'abort', reason: 'failed' }); await settle(); },
    };
  }
  function request(url) {
    let answer = null;
    listeners.fetch({ request: { url: `https://app.example${url}` }, respondWith: (r) => { answer = r; } });
    return answer;
  }
  return { open, request, timers };
}

// A test that fails part-way must not leave a port open, or the run never ends.
const openPorts = [];
test.afterEach(() => { for (const port of openPorts.splice(0)) port.close(); });

const bytesOf = (n) => Uint8Array.from({ length: n }, (_, i) => (i * 31 + 7) & 0xff);

test('the served worker is the pinned worker plus exactly the slot change', () => {
  // Line endings are the checkout's business, not the worker's.
  const lf = (file) => fs.readFileSync(file, 'utf8').replace(/\r\n/g, '\n');
  const pinned = lf(PINNED);
  const served = lf(SERVED);
  assert.equal(served, derive(pinned),
    'src/web-ui/download-sw.js no longer matches the pinned worker: make it again from the pinned file, or serve the pinned file if it has the fix');
});

for (const size of [10, 1000, 30000]) {
  test(`a ${size}-byte download finished before its request arrives is delivered in full`, async () => {
    const w = loadWorker(SERVED);
    const sink = await w.open(`slot-${size}`, size);
    const data = bytesOf(size);
    await sink.write(data);
    await sink.done();
    const res = w.request(sink.url);           // the hidden frame's request, arriving after 'done'
    assert.ok(res, 'the worker answered');
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-disposition'), /^attachment; filename="f\.bin"$/);
    assert.equal(res.headers.get('content-length'), String(size));
    assert.deepEqual(new Uint8Array(await res.arrayBuffer()), data);
  });
}

test('a download asked for before it is written still streams, in pieces', async () => {
  const w = loadWorker(SERVED);
  const sink = await w.open('slot-early', 6);
  const res = w.request(sink.url);
  assert.equal(res.status, 200);
  await sink.write([1, 2, 3]);
  await sink.write([4, 5, 6]);
  await sink.done();
  assert.deepEqual([...new Uint8Array(await res.arrayBuffer())], [1, 2, 3, 4, 5, 6]);
});

test('a slot is answered once: a second request for it is a 404, not a broken stream', async () => {
  const w = loadWorker(SERVED);
  const sink = await w.open('slot-once', 3);
  await sink.write([9, 9, 9]);
  await sink.done();
  assert.equal(w.request(sink.url).status, 200);
  const again = w.request(sink.url);
  assert.equal(again.status, 404);
  assert.equal(await again.text(), 'no such download');
});

test('a download that failed before its request arrives still shows as a failed download', async () => {
  const w = loadWorker(SERVED);
  const sink = await w.open('slot-failed', 4);
  await sink.write([1, 2]);
  await sink.abort();
  const res = w.request(sink.url);
  assert.equal(res.status, 200, 'the browser gets the download, so it can mark it failed');
  await assert.rejects(res.arrayBuffer(), 'its body errors instead of ending short');
});

test('a finished slot whose request never comes goes when it expires', async () => {
  const w = loadWorker(SERVED);
  const sink = await w.open('slot-expiring', 1);
  await sink.write([1]);
  await sink.done();
  const expiry = w.timers.filter((t) => t.ms === 60_000);
  assert.equal(expiry.length, 1, 'one expiry is set for the finished slot');
  expiry[0].fn();
  assert.equal(w.request(sink.url).status, 404);
});

test('control: the pinned worker loses a small download finished before its request', async () => {
  const w = loadWorker(PINNED);
  const sink = await w.open('slot-pinned', 10);
  await sink.write(bytesOf(10));
  await sink.done();
  assert.equal(w.request(sink.url).status, 404,
    'if the pinned worker now delivers this, it has the fix: serve it again and drop the copy');
});
