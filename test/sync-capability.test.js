'use strict';

// Whether a server supports syncing from a computer, decided before sign-in from how the device route
// refuses an unauthenticated request: guarded means present, missing means absent, anything else is unknown.

const test = require('node:test');
const assert = require('node:assert/strict');

const { probeSyncCapability } = require('../src/main/sync-capability');

const answer = (status, body) => async (url, init) => {
  answer.calls.push([url, init && init.method, init && init.headers]);
  return { ok: status >= 200 && status < 300, status, json: async () => { if (body === undefined) throw new Error('no json'); return body; } };
};
answer.calls = [];

test('a 401 or 403 from the device route means the server speaks sync; a 404 means it does not', async () => {
  assert.deepEqual(await probeSyncCapability('https://v.example.com', { httpJson: answer(401, { detail: 'Not authenticated' }) }), { kind: 'supported' });
  assert.deepEqual(await probeSyncCapability('https://v.example.com', { httpJson: answer(403, { detail: 'forbidden' }) }), { kind: 'supported' });
  assert.deepEqual(await probeSyncCapability('https://v.example.com', { httpJson: answer(404, { detail: 'Not Found' }) }), { kind: 'unsupported' });
});

test('it asks exactly GET /devices with no credential, on the given origin', async () => {
  answer.calls = [];
  await probeSyncCapability('https://v.example.com:8443', { httpJson: answer(401, {}) });
  assert.equal(answer.calls.length, 1);
  assert.equal(answer.calls[0][0], 'https://v.example.com:8443/devices');
  assert.equal(answer.calls[0][1], 'GET');
  assert.ok(!Object.keys(answer.calls[0][2] || {}).some((k) => k.toLowerCase() === 'authorization'));
});

test('a 5xx, a transport failure, or an odd 2xx is unknown — never "too old", never "supported"', async () => {
  assert.deepEqual(await probeSyncCapability('https://v.example.com', { httpJson: answer(500, {}) }), { kind: 'unknown' });
  assert.deepEqual(await probeSyncCapability('https://v.example.com', { httpJson: answer(502) }), { kind: 'unknown' });
  assert.deepEqual(await probeSyncCapability('https://v.example.com', { httpJson: async () => { throw Object.assign(new Error('refused'), { code: 'ECONNREFUSED' }); } }), { kind: 'unknown' });
  assert.deepEqual(await probeSyncCapability('https://v.example.com', { httpJson: answer(204) }), { kind: 'unknown' });
  assert.deepEqual(await probeSyncCapability('https://v.example.com', { httpJson: answer(200, '<html>') }), { kind: 'unknown' }, 'a front answering 200 with a page');
  assert.deepEqual(await probeSyncCapability('https://v.example.com', { httpJson: answer(200) }), { kind: 'unknown' }, 'a 200 whose body is not JSON');
  assert.deepEqual(await probeSyncCapability('https://v.example.com', { httpJson: answer(200, { devices: [] }) }), { kind: 'supported' }, 'a real device list is still the route being there');
});
