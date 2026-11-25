import assert from 'node:assert/strict';
import { beforeEach, test } from 'node:test';
import worker, { pickOrder, _test } from '../edge-lb/index.mjs';

// The committed config: thedemontuan.dev on n1 (primary, weight 30) and n2 (weight 70).
let calls;
let replies;
globalThis.caches = { default: { match: async () => undefined, put: async () => {} } };
globalThis.fetch = async (request, init) => {
  const node = init.cf.resolveOverride.split('-origin.')[0];
  calls.push({ node, method: request.method, url: request.url });
  const reply = replies[node] ?? 200;
  if (reply instanceof Error) throw reply;
  return new Response(node, { status: reply });
};
const ctx = { waitUntil() {} };
const call = (path, init = {}) => worker.fetch(new Request('https://thedemontuan.dev' + path, init), {}, ctx);

beforeEach(() => {
  calls = [];
  replies = {};
  _test.downUntil.clear();
});

test('weights pick the first node; a node marked down goes last', () => {
  assert.deepEqual(pickOrder(['n1', 'n2'], 0, () => 0.29), ['n1', 'n2']);
  assert.deepEqual(pickOrder(['n1', 'n2'], 0, () => 0.31), ['n2', 'n1']);
  _test.downUntil.set('n2', 10);
  assert.deepEqual(pickOrder(['n1', 'n2'], 5, () => 0.99), ['n1', 'n2']);
  assert.deepEqual(pickOrder(['n1', 'n2'], 11, () => 0.99), ['n2', 'n1']);
});

test('writes, admin, sessions and downloads go to the primary; a write sets the sticky cookie', async () => {
  const post = await call('/api/comments', { method: 'POST', body: '{}' });
  assert.match(post.headers.get('set-cookie'), /^__Host-edge-primary=1; Max-Age=15;/);
  await call('/admin/posts');
  await call('/api/dl?f=x');
  await call('/', { headers: { cookie: 'a=1; __Host-mch_session=t' } });
  await call('/', { headers: { cookie: '__Host-edge-primary=1' } });
  assert.deepEqual(calls.map((c) => c.node), ['n1', 'n1', 'n1', 'n1', 'n1']);
});

test('a pinned read reaches that node; a pinned write still reaches the primary', async () => {
  await call('/healthz', { headers: { 'X-Edge-Node': 'n2' } });
  await call('/api/comments', { method: 'POST', body: '{}', headers: { 'X-Edge-Node': 'n2' } });
  assert.deepEqual(calls.map((c) => c.node), ['n2', 'n1']);
});

test('a failing node is retried once on the other and then tried last', async () => {
  for (const [first, reply] of [['n1', 502], ['n2', new TypeError('connect')]]) {
    calls = [];
    _test.downUntil.clear();
    Math.random = () => (first === 'n1' ? 0 : 0.99);
    replies = { [first]: reply };
    const response = await call('/');
    assert.equal(response.status, 200);
    assert.deepEqual(calls.map((c) => c.node), [first, first === 'n1' ? 'n2' : 'n1']);
    assert.ok(_test.downUntil.get(first) > Date.now());
  }
});

test('public images come from the bucket with the API headers; others fall through', async () => {
  const id = 'a'.repeat(32);
  const env = { MEDIA: { get: async (key) => (key === `media/${id}.jpg` ? { body: 'jpg', size: 3 } : null) } };
  const ok = await worker.fetch(new Request(`https://thedemontuan.dev/media/${id}.jpg`), env, ctx);
  assert.equal(ok.headers.get('cache-control'), 'public, max-age=31536000, immutable');
  assert.equal(ok.headers.get('etag'), `"${id}"`);
  assert.equal(await ok.text(), 'jpg');
  const fresh = await worker.fetch(new Request(`https://thedemontuan.dev/media/${id}.jpg`, { headers: { 'If-None-Match': `"${id}"` } }), env, ctx);
  assert.equal(fresh.status, 304);
  await worker.fetch(new Request(`https://thedemontuan.dev/media/${'b'.repeat(32)}.jpg`), env, ctx);
  assert.equal(calls.length, 1);
});
