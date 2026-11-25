import assert from 'node:assert/strict';
import { beforeEach, test } from 'node:test';
import worker, { pickOrder, _test } from '../edge-lb/index.mjs';
import config from '../edge-lb/config.mjs';

// The committed config: thedemontuan.dev on n1 (primary, weight 30) and n2 (weight 70).
let calls;
let replies;
globalThis.caches = { default: { match: async () => undefined, put: async () => {} } };
globalThis.fetch = async (request, init) => {
  const node = init.cf.resolveOverride.split('-origin.')[0];
  calls.push({ node, method: request.method, url: request.url });
  const reply = replies[node] ?? 200;
  if (reply instanceof Error) throw reply;
  // A hung origin: no headers until the caller gives up.
  if (reply === 'hang') return new Promise((_, reject) => init.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError'))));
  return new Response(node, { status: reply });
};
const ctx = { waitUntil() {} };
const call = (path, init = {}, client = '203.0.113.9') =>
  worker.fetch(new Request('https://thedemontuan.dev' + path, { ...init, headers: { 'cf-connecting-ip': client, ...init.headers } }), {}, ctx);
const ipAt = (i) => `10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}`;
const clientOn = (node) => {
  for (let i = 0; ; i++) if (pickOrder(['n1', 'n2'], ipAt(i))[0] === node) return ipAt(i);
};

beforeEach(() => {
  calls = [];
  replies = {};
  _test.downUntil.clear();
  _test.timing.ttfbMs = 10_000;
});

test('a client always gets the same node; clients split by weight; a down node goes last', () => {
  const first = Array.from({ length: 20000 }, (_, i) => pickOrder(['n1', 'n2'], ipAt(i))[0]);
  const share = first.filter((n) => n === 'n2').length / first.length;
  assert.ok(share > 0.68 && share < 0.72, `n2 share ${share}`);
  for (let i = 0; i < 100; i++) assert.equal(pickOrder(['n1', 'n2'], ipAt(i))[0], first[i]);
  const onN2 = clientOn('n2');
  _test.downUntil.set('n2', 10);
  assert.deepEqual(pickOrder(['n1', 'n2'], onN2, 5), ['n1', 'n2']);
  assert.deepEqual(pickOrder(['n1', 'n2'], onN2, 11), ['n2', 'n1']);
});

test('weight 0 drains a node: it is only a fallback', () => {
  config.nodes.n2.weight = 0;
  try {
    for (let i = 0; i < 200; i++) assert.deepEqual(pickOrder(['n1', 'n2'], ipAt(i)), ['n1', 'n2']);
  } finally {
    config.nodes.n2.weight = 70;
  }
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

test('only a node may pin a read; a pinned write still reaches the primary', async () => {
  await call('/healthz', { headers: { 'X-Edge-Node': 'n2' } }, config.nodes.n1.ip);
  await call('/api/comments', { method: 'POST', body: '{}', headers: { 'X-Edge-Node': 'n2' } }, config.nodes.n1.ip);
  await call('/healthz', { headers: { 'X-Edge-Node': 'n2' } }, clientOn('n1'));
  assert.deepEqual(calls.map((c) => c.node), ['n2', 'n1', 'n1']);
});

test('a failing node is retried once on the other and then tried last', async () => {
  for (const [first, reply] of [['n1', 502], ['n2', new TypeError('connect')]]) {
    calls = [];
    _test.downUntil.clear();
    replies = { [first]: reply };
    const response = await call('/', {}, clientOn(first));
    assert.equal(response.status, 200);
    assert.deepEqual(calls.map((c) => c.node), [first, first === 'n1' ? 'n2' : 'n1']);
    assert.ok(_test.downUntil.get(first) > Date.now());
  }
});

test('a node that sends no headers in time is abandoned for the other', async () => {
  _test.timing.ttfbMs = 20;
  replies = { n2: 'hang' };
  const response = await call('/', {}, clientOn('n2'));
  assert.equal(await response.text(), 'n1');
  assert.ok(_test.downUntil.get('n2') > Date.now());
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
