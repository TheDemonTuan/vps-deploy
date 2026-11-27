import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { beforeEach, test } from 'node:test';
import worker, { Lease, pickOrder, _test } from '../edge-lb/index.mjs';
import config from '../edge-lb/config.mjs';

// A fixed two-node fleet, whatever hosts/*.yml weigh now: thedemontuan.dev on n1 (primary,
// weight 30) and n2 (weight 70), lease mc-hub-api. index.mjs reads this same object per request.
config.nodes = { n1: { ...config.nodes.n1, weight: 30 }, n2: { ...config.nodes.n2, weight: 70 } };
for (const site of Object.values(config.sites)) site.nodes = site.nodes.filter((n) => n in config.nodes);
let calls, replies, cached, telegrams, queued, points, pending, env;
globalThis.caches = {
  default: {
    match: async (request) => cached.get(request.url)?.clone(),
    put: async (request, response) => void cached.set(request.url, new Response(await response.arrayBuffer(), response)),
  },
};
globalThis.fetch = async (request, init = {}) => {
  if (!init.cf) {
    telegrams.push(JSON.parse(init.body).text);
    return new Response('{}');
  }
  const node = init.cf.resolveOverride.split('-origin.')[0];
  calls.push({ node, method: request.method, url: request.url, cf: init.cf, headers: request.headers });
  let reply = replies[node] ?? 200;
  if (typeof reply === 'function') reply = reply(request, init);
  if (reply instanceof Error) throw reply;
  if (reply instanceof Response || reply instanceof Promise) return reply;
  // A hung origin: no headers until the caller gives up.
  if (reply === 'hang') return new Promise((_, reject) => init.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError'))));
  return new Response(node, { status: reply });
};
const ctx = { waitUntil: (promise) => pending.push(promise) };
const settle = () => Promise.all(pending.splice(0));
const call = (path, init = {}, client = '203.0.113.9', host = 'thedemontuan.dev') =>
  worker.fetch(new Request(`https://${host}${path}`, { ...init, headers: { 'cf-connecting-ip': client, ...init.headers } }), env, ctx);
const ipAt = (i) => `10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}`;
const clientOn = (node) => {
  for (let i = 0; ; i++) if (pickOrder(['n1', 'n2'], ipAt(i))[0] === node) return ipAt(i);
};
const leaseCall = (node, body, key = 'node-key') =>
  call('/__edge/lease/mc-hub-api', { method: 'POST', body: JSON.stringify(body), headers: { authorization: `Bearer ${key}` } }, config.nodes[node].ip, 'api.thedemontuan.dev');
const publicJson = (body) => () => new Response(body, { headers: { 'cache-control': 'no-cache', 'content-type': 'application/json' } });

function durableObjects() {
  const objects = new Map();
  return {
    idFromName: (name) => name,
    get(id) {
      if (!objects.has(id)) {
        const data = new Map();
        const storage = { get: async (k) => structuredClone(data.get(k)), put: async (k, v) => void data.set(k, structuredClone(v)) };
        storage.transaction = async (fn) => fn(storage);
        objects.set(id, new Lease({ storage }, env));
      }
      const object = objects.get(id);
      return { fetch: (url, init) => object.fetch(new Request(url, init)) };
    },
  };
}

beforeEach(() => {
  calls = [];
  replies = {};
  cached = new Map();
  telegrams = [];
  queued = [];
  points = [];
  pending = [];
  _test.downUntil.clear();
  _test.leases.clear();
  _test.timing.ttfbMs = 3_000;
  env = {
    LEASE: durableObjects(),
    WRITES: { send: async (message) => void queued.push(structuredClone(message)) },
    METRICS: { writeDataPoint: (point) => points.push(point) },
    NODE_KEY: 'node-key',
    REPLAY_KEY: 'replay-key',
    TELEGRAM_TOKEN: 'bot',
    TELEGRAM_CHAT_ID: '1',
  };
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

test('writes, admin, sessions and downloads go to the writer; a write sets the sticky cookie', async () => {
  const post = await call('/api/comments', { method: 'POST', body: '{}' });
  assert.match(post.headers.get('set-cookie'), /^__Host-edge-primary=1; Max-Age=15;/);
  await call('/admin/posts');
  await call('/api/dl?f=x');
  await call('/', { headers: { cookie: 'a=1; __Host-mch_session=t' } });
  await call('/', { headers: { cookie: '__Host-edge-primary=1' } });
  assert.deepEqual(calls.map((c) => c.node), ['n1', 'n1', 'n1', 'n1', 'n1']);
  assert.deepEqual(points[0].blobs, ['thedemontuan.dev', 'n1', 'POST', 'origin']);
  assert.equal(points[0].doubles[0], 200);
});

test('a signed-in or sticky read moves to the other node while the writer fails, and back once it is up', async () => {
  replies.n1 = 502;
  const page = await call('/', { headers: { cookie: '__Host-mch_session=t' } }, clientOn('n1'));
  assert.equal(page.status, 200);
  assert.equal(await page.text(), 'n2');
  await call('/admin/posts', { headers: { cookie: '__Host-edge-primary=1' } });
  assert.deepEqual(calls.map((c) => c.node), ['n1', 'n2', 'n2']);
  assert.equal(cached.size, 0);
  _test.downUntil.clear();
  replies.n1 = 200;
  await call('/', { headers: { cookie: '__Host-mch_session=t' } });
  assert.equal(calls.at(-1).node, 'n1');
});

test('a 204 write (a view count) sets no sticky cookie, so the next read stays balanced', async () => {
  replies.n1 = () => new Response(null, { status: 204 });
  const view = await call('/api/posts/x/views', { method: 'POST', body: '{}' }, clientOn('n2'));
  assert.equal(view.status, 204);
  assert.equal(view.headers.get('set-cookie'), null);
  await call('/', {}, clientOn('n2'));
  assert.deepEqual(calls.map((c) => c.node), ['n1', 'n2']);
});

test('writes over a reader address budget are refused at the edge; reads, nodes, other addresses and a failing limiter pass', async () => {
  const counts = new Map();
  env.WRITE_LIMIT = { limit: async ({ key }) => ({ success: counts.set(key, (counts.get(key) ?? 0) + 1).get(key) <= 2 }) };
  const write = (client) => call('/api/feedback', { method: 'POST', body: '{}' }, client);
  assert.deepEqual([(await write()).status, (await write()).status], [200, 200]);
  const refused = await write();
  assert.equal(refused.status, 429);
  assert.equal(refused.headers.get('retry-after'), '60');
  assert.equal((await refused.json()).error.code, 'RATE_LIMITED');
  assert.equal(calls.length, 2);
  assert.deepEqual(points.at(-1).blobs, ['thedemontuan.dev', 'edge', 'POST', 'limited']);
  assert.equal((await call('/')).status, 200);
  assert.equal((await write('203.0.113.10')).status, 200);
  assert.equal((await write(config.nodes.n2.ip)).status, 200);
  env.WRITE_LIMIT = { limit: async () => { throw new Error('limiter down'); } };
  assert.equal((await write()).status, 200);
  assert.equal(calls.length, 6);
  assert.equal(counts.has(config.nodes.n2.ip), false);
});

test('only a node (or the cron, with the derived pin key) may pin a read; a pinned write still reaches the writer', async () => {
  await call('/healthz', { headers: { 'X-Edge-Node': 'n2' } }, config.nodes.n1.ip);
  await call('/api/comments', { method: 'POST', body: '{}', headers: { 'X-Edge-Node': 'n2' } }, config.nodes.n1.ip);
  await call('/healthz', { headers: { 'X-Edge-Node': 'n2' } }, clientOn('n1'));
  const pin = createHash('sha256').update('pin:node-key').digest('hex');
  await call('/healthz', { headers: { 'X-Edge-Node': 'n2', 'X-Edge-Pin': pin } }, clientOn('n1'));
  await call('/healthz', { headers: { 'X-Edge-Node': 'n2', 'X-Edge-Pin': 'node-key' } }, clientOn('n1'));
  assert.deepEqual(calls.map((c) => c.node), ['n2', 'n1', 'n1', 'n2', 'n1']);
  assert.equal(calls[3].headers.has('x-edge-pin'), false);
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

// A node that does not route the site yet answers Traefik's 503 (platform/edge/dynamic/zz-unrouted.yml).
test('when every other node fails, the one that only ran out of time for its headers is waited for', async () => {
  _test.timing.ttfbMs = 20;
  // n1 sends headers after 60 ms (a stalled tunnel), unless the caller gives up first.
  replies.n1 = (request, init) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => resolve(new Response('n1')), 60);
    init.signal?.addEventListener('abort', () => (clearTimeout(timer), reject(new DOMException('aborted', 'AbortError'))));
  });
  replies.n2 = 503;
  const response = await call('/ads.txt', {}, clientOn('n1'));
  assert.equal(await response.text(), 'n1');
  assert.deepEqual(calls.map((c) => c.node), ['n1', 'n2', 'n1']);
  // Nothing stalled: the last failure is the answer, nothing is tried twice.
  replies = { n1: 502, n2: 503 };
  calls = [];
  _test.downUntil.clear();
  assert.equal((await call('/ads.txt', {}, clientOn('n1'))).status, 503);
  assert.equal(calls.length, 2);
});

test('a primary_paths read (a download) waits for the writer past the header deadline; other reads move on', async () => {
  _test.timing.ttfbMs = 20;
  // Headers after 60 ms, unless the caller gives up first.
  replies.n1 = (request, init) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => resolve(new Response('n1')), 60);
    init.signal?.addEventListener('abort', () => (clearTimeout(timer), reject(new DOMException('aborted', 'AbortError'))));
  });
  assert.equal(await (await call('/api/dl?t=x')).text(), 'n1');
  assert.equal(_test.downUntil.has('n1'), false);
  assert.equal(await (await call('/', {}, clientOn('n1'))).text(), 'n2');
  assert.ok(_test.downUntil.get('n1') > Date.now());
});

test('public images come from the bucket with the API headers; others fall through', async () => {
  const id = 'a'.repeat(32);
  env.MEDIA = { get: async (key) => (key === `media/${id}.jpg` ? { body: 'jpg', size: 3 } : null) };
  const ok = await call(`/media/${id}.jpg`);
  assert.equal(ok.headers.get('cache-control'), 'public, max-age=31536000, immutable');
  assert.equal(ok.headers.get('etag'), `"${id}"`);
  assert.equal(await ok.text(), 'jpg');
  const fresh = await call(`/media/${id}.jpg`, { headers: { 'If-None-Match': `"${id}"` } });
  assert.equal(fresh.status, 304);
  await call(`/media/${'b'.repeat(32)}.jpg`);
  assert.equal(calls.length, 1);
});

test('a node takes the lease only with its key from its own address, and only once the writer stopped renewing', async () => {
  assert.equal((await leaseCall('n2', { op: 'promote' }, 'guess')).status, 404);
  assert.equal((await call('/__edge/lease/mc-hub-api', { method: 'POST', body: '{"op":"promote"}', headers: { authorization: 'Bearer node-key' } })).status, 404);
  assert.deepEqual(await (await leaseCall('n1', { op: 'beat' })).json(), { writer: 'n1', epoch: 0, version: 0, down: [], lapiGrant: true });
  const refused = await leaseCall('n2', { op: 'promote' });
  assert.equal(refused.status, 409);
  assert.equal((await refused.json()).writer, 'n1');
  assert.equal(telegrams.length, 0);

  const forced = await leaseCall('n2', { op: 'promote', force: true });
  assert.deepEqual(await forced.json(), { writer: 'n2', epoch: 1, version: 1, down: [], lapiGrant: false });
  assert.match(telegrams[0], /n2 is now the writer \(was n1, forced\)/);
  _test.leases.clear();
  await call('/api/comments', { method: 'POST', body: '{}' });
  await call('/admin/posts');
  assert.deepEqual(calls.map((c) => c.node), ['n2', 'n2']);
  // The old writer learns it from its next renewal and steps down.
  assert.equal((await (await leaseCall('n1', { op: 'beat' })).json()).writer, 'n2');
});

test("a reader's write is queued while the writer is down and replayed with a signed address", async () => {
  replies = { n1: 530 };
  const views = await call('/api/posts/a-post/views', { method: 'POST', body: '{"visitor":"x"}', headers: { 'content-type': 'application/json', origin: 'https://thedemontuan.dev' } });
  assert.equal(views.status, 202);
  assert.deepEqual(await views.json(), { queued: true });
  assert.equal(queued.length, 1);
  assert.deepEqual(queued[0].headers, { 'content-type': 'application/json' });
  assert.equal(queued[0].ip, '203.0.113.9');
  assert.equal(points[0].blobs[3], 'queued');

  // Not queued: comments and feedback (a captcha token and no dedupe), admin writes (their session
  // would not survive the replay), replays. The reader gets JSON the site shows, and keeps the text.
  for (const [path, headers] of [['/api/posts/a/comments', {}], ['/api/feedback', {}], ['/api/posts/a/comments', { cookie: '__Host-mch_session=t' }],
    ['/api/posts/a/views', { 'x-edge-replay': '1.2.3.4 1 ab' }]]) {
    const refused = await call(path, { method: 'POST', body: '{}', headers });
    assert.equal(refused.status, 503);
    assert.equal(refused.headers.get('retry-after'), '60');
    assert.equal((await refused.json()).error.code, 'WRITER_UNAVAILABLE');
  }
  assert.equal(points.at(-1).blobs[3], 'unavailable');
  // The API's own JSON errors pass (a fenced writer's READ_ONLY, a full push list).
  replies = { n1: () => Response.json({ error: { code: 'QUEUE_FULL' } }, { status: 503 }) };
  assert.equal((await (await call('/api/push/subscribe', { method: 'POST', body: '{}' })).json()).error.code, 'QUEUE_FULL');
  replies = { n1: new TypeError('connect') };
  assert.equal((await call('/api/feedback/7/vote', { method: 'POST', body: '{"vote":true}' })).status, 202);
  assert.equal(queued.length, 2);

  // Replay: still down, then throttled (Traefik counts every replay against the Worker's address),
  // then back.
  const outcomes = [];
  const batch = () => ({
    messages: queued.map((body) => ({ body, attempts: 1, ack: () => outcomes.push('ack'), retry: ({ delaySeconds }) => outcomes.push(delaySeconds) })),
  });
  replies = { n1: 502 };
  await worker.queue(batch(), env);
  replies = { n1: 429 };
  await worker.queue(batch(), env);
  assert.deepEqual(outcomes, [60, 60, 60, 60]);
  calls = [];
  replies = { n1: 201 };
  await worker.queue(batch(), env);
  assert.deepEqual(outcomes.slice(4), ['ack', 'ack']);
  const replay = calls[0];
  assert.equal(replay.url, 'https://thedemontuan.dev/api/posts/a-post/views');
  const [ip, at, mac] = replay.headers.get('x-edge-replay').split(' ');
  assert.equal(ip, '203.0.113.9');
  assert.equal(mac, createHmac('sha256', 'replay-key').update(`${ip} ${at}`).digest('hex'));
});

test('cacheable reads are served from the edge for ttl_seconds, stale when every node fails, and purged after a fanout', async () => {
  replies = { n1: publicJson('v1'), n2: publicJson('v1') };
  assert.equal(await (await call('/api/posts?limit=1')).text(), 'v1');
  await settle();
  const hit = await call('/api/posts?limit=1');
  assert.equal(hit.headers.get('x-edge-cache'), 'HIT');
  assert.equal(hit.headers.get('cache-control'), 'no-cache');
  assert.equal(await hit.text(), 'v1');
  assert.equal(calls.length, 1);

  // Expired: back to the nodes; when both fail, the stored copy.
  for (const response of cached.values()) response.headers.set('x-edge-stored', String(Date.now() - 31_000));
  replies = { n1: 503, n2: new TypeError('connect') };
  const stale = await call('/api/posts?limit=1');
  assert.equal(stale.headers.get('x-edge-cache'), 'STALE');
  assert.equal(await stale.text(), 'v1');

  // The admin's purge: after its fanout the lease's version moves and the old copy is not used.
  replies = { n1: publicJson('v2'), n2: publicJson('v2') };
  _test.downUntil.clear();
  config.rules['mc-hub'].fanout[0].delay_seconds = 0;
  try {
    await call('/admin/revalidate', { method: 'POST', body: '{}', headers: { cookie: '__Host-mch_session=t' } });
    await settle();
  } finally {
    config.rules['mc-hub'].fanout[0].delay_seconds = 8;
  }
  _test.leases.clear();
  assert.equal(await (await call('/api/posts?limit=1')).text(), 'v2');

  // Never stored: no cache headers, private, cookies; never looked up: other paths.
  replies = { n2: () => new Response('x', { headers: { 'cache-control': 'private' } }) };
  await call('/datapack/x/', {}, clientOn('n2'));
  replies = { n2: () => new Response('x') };
  await call('/datapack/y/', {}, clientOn('n2'));
  await settle();
  assert.deepEqual([...cached.keys()].map((k) => new URL(k).pathname), ['/api/posts', '/api/posts']);
});

test('hashed assets try the next node on 404 without marking it down, and only successes are cached', async () => {
  replies = { n2: 404 };
  const response = await call('/_astro/app.abc.js', {}, clientOn('n2'));
  assert.equal(await response.text(), 'n1');
  assert.deepEqual(calls.map((c) => c.node), ['n2', 'n1']);
  assert.deepEqual(calls[0].cf.cacheTtlByStatus, { '200-299': 31536000, '300-599': -1 });
  assert.equal(_test.downUntil.has('n2'), false);
  replies = { n1: 404, n2: 404 };
  assert.equal((await call('/_astro/gone.js')).status, 404);
});

test('the cron checks every node of each leased site and alerts after two failures and on recovery', async () => {
  replies = { n2: 502 };
  await worker.scheduled({}, env);
  assert.equal(telegrams.length, 0);
  await worker.scheduled({}, env);
  // The writer (n1) never renewed the lease here, so that is reported as well.
  assert.equal(telegrams.length, 1);
  assert.match(telegrams[0], /🔴 <b>n2 · thedemontuan.dev<\/b>: HTTP 502\. Readers are sent to the other nodes/);
  assert.match(telegrams[0], /🔴 <b>n2 · api.thedemontuan.dev<\/b>: HTTP 502/);
  assert.match(telegrams[0], /🔴 <b>Lease<\/b>: writer n1 has not renewed the lease/);
  assert.doesNotMatch(telegrams[0], /n1 · thedemontuan/);
  replies = {};
  await leaseCall('n1', { op: 'beat' });
  await worker.scheduled({}, env);
  assert.match(telegrams[1], /✅ <b>n2 · thedemontuan.dev<\/b>: back to normal, after \d+ min/);
  assert.match(telegrams[1], /✅ <b>Lease<\/b>: back to normal/);
});

test('a read answered 500 is retried on the next node without marking the first one down', async () => {
  replies = { n2: 500 };
  assert.equal(await (await call('/', {}, clientOn('n2'))).text(), 'n1');
  assert.equal(_test.downUntil.has('n2'), false);
  replies = { n1: 500, n2: 500 };
  assert.equal((await call('/')).status, 500);
});

test('clients start on another node while theirs fails its check, and a replica whose follower stopped is read last', async () => {
  const client = clientOn('n2');
  replies = { n2: 502 };
  await worker.scheduled({}, env);
  replies = {};
  calls = [];
  await call('/', {}, client);
  assert.deepEqual(calls.map((c) => c.node), ['n1']);
  await worker.scheduled({}, env);
  _test.leases.clear();
  calls = [];
  await call('/', {}, client);
  assert.deepEqual(calls.map((c) => c.node), ['n2']);
  const now = Math.floor(Date.now() / 1000);
  await leaseCall('n1', { op: 'beat', synced: now });
  assert.deepEqual((await (await leaseCall('n2', { op: 'beat', synced: now - 600 })).json()).down, ['n2']);
  assert.deepEqual((await (await leaseCall('n2', { op: 'beat', synced: now })).json()).down, []);
});

test('a writer failing three checks in a row hands the lease to a replica that was current, never to a stale one', async () => {
  const now = Math.floor(Date.now() / 1000);
  await leaseCall('n1', { op: 'beat', synced: now });
  await leaseCall('n2', { op: 'beat', synced: now - 600 });
  await worker.scheduled({}, env);
  replies = { n1: 502 };
  for (let i = 0; i < 3; i++) await worker.scheduled({}, env);
  assert.equal((await (await leaseCall('n2', { op: 'beat', synced: now })).json()).writer, 'n1');
  await worker.scheduled({}, env);
  const state = await (await leaseCall('n2', { op: 'beat', synced: now })).json();
  assert.deepEqual([state.writer, state.epoch, state.down], ['n2', 1, ['n1']]);
  assert.equal(state.lapiGrant, false); // old writer renewed moments before its health checks failed
  assert.ok(telegrams.some((t) => /n2 is now the writer \(was n1, failing 4 checks in a row\)/.test(t)));
  _test.leases.clear();
  calls = [];
  await call('/api/comments', { method: 'POST', body: '{}' });
  assert.deepEqual(calls.map((c) => c.node), ['n2']);
});

test('a writer that stops renewing hands the lease to the replica holding its data, never to one too far behind', async () => {
  const real = Date.now;
  let offset = 0;
  Date.now = () => real() + offset;
  const beat = async (node, txid) => (await leaseCall(node, { op: 'beat', synced: Math.floor(Date.now() / 1000), txid })).json();
  try {
    await beat('n1', '0000000000000100');
    await beat('n2', '00000000000000f0');
    await worker.scheduled({}, env);
    // n1 still answers its checks but no longer renews (its writer-lease fenced it after 150 s).
    offset = 181_000;
    await beat('n2', '00000000000000f0');
    await worker.scheduled({}, env);
    assert.equal((await beat('n2', '00000000000000f0')).writer, 'n1');
    assert.ok(telegrams.some((t) => /Needs a person<\/b>: writer n1 is down \(no lease renewal for 3 min\) and no replica may take over/.test(t)));
    // Within PROMOTE_LAG_TXIDS of what n1 last reported.
    await beat('n2', '00000000000000fc');
    await worker.scheduled({}, env);
    const state = await beat('n2', '00000000000000fc');
    assert.deepEqual([state.writer, state.epoch], ['n2', 1]);
    assert.equal(state.lapiGrant, true); // old writer's last grant has expired
    assert.ok(telegrams.some((t) => /n2 is now the writer \(was n1, no lease renewal for 3 min, 4 transactions behind its last report\)/.test(t)));
  } finally {
    Date.now = real;
  }
});

test('only a second durable copy is acknowledged and force cannot elect below that floor', async () => {
  const key = createHash('sha256').update('quorum:node-key').digest('hex');
  const floor = { epoch: 0, txid: '0000000000000042' };
  await leaseCall('n1', { op: 'beat' });
  assert.equal((await leaseCall('n2', { op: 'promote', force: true }, key)).status, 400);
  replies.n2 = (req) => new URL(req.url).pathname === '/api/_replication'
    ? new Response(null, { status: 204, headers: { 'X-Follower-Epoch': '0', 'X-Follower-Txid': floor.txid } })
    : new Response(null, { status: 200 });
  const receipt = await leaseCall('n1', { op: 'confirm', ...floor }, key);
  assert.equal(receipt.status, 204);
  assert.equal((await leaseCall('n1', { op: 'confirm', epoch: 0, txid: '0000000000000040' }, key)).status, 204);
  assert.equal((await call('/api/posts/demo/views', { method: 'POST', body: '{}' })).status, 503);
  assert.equal(queued.length, 0);
  for (const position of [null, { ...floor, txid: '0000000000000040' }, { ...floor, epoch: 1 }]) {
    const refused = await leaseCall('n2', { op: 'promote', force: true, position });
    assert.equal(refused.status, 409);
    assert.deepEqual((await refused.json()).floor, floor);
  }
  const next = await leaseCall('n2', { op: 'promote', force: true, position: floor });
  assert.equal(next.status, 200);
  assert.equal((await next.json()).writer, 'n2');
  assert.equal((await leaseCall('n1', { op: 'confirm', ...floor }, key)).status, 409);
});

test('a writer without a durable follower cannot confirm', async () => {
  const key = createHash('sha256').update('quorum:node-key').digest('hex');
  const confirmation = await leaseCall('n1', { op: 'confirm', epoch: 0, txid: '0000000000000042' }, key);
  assert.equal(confirmation.status, 503);
  assert.equal((await (await leaseCall('n1', { op: 'beat' })).json()).floor, undefined);
}, { timeout: 6000 });
