import assert from 'node:assert/strict';
import { mkdtemp, mkdir, copyFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { test } from 'node:test';

const sha = 'a'.repeat(40);

async function loadWrapper(kind, runtime) {
  const directory = await mkdtemp(join(tmpdir(), 'uptimeflare-wrapper-'));
  await mkdir(join(directory, 'runtime'));
  await writeFile(join(directory, 'package.json'), '{"type":"module"}');
  await writeFile(join(directory, 'runtime', kind === 'monitor' ? 'index.js' : 'worker.js'), runtime);
  await copyFile(new URL(`../uptimeflare-${kind}.mjs`, import.meta.url), join(directory, 'entry.mjs'));
  const module = await import(pathToFileURL(join(directory, 'entry.mjs')).href);
  return { module, dispose: () => rm(directory, { recursive: true, force: true }) };
}

test('monitor identity is no-store and missing identity fails closed', async () => {
  const loaded = await loadWrapper('monitor', 'export class RemoteChecker {}\nexport default { scheduled() { return "cron"; } };');
  try {
    const response = await loaded.module.default.fetch(new Request('https://monitor/__release'), { RELEASE_SHA: sha });
    assert.equal(response.status, 200);
    assert.equal(await response.text(), sha + '\n');
    assert.equal(response.headers.get('Cache-Control'), 'no-store');
    assert.equal((await loaded.module.default.fetch(new Request('https://monitor/__release'), {})).status, 503);
    assert.equal((await loaded.module.default.fetch(new Request('https://monitor/not-release'), {})).status, 404);
  } finally { await loaded.dispose(); }
});

test('web release checks use a fixed internal monitor target and reject malformed identity', async () => {
  const loaded = await loadWrapper('web', 'export class DOQueueHandler {}\nexport default { fetch() { return new Response("OpenNext HTML"); } };');
  try {
    let target;
    const env = { RELEASE_SHA: sha, MONITOR_WORKER: { async fetch(url) { target = url; return new Response(sha + '\n'); } } };
    const monitor = await loaded.module.default.fetch(new Request('https://status.tuannguyenviet.site/__monitor_release?target=https://evil.example'), env);
    assert.equal(target, 'https://monitor.internal/__release');
    assert.equal(await monitor.text(), sha + '\n');
    assert.equal(monitor.headers.get('Cache-Control'), 'no-store');
    const release = await loaded.module.default.fetch(new Request('https://status.tuannguyenviet.site/__release'), env);
    assert.equal(await release.text(), sha + '\n');
    env.MONITOR_WORKER.fetch = async () => new Response('<html>challenge</html>');
    assert.equal((await loaded.module.default.fetch(new Request('https://status.tuannguyenviet.site/__monitor_release'), env)).status, 503);
  } finally { await loaded.dispose(); }
});
