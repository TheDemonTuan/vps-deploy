import assert from 'node:assert/strict';
import { mkdtemp, mkdir, copyFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';

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

test('failed browser navigation logs only allowlisted edge evidence and stays failed', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'uptimeflare-browser-'));
  try {
    await writeFile(join(directory, 'package.json'), '{"type":"module"}');
    await mkdir(join(directory, 'node_modules/playwright'), { recursive: true });
    await writeFile(join(directory, 'node_modules/playwright/package.json'), '{"type":"module","exports":"./index.js"}');
    await copyFile(new URL('../uptimeflare-http.mjs', import.meta.url), join(directory, 'entry.mjs'));
    for (const malicious of [false, true]) {
      const headers = malicious ? { 'cf-ray': 'private-cookie', 'cf-mitigated': 'private-token' } : { 'cf-ray': 'a505f19aab82fe01-SIN', 'cf-mitigated': 'challenge' };
      await writeFile(join(directory, 'node_modules/playwright/index.js'), `
        export const chromium = { async launch() { return {
          async close() {}, async newContext() { return { async newPage() { return {
            async route() {}, async goto() { return {
              status() { return 403; }, url() { return 'https://status.tuannguyenviet.site/'; },
              headers() { return ${JSON.stringify(headers)}; },
              async text() { return 'error code: 1010; private-response-body; secret=do-not-log'; }
            }; }
          }; } }; }
        }; } };
      `);
      const result = spawnSync(process.execPath, [join(directory, 'entry.mjs')], { encoding: 'utf8' });
      assert.equal(result.status, 1);
      assert.equal(result.stdout, '');
      assert.match(result.stderr, /failed at navigation \(HTTP_403\)/);
      assert.match(result.stderr, malicious ? /edge ray=unavailable mitigation=none error=1010/ : /edge ray=a505f19aab82fe01-SIN mitigation=challenge error=1010/);
      assert.doesNotMatch(result.stderr, /private-|do-not-log/);
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
});
