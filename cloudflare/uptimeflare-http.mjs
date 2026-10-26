import { chromium } from 'playwright';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const origin = 'https://status.tuannguyenviet.site';
const limit = 8 * 1024 * 1024;
let browser;
let stage = 'request';
let failureCode = 'unclassified';
let edgeEvidence = '';
try {
  let input = '';
  for await (const chunk of process.stdin) {
    input += chunk.toString('utf8');
    if (Buffer.byteLength(input) > 2048) throw new Error('Probe request exceeds size limit');
  }
  const request = JSON.parse(input);
  if (!request || Array.isArray(request) || Object.keys(request).sort().join(',') !== 'monitor_sha,web_sha') throw new Error('Invalid probe request');
  const { web_sha: webSha, monitor_sha: monitorSha } = request;
  if ([webSha, monitorSha].some(value => typeof value !== 'string' || (value !== '' && !/^[0-9a-f]{40}$/.test(value)))) throw new Error('Invalid public release identity');
  stage = 'launch';
  browser = await chromium.launch({ headless: true, executablePath: '/usr/bin/chromium-browser', chromiumSandbox: true, args: ['--disable-dev-shm-usage'] });
  stage = 'navigation';
  const context = await browser.newContext({ serviceWorkers: 'block' });
  await context.routeWebSocket('**/*', socket => socket.close());
  await context.route('**/*', route => {
    const url = new URL(route.request().url());
    return url.origin === origin && route.request().method() === 'GET' ? route.continue() : route.abort();
  });
  const page = await context.newPage();
  const home = await page.goto(origin + '/', { waitUntil: 'domcontentloaded', timeout: 30_000 });
  if (!home || home.status() !== 200 || home.url() !== origin + '/') {
    failureCode = home ? 'HTTP_' + home.status() : 'NO_RESPONSE';
    if (home) {
      const headers = home.headers();
      const ray = /^[a-f0-9]{16}(?:-[A-Z]{3})?$/.test(headers['cf-ray'] || '') ? headers['cf-ray'] : 'unavailable';
      const mitigation = headers['cf-mitigated'] === 'challenge' ? 'challenge' : 'none';
      // Match an explicit provider error label, never arbitrary digits in application HTML.
      const body = await home.text();
      const code = body.length <= limit ? /(?:error code:\s*|Error\s+)(1\d{3})\b/i.exec(body)?.[1] : undefined;
      edgeEvidence = `; edge ray=${ray} mitigation=${mitigation} error=${code || 'unavailable'}`;
    }
    throw new Error('Public browser navigation did not return the fixed status page');
  }
  stage = 'read-html';
  const html = await home.body();
  if (html.byteLength > limit) throw new Error('Public HTML exceeds size limit');
  const result = {
    '/': { status: home.status(), headers: Object.fromEntries(Object.entries(home.headers()).filter(([name]) => ['content-type', 'cache-control'].includes(name))), body: html.toString('base64') },
  };
  stage = 'enumerate-resources';
  const resources = await page.evaluate(() => Array.from(document.querySelectorAll('script[src],link[rel="stylesheet"][href]'), node => node.getAttribute(node.tagName === 'SCRIPT' ? 'src' : 'href')).filter(path => path.startsWith('/_next/static/')));
  const paths = new Set(['/api/data', ...resources]);
  if (webSha) paths.add('/__release?smoke=' + webSha);
  if (monitorSha) paths.add('/__monitor_release?smoke=' + monitorSha);
  for (const path of paths) {
    stage = 'validate-resource';
    const url = new URL(path, origin);
    if (url.origin !== origin || (path !== '/api/data' && !path.startsWith('/__release?smoke=') && !path.startsWith('/__monitor_release?smoke=') && !url.pathname.startsWith('/_next/static/'))) {
      throw new Error('Unexpected public readiness resource origin/path');
    }
    stage = 'fetch-resources';
    result[path] = await page.evaluate(async ({ path, limit }) => {
      const response = await fetch(path, { cache: 'no-store', redirect: 'error' });
      const bytes = new Uint8Array(await response.arrayBuffer());
      if (bytes.byteLength > limit) throw new Error('Public readiness response exceeds size limit');
      let binary = '';
      for (let start = 0; start < bytes.length; start += 32768) {
        binary += String.fromCharCode(...bytes.subarray(start, start + 32768));
      }
      return { status: response.status, headers: Object.fromEntries(['content-type', 'cache-control'].filter(name => response.headers.has(name)).map(name => [name, response.headers.get(name)])), body: btoa(binary) };
    }, { path, limit });
  }
  stage = 'serialize';
  const scriptSha256 = createHash('sha256').update(readFileSync(fileURLToPath(import.meta.url))).digest('hex');
  const evidence = JSON.stringify({ script_sha256: scriptSha256, responses: result });
  if (Buffer.byteLength(evidence) > 16 * 1024 * 1024) throw new Error('Probe evidence exceeds size limit');
  process.stdout.write(evidence);
} catch (error) {
  const network = /net::([A-Z_]+)/.exec(String(error))?.[1] || failureCode;
  process.stderr.write(`Actual Chromium public readiness failed at ${stage} (${network})${edgeEvidence}; no response bodies or credentials logged.\n`);
  process.exitCode = 1;
} finally {
  if (browser) await browser.close();
}
