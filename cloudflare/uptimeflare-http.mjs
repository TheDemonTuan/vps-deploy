import { chromium } from 'playwright';

const origin = 'https://status.tuannguyenviet.site';
const limit = 8 * 1024 * 1024;
const [webSha = '', monitorSha = ''] = process.argv.slice(2);
if ([webSha, monitorSha].some(value => value && !/^[0-9a-f]{40}$/.test(value))) {
  throw new Error('Invalid public release identity');
}
const browser = await chromium.launch({ headless: true });
let stage = 'navigation';
try {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.route('**/*', route => {
    const url = new URL(route.request().url());
    return url.origin === origin ? route.continue() : route.abort();
  });
  const home = await page.goto(origin + '/', { waitUntil: 'domcontentloaded', timeout: 30_000 });
  if (!home || home.status() !== 200 || home.url() !== origin + '/') {
    throw new Error('Public browser navigation did not return the fixed status page');
  }
  stage = 'read-html';
  const html = await home.body();
  if (html.byteLength > limit) throw new Error('Public HTML exceeds size limit');
  const result = {
    '/': { status: home.status(), headers: home.headers(), body: html.toString('base64') },
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
      return { status: response.status, headers: Object.fromEntries(response.headers), body: btoa(binary) };
    }, { path, limit });
  }
  process.stdout.write(JSON.stringify(result));
} catch (error) {
  const network = /net::([A-Z_]+)/.exec(String(error))?.[1] || 'unclassified';
  process.stderr.write(`Actual Chromium public readiness failed at ${stage} (${network}); no response bodies or credentials logged.\n`);
  process.exitCode = 1;
} finally {
  await browser.close();
}
