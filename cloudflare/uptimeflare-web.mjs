import web from './runtime/worker.js';
export * from './runtime/worker.js';

export default {
  ...web,
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method === 'GET' && url.pathname === '/__release') {
      if (!/^[0-9a-f]{40}$/.test(env.RELEASE_SHA || '')) return new Response(null, { status: 503 });
      return new Response(env.RELEASE_SHA + '\n', {
        headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' },
      });
    }
    if (request.method === 'GET' && url.pathname === '/__monitor_release') {
      const response = await env.MONITOR_WORKER.fetch('https://monitor.internal/__release');
      const release = await response.text();
      if (response.status !== 200 || !/^[0-9a-f]{40}\n$/.test(release)) return new Response(null, { status: 503 });
      return new Response(release, {
        headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' },
      });
    }
    return web.fetch(request, env, ctx);
  },
};
