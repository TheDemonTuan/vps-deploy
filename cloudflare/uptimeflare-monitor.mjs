import monitor from './runtime/index.js';
export * from './runtime/index.js';

export default {
  ...monitor,
  fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/__release' && request.method === 'GET') {
      if (!/^[0-9a-f]{40}$/.test(env.RELEASE_SHA || '')) return new Response(null, { status: 503 });
      return new Response(env.RELEASE_SHA + '\n', {
        headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' },
      });
    }
    return monitor.fetch ? monitor.fetch(request, env, ctx) : new Response(null, { status: 404 });
  },
};
