// CT Campeador TEST - notificaciones Push aisladas de la web oficial.
const TEST_BASE = 'https://ligasdetenis.github.io/ct-campeador-pruebas/';
const PROD_BASE = 'https://ligasdetenis.github.io/ct-campeador-liga/';

function testDestination(value) {
  try {
    const supplied = new URL(value || TEST_BASE, TEST_BASE);
    const test = new URL(TEST_BASE);
    const prod = new URL(PROD_BASE);
    if (supplied.origin !== test.origin) return TEST_BASE;

    // Preservar parámetros de la notificación sin abrir nunca producción.
    if (supplied.pathname.startsWith(prod.pathname)) {
      const suffix = supplied.pathname.slice(prod.pathname.length);
      return TEST_BASE + suffix + supplied.search + supplied.hash;
    }
    if (supplied.pathname.startsWith(test.pathname)) return supplied.toString();
    return TEST_BASE;
  } catch (_) {
    return TEST_BASE;
  }
}

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', event => event.waitUntil(clients.claim()));

self.addEventListener('push', event => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (_) {
    data = { body: event.data ? event.data.text() : '' };
  }
  const title = data.title || 'CT Campeador TEST';
  const options = {
    body: data.body || 'Tienes un nuevo aviso de la liga de pruebas.',
    icon: data.icon || 'apple-touch-icon.png',
    badge: data.badge || 'apple-touch-icon.png',
    tag: data.tag || 'ct-campeador-test',
    renotify: true,
    data: { url: testDestination(data.url) }
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  const target = testDestination(event.notification?.data?.url);
  event.waitUntil((async () => {
    const list = await clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const client of list) {
      if (!client.url || !client.url.startsWith(TEST_BASE)) continue;
      try { client.postMessage({ type: 'PUSH_DEEP_LINK', url: target }); } catch (_) {}
      if ('focus' in client) {
        try { await client.focus(); } catch (_) {}
      }
      return;
    }
    if (clients.openWindow) await clients.openWindow(target);
  })());
});
