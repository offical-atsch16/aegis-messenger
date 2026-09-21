// Service Worker for AegisChat PWA Web Push Notifications & Calls

self.addEventListener('install', (event) => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

// Push Notification Handler
self.addEventListener('push', (event) => {
  let data = {};
  if (event.data) {
    try {
      data = event.data.json();
    } catch (e) {
      data = { title: 'AegisChat', body: event.data.text() };
    }
  }

  const notificationType = data.type || 'message';
  let title = data.title || 'AegisChat';
  let body = data.body || 'Neue verschlüsselte Nachricht erhalten';
  let options = {
    body: body,
    icon: '/favicon.svg',
    badge: '/favicon.svg',
    data: data
  };

  if (notificationType === 'call') {
    title = data.title || 'AegisChat Call';
    body = data.body || 'Eingehender verschlüsselter Anruf...';
    options.body = body;
    options.vibrate = [300, 100, 300, 100, 300, 100, 300];
    options.requireInteraction = true;
    options.tag = 'aegis-call';
    options.renotify = true;
  } else if (notificationType === 'contact') {
    title = data.title || 'AegisChat';
    body = data.body || 'Neuer Kontakt hat sich verbunden';
    options.body = body;
    options.vibrate = [100, 50, 100];
    options.tag = 'aegis-contact';
  } else {
    // Standard message
    options.vibrate = [100, 50, 100];
    options.tag = 'aegis-message';
  }

  event.waitUntil(
    self.registration.showNotification(title, options)
  );
});

// Notification Click Handler
self.addEventListener('notificationclick', (event) => {
  event.notification.close();

  const urlToOpen = new URL('/', self.location.origin).href;

  const promiseChain = self.clients.matchAll({
    type: 'window',
    includeUncontrolled: true
  }).then((windowClients) => {
    for (let i = 0; i < windowClients.length; i++) {
      const client = windowClients[i];
      if (client.url === urlToOpen && 'focus' in client) {
        return client.focus();
      }
    }
    if (self.clients.openWindow) {
      return self.clients.openWindow(urlToOpen);
    }
  });

  event.waitUntil(promiseChain);
});
