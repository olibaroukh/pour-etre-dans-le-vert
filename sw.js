// Service Worker minimal — sert uniquement à permettre au navigateur de détecter
// une nouvelle version du fichier pour_etre_dans_le_vert.html et à proposer un
// rechargement propre. Ne met rien en cache pour offline (volontairement) afin
// de toujours servir la dernière version disponible sur le réseau.
// (Même principe que sw.js sur bilan-passage / observations-terrain.)

const SW_VERSION = '2026.07.18-1';

self.addEventListener('install', (event) => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

// Laisse passer toutes les requêtes réseau normalement (pas de cache offline)
self.addEventListener('fetch', (event) => {
  event.respondWith(fetch(event.request));
});
