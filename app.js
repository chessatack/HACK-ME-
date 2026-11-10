'use strict';
(() => {
  // Clickjacking-Schutz (GitHub Pages kann keine Sicherheits-Header senden)
  if (window.top !== window.self) {
    document.documentElement.hidden = true;
    try { window.top.location = window.self.location; } catch { /* blockiert */ }
    return;
  }

  // Mirror-Schutz: läuft die Seite auf einer fremden Adresse (Kopie), wird sie gesperrt
  // und der Besucher zur echten Seite geschickt.
  const HOME = (typeof SITE_CONFIG !== 'undefined' && /^https:\/\/[a-z0-9.-]+$/i.test(SITE_CONFIG.SITE) && !SITE_CONFIG.SITE.includes('deinname')) ? SITE_CONFIG.SITE : null;
  if (HOME && location.origin !== HOME && location.protocol !== 'file:' && !/^(localhost|127\.0\.0\.1)$/.test(location.hostname)) {
    document.documentElement.hidden = true;
    location.replace(HOME + location.pathname + location.hash);
    return;
  }

  const API = (typeof SITE_CONFIG !== 'undefined' && /^https:\/\/[a-z0-9.-]+\.supabase\.co\/functions\/v1\/[a-z0-9_-]+$/i.test(SITE_CONFIG.API) && !SITE_CONFIG.API.includes('DEIN-')) ? SITE_CONFIG.API : null;

  // Besuch melden (einmal pro Seitenaufruf). Server zählt + begrenzt Spam.
  function track() {
    if (!API || navigator.webdriver) return;
    fetch(API + '/hit', {
      method: 'POST', mode: 'cors', credentials: 'omit', keepalive: true, referrerPolicy: 'no-referrer',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        path: location.pathname + location.hash,
        ref: document.referrer ? new URL(document.referrer).origin : '',
        screen: `${screen.width}x${screen.height}`,
      }),
    }).then((r) => {
      if (r.status === 429) { const b = document.getElementById('limitBanner'); if (b) b.hidden = false; }
      if (r.status === 403) r.json().then((d) => { if (d && d.blocked) showBlocked(); }).catch(() => {});
    }).catch(() => {});
  }

  // Gesperrte Besucher: Inhalt ausblenden, nur Sperrhinweis zeigen
  function showBlocked() {
    document.querySelectorAll('body > *:not(.aurora):not(.grid-bg)').forEach((e) => { e.hidden = true; });
    const box = document.createElement('main'); box.className = 'login-wrap';
    const card = document.createElement('div'); card.className = 'card glow login';
    const h = document.createElement('h2'); h.textContent = '⛔ Zugang gesperrt';
    const p = document.createElement('p'); p.className = 'muted'; p.textContent = 'Dein Zugriff auf diese Seite wurde gesperrt.';
    card.append(h, p); box.append(card); document.body.append(box);
  }

  document.addEventListener('DOMContentLoaded', () => {
    const y = document.getElementById('year'); if (y) y.textContent = String(new Date().getFullYear());

    const net = document.getElementById('netStatus');
    const setNet = () => { if (net) net.textContent = navigator.onLine ? '' : '● Offline-Modus'; };
    addEventListener('online', setNet); addEventListener('offline', setNet); setNet();

    // Elemente beim Scrollen einblenden
    const io = 'IntersectionObserver' in window ? new IntersectionObserver((es) => es.forEach((e) => {
      if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); }
    }), { threshold: 0.12 }) : null;
    document.querySelectorAll('.reveal').forEach((el) => io ? io.observe(el) : el.classList.add('in'));

    // App-Installation
    let deferred = null;
    const btn = document.getElementById('installBtn');
    addEventListener('beforeinstallprompt', (e) => { e.preventDefault(); deferred = e; if (btn) btn.hidden = false; });
    btn?.addEventListener('click', async () => { if (!deferred) return; deferred.prompt(); await deferred.userChoice; deferred = null; btn.hidden = true; });

    track();
  });

  if ('serviceWorker' in navigator && location.protocol === 'https:') {
    addEventListener('load', () => navigator.serviceWorker.register('sw.js', { scope: './' }).catch(() => {}));
  }
})();
