'use strict';
(() => {
  if (window.top !== window.self) { document.documentElement.hidden = true; return; }

  const $ = (id) => document.getElementById(id);
  const API = (typeof SITE_CONFIG !== 'undefined' && /^https:\/\/[a-z0-9.-]+\.supabase\.co\/functions\/v1\/[a-z0-9_-]+$/i.test(SITE_CONFIG.API) && !SITE_CONFIG.API.includes('DEIN-')) ? SITE_CONFIG.API : null;
  const IDLE_MS = 10 * 60 * 1000;

  // Alles Sensible nur im Arbeitsspeicher – nie in localStorage/Cookies
  let S = null; // { token, key, salt, iter, data }
  let pick = null; // gewähltes Bild (ob richtig, weiß nur der Server)
  let idleAt = 0, tick = null;

  const msg = (el, text, kind) => { el.textContent = text; el.className = 'msg' + (kind ? ' ' + kind : ''); };
  const fmt = (ts) => new Date(ts).toLocaleString('de-DE', { dateStyle: 'short', timeStyle: 'medium' });
  const flag = (cc) => /^[A-Z]{2}$/.test(cc || '') ? String.fromCodePoint(...[...cc].map((c) => 0x1f1a5 + c.charCodeAt(0))) + ' ' + cc : (cc || '??');

  async function api(path, opts = {}) {
    const headers = { 'Content-Type': 'application/json' };
    if (S?.token) headers.Authorization = 'Bearer ' + S.token;
    const res = await fetch(API + path, {
      method: opts.method || 'GET', headers, mode: 'cors', credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer',
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
    let data = {}; try { data = await res.json(); } catch { /* leer */ }
    if (res.status === 401 && S) { lock('Sitzung abgelaufen. Bitte neu anmelden.'); throw new Error('session'); }
    return { status: res.status, ok: res.ok, data };
  }

  if (!API) msg($('loginMsg'), 'Backend nicht eingerichtet: Adresse in config.js eintragen.', 'warn');

  /* ======================= Schritt 1: Getränk wählen ======================= */
  // Bilder liegen NICHT auf GitHub, sondern geschützt in der Datenbank.
  // Der Server liefert sie nur an diese Seite (keine Direktlinks) – als Blob, ohne Dateiadresse.
  const blobs = new Map();
  async function loadImage(id) {
    if (blobs.has(id)) return blobs.get(id);
    const r = await fetch(API + '/media/' + id, { mode: 'cors', credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer' });
    if (!r.ok) throw new Error('img');
    const u = URL.createObjectURL(await r.blob()); blobs.set(id, u); return u;
  }
  async function loadGate() {
    const grid = $('pickGrid');
    if (!API) return;
    try {
      const g = await api('/gate');
      if (g.status === 403) return msg($('loginMsg'), '⛔ Zugang gesperrt.', 'err');
      if (!g.ok) return msg($('loginMsg'), 'Server nicht erreichbar.', 'err');
      const btns = await Promise.all(g.data.ids.map(async (id, i) => {
        const b = el('button', null, 'pick'); b.type = 'button'; b.dataset.id = id;
        const img = el('img'); img.alt = 'Getränk ' + (i + 1); img.draggable = false; img.width = 600; img.height = 600;
        img.src = await loadImage(id);
        b.append(img);
        b.addEventListener('click', () => {
          pick = id; $('pickedImg').src = img.src;
          $('stepPick').hidden = true; $('stepPw').hidden = false; msg($('loginMsg'), ''); $('pw').focus();
        });
        return b;
      }));
      grid.replaceChildren(...btns);
    } catch { msg($('loginMsg'), 'Bilder konnten nicht geladen werden.', 'err'); }
  }
  // Rechtsklick / Ziehen / langes Drücken auf geschützten Bildern verhindern
  document.addEventListener('contextmenu', (e) => { if (e.target.closest?.('.protect, .pick')) e.preventDefault(); });
  document.addEventListener('dragstart', (e) => { if (e.target.tagName === 'IMG') e.preventDefault(); });
  $('backBtn').addEventListener('click', () => { pick = null; $('stepPw').hidden = true; $('stepPick').hidden = false; msg($('loginMsg'), ''); });

  /* ======================= Falle ======================= */
  // Köder-Passwörter (z. B. aus zugang-backup.json) tragen eine versteckte Prüfsumme.
  // Wer so eins benutzt, hat die Falle geschluckt → Server sperrt dauerhaft.
  const BA = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  function isBait(pw) {
    if (pw.length < 9) return false;
    const body = pw.slice(0, -3);
    let h = 0x811c9dc5;
    for (const ch of 'sp' + body + 'zi') { h ^= ch.charCodeAt(0); h = Math.imul(h, 0x01000193) >>> 0; }
    let tag = '';
    for (let i = 0; i < 3; i++) { tag += BA[h % 57]; h = Math.floor(h / 57); }
    return pw.slice(-3) === tag;
  }

  /* ======================= Schritt 2: Passwort ======================= */
  $('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!API) return;
    const out = $('loginMsg'), btn = $('loginBtn'), bar = $('loginProgress');
    const pw = $('pw').value;
    if (!pw) return msg(out, 'Bitte Passwort eingeben.', 'err');
    if (!pick) return msg(out, 'Bitte zuerst ein Bild wählen.', 'err');

    btn.disabled = true; bar.hidden = false; msg(out, 'Sichere Verbindung wird aufgebaut …');
    try {
      const ch = await api('/challenge');
      if (ch.status === 429) return msg(out, `Gesperrt. Noch ${wait(ch.data.retry)}.`, 'err');
      if (!ch.ok) return msg(out, ch.data.error || 'Server nicht erreichbar.', 'err');

      msg(out, 'Bot-Prüfung & Schlüssel werden berechnet …');
      const [n, keys] = await Promise.all([
        VaultCrypto.solvePow(ch.data.c, ch.data.bits),
        VaultCrypto.derive(pw, ch.data.salt, ch.data.iter),
      ]);
      const r = await api('/login', { method: 'POST', body: { c: ch.data.c, n, auth: keys.auth, pick, bait: isBait(pw) } });

      if (r.status === 429) {
        pick = null; $('stepPw').hidden = true; $('stepPick').hidden = false; $('pickGrid').replaceChildren();
        return msg(out, `⛔ Gesperrt für ${wait(r.data.retry)}.`, 'err');
      }
      if (!r.ok) {
        pick = null; $('stepPw').hidden = true; $('stepPick').hidden = false;
        return msg(out, r.data.left != null ? `Bild oder Passwort falsch. Noch ${r.data.left} Versuch(e).` : (r.data.error || 'Fehler.'), 'err');
      }

      let data = { notes: [], updated: '' };
      if (r.data.vault) data = await VaultCrypto.decrypt(r.data.vault, keys.key);
      S = { token: r.data.token, key: keys.key, salt: ch.data.salt, iter: ch.data.iter, data: normalize(data) };
      msg(out, '');
      pick = null; $('stepPw').hidden = true; $('stepPick').hidden = false;
      $('doneImg').src = $('pickedImg').src;
      showSecret();
      $('loginView').hidden = true; $('doneView').hidden = false; // „Geschafft du Bubis!“
    } catch (err) {
      if (err.message !== 'session') msg(out, 'Verbindung fehlgeschlagen.', 'err');
    } finally {
      $('pw').value = ''; btn.disabled = false; bar.hidden = true;
    }
  });

  function wait(sec) {
    sec = Number(sec) || 0;
    if (sec > 365 * 86400) return 'immer (dauerhaft)';
    return sec >= 3600 ? `${Math.ceil(sec / 3600)} Std.` : sec >= 60 ? `${Math.ceil(sec / 60)} Min.` : `${sec} Sek.`;
  }
  function normalize(d) {
    const notes = Array.isArray(d?.notes) ? d.notes.map((x) => ({ title: String(x.title ?? ''), body: String(x.body ?? '') })) : [];
    return { notes, updated: String(d?.updated ?? ''), secret: String(d?.secret ?? '') };
  }

  // Geheimes Kennwort: steht nur verschlüsselt im Tresor, wird erst nach dem Entschlüsseln angezeigt
  function showSecret() {
    document.querySelectorAll('[data-secret]').forEach((e) => { e.textContent = S?.data.secret || '—'; });
  }

  /* ======================= Dashboard ======================= */
  $('enterBtn').addEventListener('click', () => { if (S) showAdmin(); });
  function showAdmin() {
    $('loginView').hidden = true; $('doneView').hidden = true; $('adminView').hidden = false;
    renderNotes(); loadData(); bump();
    tick = setInterval(() => {
      const left = idleAt - Date.now();
      if (left <= 0) return lock('Automatisch gesperrt (Inaktivität).');
      $('timer').textContent = `🔒 Sperre in ${Math.floor(left / 60000)}:${String(Math.floor(left / 1000) % 60).padStart(2, '0')}`;
    }, 1000);
  }

  async function lock(reason) {
    const t = S?.token;
    S = null; clearInterval(tick); $('timer').textContent = '';
    ['visitRows', 'attemptRows', 'notes', 'countries', 'devices', 'blocks'].forEach((id) => $(id).replaceChildren());
    document.querySelectorAll('[data-secret]').forEach((e) => { e.textContent = ''; });
    $('doneImg').removeAttribute('src');
    $('adminView').hidden = true; $('doneView').hidden = true; $('loginView').hidden = false;
    if (reason) msg($('loginMsg'), reason, 'warn');
    if (t) fetch(API + '/admin/logout', { method: 'POST', mode: 'cors', headers: { Authorization: 'Bearer ' + t }, keepalive: true }).catch(() => {});
  }

  function el(tag, text, cls) { const e = document.createElement(tag); if (text != null) e.textContent = String(text); if (cls) e.className = cls; return e; }
  function row(cells) { const tr = document.createElement('tr'); cells.forEach((c) => tr.append(c instanceof Node ? c : el('td', c))); return tr; }
  function td(text, cls, title) { const t = el('td', text, cls); if (title) t.title = title; return t; }

  async function loadData() {
    const r = await api('/admin/data');
    if (!r.ok) return;
    const d = r.data;
    $('sTotal').textContent = d.stats.total; $('sToday').textContent = d.stats.today; $('sUnique').textContent = d.stats.unique;
    $('sFails').textContent = d.attempts.filter((a) => !a.ok).length;

    bars($('countries'), d.countries.map((x) => [flag(x.country), x.n]));
    bars($('devices'), d.devices.map((x) => [x.device, x.n]));

    const isBlocked = new Set(d.blocks.map((b) => b.ipkey));
    const mark = (tr, key) => { if (key === d.me) tr.classList.add('me'); if (isBlocked.has(key)) tr.classList.add('blocked'); return tr; };

    $('visitRows').replaceChildren(...(d.visits.length ? d.visits.map((v) => mark(row([
      td(fmt(v.ts)), td(v.ip, 'ip'), td([flag(v.country), v.city, v.region].filter(Boolean).join(' · ')),
      td(v.device, '', v.ua), td(v.path), td(v.org), blockCell(v.ip, v.ipkey, d.me, isBlocked),
    ]), v.ipkey)) : [row([td('Noch keine Besuche', 'muted')])]));

    $('attemptRows').replaceChildren(...(d.attempts.length ? d.attempts.map((a) => mark(row([
      td(fmt(a.ts)), td(a.ok ? '✓ Erfolg' : '✗ ' + (a.detail || 'Falsch'), a.ok ? 'good' : 'bad'), td(a.ip, 'ip'),
      td([flag(a.country), a.city].filter(Boolean).join(' · ')), td(a.device), blockCell(a.ip, a.ipkey, d.me, isBlocked),
    ]), a.ipkey)) : [row([td('Keine Versuche', 'muted')])]));

    const b = $('blocks');
    if (!d.blocks.length) b.replaceChildren(el('span', 'Keine'));
    else b.replaceChildren(...d.blocks.map((x) => {
      const r = el('div', null, 'row space');
      const forever = x.until > Date.now() + 50 * 365 * 864e5;
      const info = el('div'); info.append(el('div', x.ipkey, 'mono'), el('small', `${x.reason || ''} · ${forever ? 'dauerhaft' : 'bis ' + fmt(x.until)}`, 'muted'));
      r.append(info);
      const u = el('button', 'Freigeben', 'btn sm'); u.type = 'button';
      u.addEventListener('click', async () => { await api('/admin/unblock', { method: 'POST', body: { ipkey: x.ipkey } }); loadData(); });
      r.append(u); return r;
    }));
  }

  function blockCell(ip, key, me, isBlocked) {
    const c = document.createElement('td');
    if (key === me || isBlocked.has(key)) return c;
    const b = el('button', '⛔ Sperren', 'btn sm danger'); b.type = 'button';
    b.addEventListener('click', () => doBlock(ip, 0));
    c.append(b); return c;
  }
  async function doBlock(ip, hours) {
    if (!confirm(`${ip} ${hours ? 'für ' + hours + ' Std.' : 'dauerhaft'} sperren?`)) return false;
    const r = await api('/admin/block', { method: 'POST', body: { ip, hours } });
    if (!r.ok) { alert(r.data.error || 'Fehler'); return false; }
    loadData(); return true;
  }
  $('blockForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const ip = $('blockIp').value.trim(), out = $('blockMsg');
    if (!ip) return msg(out, 'IP eingeben.', 'err');
    if (await doBlock(ip, Number($('blockDur').value))) { $('blockIp').value = ''; msg(out, '✓ Gesperrt', 'ok'); }
  });

  function bars(box, items) {
    const max = Math.max(1, ...items.map((i) => i[1]));
    box.replaceChildren(...(items.length ? items.map(([label, n]) => {
      const b = el('div', null, 'bar');
      const track = el('div', null, 'track'), fill = el('div', null, 'fill');
      fill.style.width = (n / max * 100).toFixed(1) + '%';
      track.append(fill); b.append(el('span', label), track, el('span', n)); return b;
    }) : [el('span', 'Noch keine Daten', 'muted')]));
  }

  /* ======================= Tabs ======================= */
  document.querySelectorAll('.tabs button').forEach((t) => t.addEventListener('click', () => {
    document.querySelectorAll('.tabs button').forEach((x) => x.setAttribute('aria-selected', String(x === t)));
    document.querySelectorAll('.tab').forEach((p) => { p.hidden = p.id !== t.dataset.tab; });
  }));
  $('refreshBtn').addEventListener('click', loadData);
  $('lockBtn').addEventListener('click', () => lock());

  /* ======================= Notizen ======================= */
  function renderNotes() {
    const box = $('notes'); box.replaceChildren();
    S.data.notes.forEach((n, i) => {
      const w = el('div', null, 'note');
      const t = el('input'); t.value = n.title; t.placeholder = 'Titel'; t.maxLength = 200; t.setAttribute('aria-label', 'Titel');
      t.addEventListener('input', () => { S.data.notes[i].title = t.value; dirty(); });
      const b = el('textarea'); b.value = n.body; b.placeholder = 'Inhalt'; b.maxLength = 20000; b.setAttribute('aria-label', 'Inhalt');
      b.addEventListener('input', () => { S.data.notes[i].body = b.value; dirty(); });
      const r = el('div', null, 'row end'); const d = el('button', 'Löschen', 'btn sm danger'); d.type = 'button';
      d.addEventListener('click', () => { if (confirm('Notiz löschen?')) { S.data.notes.splice(i, 1); renderNotes(); dirty(); } });
      r.append(d); w.append(t, b, r); box.append(w);
    });
    $('saveState').textContent = S.data.updated ? 'Gespeichert ' + fmt(S.data.updated) : '';
  }
  const dirty = () => { $('saveState').textContent = '● Ungespeichert'; };
  $('addNote').addEventListener('click', () => { S.data.notes.push({ title: '', body: '' }); renderNotes(); dirty(); });
  $('saveBtn').addEventListener('click', async (e) => {
    e.target.disabled = true;
    try {
      S.data.updated = new Date().toISOString();
      const vault = await VaultCrypto.encrypt(S.data, S.key);
      const r = await api('/admin/vault', { method: 'PUT', body: { vault } });
      $('saveState').textContent = r.ok ? '✓ Gespeichert ' + fmt(S.data.updated) : 'Fehler beim Speichern';
    } finally { e.target.disabled = false; }
  });

  /* ======================= Passwort ======================= */
  $('pwForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const out = $('pwMsg'), cur = $('curPw').value, a = $('newPw').value, b = $('newPw2').value;
    if (a.length < 16) return msg(out, 'Mindestens 16 Zeichen.', 'err');
    if (a !== b) return msg(out, 'Passwörter stimmen nicht überein.', 'err');
    msg(out, 'Schlüssel werden berechnet …');
    try {
      const old = await VaultCrypto.derive(cur, S.salt, S.iter);
      const salt = VaultCrypto.newSalt();
      const neu = await VaultCrypto.derive(a, salt, S.iter);
      const vault = await VaultCrypto.encrypt(S.data, neu.key);
      const r = await api('/admin/password', { method: 'POST', body: { current: old.auth, salt, auth: neu.auth, vault } });
      if (!r.ok) return msg(out, r.data.error || 'Fehler.', 'err');
      S.key = neu.key; S.salt = salt;
      msg(out, '✓ Passwort geändert. Andere Geräte wurden abgemeldet.', 'ok');
    } finally { $('curPw').value = ''; $('newPw').value = ''; $('newPw2').value = ''; }
  });

  $('clearVisits').addEventListener('click', async () => {
    if (!confirm('Besucher-Log wirklich komplett löschen?')) return;
    const r = await api('/admin/visits', { method: 'DELETE' });
    msg($('dataMsg'), r.ok ? '✓ Geleert' : 'Fehler', r.ok ? 'ok' : 'err'); loadData();
  });

  /* ======================= Auto-Sperre ======================= */
  function bump() { idleAt = Date.now() + IDLE_MS; }
  ['pointerdown', 'keydown', 'scroll'].forEach((ev) => addEventListener(ev, () => { if (S) bump(); }, { passive: true }));
  addEventListener('pagehide', () => { if (S) lock(); });
  if (API) loadGate();
})();
