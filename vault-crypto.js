'use strict';

const VaultCrypto = (() => {
  const te = new TextEncoder(), td = new TextDecoder();
  const AAD = te.encode('vault-v2');

  const b64 = (buf) => { let s = ''; for (const x of new Uint8Array(buf)) s += String.fromCharCode(x); return btoa(s); };
  const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

  async function derive(password, saltB64, iter) {
    if (!(iter >= 600000)) iter = 600000;
    const base = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: unb64(saltB64), iterations: iter }, base, 512));
    const auth = b64(bits.slice(0, 32));
    const key = await crypto.subtle.importKey('raw', bits.slice(32), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    bits.fill(0);
    return { auth, key };
  }

  async function encrypt(obj, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: AAD }, key, te.encode(JSON.stringify(obj)));
    return { v: 2, iv: b64(iv), ct: b64(ct) };
  }

  async function decrypt(vault, key) {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(vault.iv), additionalData: AAD }, key, unb64(vault.ct));
    return JSON.parse(td.decode(pt));
  }

  const newSalt = () => b64(crypto.getRandomValues(new Uint8Array(16)));

  async function solvePow(challenge, bits, onProgress) {
    const full = bits >> 3, rest = bits & 7, mask = rest ? (0xff << (8 - rest)) & 0xff : 0;
    const ok = (h) => { for (let i = 0; i < full; i++) if (h[i] !== 0) return false; return !rest || (h[full] & mask) === 0; };
    const BATCH = 512;
    for (let start = 0; start < 1e8; start += BATCH) {
      const jobs = [];
      for (let n = start; n < start + BATCH; n++) jobs.push(crypto.subtle.digest('SHA-256', te.encode(`${challenge}:${n}`)));
      const res = await Promise.all(jobs);
      for (let i = 0; i < res.length; i++) if (ok(new Uint8Array(res[i]))) return String(start + i);
      if (onProgress && start % 8192 === 0) onProgress(start);
    }
    throw new Error('pow');
  }

  return Object.freeze({ derive, encrypt, decrypt, newSalt, solvePow });
})();
