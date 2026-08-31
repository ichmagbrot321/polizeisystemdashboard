// api/roblox.js
//
// Proxy + Cache für die öffentliche Roblox-API. Wird vom Dashboard für die
// Bürgerakten-Suche (Live-Namenssuche) und für Avatar-Fotos genutzt.
//
// Warum ein eigener Proxy statt direktem Browser-Fetch:
//   1. Roblox erlaubt keine CORS-Anfragen direkt aus dem Browser.
//   2. Bei schnellem Tippen (z. B. "h", "hu", "hun", "hund", ...) würden sonst
//      viele parallele Anfragen an Roblox gehen -> Rate-Limit (429), genau das
//      Problem "muss dann schauen und will weitermachen geht nicht".
//
// Robustheit hier:
//   - In-Memory-Cache mit TTL (überlebt nur innerhalb einer warmen Lambda-
//     Instanz, aber genau das federt Tippschübe ab).
//   - In-Flight-Deduplizierung: gleiche Anfrage, die noch läuft, wird nicht
//     zweimal an Roblox geschickt, sondern das gleiche Promise wird geteilt.
//   - Retry mit Backoff bei 429/5xx (max. 2 Versuche).
//   - Client (index.html) bricht außerdem alte Anfragen per AbortController ab,
//     wenn währenddessen weitergetippt wird — das reduziert die Last zusätzlich.
//
// Kein API-Key nötig, da öffentliche Roblox-Endpunkte verwendet werden.

const SEARCH_TTL_MS = 5 * 60 * 1000; // 5 Minuten
const AVATAR_TTL_MS = 30 * 60 * 1000; // 30 Minuten

const cache = new Map(); // key -> { data, expires }
const inFlight = new Map(); // key -> Promise

function getCached(key) {
  const hit = cache.get(key);
  if (!hit) return undefined;
  if (Date.now() > hit.expires) {
    cache.delete(key);
    return undefined;
  }
  return hit.data;
}
function setCached(key, data, ttl) {
  cache.set(key, { data, expires: Date.now() + ttl });
  // simple Bounded-Cache, damit der Speicher nicht unbegrenzt wächst
  if (cache.size > 2000) {
    const oldestKey = cache.keys().next().value;
    cache.delete(oldestKey);
  }
}

async function fetchWithRetry(url, opts = {}, retries = 2) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    let res;
    try {
      res = await fetch(url, opts);
    } catch (err) {
      if (attempt === retries) throw err;
      await new Promise((r) => setTimeout(r, 300 * Math.pow(3, attempt)));
      continue;
    }
    if (res.status === 429 || res.status >= 500) {
      if (attempt === retries) return res;
      const retryAfter = Number(res.headers.get('retry-after')) * 1000 || 300 * Math.pow(3, attempt);
      await new Promise((r) => setTimeout(r, retryAfter));
      continue;
    }
    return res;
  }
}

// Dedupliziert gleichzeitige identische Anfragen (z. B. mehrere schnelle
// Tastenanschläge, die trotz Client-Debounce kurz überlappen).
async function dedup(key, fn) {
  if (inFlight.has(key)) return inFlight.get(key);
  const p = fn().finally(() => inFlight.delete(key));
  inFlight.set(key, p);
  return p;
}

function sendJson(res, status, obj) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(obj));
}

module.exports = async (req, res) => {
  const url = new URL(req.url, `https://${req.headers.host}`);
  const action = url.searchParams.get('action');

  try {
    if (action === 'search') {
      const q = (url.searchParams.get('q') || '').trim();
      if (q.length < 3) return sendJson(res, 200, { users: [] }); // Roblox verlangt min. 3 Zeichen
      const cacheKey = `search:${q.toLowerCase()}`;
      const cached = getCached(cacheKey);
      if (cached) return sendJson(res, 200, { users: cached, cached: true });

      const users = await dedup(cacheKey, async () => {
        const r = await fetchWithRetry(
          `https://users.roblox.com/v1/users/search?keyword=${encodeURIComponent(q)}&limit=10`
        );
        if (!r || !r.ok) return [];
        const data = await r.json().catch(() => ({ data: [] }));
        return (data.data || []).map((u) => ({
          id: u.id,
          name: u.name,
          displayName: u.displayName,
        }));
      });
      setCached(cacheKey, users, SEARCH_TTL_MS);
      return sendJson(res, 200, { users });
    }

    if (action === 'avatar') {
      const idsParam = url.searchParams.get('ids') || url.searchParams.get('id');
      if (!idsParam) return sendJson(res, 400, { error: "Parameter 'ids' fehlt" });
      const ids = idsParam.split(',').map((s) => s.trim()).filter(Boolean).slice(0, 25);

      const result = {};
      const missing = [];
      for (const id of ids) {
        const c = getCached(`avatar:${id}`);
        if (c) result[id] = c;
        else missing.push(id);
      }
      if (missing.length > 0) {
        const fetched = await dedup(`avatar-batch:${missing.join(',')}`, async () => {
          const r = await fetchWithRetry(
            `https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${missing.join(',')}&size=150x150&format=Png&isCircular=false`
          );
          if (!r || !r.ok) return {};
          const data = await r.json().catch(() => ({ data: [] }));
          const map = {};
          for (const item of data.data || []) {
            map[item.targetId] = item.state === 'Completed' ? item.imageUrl : null;
          }
          return map;
        });
        for (const id of missing) {
          const val = fetched[id] ?? null;
          setCached(`avatar:${id}`, val, AVATAR_TTL_MS);
          result[id] = val;
        }
      }
      return sendJson(res, 200, { avatars: result });
    }

    if (action === 'profile') {
      const id = url.searchParams.get('id');
      if (!id) return sendJson(res, 400, { error: "Parameter 'id' fehlt" });
      const cacheKey = `profile:${id}`;
      const cached = getCached(cacheKey);
      if (cached) return sendJson(res, 200, cached);
      const profile = await dedup(cacheKey, async () => {
        const r = await fetchWithRetry(`https://users.roblox.com/v1/users/${id}`);
        if (!r || !r.ok) return null;
        const data = await r.json().catch(() => null);
        if (!data) return null;
        return { id: data.id, name: data.name, displayName: data.displayName, created: data.created };
      });
      if (!profile) return sendJson(res, 404, { error: 'Roblox-Nutzer nicht gefunden' });
      setCached(cacheKey, profile, AVATAR_TTL_MS);
      return sendJson(res, 200, profile);
    }

    return sendJson(res, 400, { error: "Unbekannte oder fehlende 'action'" });
  } catch (err) {
    return sendJson(res, 502, { error: `Roblox-API-Fehler: ${err.message}` });
  }
};
