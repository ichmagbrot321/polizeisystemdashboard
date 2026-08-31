// api/bot.js
//
// Generischer Proxy zwischen dem Dashboard-Frontend und der Bot-HTTP-API.
// Liest die signierte Session-Cookie (gesetzt von api/callback.js), prüft sie,
// und leitet Anfragen anhand des "resource"-Parameters an den passenden Pfad
// der Bot-API weiter — inklusive automatischem Einfügen von actor_id aus der
// Session (der Client kann sich NICHT als jemand anderes ausgeben).
//
// "me", "guilds" und "logout" werden direkt aus der Session beantwortet, ohne
// den Bot zu kontaktieren.
//
// Neue Ressourcen hinzufügen: einfach einen neuen Eintrag in RESOURCE_MAP
// ergänzen — an dieser Datei muss sonst nichts geändert werden.
//
// Benötigte Umgebungsvariablen (dieselben wie in api/callback.js):
//   SESSION_SECRET, BOT_API_URL, BOT_API_KEY

const crypto = require('crypto');

// Muss mit BOT_ENTWICKLER_ID / BOT_OWNER_ID / admin_lock.ADMIN_USER_ID im Bot übereinstimmen.
const ADMIN_USER_ID = '1523178659182284954';

// ---------------------------------------------------------------------------
// Session verifizieren (Gegenstück zu sign() in api/callback.js)
// ---------------------------------------------------------------------------

function verifySession(cookieValue) {
  if (!cookieValue) return null;
  const parts = cookieValue.split('.');
  if (parts.length !== 2) return null;
  const [data, sig] = parts;
  let expected;
  try {
    expected = crypto.createHmac('sha256', process.env.SESSION_SECRET).update(data).digest('base64url');
  } catch {
    return null;
  }
  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expected);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) return null;
  let payload;
  try {
    payload = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (!payload.exp || Date.now() > payload.exp) return null;
  return payload;
}

function parseCookies(header) {
  const out = {};
  (header || '').split(';').forEach((part) => {
    const idx = part.indexOf('=');
    if (idx === -1) return;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    if (key) out[key] = decodeURIComponent(val);
  });
  return out;
}

// ---------------------------------------------------------------------------
// Ressourcen-Zuordnung: resource-Name -> { method?, global?, path(guild, target, query) }
// method fehlt = die HTTP-Methode der eingehenden Anfrage wird 1:1 durchgereicht
// (für Ressourcen, die sowohl GET als auch POST unterstützen, z. B. config).
// global: true = Ressource ist NICHT an einen Server gebunden (Support-Fälle,
// Admin-Sperrsystem) und nur für ADMIN_USER_ID sichtbar.
// ---------------------------------------------------------------------------

const RESOURCE_MAP = {
  // -- Pro-Server-Ressourcen (dashboard_api.py, DashboardAPI-Cog) --
  schema: { method: 'GET', path: (g) => `/api/guilds/${g}/schema` },
  config: { path: (g) => `/api/guilds/${g}/config` },
  channels: { method: 'GET', path: (g) => `/api/guilds/${g}/channels` },
  roles: { method: 'GET', path: (g) => `/api/guilds/${g}/roles` },
  stats: { method: 'GET', path: (g) => `/api/guilds/${g}/stats` },
  bewerbungsfragen: { path: (g) => `/api/guilds/${g}/bewerbungsfragen` },
  personalakten: { method: 'GET', path: (g) => `/api/guilds/${g}/personalakten` },
  personalakte: { method: 'GET', path: (g, t) => `/api/guilds/${g}/personalakte/${t}` },
  personalakte_kuendigen: { method: 'POST', path: (g, t) => `/api/guilds/${g}/personalakte/${t}/kuendigen` },
  personalakte_verwarnen: { method: 'POST', path: (g, t) => `/api/guilds/${g}/personalakte/${t}/verwarnen` },
  personalakte_suspendieren: { method: 'POST', path: (g, t) => `/api/guilds/${g}/personalakte/${t}/suspendieren` },
  personalakte_suspendierung_aufheben: {
    method: 'POST',
    path: (g, t) => `/api/guilds/${g}/personalakte/${t}/suspendierung-aufheben`,
  },
  personalakte_widerruf: { method: 'POST', path: (g, t) => `/api/guilds/${g}/personalakte/${t}/widerruf` },
  personalakte_loeschen: { method: 'POST', path: (g, t) => `/api/guilds/${g}/personalakte/${t}/loeschen` },
  buergerakten: { path: (g) => `/api/guilds/${g}/buergerakten` },
  buergerakte: { method: 'GET', path: (g, _t, q) => `/api/guilds/${g}/buergerakte/${q.roblox_id}` },

  // -- Globale, nur für ADMIN_USER_ID sichtbare Ressourcen --
  support_cases: { method: 'GET', global: true, path: () => `/api/support/cases` },
  support_case_status: { method: 'POST', global: true, path: (_g, t) => `/api/support/cases/${t}/status` },
  admin_guilds: { method: 'GET', global: true, path: () => `/api/admin/guilds` },
  admin_lock: { method: 'POST', global: true, path: (_g, t) => `/api/admin/guilds/${t}/lock` },
  admin_unlock: { method: 'POST', global: true, path: (_g, t) => `/api/admin/guilds/${t}/unlock` },
  admin_unlock_owner: { method: 'POST', global: true, path: (_g, t) => `/api/admin/owners/${t}/unlock` },
};

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

function sendJson(res, status, obj) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(obj));
}

module.exports = async (req, res) => {
  const url = new URL(req.url, `https://${req.headers.host}`);
  const resource = url.searchParams.get('resource');
  const cookies = parseCookies(req.headers.cookie);
  const session = verifySession(cookies.dash_session);

  // -- Lokal beantwortete Ressourcen (kein Bot-Kontakt nötig) --
  if (resource === 'me') {
    if (!session) return sendJson(res, 401, { error: 'Nicht eingeloggt' });
    return sendJson(res, 200, { user: session.u });
  }
  if (resource === 'guilds') {
    if (!session) return sendJson(res, 401, { error: 'Nicht eingeloggt' });
    return sendJson(res, 200, { managed: session.g, unmanaged: session.un });
  }
  if (resource === 'logout') {
    res.setHeader('Set-Cookie', 'dash_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
    return sendJson(res, 200, { ok: true });
  }

  if (!session) return sendJson(res, 401, { error: 'Nicht eingeloggt' });
  if (!resource) return sendJson(res, 400, { error: "Parameter 'resource' fehlt" });

  const mapping = RESOURCE_MAP[resource];
  if (!mapping) return sendJson(res, 404, { error: `Unbekannte Ressource: ${resource}` });

  if (mapping.global) {
    if (session.u.id !== ADMIN_USER_ID) return sendJson(res, 403, { error: 'Keine Berechtigung' });
  } else {
    const guild = url.searchParams.get('guild');
    if (!guild) return sendJson(res, 400, { error: "Parameter 'guild' fehlt" });
    const hatZugriff = Array.isArray(session.g) && session.g.some((g) => g.id === guild);
    // Der Bot-Owner darf auf jeden Server zugreifen (spiegelt ist_bot_owner() im Bot).
    if (!hatZugriff && session.u.id !== ADMIN_USER_ID) {
      return sendJson(res, 403, { error: 'Kein Zugriff auf diesen Server' });
    }
  }

  const guild = url.searchParams.get('guild');
  const target = url.searchParams.get('target');
  const query = Object.fromEntries(url.searchParams);
  const method = mapping.method || req.method;

  let botPath;
  try {
    botPath = mapping.path(guild, target, query);
  } catch (err) {
    return sendJson(res, 400, { error: `Ungültige Parameter für '${resource}': ${err.message}` });
  }

  // Zusätzliche Query-Parameter (z. B. 'search') unverändert durchreichen —
  // resource/guild/target sind reine Routing-Parameter des Proxys.
  const extra = new URLSearchParams();
  for (const [key, value] of url.searchParams) {
    if (['resource', 'guild', 'target'].includes(key)) continue;
    extra.set(key, value);
  }
  const qs = extra.toString();
  const fullPath = qs ? `${botPath}?${qs}` : botPath;

  if (!process.env.BOT_API_URL) {
    return sendJson(res, 500, { error: 'BOT_API_URL ist auf dem Server nicht gesetzt.' });
  }

  let body;
  if (method === 'POST') {
    let raw = '';
    for await (const chunk of req) raw += chunk;
    let parsed = {};
    if (raw) {
      try {
        parsed = JSON.parse(raw);
      } catch {
        return sendJson(res, 400, { error: 'Ungültiger JSON-Body' });
      }
    }
    // actor_id kommt IMMER aus der geprüften Session, nie vom Client — verhindert Spoofing.
    parsed.actor_id = session.u.id;
    body = JSON.stringify(parsed);
  }

  let botRes;
  try {
    botRes = await fetch(`${process.env.BOT_API_URL}${fullPath}`, {
      method,
      headers: {
        'X-API-Key': process.env.BOT_API_KEY || '',
        ...(body ? { 'Content-Type': 'application/json' } : {}),
      },
      body,
    });
  } catch (err) {
    return sendJson(res, 502, {
      error: `Bot-API unter ${process.env.BOT_API_URL}${fullPath} nicht erreichbar (${err.cause?.code || err.message}).`,
    });
  }

  const text = await botRes.text();
  res.statusCode = botRes.status;
  res.setHeader('Content-Type', 'application/json');
  res.end(text);
};
