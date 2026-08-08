// api/bot.js
//
// Einziger Endpunkt zwischen dem Dashboard (Browser) und der Bot-API auf
// Infynix. Prüft bei jeder Anfrage das Session-Cookie und die Zugriffsstufe
// (Admin/Staff/Dienstaufsicht/Beamter) des Users für den angefragten Server,
// bevor irgendwas an den Bot weitergereicht wird — der Bot-API-Key bleibt
// dabei immer server-seitig. Bei schreibenden Aktionen (Kündigen, Widerruf,
// Löschen, Bürgerakte anlegen) wird die handelnde Person (actor_id) immer
// aus dem verifizierten Cookie genommen, nie aus dem was der Browser schickt.
//
// Aufruf vom Frontend, u. a.:
//   GET  /api/bot?resource=me
//   GET  /api/bot?resource=logout
//   GET  /api/bot?resource=guilds
//   GET  /api/bot?resource=schema|config|channels|roles|stats&guild=ID        (nur Admin)
//   POST /api/bot?resource=config&guild=ID              Body: {key, value}    (nur Admin)
//   GET  /api/bot?resource=bewerbungsfragen&guild=ID                          (nur Admin)
//   POST /api/bot?resource=bewerbungsfragen&guild=ID     Body: {art, fragen}  (nur Admin)
//   GET  /api/bot?resource=personalakten&guild=ID                            (Admin/Staff)
//   GET  /api/bot?resource=personalakte&guild=ID&target=UID   (Admin/Staff, sonst nur eigene Akte)
//   POST /api/bot?resource=personalakte_kuendigen&guild=ID&target=UID  Body: {grund, kategorie} (Admin/Staff)
//   POST /api/bot?resource=personalakte_widerruf&guild=ID&target=UID  Body: {aktenzeichen}       (Dienstaufsicht)
//   POST /api/bot?resource=personalakte_loeschen&guild=ID&target=UID  Body: {aktenzeichen}        (Dienstaufsicht)
//   GET  /api/bot?resource=buergerakten&guild=ID&search=NAME                  (jede Zugriffsstufe)
//   GET  /api/bot?resource=buergerakte&guild=ID&roblox_id=ID                  (jede Zugriffsstufe)
//   POST /api/bot?resource=buergerakten&guild=ID   Body: {roblox_name, text}  (jede Zugriffsstufe)
//
// Benötigte Umgebungsvariablen auf Vercel:
//   SESSION_SECRET   -> derselbe Wert wie in api/callback.js
//   BOT_API_URL      -> z. B. http://server.infynix.de:40002
//   BOT_API_KEY      -> derselbe Wert wie DASHBOARD_API_KEY auf dem Bot-Host

const crypto = require('crypto');

// resource -> nötige Mindest-Zugriffsstufe(n). 'any' = jede der vier Stufen reicht.
const RESSOURCEN_RECHTE = {
  schema: ['admin'],
  config: ['admin'],
  channels: ['admin'],
  roles: ['admin'],
  stats: ['admin'],
  bewerbungsfragen: ['admin'],
  personalakten: ['admin', 'staff'],
  personalakte: ['admin', 'staff', 'officer'], // 'officer' wird unten auf die eigene Akte eingeschränkt
  personalakte_kuendigen: ['admin', 'staff'],
  personalakte_widerruf: ['dienstaufsicht'],
  personalakte_loeschen: ['dienstaufsicht'],
  buergerakten: ['admin', 'staff', 'dienstaufsicht', 'officer'],
  buergerakte: ['admin', 'staff', 'dienstaufsicht', 'officer'],
};

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach((teil) => {
    const idx = teil.indexOf('=');
    if (idx === -1) return;
    out[teil.slice(0, idx).trim()] = decodeURIComponent(teil.slice(idx + 1).trim());
  });
  return out;
}

function verify(cookieValue) {
  if (!cookieValue) return null;
  const punkt = cookieValue.lastIndexOf('.');
  if (punkt === -1) return null;
  const data = cookieValue.slice(0, punkt);
  const sig = cookieValue.slice(punkt + 1);
  const erwartet = crypto
    .createHmac('sha256', process.env.SESSION_SECRET)
    .update(data)
    .digest('base64url');
  if (
    erwartet.length !== sig.length ||
    !crypto.timingSafeEqual(Buffer.from(erwartet), Buffer.from(sig))
  ) {
    return null;
  }
  try {
    const session = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
    if (!session.exp || session.exp < Date.now()) return null;
    return session;
  } catch {
    return null;
  }
}

async function botFetch(path, options = {}) {
  const res = await fetch(`${process.env.BOT_API_URL}${path}`, {
    ...options,
    headers: { ...(options.headers || {}), 'X-API-Key': process.env.BOT_API_KEY },
  });
  const body = await res.json().catch(() => ({ error: 'Ungültige Antwort vom Bot' }));
  return { status: res.status, body };
}

async function readJsonBody(req) {
  // Vercel parst JSON-Bodies bei Node-Functions bereits automatisch nach req.body.
  // Den rohen Stream hier nochmal zu lesen liefert nichts mehr (schon konsumiert) —
  // das war die Ursache der 400-Fehler beim Speichern.
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string' && req.body.length > 0) {
    try {
      return JSON.parse(req.body);
    } catch {
      return {};
    }
  }
  let raw = '';
  for await (const chunk of req) raw += chunk;
  try {
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

function hatZugriff(guildSession, erlaubteStufen) {
  return erlaubteStufen.some((stufe) => guildSession[stufe] === true);
}

module.exports = async (req, res) => {
  res.setHeader('Content-Type', 'application/json');

  const url = new URL(req.url, `https://${req.headers.host}`);
  const resource = url.searchParams.get('resource');
  const guildId = url.searchParams.get('guild');
  const target = url.searchParams.get('target');
  const session = verify(parseCookies(req).dash_session);

  if (resource === 'logout') {
    res.setHeader(
      'Set-Cookie',
      'dash_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'
    );
    res.statusCode = 200;
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  if (!session) {
    res.statusCode = 401;
    res.end(JSON.stringify({ error: 'Nicht angemeldet' }));
    return;
  }

  if (resource === 'me') {
    res.statusCode = 200;
    res.end(JSON.stringify({ loggedIn: true, user: session.u, guilds: session.g }));
    return;
  }

  if (resource === 'guilds') {
    res.statusCode = 200;
    res.end(JSON.stringify({ managed: session.g, unmanaged: session.un || [] }));
    return;
  }

  const guildSession = guildId ? session.g.find((g) => g.id === guildId) : null;
  if (!guildSession) {
    res.statusCode = 403;
    res.end(JSON.stringify({ error: 'Kein Zugriff auf diesen Server' }));
    return;
  }

  const erlaubteStufen = RESSOURCEN_RECHTE[resource];
  if (!erlaubteStufen) {
    res.statusCode = 400;
    res.end(JSON.stringify({ error: 'Unbekannte Ressource' }));
    return;
  }
  if (!hatZugriff(guildSession, erlaubteStufen)) {
    res.statusCode = 403;
    res.end(JSON.stringify({ error: 'Keine ausreichende Berechtigung für diese Ansicht' }));
    return;
  }

  // Reine "Beamter"-Stufe darf bei Personalakten nur die eigene Akte sehen.
  if (
    resource === 'personalakte' &&
    !guildSession.admin &&
    !guildSession.staff &&
    target !== session.u.id
  ) {
    res.statusCode = 403;
    res.end(JSON.stringify({ error: 'Du kannst nur deine eigene Personalakte einsehen' }));
    return;
  }

  // ---- Lesende Ressourcen -------------------------------------------------
  if (req.method === 'GET') {
    let pfad;
    if (resource === 'personalakte') pfad = `/api/guilds/${guildId}/personalakte/${target}`;
    else if (resource === 'buergerakte') pfad = `/api/guilds/${guildId}/buergerakte/${url.searchParams.get('roblox_id')}`;
    else if (resource === 'buergerakten') {
      const search = url.searchParams.get('search');
      pfad = `/api/guilds/${guildId}/buergerakten${search ? `?search=${encodeURIComponent(search)}` : ''}`;
    } else pfad = `/api/guilds/${guildId}/${resource}`;

    const { status, body } = await botFetch(pfad);
    res.statusCode = status;
    res.end(JSON.stringify(body));
    return;
  }

  // ---- Schreibende Ressourcen (POST) --------------------------------------
  const eingabe = await readJsonBody(req);

  if (resource === 'config' || resource === 'bewerbungsfragen') {
    const { status, body } = await botFetch(`/api/guilds/${guildId}/${resource}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(eingabe),
    });
    res.statusCode = status;
    res.end(JSON.stringify(body));
    return;
  }

  if (resource === 'personalakte_kuendigen' || resource === 'personalakte_widerruf' || resource === 'personalakte_loeschen') {
    if (!target) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: 'target fehlt' }));
      return;
    }
    const aktion = resource.replace('personalakte_', '');
    const { status, body } = await botFetch(`/api/guilds/${guildId}/personalakte/${target}/${aktion}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...eingabe, actor_id: session.u.id }),
    });
    res.statusCode = status;
    res.end(JSON.stringify(body));
    return;
  }

  if (resource === 'buergerakten') {
    const { status, body } = await botFetch(`/api/guilds/${guildId}/buergerakten`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...eingabe, actor_id: session.u.id }),
    });
    res.statusCode = status;
    res.end(JSON.stringify(body));
    return;
  }

  res.statusCode = 400;
  res.end(JSON.stringify({ error: 'Diese Ressource unterstützt kein POST' }));
};
