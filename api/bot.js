// api/bot.js
//
// Einziger Endpunkt zwischen dem Dashboard (Browser) und der Bot-API auf
// Infynix. Prüft bei jeder Anfrage das Session-Cookie und ob der User für
// den angefragten Server überhaupt "Server verwalten"-Rechte hat, bevor
// irgendwas an den Bot weitergereicht wird — der Bot-API-Key bleibt dabei
// immer server-seitig und wird nie an den Browser ausgeliefert.
//
// Aufruf vom Frontend:
//   GET  /api/bot?resource=me
//   GET  /api/bot?resource=logout
//   GET  /api/bot?resource=guilds
//   GET  /api/bot?resource=schema&guild=ID
//   GET  /api/bot?resource=config&guild=ID
//   GET  /api/bot?resource=channels&guild=ID
//   GET  /api/bot?resource=roles&guild=ID
//   GET  /api/bot?resource=stats&guild=ID
//   POST /api/bot?resource=config&guild=ID   Body: {"key": "...", "value": ...}
//
// Benötigte Umgebungsvariablen auf Vercel:
//   SESSION_SECRET   -> derselbe Wert wie in api/callback.js
//   BOT_API_URL      -> z. B. http://server.infynix.de:40002
//   BOT_API_KEY      -> derselbe Wert wie DASHBOARD_API_KEY auf dem Bot-Host

const crypto = require('crypto');

const ERLAUBTE_RESSOURCEN = ['schema', 'config', 'channels', 'roles', 'stats'];

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

async function readBody(req) {
  let raw = '';
  for await (const chunk of req) raw += chunk;
  return raw;
}

module.exports = async (req, res) => {
  res.setHeader('Content-Type', 'application/json');

  const url = new URL(req.url, `https://${req.headers.host}`);
  const resource = url.searchParams.get('resource');
  const guildId = url.searchParams.get('guild');
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
    const { status, body } = await botFetch('/api/guilds');
    if (status !== 200) {
      res.statusCode = status;
      res.end(JSON.stringify(body));
      return;
    }
    const erlaubteIds = new Set(session.g.map((g) => g.id));
    const gemeinsam = (body.guilds || []).filter((g) => erlaubteIds.has(g.id));
    res.statusCode = 200;
    res.end(JSON.stringify({ guilds: gemeinsam }));
    return;
  }

  if (!guildId || !session.g.some((g) => g.id === guildId)) {
    res.statusCode = 403;
    res.end(JSON.stringify({ error: 'Kein Zugriff auf diesen Server' }));
    return;
  }

  if (!ERLAUBTE_RESSOURCEN.includes(resource)) {
    res.statusCode = 400;
    res.end(JSON.stringify({ error: 'Unbekannte Ressource' }));
    return;
  }

  if (req.method === 'POST' && resource === 'config') {
    const raw = await readBody(req);
    const { status, body } = await botFetch(`/api/guilds/${guildId}/config`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: raw,
    });
    res.statusCode = status;
    res.end(JSON.stringify(body));
    return;
  }

  const { status, body } = await botFetch(`/api/guilds/${guildId}/${resource}`);
  res.statusCode = status;
  res.end(JSON.stringify(body));
};
