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
// NEU:
//   - Globale Security-/Admin-Ressourcen für Server-Sperre (bereits vorhanden),
//     zusätzlich User-Sperre, IP-Sperre und Support-Fall-Verwaltung — alle nur
//     für ADMIN_USER_ID sichtbar (siehe global:true unten).
//   - buergerakten/buergerakte reichen jetzt optionale Roblox-Felder
//     (roblox_user_id, roblox_avatar_url) durch, die vom Frontend über den
//     separaten /api/roblox-Proxy ermittelt wurden.
//   - Support-System auf DAUERHAFTE TICKETS umgestellt (statt Einweg-
//     "Fälle"): support_ticket_mine/create/message/close sind für JEDEN
//     eingeloggten Nutzer aufrufbar (anyUser) — ob jemand wirklich nur sein
//     eigenes Ticket sehen/schließen darf, prüft dashboard_api.py serverseitig
//     anhand von actor_id gegen ticket.ersteller_id (oder ADMIN_USER_ID).
//     support_tickets_all/reply/reopen bleiben admin-only (global), da nur
//     der Bot-Entwickler Tickets serverübergreifend bearbeitet.
//
// WICHTIG: Wer im Bot tatsächlich "Verwarnen/Suspendieren/Kündigen" darf
// (aktuell nur admin/staff), wird SERVERSEITIG im Bot geprüft, nicht hier.
// Dieser Proxy reicht nur durch. Um "normale Polizisten" dafür freizuschalten,
// muss die Berechtigung im Bot (dashboard_api.py-Cog, /api/guilds/.../personalakte/...)
// angepasst werden — das Frontend zeigt die Buttons bereits an, wenn
// access.is_officer_kann_handeln (oder eine ähnliche neue Flag) vom Bot kommt.
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
// Ressourcen-Zuordnung: resource-Name -> { method?, global?, anyUser?, path(guild, target, query) }
// method fehlt = die HTTP-Methode der eingehenden Anfrage wird 1:1 durchgereicht
// (für Ressourcen, die sowohl GET als auch POST unterstützen, z. B. config).
// global: true = Ressource ist NICHT an einen Server gebunden und nur für
//   ADMIN_USER_ID sichtbar (Support-Ticket-Verwaltung, Admin-Sperrsystem).
// anyUser: true = kein Guild-Zugriff nötig, aber jede gültige Session darf
//   die Ressource aufrufen (z. B. das eigene Support-Ticket).
// ---------------------------------------------------------------------------

const RESOURCE_MAP = {
  // -- Pro-Server-Ressourcen (dashboard_api.py, DashboardAPI-Cog) --
  schema: { method: 'GET', path: (g) => `/api/guilds/${g}/schema` },
  config: { path: (g) => `/api/guilds/${g}/config` },
  channels: { method: 'GET', path: (g) => `/api/guilds/${g}/channels` },
  roles: { method: 'GET', path: (g) => `/api/guilds/${g}/roles` },
  stats: { method: 'GET', path: (g) => `/api/guilds/${g}/stats` },
  bewerbungsfragen: { path: (g) => `/api/guilds/${g}/bewerbungsfragen` },
  officer_permission: { path: (g) => `/api/guilds/${g}/officer-permission` },
  modules: { path: (g) => `/api/guilds/${g}/modules` },
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
  admin_guilds: { method: 'GET', global: true, path: () => `/api/admin/guilds` },
  admin_lock: { method: 'POST', global: true, path: (_g, t) => `/api/admin/guilds/${t}/lock` },
  admin_unlock: { method: 'POST', global: true, path: (_g, t) => `/api/admin/guilds/${t}/unlock` },
  admin_unlock_owner: { method: 'POST', global: true, path: (_g, t) => `/api/admin/owners/${t}/unlock` },

  // -- NEU: dauerhaftes Support-Ticket-System (ersetzt die alten support_case_*
  //    "Einweg-Fälle") --
  // Für JEDEN eingeloggten Nutzer aufrufbar: eigenes Ticket abrufen/eröffnen/
  // beantworten/schließen. dashboard_api.py MUSS serverseitig sicherstellen,
  // dass "message"/"close" nur auf das eigene Ticket wirken (actor_id ==
  // ticket.ersteller_id) — sonst könnte jeder fremde Tickets schließen.
  support_ticket_mine: { method: 'GET', anyUser: true, path: () => `/api/support/tickets/mine` },
  support_ticket_unread: { method: 'GET', anyUser: true, path: () => `/api/support/tickets/unread` },
  support_ticket_create: { method: 'POST', anyUser: true, path: () => `/api/support/tickets` },
  support_ticket_message: { method: 'POST', anyUser: true, path: (_g, t) => `/api/support/tickets/${t}/messages` },
  support_ticket_close: { method: 'POST', anyUser: true, path: (_g, t) => `/api/support/tickets/${t}/close` },

  // Nur für ADMIN_USER_ID (den Bot-Entwickler): alle Tickets serverübergreifend
  // einsehen, beantworten und wieder öffnen.
  support_tickets_all: { method: 'GET', global: true, path: () => `/api/support/tickets` },
  support_tickets_unread_count: { method: 'GET', global: true, path: () => `/api/support/tickets/unread-count` },
  support_ticket_reply: { method: 'POST', global: true, path: (_g, t) => `/api/support/tickets/${t}/reply` },
  support_ticket_reopen: { method: 'POST', global: true, path: (_g, t) => `/api/support/tickets/${t}/reopen` },

  // -- User-/IP-Sperrsystem --
  security_locks: { method: 'GET', global: true, path: () => `/api/security/locks` },
  security_lock_user: { method: 'POST', global: true, path: (_g, t) => `/api/security/users/${t}/lock` },
  security_unlock_user: { method: 'POST', global: true, path: (_g, t) => `/api/security/users/${t}/unlock` },
  security_lock_ip: { method: 'POST', global: true, path: () => `/api/security/ip/lock` },
  security_unlock_ip: { method: 'POST', global: true, path: (_g, t) => `/api/security/ip/${t}/unlock` },
  security_seen: { method: 'GET', global: true, path: (_g, t) => `/api/security/seen/${t}` },

  // -- NEU: SENTINEL — Advanced Threat Detection System --
  sentinel_stats: { method: 'GET', global: true, path: () => `/api/sentinel/stats` },
  sentinel_threat_log: { method: 'GET', global: true, path: () => `/api/sentinel/threat-log` },
  sentinel_users: { method: 'GET', global: true, path: () => `/api/sentinel/users` },
  sentinel_ips: { method: 'GET', global: true, path: () => `/api/sentinel/ips` },
  sentinel_user_detail: { method: 'GET', global: true, path: (_g, t) => `/api/sentinel/user/${t}` },
  sentinel_add_flag: { method: 'POST', global: true, path: (_g, t) => `/api/sentinel/user/${t}/flag` },
  sentinel_user_unlock: { method: 'POST', global: true, path: (_g, t) => `/api/sentinel/user/${t}/unlock` },
  sentinel_ip_unlock: { method: 'POST', global: true, path: (_g, t) => `/api/sentinel/ip/${t}/unlock` },
  sentinel_get_captcha: { method: 'GET', global: true, path: (_g, t) => `/api/sentinel/captcha/${t}` },
  sentinel_verify_captcha: { method: 'POST', global: true, path: () => `/api/sentinel/captcha/verify` },
  sentinel_blacklist: { method: 'GET', global: true, path: () => `/api/sentinel/blacklist` },
  sentinel_whitelist: { method: 'GET', global: true, path: () => `/api/sentinel/whitelist` },
  sentinel_whitelist_add: { method: 'POST', global: true, path: () => `/api/sentinel/whitelist/add` },
  sentinel_whitelist_remove: { method: 'POST', global: true, path: () => `/api/sentinel/whitelist/remove` },

  // -- NEU: Dienstanweisungen --
  dienstanweisungen: { method: 'GET', path: (g) => `/api/guilds/${g}/dienstanweisungen` },
  dienstanweisung_erstellen: { method: 'POST', path: (g) => `/api/guilds/${g}/dienstanweisungen` },
  dienstanweisung_abrufen: { method: 'GET', path: (g, t) => `/api/guilds/${g}/dienstanweisungen/${t}` },
  dienstanweisung_bestaetigen: { method: 'POST', path: (g, t) => `/api/guilds/${g}/dienstanweisungen/${t}/bestaetigen` },
  dienstanweisung_loeschen: { method: 'DELETE', path: (g, t) => `/api/guilds/${g}/dienstanweisungen/${t}` },

  // -- NEU: Fahrzeuge --
  fahrzeuge: { method: 'GET', path: (g) => `/api/guilds/${g}/fahrzeuge` },
  fahrzeug_erstellen: { method: 'POST', path: (g) => `/api/guilds/${g}/fahrzeuge` },
  fahrzeug_abrufen: { method: 'GET', path: (g, t) => `/api/guilds/${g}/fahrzeuge/${t}` },
  fahrzeug_aktualisieren: { method: 'PUT', path: (g, t) => `/api/guilds/${g}/fahrzeuge/${t}` },
  fahrzeug_loeschen: { method: 'DELETE', path: (g, t) => `/api/guilds/${g}/fahrzeuge/${t}` },

  // -- NEU: Audit-Log --
  audit_logs: { method: 'GET', path: (g) => `/api/guilds/${g}/audit-logs` },

  // -- NEU: Krankmeldungen --
  krankenmeldungen: { method: 'GET', path: (g) => `/api/guilds/${g}/krankenmeldungen` },
  krankenmeldungen_meine: { method: 'GET', path: (g) => `/api/guilds/${g}/krankenmeldungen/meine` },
  krankenmeldung_erstellen: { method: 'POST', path: (g) => `/api/guilds/${g}/krankenmeldungen` },
  krankenmeldung_genehmigen: { method: 'POST', path: (g, t) => `/api/guilds/${g}/krankenmeldungen/${t}/genehmigen` },
  krankenmeldung_ablehnen: { method: 'POST', path: (g, t) => `/api/guilds/${g}/krankenmeldungen/${t}/ablehnen` },

  // -- NEU: Messenger --
  messenger_channels: { method: 'GET', path: (g) => `/api/guilds/${g}/messenger/channels` },
  messenger_channel_erstellen: { method: 'POST', path: (g) => `/api/guilds/${g}/messenger/channels` },
  messenger_nachrichten: { method: 'GET', anyUser: true, path: (_g, t) => `/api/messenger/channels/${t}/nachrichten` },
  messenger_nachricht_senden: { method: 'POST', anyUser: true, path: (_g, t) => `/api/messenger/channels/${t}/nachrichten` },
};

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

function sendJson(res, status, obj) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(obj));
}

function getClientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return fwd.split(',')[0].trim();
  return req.socket?.remoteAddress || 'unknown';
}

module.exports = async (req, res) => {
  const url = new URL(req.url, `https://${req.headers.host}`);
  const resource = url.searchParams.get('resource');
  const cookies = parseCookies(req.headers.cookie);
  const session = verifySession(cookies.dash_session);

  // -- Lokal beantwortete Ressourcen (kein Bot-Kontakt nötig) --
  if (resource === 'me') {
    if (!session) return sendJson(res, 401, { error: 'Nicht eingeloggt' });
    return sendJson(res, 200, { user: session.u, isAdmin: !!session.isAdmin });
  }
  if (resource === 'guilds') {
    if (!session) return sendJson(res, 401, { error: 'Nicht eingeloggt' });
    return sendJson(res, 200, { managed: session.g, unmanaged: session.un });
  }
  if (resource === 'logout') {
    res.setHeader('Set-Cookie', 'dash_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
    return sendJson(res, 200, { ok: true });
  }
  // Health-Check: Ping an den Bot, um zu prüfen ob er erreichbar ist.
  if (resource === 'health_check') {
    if (!session) return sendJson(res, 401, { error: 'Nicht eingeloggt' });
    if (!process.env.BOT_API_URL) return sendJson(res, 500, { ok: false, error: 'BOT_API_URL nicht gesetzt' });
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      const r = await fetch(`${process.env.BOT_API_URL}/api/health`, {
        headers: { 'X-API-Key': process.env.BOT_API_KEY || '' },
        signal: controller.signal,
      });
      clearTimeout(timeout);
      if (r.ok) return sendJson(res, 200, { ok: true });
      return sendJson(res, 200, { ok: false, status: r.status });
    } catch (err) {
      return sendJson(res, 200, { ok: false, error: err.message });
    }
  }

  if (!session) return sendJson(res, 401, { error: 'Nicht eingeloggt' });
  if (!resource) return sendJson(res, 400, { error: "Parameter 'resource' fehlt" });

  const mapping = RESOURCE_MAP[resource];
  if (!mapping) return sendJson(res, 404, { error: `Unbekannte Ressource: ${resource}` });

  if (mapping.global) {
    // Doppelte Prüfung mit Absicht: sowohl das Session-Flag (schnell) als auch
    // der direkte ID-Vergleich (falls eine alte Session noch kein isAdmin-Feld hat).
    if (session.u.id !== ADMIN_USER_ID) return sendJson(res, 403, { error: 'Keine Berechtigung' });
  } else if (mapping.anyUser) {
    // Kein Guild-Zugriff nötig, aber eine gültige Session ist bereits weiter
    // oben (if (!session) ...) sichergestellt.
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
  // Admin-/globale Ressourcen bekommen die aufrufende Discord-User-ID zusätzlich
  // als Query-Parameter mit — der Bot prüft das serverseitig NOCHMAL gegen
  // ADMIN_USER_ID (siehe _require_admin_actor in dashboard_api.py), damit ein
  // durchgesickerter API-Key allein nicht für Admin-Aktionen reicht. Bei GET-
  // Anfragen gibt es keinen Body, deshalb hier als Query-Parameter.
  if (mapping.global) {
    extra.set('requester_id', session.u.id);
  }
  // Ebenso bei "anyUser"-Ressourcen: der Bot muss wissen, WER die Anfrage
  // stellt, um z. B. "nur mein eigenes Ticket" durchzusetzen — auch bei GET,
  // wo es (anders als bei POST) keinen Body mit actor_id gibt.
  if (mapping.anyUser) {
    extra.set('actor_id', session.u.id);
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
    // Bei Sperr-Aktionen die tatsächliche Anfrager-IP mitschicken (nicht vom
    // Client fälschbar), damit z. B. "security_lock_ip" ohne manuelle Eingabe
    // aus dem Support-Fall heraus funktioniert, wenn keine IP übergeben wurde.
    if (resource.startsWith('security_') && !parsed.ip) {
      parsed.request_ip = getClientIp(req);
    }
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
