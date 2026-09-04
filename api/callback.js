// api/callback.js
//
// Discord leitet den Browser nach dem Login hierher um: /api/callback?code=...
// Diese Funktion tauscht den Code gegen ein Access-Token, holt den
// eingeloggten User, seine Discord-Server UND (für jeden Server, auf dem der
// Bot schon ist) seine Zugriffsstufe im Polizei-System (Admin / Staff /
// Dienstaufsicht / Beamter, rollenbasiert über die Bot-API). Nur Server, wo
// mindestens eine dieser Stufen zutrifft, landen im Dashboard. Das Ergebnis
// wird in einem signierten, httpOnly-Cookie gespeichert.
//
// NEU (Sicherheits-Layer):
//   - Erfasst die Client-IP und prüft sie + die Discord-User-ID gegen eine
//     globale Sperrliste im Bot, BEVOR die Session ausgestellt wird.
//   - Markiert die Session mit einem Best-Effort-VPN/Proxy-Hinweis (nur ein
//     Signal für den Admin-Bereich, kein hartes Blocken — siehe Hinweis unten).
//   - Speichert die IP in der Session, damit beim Sperren eines Users im
//     Admin-Bereich automatisch auch dessen zuletzt bekannte IP mitgesperrt
//     werden kann (deckt "gleiches Netzwerk/WLAN" ab, da dort ohnehin dieselbe
//     öffentliche IP genutzt wird — NAT).
//
// Ehrlicher Hinweis zu VPN-Erkennung: Es gibt KEINE Methode, die eine Sperre
// zu 100% gegen jede Art von VPN/Proxy immun macht. Die Proxy/Hosting-Flags
// von IP-Intelligence-Diensten sind Heuristiken (Datenbank bekannter
// Rechenzentrums-/VPN-IP-Bereiche) und können sowohl False Positives
// (z. B. manche Firmen-/Mobilfunknetze) als auch False Negatives (neue,
// unbekannte residential-Proxies) haben. Deshalb wird der VPN-Hinweis hier nur
// als Warn-Badge im Admin-Bereich angezeigt, nicht automatisch als Blockgrund
// verwendet. Die eigentliche, verlässliche Sperre ist die User-ID-Sperre
// (Discord-Login lässt sich nicht faken) plus die IP-Sperre als Zusatzschicht.
//
// Benötigte Umgebungsvariablen auf Vercel:
//   DISCORD_CLIENT_ID
//   DISCORD_CLIENT_SECRET
//   DISCORD_REDIRECT_URI   -> exakt https://DEINE-DOMAIN.vercel.app/api/callback
//   SESSION_SECRET         -> ein langer zufälliger String, frei erfunden
//   BOT_API_URL, BOT_API_KEY

const crypto = require('crypto');

const MANAGE_GUILD = 0x20;
const ADMINISTRATOR = 0x8;

// Muss mit ADMIN_USER_ID in api/bot.js übereinstimmen.
const ADMIN_USER_ID = '1523178659182284954';

// Timeout für Aufrufe an den Bot-Host — ohne das hängt die Funktion bis zum
// Vercel-Timeout, wenn der Host nicht antwortet (statt schnell zu scheitern).
const BOT_FETCH_TIMEOUT_MS = 8000;
// Timeout für die IP-Intelligence-Abfrage (Drittanbieter, darf Login nie blockieren)
const IP_INTEL_TIMEOUT_MS = 2500;

function sign(payload) {
  if (!process.env.SESSION_SECRET) {
    throw new Error('SESSION_SECRET ist nicht gesetzt.');
  }
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto
    .createHmac('sha256', process.env.SESSION_SECRET)
    .update(data)
    .digest('base64url');
  return `${data}.${sig}`;
}

// Wirft einen sprechenden Fehler statt eines rohen "fetch failed",
// damit man im Vercel-Log sofort sieht: welcher Pfad, welcher Grund.
async function botFetch(path, opts = {}) {
  if (!process.env.BOT_API_URL) {
    throw new Error(`BOT_API_URL ist nicht gesetzt (Aufruf: ${path})`);
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), BOT_FETCH_TIMEOUT_MS);
  let res;
  try {
    res = await fetch(`${process.env.BOT_API_URL}${path}`, {
      headers: { 'X-API-Key': process.env.BOT_API_KEY || '' },
      signal: controller.signal,
      ...opts,
    });
  } catch (err) {
    throw new Error(
      `Bot-API unter ${process.env.BOT_API_URL}${path} nicht erreichbar (${err.cause?.code || err.message}). ` +
        `Prüfe BOT_API_URL, ob der Bot läuft und ob der Port beim Hoster freigegeben ist.`
    );
  } finally {
    clearTimeout(timeout);
  }
  if (!res.ok) return null;
  return res.json().catch(() => null);
}

function getClientIp(req) {
  // Vercel setzt x-forwarded-for; erster Eintrag ist die tatsächliche Client-IP.
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return fwd.split(',')[0].trim();
  return req.socket?.remoteAddress || 'unknown';
}

// Best-effort, kostenloses IP-Intelligence-Signal (kein API-Key nötig,
// ip-api.com Free-Tier ~45 Anfragen/Minute). Darf den Login niemals blockieren
// oder verzögern, falls der Dienst nicht antwortet — daher eigener kurzer
// Timeout und Fehler werden verschluckt.
async function checkIpIntel(ip) {
  if (!ip || ip === 'unknown' || ip.startsWith('127.') || ip.startsWith('::1')) {
    return { proxy: false, hosting: false, checked: false };
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), IP_INTEL_TIMEOUT_MS);
  try {
    const r = await fetch(`http://ip-api.com/json/${ip}?fields=status,proxy,hosting,countryCode,isp`, {
      signal: controller.signal,
    });
    clearTimeout(timeout);
    if (!r.ok) return { proxy: false, hosting: false, checked: false };
    const d = await r.json();
    if (d.status !== 'success') return { proxy: false, hosting: false, checked: false };
    return { proxy: !!d.proxy, hosting: !!d.hosting, countryCode: d.countryCode, isp: d.isp, checked: true };
  } catch {
    clearTimeout(timeout);
    return { proxy: false, hosting: false, checked: false };
  }
}

module.exports = async (req, res) => {
  try {
    // Prüfe kritische Umgebungsvariablen VOR dem Start
    if (!process.env.SESSION_SECRET) {
      res.statusCode = 500;
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.end('SESSION_SECRET fehlt auf dem Server.');
      return;
    }
    if (!process.env.DISCORD_CLIENT_ID || !process.env.DISCORD_CLIENT_SECRET) {
      res.statusCode = 500;
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.end('Discord-Umgebungsvariablen fehlen auf dem Server.');
      return;
    }

    const url = new URL(req.url, `https://${req.headers.host}`);
    const code = url.searchParams.get('code');
    const fehler = url.searchParams.get('error');

    if (fehler) {
      res.statusCode = 302;
      res.setHeader('Location', '/?login_error=1');
      res.end();
      return;
    }
    if (!code) {
      res.statusCode = 400;
      res.end('Fehlender OAuth-Code.');
      return;
    }

    let tokenRes;
    try {
      tokenRes = await fetch('https://discord.com/api/oauth2/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: process.env.DISCORD_CLIENT_ID,
          client_secret: process.env.DISCORD_CLIENT_SECRET,
          grant_type: 'authorization_code',
          code,
          redirect_uri: process.env.DISCORD_REDIRECT_URI,
        }),
      });
    } catch (err) {
      throw new Error(`Token-Tausch mit Discord fehlgeschlagen (Netzwerk): ${err.message}`);
    }
    if (!tokenRes.ok) {
      const body = await tokenRes.text().catch(() => '');
      console.error('[callback] Discord-Token-Tausch abgelehnt:', tokenRes.status, body);
      res.statusCode = 302;
      res.setHeader('Location', '/?login_error=1');
      res.end();
      return;
    }
    const token = await tokenRes.json();

    const [userRes, guildsRes] = await Promise.all([
      fetch('https://discord.com/api/users/@me', {
        headers: { Authorization: `Bearer ${token.access_token}` },
      }),
      fetch('https://discord.com/api/users/@me/guilds', {
        headers: { Authorization: `Bearer ${token.access_token}` },
      }),
    ]);
    const user = await userRes.json();
    const guilds = await guildsRes.json();

    const clientIp = getClientIp(req);

    // -----------------------------------------------------------------
    // Globale Sperrprüfung (User-ID und IP) — läuft VOR dem Ausstellen
    // der Session. Der Bot-Owner (ADMIN_USER_ID) kann sich immer einloggen,
    // damit er sich selbst nicht aussperren kann.
    // -----------------------------------------------------------------
    if (user.id !== ADMIN_USER_ID) {
      try {
        const sperrCheck = await botFetch(
          `/api/security/check?user_id=${encodeURIComponent(user.id)}&ip=${encodeURIComponent(clientIp)}`
        );
        if (sperrCheck && sperrCheck.gesperrt) {
          res.statusCode = 302;
          res.setHeader('Location', `/?login_error=locked${sperrCheck.grund ? `&reason=${encodeURIComponent(sperrCheck.grund)}` : ''}`);
          res.end();
          return;
        }
      } catch (err) {
        // Fail-open: wenn der Bot down ist, soll das Dashboard nicht für ALLE ausfallen.
        // Wir loggen den Fehler, lassen den Login aber durch.
        console.error('[callback] Sperrprüfung fehlgeschlagen (fail-open):', err.message);
      }
    }

    const ipIntel = await checkIpIntel(clientIp);

    // Discord-Admin-Server (für "Server ohne Bot" / Bot einladen — reine Discord-Berechtigung, unabhängig vom Polizei-System)
    const discordAdminGuilds = (Array.isArray(guilds) ? guilds : [])
      .filter((g) => g.owner === true || (parseInt(g.permissions, 10) & (MANAGE_GUILD | ADMINISTRATOR)) !== 0)
      .map((g) => ({ id: g.id, name: g.name, icon: g.icon }));

    // Server, auf denen der Bot schon ist — Grundlage für die Rollen-Zugriffsprüfung.
    // Auch hier fail-open: wenn der Bot nicht antwortet, ist die Liste leer.
    let botGuilds = [];
    let botGuildIds = new Set();
    try {
      const botGuildsData = await botFetch('/api/guilds');
      botGuilds = botGuildsData ? botGuildsData.guilds || [] : [];
      botGuildIds = new Set(botGuilds.map((g) => g.id));
    } catch (err) {
      console.error('[callback] Bot-Guild-Liste nicht erreichbar (fail-open):', err.message);
    }

    // Für jeden Server, auf dem der Bot ist UND der User Mitglied ist: Zugriffsstufe abfragen.
    const eigeneBotGuilds = (Array.isArray(guilds) ? guilds : []).filter((g) => botGuildIds.has(g.id));
    let accessResults = [];
    try {
      accessResults = await Promise.all(
        eigeneBotGuilds.map((g) => botFetch(`/api/guilds/${g.id}/access/${user.id}`))
      );
    } catch (err) {
      console.error('[callback] Zugriffsprüfung fehlgeschlagen (fail-open):', err.message);
    }
    const managed = [];
    eigeneBotGuilds.forEach((g, i) => {
      const access = accessResults[i];
      if (!access) return;
      const { is_admin, is_staff, is_dienstaufsicht, is_officer, dienstnummer } = access;
      if (!is_admin && !is_staff && !is_dienstaufsicht && !is_officer) return;
      const live = botGuilds.find((bg) => bg.id === g.id);
      managed.push({
        id: g.id,
        name: (live && live.name) || g.name,
        icon: (live && live.icon) || null,
        member_count: live ? live.member_count : null,
        admin: !!is_admin,
        staff: !!is_staff,
        dienstaufsicht: !!is_dienstaufsicht,
        officer: !!is_officer,
        dienstnummer: dienstnummer || null,
      });
    });

    const unmanaged = discordAdminGuilds.filter((g) => !botGuildIds.has(g.id));

    const session = {
      u: { id: user.id, name: user.username, avatar: user.avatar },
      g: managed,
      un: unmanaged,
      ip: clientIp,
      vpn: !!(ipIntel.proxy || ipIntel.hosting),
      isAdmin: user.id === ADMIN_USER_ID,
      exp: Date.now() + 1000 * 60 * 60 * 24 * 7, // 7 Tage
    };
    const cookieValue = sign(session);

    // Letzte bekannte IP + VPN-Signal beim Bot hinterlegen, damit der
    // Admin-Bereich (Support-Fälle / Sperren) sie anzeigen kann, ohne dass
    // der Client das selbst mitschicken müsste (Spoofing-Schutz).
    botFetch(`/api/security/seen`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_id: user.id,
        ip: clientIp,
        vpn_verdacht: !!(ipIntel.proxy || ipIntel.hosting),
        isp: ipIntel.isp || null,
        country: ipIntel.countryCode || null,
      }),
    }).catch((err) => console.error('[callback] Konnte "seen"-Info nicht an Bot melden:', err.message));

    res.setHeader(
      'Set-Cookie',
      `dash_session=${cookieValue}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`
    );
    res.statusCode = 302;
    res.setHeader('Location', '/');
    res.end();
  } catch (err) {
    console.error('[callback] Login fehlgeschlagen:', err);
    res.statusCode = 500;
    res.end('Fehler beim Login: ' + err.message);
  }
};
