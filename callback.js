// api/callback.js
//
// Discord leitet den Browser nach dem Login hierher um: /api/callback?code=...
// Diese Funktion tauscht den Code gegen ein Access-Token, holt den
// eingeloggten User und seine Server, filtert auf Server wo er
// "Server verwalten" (oder Administrator/Owner) ist, und speichert das
// Ergebnis in einem signierten, httpOnly-Cookie. Danach geht's zurück zur
// Startseite.
//
// Benötigte Umgebungsvariablen auf Vercel:
//   DISCORD_CLIENT_ID
//   DISCORD_CLIENT_SECRET
//   DISCORD_REDIRECT_URI   -> exakt https://DEINE-DOMAIN.vercel.app/api/callback
//   SESSION_SECRET         -> ein langer zufälliger String, frei erfunden

const crypto = require('crypto');

const MANAGE_GUILD = 0x20;
const ADMINISTRATOR = 0x8;

function sign(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto
    .createHmac('sha256', process.env.SESSION_SECRET)
    .update(data)
    .digest('base64url');
  return `${data}.${sig}`;
}

module.exports = async (req, res) => {
  try {
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

    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
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
    if (!tokenRes.ok) {
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

    const verwaltbar = (Array.isArray(guilds) ? guilds : [])
      .filter(
        (g) =>
          g.owner === true ||
          (parseInt(g.permissions, 10) & (MANAGE_GUILD | ADMINISTRATOR)) !== 0
      )
      .map((g) => ({ id: g.id, name: g.name, icon: g.icon }));

    const session = {
      u: { id: user.id, name: user.username, avatar: user.avatar },
      g: verwaltbar,
      exp: Date.now() + 1000 * 60 * 60 * 24 * 7, // 7 Tage
    };
    const cookieValue = sign(session);

    res.setHeader(
      'Set-Cookie',
      `dash_session=${cookieValue}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`
    );
    res.statusCode = 302;
    res.setHeader('Location', '/');
    res.end();
  } catch (err) {
    res.statusCode = 500;
    res.end('Fehler beim Login: ' + err.message);
  }
};
