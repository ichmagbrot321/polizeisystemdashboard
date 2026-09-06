// api/check-vpn.js
//
// Browser-VPN-Check-Proxy. ip-api.com blockt direkte Browser-Anfragen oft
// mit 403 (CORS / User-Agent-Filter). Dieser Endpoint macht den Aufruf
// serverseitig (wo CORS keine Rolle spielt) und liefert die Daten an den
// Browser zurück.
//
// Optional: Wenn IPINFO_TOKEN gesetzt ist, wird stattdessen ipinfo.io
// verwendet (zuverlässiger, 50k Anfragen/Monate Free-Tier).

const TIMEOUT_MS = 4000;

module.exports = async (req, res) => {
  // Optional: User-IP aus Headers (Vercel/Cloudflare) übernehmen
  const fwd = req.headers['x-forwarded-for'];
  const clientIp = (fwd ? fwd.split(',')[0].trim() : null) || req.socket?.remoteAddress || '';

  // Hilfsfunktion: Timeout für fetch
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  const setCors = () => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Cache-Control', 'no-store');
  };

  // Preflight
  if (req.method === 'OPTIONS') {
    setCors();
    res.statusCode = 204;
    res.end();
    return;
  }

  try {
    let data;

    if (process.env.IPINFO_TOKEN) {
      // ipinfo.io (mit Token, zuverlässig)
      const r = await fetch(`https://ipinfo.io/${clientIp || ''}?token=${process.env.IPINFO_TOKEN}`, {
        signal: controller.signal,
        headers: { 'Accept': 'application/json' }
      });
      clearTimeout(timeout);
      if (!r.ok) throw new Error(`ipinfo ${r.status}`);
      const d = await r.json();
      // ipinfo hat kein "proxy"-Feld — heuristisch über Org/Hosting
      const org = (d.org || '').toLowerCase();
      const isHosting = /(hosting|datacenter|cloud|server|vps|dedicated|vpn|proxy)/i.test(org);
      data = {
        status: 'success',
        country: d.country,
        isp: d.org,
        proxy: isHosting,
        hosting: isHosting,
        ip: d.ip
      };
    } else {
      // ip-api.com (Free, kein Token nötig)
      // User-Agent ist hier wichtig — sonst blockt die API mit 403
      const r = await fetch(`http://ip-api.com/json/${clientIp || ''}?fields=status,proxy,hosting,countryCode,isp,query`, {
        signal: controller.signal,
        headers: { 'User-Agent': 'Polizei-Dashboard/1.0 (Vercel Serverless)' }
      });
      clearTimeout(timeout);
      if (!r.ok) throw new Error(`ip-api ${r.status}`);
      data = await r.json();
    }

    setCors();
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(data));
  } catch (err) {
    clearTimeout(timeout);
    setCors();
    // Fail-open: lieber "kein VPN" zurückgeben als crashen — der eigentliche
    // VPN-Check läuft beim Login in api/callback.js ohnehin serverseitig.
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ status: 'error', error: err.message || 'lookup failed' }));
  }
};
