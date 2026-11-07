
// ═══════════════════════════════════════════════════════
// IPTV Relay (Vercel serverless) — ينفّذ جلسة Stalker كاملة في طلب واحد
// من IP غير تابع لـ Cloudflare (الذي تحجبه بعض البوابات بـ 403).
//
// مهم: لأن Vercel serverless قد يغيّر الـIP بين طلب وآخر، ننفّذ
// الجلسة بأكملها (handshake → get_profile → channels → create_link) داخل
// استدعاء واحد = نفس الـIP مضمون طوال الجلسة.
//
// الأمان: يشترط سرًّا (X-Relay-Secret) حتى لا يُساء استخدامه كبروكسي مفتوح.
// ═══════════════════════════════════════════════════════

const STB_UA = "Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3";
const RELAY_SECRET = process.env.RELAY_SECRET || "change-me-to-a-long-random-string";
const ALLOW_HOSTS = (process.env.ALLOW_HOSTS || "")
  .split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);

function stbHeaders(host, mac, extra = {}) {
  const h = {
    "User-Agent": STB_UA,
    "Accept": "*/*",
    "Accept-Encoding": "identity",
    "Connection": "close",
    "Referer": host.replace(/\/+$/, "") + "/c/",
    ...extra,
  };
  if (mac) {
    h["Cookie"] = `mac=${encodeURIComponent(mac)}; stb_lang=en; timezone=Europe/London`;
    h["X-User-Agent"] = "Model: MAG250; Link: WiFi";
  }
  return h;
}

function normalizeMacHost(host) {
  if (!host) return host;
  host = String(host).trim();
  if (!/^https?:\/\//i.test(host)) host = "http://" + host;
  try {
    const u = new URL(host);
    const authMatch = host.match(/^https?:\/\/([^\/?#]+)/i);
    const authority = authMatch ? authMatch[1] : u.host;
    const p = u.pathname.replace(/\/+$/, "");
    const low = p.toLowerCase();
    if (low.includes("/stalker_portal")) {
      const idx = low.indexOf("/stalker_portal");
      return `${u.protocol}//${authority}${p.slice(0, idx + "/stalker_portal".length)}`;
    }
    return `${u.protocol}//${authority}`;
  } catch {
    return host.replace(/\/+$/, "");
  }
}

const PREFIXES = ["/portal.php", "/server/load.php", "/stalker_portal/server/load.php", "/c/portal.php"];

async function stalkerLogin(b, mac) {
  for (const p of PREFIXES) {
    try {
      const url = `${b}${p}?type=stb&action=handshake&token=&JsHttpRequest=1-xml`;
      const r = await fetch(url, { headers: stbHeaders(b, mac), signal: AbortSignal.timeout(10000), redirect: "follow" });
      if (r.status !== 200) continue;
      const txt = await r.text();
      const m = txt.match(/"token"\s*:\s*"([^"]+)"/) || txt.match(/token["']?\s*[:=]\s*["']?([A-Za-z0-9]{8,})/i);
      const token = m ? m[1] : null;
      if (!token) continue;
      let expiry = null;
      try {
        const purl = `${b}${p}?type=stb&action=get_profile&JsHttpRequest=1-xml`;
        const pr = await fetch(purl, { headers: stbHeaders(b, mac, { Authorization: `Bearer ${token}` }), signal: AbortSignal.timeout(10000) });
        const ptxt = await pr.text();
        const em = ptxt.match(/"(?:phone|end_date|exp_date)"\s*:\s*"([^"]+)"/i);
        if (em) expiry = em[1];
      } catch (_) {}
      return { token, prefix: p, expiry };
    } catch (_) {}
  }
  return null;
}

async function stalkerCreateLink(b, mac, token, prefix, cmd) {
  try {
    const url = `${b}${prefix}?type=itv&action=create_link&cmd=${encodeURIComponent(cmd)}&JsHttpRequest=1-xml`;
    const r = await fetch(url, { headers: stbHeaders(b, mac, { Authorization: `Bearer ${token}` }), signal: AbortSignal.timeout(10000) });
    if (r.status !== 200) return null;
    const data = JSON.parse(await r.text());
    let link = (data?.js?.cmd || "").toString();
    link = link.replace(/^ffmpeg\s+/i, "").trim();
    return link || null;
  } catch { return null; }
}

async function stalkerGetChannelsPaged(b, mac, token, prefix, maxTotal = 300) {
  const out = [];
  const pageSize = 14;
  const maxPages = Math.ceil(maxTotal / pageSize) + 1;
  for (let p = 1; p <= maxPages && out.length < maxTotal; p++) {
    let data = null;
    try {
      const url = `${b}${prefix}?type=itv&action=get_ordered_list&genre=*&force_ch_link_check=&fav=0&p=${p}&JsHttpRequest=1-xml`;
      const r = await fetch(url, { headers: stbHeaders(b, mac, { Authorization: `Bearer ${token}` }), signal: AbortSignal.timeout(10000), redirect: "follow" });
      if (r.status !== 200) break;
      data = JSON.parse(await r.text());
    } catch { break; }
    const list = data?.js?.data || [];
    if (!Array.isArray(list) || list.length === 0) break;
    for (const ch of list) { if (out.length >= maxTotal) break; out.push(ch); }
    const total = Number(data?.js?.total_items || 0);
    if (total && p * pageSize >= total) break;
  }
  return out;
}

async function buildM3U(b, mac, login, limit) {
  const channels = await stalkerGetChannelsPaged(b, mac, login.token, login.prefix, limit);
  if (!channels.length) return { ok: false, reason: "empty" };
  const slice = channels.slice(0, limit);
  const results = new Array(slice.length);
  let idx = 0;
  const worker = async () => {
    while (idx < slice.length) {
      const i = idx++;
      const ch = slice[i];
      const cmd = ch.cmd || (ch.cmds && ch.cmds[0] && ch.cmds[0].url) || "";
      let url = null;
      if (cmd) {
        const direct = /^https?:\/\//i.test(cmd.replace(/^ffmpeg\s+/i, "")) ? cmd.replace(/^ffmpeg\s+/i, "").trim() : null;
        url = direct || await stalkerCreateLink(b, mac, login.token, login.prefix, cmd);
      }
      results[i] = { ch, url };
    }
  };
  const pool = [];
  for (let k = 0; k < 8; k++) pool.push(worker());
  await Promise.all(pool);
  let m3u = "#EXTM3U\n";
  let resolved = 0;
  for (const res of results) {
    if (!res || !res.url) continue;
    const name = (res.ch.name || "Channel").toString();
    const logoRaw = res.ch.logo || "";
    const logo = logoRaw && /^https?:/i.test(logoRaw) ? ` tvg-logo="${logoRaw}"` : "";
    m3u += `#EXTINF:-1${logo},${name}\n${res.url}\n`;
    resolved++;
  }
  return { ok: resolved > 0, m3u, total: channels.length, resolved };
}

function json(res, status, obj) {
  res.status(status).setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.end(JSON.stringify(obj));
}

async function readBody(req) {
  if (req.body && typeof req.body === "object") return req.body;
  if (typeof req.body === "string" && req.body) { try { return JSON.parse(req.body); } catch { return {}; } }
  return await new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => { data += c; });
    req.on("end", () => { try { resolve(JSON.parse(data || "{}")); } catch { resolve({}); } });
    req.on("error", () => resolve({}));
  });
}

// نقطة الدخول (Vercel): POST /api/relay
module.exports = async (req, res) => {
  // CORS preflight
  if (req.method === "OPTIONS") {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Relay-Secret");
    res.status(204).end();
    return;
  }

  // فحص صحة
  if (req.method === "GET") {
    return json(res, 200, { status: "ok", relay: "iptv-vercel", ts: Date.now() });
  }

  // التحقق من السرّ
  if ((req.headers["x-relay-secret"] || "") !== RELAY_SECRET) {
    return json(res, 401, { error: "unauthorized" });
  }

  const body = await readBody(req);
  const op = (body.op || "login").toString();
  const portal = (body.portal || "").toString();
  const mac = (body.mac || "").toString().toUpperCase().trim();
  const limit = Math.min(Math.max(Number(body.limit) || 150, 1), 400);

  if (!portal || !mac) return json(res, 400, { error: "missing portal or mac" });

  const b = normalizeMacHost(portal).replace(/\/+$/, "");
  try {
    const host = new URL(b).hostname.toLowerCase();
    if (ALLOW_HOSTS.length && !ALLOW_HOSTS.includes(host)) {
      return json(res, 403, { error: "host not allowed" });
    }
  } catch { return json(res, 400, { error: "bad portal url" }); }

  const login = await stalkerLogin(b, mac);
  if (!login) return json(res, 200, { ok: false, reason: "login", base: b });

  if (op === "login") {
    return json(res, 200, { ok: true, token: login.token, prefix: login.prefix, expiry: login.expiry, base: b });
  }
  if (op === "createlink") {
    const cmd = (body.cmd || "").toString();
    if (!cmd) return json(res, 400, { error: "missing cmd" });
    const link = await stalkerCreateLink(b, mac, login.token, login.prefix, cmd);
    return json(res, 200, { ok: !!link, url: link, base: b });
  }
  if (op === "m3u") {
    const out = await buildM3U(b, mac, login, limit);
    return json(res, 200, { ...out, base: b, prefix: login.prefix });
  }
  return json(res, 400, { error: "unknown op" });
};
