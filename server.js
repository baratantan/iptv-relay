// ═══════════════════════════════════════════════════════
// IPTV Relay — ممر رفيع يُمرّر طلبات بوابة Stalker من IP غير محجوب
// الهدف: البوبات التي تحجب IP الـ Cloudflare تقبل IP خادم Render هذا.
// البوت (على Cloudflare) يرسل الطلب هنا → يُعيد توجيهه للبوابة بنفس الترويسات.
//
// الأمان:
//  - يشترط سرًّا (X-Relay-Secret) حتى لا يُساء استخدامه كبروكسي مفتوح.
//  - يسمح فقط بالمضيفين المدرجين في ALLOW_HOSTS (إن ضُبطت).
// ═══════════════════════════════════════════════════════

const http = require("http");
const https = require("https");
const { URL } = require("url");

const PORT = process.env.PORT || 8080;
// غيّر هذا السر إلى قيمة طويلة عشوائية (واضبط نفسه في البوت)
const RELAY_SECRET = process.env.RELAY_SECRET || "change-me-to-a-long-random-string";
// اختياري: قيّد المضيفين المسموحين (مفصولة بفاصلة)، اتركها فارغة للسماح بالكل
const ALLOW_HOSTS = (process.env.ALLOW_HOSTS || "")
  .split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);

// الترويسات التي نمرّرها من البوت إلى البوابة
const FORWARD_HEADERS = [
  "user-agent", "accept", "accept-encoding", "cookie",
  "x-user-agent", "authorization", "referer",
];

function send(res, status, body, type = "application/json") {
  res.writeHead(status, {
    "Content-Type": type,
    "Access-Control-Allow-Origin": "*",
  });
  res.end(body);
}

const server = http.createServer((req, res) => {
  // فحص صحة بسيط
  if (req.url === "/" || req.url === "/health") {
    return send(res, 200, JSON.stringify({ status: "ok", relay: "iptv", ts: Date.now() }));
  }

  let target;
  try {
    const u = new URL(req.url, `http://localhost:${PORT}`);
    if (u.pathname !== "/relay") return send(res, 404, JSON.stringify({ error: "not found" }));
    const raw = u.searchParams.get("url");
    if (!raw) return send(res, 400, JSON.stringify({ error: "missing url" }));
    target = new URL(raw);
  } catch (e) {
    return send(res, 400, JSON.stringify({ error: "bad url" }));
  }

  // التحقق من السر
  if ((req.headers["x-relay-secret"] || "") !== RELAY_SECRET) {
    return send(res, 401, JSON.stringify({ error: "unauthorized" }));
  }
  // التحقق من المضيف المسموح
  if (ALLOW_HOSTS.length && !ALLOW_HOSTS.includes(target.hostname.toLowerCase())) {
    return send(res, 403, JSON.stringify({ error: "host not allowed" }));
  }
  if (!/^https?:$/.test(target.protocol)) {
    return send(res, 400, JSON.stringify({ error: "only http/https" }));
  }

  // تجهيز الطلب الممرّر
  const outHeaders = {};
  for (const h of FORWARD_HEADERS) {
    if (req.headers[h] != null) outHeaders[h] = req.headers[h];
  }
  outHeaders["host"] = target.host;

  const lib = target.protocol === "https:" ? https : http;
  const opts = {
    method: req.method,
    headers: outHeaders,
    timeout: 20000,
  };

  const proxied = lib.request(target, opts, (pr) => {
    const chunks = [];
    pr.on("data", (c) => chunks.push(c));
    pr.on("end", () => {
      const buf = Buffer.concat(chunks);
      res.writeHead(pr.statusCode || 502, {
        "Content-Type": pr.headers["content-type"] || "text/plain; charset=utf-8",
        "Access-Control-Allow-Origin": "*",
        // نمرّر حالة البوابة الأصلية للبوت ليقرأها
        "X-Origin-Status": String(pr.statusCode || 0),
        // نمرّر الـ Location إن وجد (مفيد لـ 302 في البث)
        ...(pr.headers["location"] ? { "X-Origin-Location": pr.headers["location"] } : {}),
      });
      res.end(buf);
    });
  });

  proxied.on("timeout", () => { proxied.destroy(); });
  proxied.on("error", (e) => {
    if (!res.headersSent) send(res, 502, JSON.stringify({ error: "relay fetch failed", detail: String(e) }));
  });

  // مرّر جسم POST إن وجد
  req.pipe(proxied);
});

// ملاحظة: Render يشترط الربط على 0.0.0.0 وعلى PORT المُعطى — هذا طبيعي لمنصة استضافة.
server.listen(PORT, "0.0.0.0", () => {
  console.log(`IPTV relay listening on :${PORT}`);
});
