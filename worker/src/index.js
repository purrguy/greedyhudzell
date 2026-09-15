/**
 * greedyhudzell.xyz — unified Worker
 * - Key system (Work.ink + D1)
 * - Admin: generate / renew / revoke / key
 * - Lua proxies + Obfuscator
 *
 * Bindings: DB (D1)
 * Secrets: ADMIN_SECRET, ROTATION_SECRET, LUAOBF_API_KEY (optional)
 * Vars: SITE_NAME
 */
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};
const SESSION_TTL = 30 * 60;
const KEY_TTL = 24 * 60 * 60;
const PLAN_TTL = {
  day: 24 * 60 * 60,
  week: 7 * 24 * 60 * 60,
  month: 30 * 24 * 60 * 60,
  year: 365 * 24 * 60 * 60,
};
function planTtl(plan) {
  return PLAN_TTL[plan] || PLAN_TTL.day;
}
const GAMEPASS_BY_PLAN = {
  week: "1963350769",
  month: "1965054742",
  year: "1966320456",
};
const GAMEPASS_STORE = {
  week: "https://www.roblox.com/game-pass/1963350769",
  month: "https://www.roblox.com/game-pass/1965054742",
  year: "https://www.roblox.com/game-pass/1966320456",
};
const DISCORD_REDEEM_CHANNEL = "https://discord.com/channels/1422222409846620201/1448630361390055454";
const DISCORD_INVITE = "https://discord.gg/sbVuaT9a2T";
/** Public Discord application id (OAuth). Secret stays in env only. */
const DEFAULT_DISCORD_CLIENT_ID = "1426282728520679454";
const FREE_KEY_LINK = "https://work.ink/28wp/Greedy-hudzell";

const REDEEM_SUPPORT_HINT =
  "If you bought the Game Pass but could not redeem it, write in Discord: https://discord.com/channels/1422222409846620201/1448630361390055454";

const GH = "https://raw.githubusercontent.com/mixask/GH/main";
const LUAOBF_ENDPOINTS = [
  {
    newscript: "https://luaobfuscator.com/api/obfuscator/newscript",
    obfuscate: "https://luaobfuscator.com/api/obfuscator/obfuscate",
  },
  {
    newscript: "https://api.luaobfuscator.com/v1/obfuscator/newscript",
    obfuscate: "https://api.luaobfuscator.com/v1/obfuscator/obfuscate",
  },
];
const LUAOBF_FALLBACK = "11ad3847-d943-4a76-ee19-f9acab3e85144ea9";
const jsonHeaders = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
};
function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...jsonHeaders, ...corsHeaders, ...extraHeaders },
  });
}
function html(body, status = 200, extraHeaders = {}) {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders,
    },
  });
}
function plain(body, status = 200) {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-cache",
      ...corsHeaders,
    },
  });
}
function now() {
  return Math.floor(Date.now() / 1000);
}
function getClientIP(request) {
  return (
    request.headers.get("CF-Connecting-IP") ||
    request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() ||
    ""
  );
}
async function sha256(value) {
  const data = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function randomString(length = 32) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function generateKey() {
  const bytes = new Uint8Array(12);
  crypto.getRandomValues(bytes);
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let value = "";
  for (const byte of bytes) value += alphabet[byte % alphabet.length];
  return `GH-${value.slice(0, 4)}-${value.slice(4, 8)}-${value.slice(8, 12)}`;
}
function cookie(name, value, maxAge) {
  return `${name}=${encodeURIComponent(value)}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}
function getCookie(request, name) {
  const cookies = request.headers.get("Cookie") || "";
  for (const part of cookies.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return decodeURIComponent(rest.join("="));
  }
  return null;
}
/* ===================== WORK.INK ===================== */
function normalizeWorkInkToken(raw) {
  if (raw == null) return "";
  let t = String(raw).trim();
  if (!t) return "";
  // strip wrapping quotes
  if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) {
    t = t.slice(1, -1).trim();
  }
  // decode once if percent-encoded
  if (t.includes("%")) {
    try {
      const d = decodeURIComponent(t);
      if (d && d.length <= 500) t = d.trim();
    } catch (_) {}
  }
  // work.ink sometimes appends extra query junk
  if (t.includes("?")) t = t.split("?")[0];
  if (t.includes("#")) t = t.split("#")[0];
  return t.slice(0, 500);
}

async function validateWorkInkToken(token) {
  const t = normalizeWorkInkToken(token);
  if (!t) return { valid: false, reason: "missing_token" };
  const candidates = [t];
  // also try URI-encoded form if different
  try {
    const enc = encodeURIComponent(t);
    if (enc !== t) candidates.push(enc);
  } catch (_) {}

  let lastReason = "workink_invalid";
  for (const cand of candidates) {
    try {
      // path segment: prefer encode so special chars are safe
      const pathTok = cand.includes("%") ? cand : encodeURIComponent(cand);
      const response = await fetch(`https://work.ink/_api/v2/token/isValid/${pathTok}`, {
        method: "GET",
        headers: { Accept: "application/json" },
        cf: { cacheTtl: 0, cacheEverything: false },
      });
      if (!response.ok) {
        lastReason = "workink_http_" + response.status;
        continue;
      }
      const data = await response.json().catch(() => ({}));
      const ok =
        data.valid === true ||
        data.success === true ||
        data.isValid === true ||
        data.status === "valid" ||
        data.status === true;
      if (ok) {
        return {
          valid: true,
          byIp: data.info?.byIp ?? data.byIp ?? null,
          info: data.info ?? data,
          reason: "ok",
        };
      }
      lastReason = "workink_invalid";
    } catch (error) {
      console.error("Work.ink validation error:", error);
      lastReason = "workink_request_failed";
    }
  }
  return { valid: false, reason: lastReason };
}

function extractWorkInkToken(request, url, pathToken) {
  if (pathToken) return normalizeWorkInkToken(pathToken);
  const sp = url.searchParams;
  return normalizeWorkInkToken(
    sp.get("token") || sp.get("t") || sp.get("code") || sp.get("key") || ""
  );
}
/* ===================== DB / SESSION ===================== */
async function createSession(env, ipHash) {
  const timestamp = now();
  const sessionId = `GH-${randomString(32)}`;
  await env.DB.prepare(
    `INSERT INTO sessions (session_id, ip_hash, step1, step2, created_at, expires_at)
     VALUES (?, ?, 1, 0, ?, ?)`
  )
    .bind(sessionId, ipHash, timestamp, timestamp + SESSION_TTL)
    .run();
  return sessionId;
}
async function getSession(env, sessionId) {
  if (!sessionId) return null;
  return (
    (await env.DB.prepare(`SELECT * FROM sessions WHERE session_id = ? LIMIT 1`).bind(sessionId).first()) ||
    null
  );
}
async function validSession(env, sessionId, ipHash) {
  const session = await getSession(env, sessionId);
  if (!session) return { valid: false, reason: "session_not_found" };
  if (session.expires_at <= now()) return { valid: false, reason: "session_expired" };
  if (session.ip_hash !== ipHash) return { valid: false, reason: "ip_mismatch" };
  return { valid: true, session };
}
/* ===================== HTML SHELL ===================== */
function pageShell(title, content) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#080808;color:#fff;font-family:Arial,sans-serif}
.card{width:min(460px,calc(100% - 32px));background:#111;border:1px solid #292929;border-radius:18px;padding:30px;box-shadow:0 20px 60px rgba(0,0,0,.5)}
.card.wide{width:min(980px,calc(100% - 24px))}
.logo{font-size:25px;font-weight:800;letter-spacing:1px;margin-bottom:24px}
.step{padding:12px 14px;border-radius:10px;background:#181818;margin:8px 0}
.ok{color:#6dff9a}
button{width:100%;padding:13px;margin-top:12px;border:0;border-radius:10px;background:#fff;color:#000;font-weight:700;cursor:pointer}
button.secondary{background:#181818;color:#fff;border:1px solid #333}
button:disabled{opacity:.55;cursor:wait}
input,select,textarea{width:100%;padding:13px;border-radius:10px;border:1px solid #333;background:#080808;color:#fff;outline:none}
textarea{min-height:200px;font-family:ui-monospace,monospace;resize:vertical}
label{display:block;margin:16px 0 7px;font-size:14px;color:#aaa}
.muted{color:#888;font-size:13px;line-height:1.5}
.error{color:#ff6d6d}
.nav{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}
.nav a{color:#aaa;text-decoration:none;font-size:13px}
.nav a:hover{color:#fff}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media(max-width:800px){.grid{grid-template-columns:1fr}}
.chk{display:flex;align-items:center;gap:8px;font-size:13px;margin:4px 0;color:#ccc}
.plugins{display:grid;grid-template-columns:1fr 1fr;gap:4px 10px}
@media(max-width:600px){.plugins{grid-template-columns:1fr}}
.actions{display:flex;gap:8px;flex-wrap:wrap}
.actions button{flex:1;min-width:120px}
</style>
</head>
<body>
<div class="card${title.includes("Obfuscator") ? " wide" : ""}">
${content}
</div>
</body>
</html>`;
}
/* ===================== KEY FLOW ===================== */
async function handleGetKeyToken(request, env, token) {
  const work = await validateWorkInkToken(token);
  if (!work.valid) {
    return html(
      pageShell("Failed", `<div class="logo">${env.SITE_NAME}</div><h2>FAILED</h2><p>Invalid or expired Work.ink token.</p>`),
      403
    );
  }
  const currentIP = getClientIP(request);
  if (!currentIP) {
    return html(
      pageShell("Failed", `<div class="logo">${env.SITE_NAME}</div><h2>FAILED</h2><p>Unable to identify your IP address.</p>`),
      403
    );
  }
  const ipHash = await sha256(currentIP);
  const sessionId = await createSession(env, ipHash);
  return html(
    pageShell(
      "Step 1 Complete",
      `<div class="logo">${env.SITE_NAME}</div>
      <div class="step ok">✓ STEP 1 COMPLETE</div>
      <p class="muted">Work.ink token verified successfully.</p>
      <p class="muted">Continue to the second required step.</p>
      <a href="/step2"><button>CONTINUE TO STEP 2</button></a>`
    ),
    200,
    { "Set-Cookie": cookie("GH_SESSION", sessionId, SESSION_TTL) }
  );
}
async function handleStep2(request, env) {
  const sessionId = getCookie(request, "GH_SESSION");
  const currentIP = getClientIP(request);
  const ipHash = await sha256(currentIP);
  const result = await validSession(env, sessionId, ipHash);
  if (!result.valid || result.session.step1 !== 1) {
    return html(
      pageShell("Failed", `<div class="logo">${env.SITE_NAME}</div><h2>FAILED</h2><p>Please complete Step 1 first.</p>`),
      403
    );
  }
  const secondWorkInkLink = "https://work.ink/28wp/greedy-hudzell-12";
  return html(
    pageShell(
      "Step 2",
      `<div class="logo">${env.SITE_NAME}</div>
      <div class="step ok">✓ STEP 1 COMPLETE</div>
      <p class="muted">Complete Work.ink Step 2, then you will return here to generate a key.</p>
      <a href="${secondWorkInkLink}"><button>CONTINUE TO STEP 2</button></a>
      <p class="muted" style="margin-top:18px">Already finished the unlock?</p>
      <a href="/finish"><button style="background:#333">I FINISHED STEP 2 — GENERATE KEY</button></a>`
    )
  );
}
async function handleFinish(request, env, token) {
  const sessionId = getCookie(request, "GH_SESSION");
  const currentIP = getClientIP(request);
  const ipHash = await sha256(currentIP);
  const sessionResult = await validSession(env, sessionId, ipHash);
  if (!sessionResult.valid) {
    return html(
      pageShell("Failed", `<div class="logo">${env.SITE_NAME}</div><h2>FAILED</h2><p>Your session is invalid or expired. Complete Step 1 again (same browser).</p><p class="muted">reason: ${sessionResult.reason || "unknown"}</p>`),
      403
    );
  }
  if (sessionResult.session.step1 !== 1) {
    return html(
      pageShell("Failed", `<div class="logo">${env.SITE_NAME}</div><h2>FAILED</h2><p>Please complete Step 1 first.</p>`),
      403
    );
  }

  // Step 2 token: try Work.ink API, but do not hard-fail.
  // Work.ink one-time tokens often return valid:false on the second check / after redirect.
  // Modes via env.WORKINK_STEP2_MODE: "strict" | "soft" (default) | "off"
  const mode = String(env.WORKINK_STEP2_MODE || "soft").toLowerCase();
  const normalized = normalizeWorkInkToken(token);
  let work = { valid: false, reason: "skipped" };

  if (mode === "off") {
    work = { valid: true, reason: "step2_off" };
  } else if (normalized) {
    work = await validateWorkInkToken(normalized);
    if (!work.valid && mode === "soft") {
      // Accept non-empty token + valid step1 session (soft)
      if (normalized.length >= 8) {
        console.log("[GH] step2 soft-accept token len", normalized.length, "api_reason", work.reason);
        work = { valid: true, reason: "soft_accept", api_reason: work.reason };
      }
    }
  } else if (mode === "soft") {
    // No token in URL (wrong Work.ink destination) but session OK → still allow finish
    console.log("[GH] step2 soft-accept missing token, session ok");
    work = { valid: true, reason: "soft_no_token" };
  }

  if (!work.valid) {
    const why = work.reason || "invalid";
    const hint =
      why === "missing_token"
        ? "No token in URL. Work.ink Step 2 destination must be <code>https://YOUR_DOMAIN/finish?token={token}</code>."
        : "Token rejected by Work.ink (" + why + "). Set env WORKINK_STEP2_MODE=soft or fix the Step 2 destination URL.";
    return html(
      pageShell(
        "Failed",
        `<div class="logo">${env.SITE_NAME}</div><h2>FAILED</h2><p>Invalid Work.ink Step 2 token.</p><p class="muted">${hint}</p>`
      ),
      403
    );
  }
  await env.DB.prepare(`UPDATE sessions SET step2 = 1 WHERE session_id = ?`).bind(sessionId).run();
  return html(
    pageShell(
      "Key Generator",
      `<div class="logo">${env.SITE_NAME}</div>
      <div class="step ok">✓ STEP 1 COMPLETE</div>
      <div class="step ok">✓ STEP 2 COMPLETE</div>
      <label>Roblox username</label>
      <input id="username" maxlength="20" placeholder="Not displayname!" autocomplete="off">
      <button onclick="generateKey()">GENERATE KEY</button>
      <p id="result" class="muted"></p>
      <script>
      async function generateKey() {
        const username = document.getElementById("username").value.trim();
        const result = document.getElementById("result");
        if (!username) { result.textContent = "Enter your Roblox username."; return; }
        result.textContent = "Generating...";
        try {
          const response = await fetch("/generate-key", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username })
          });
          const data = await response.json();
          if (!data.success) { result.textContent = data.reason || "Failed to generate key."; return; }
          result.innerHTML = "Your key:<br><br><strong>" + data.key + "</strong>";
        } catch { result.textContent = "Network error."; }
      }
      </script>`
    )
  );
}
async function handleGenerateKey(request, env) {
  const sessionId = getCookie(request, "GH_SESSION");
  const currentIP = getClientIP(request);
  if (!currentIP) return json({ success: false, reason: "ip_unavailable" }, 403);
  const ipHash = await sha256(currentIP);
  const sessionResult = await validSession(env, sessionId, ipHash);
  if (!sessionResult.valid) return json({ success: false, reason: sessionResult.reason }, 403);
  if (sessionResult.session.step1 !== 1 || sessionResult.session.step2 !== 1) {
    return json({ success: false, reason: "steps_not_completed" }, 403);
  }
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ success: false, reason: "invalid_json" }, 400);
  }
  const username = typeof body.username === "string" ? body.username.trim() : "";
  if (username.length < 3 || username.length > 20 || !/^[A-Za-z0-9_]+$/.test(username)) {
    return json({ success: false, reason: "invalid_username" }, 400);
  }
  const existing = await env.DB.prepare(`SELECT key FROM keys WHERE session_id = ? LIMIT 1`).bind(sessionId).first();
  if (existing) return json({ success: true, key: existing.key, already_generated: true });
  const key = generateKey();
  const timestamp = now();
  try {
    await env.DB.prepare(
      `INSERT INTO keys (key, username, session_id, created_at, expires_at, revoked, executed, last_execution, plan, activated)
       VALUES (?, ?, ?, ?, ?, 0, 0, NULL, ?, 0)`
    )
      .bind(key, username, sessionId, timestamp, timestamp + KEY_TTL, "day")
      .run();
  } catch (e) {
    console.error("generate-key activated insert:", String(e));
    await env.DB.prepare(
      `INSERT INTO keys (key, username, session_id, created_at, expires_at, revoked, executed, last_execution, plan)
       VALUES (?, ?, ?, ?, ?, 0, 0, NULL, ?)`
    )
      .bind(key, username, sessionId, timestamp, timestamp + KEY_TTL, "day")
      .run();
  }
  return json({ success: true, key, expires_at: timestamp + KEY_TTL, activated: 0 });
}
async function handleValidate(request, env) {
  if (request.method !== "POST") return json({ valid: false, reason: "method_not_allowed" }, 405);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ valid: false, reason: "invalid_json" }, 400);
  }
  const key = typeof body.key === "string" ? body.key.trim() : "";
  const username = typeof body.username === "string" ? body.username.trim() : "";
  const discordId = String(body.discord_id || body.discordId || "").replace(/\D/g, "") || null;
  if (!key || !username) return json({ valid: false, reason: "missing_key_or_username" });
  const record = await env.DB.prepare(`SELECT * FROM keys WHERE key = ? LIMIT 1`).bind(key).first();
  if (!record) return json({ valid: false, reason: "invalid_key" });
  if (record.revoked === 1) return json({ valid: false, reason: "revoked" });
  if (Number(record.expires_at) <= now()) return json({ valid: false, reason: "expired" });
  {
    const ban = await isBanned(env, key, username, body.user_id || body.userId || body.roblox_id);
    if (ban) {
      return json({
        valid: false,
        reason: "banned",
        message: ban.reason || "Key, username or userId is banned from GH.",
      });
    }
  }

  // Keys start inactive; Discord Verify sets activated = 1
  // Legacy rows: activated NULL → allow if already executed/discord linked
  const act = record.activated;
  if (act === 0 || act === "0") {
    return json({
      valid: false,
      reason: "not_activated",
      message: "Key is inactive. Use Verify in Discord to activate.",
    });
  }

  // Roblox username bind: pending_* can claim once; otherwise must match
  const isPending = String(record.username || "").startsWith("pending_");
  if (record.username !== username) {
    if (isPending) {
      try {
        await env.DB.prepare(`UPDATE keys SET username = ? WHERE key = ?`).bind(username, key).run();
      } catch {
        return json({ valid: false, reason: "bind_failed" });
      }
    } else {
      return json({
        valid: false,
        reason: "username_mismatch",
        bound_username: record.username,
        message: "Key is bound to another Roblox account. Paid keys can /rewire.",
      });
    }
  }

  // Discord bind: if key already has discord_id, client must send the same one
  if (record.discord_id) {
    if (discordId && String(record.discord_id) !== discordId) {
      return json({
        valid: false,
        reason: "discord_mismatch",
        message: "Key is bound to another Discord account",
      });
    }
  } else if (discordId) {
    // first time: attach discord_id if column exists
    try {
      await env.DB.prepare(`UPDATE keys SET discord_id = ? WHERE key = ?`).bind(discordId, key).run();
    } catch (_) {}
  }

  const timestamp = now();
  await env.DB.prepare(`UPDATE keys SET executed = 1, last_execution = ? WHERE key = ?`).bind(timestamp, key).run();

  let discordBound = record.discord_id || discordId || null;
  return json({
    valid: true,
    expires_at: record.expires_at,
    plan: record.plan || "day",
    username: username,
    discord_id: discordBound,
    discord_linked: Boolean(discordBound),
    paid: isPaidPlan(record.plan, key),
    rewire_allowed: isPaidPlan(record.plan, key),
  });
}
/* ===================== ADMIN ===================== */
function adminAuthorized(request, env) {
  const auth = request.headers.get("Authorization");
  if (!auth || !auth.startsWith("Bearer ")) return false;
  return auth.slice(7) === env.ADMIN_SECRET;
}
async function createRotationToken(env) {
  const interval = Math.floor(Date.now() / 1000 / 600);
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.ROTATION_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(String(interval)));
  return [...new Uint8Array(signature)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function handleAdminKeys(request, env, rotation) {
  if (!adminAuthorized(request, env)) return json({ error: "Unauthorized" }, 401);
  const expectedRotation = await createRotationToken(env);
  if (rotation !== expectedRotation) return json({ error: "Invalid rotation" }, 403);
  const url = new URL(request.url);
  const search = url.searchParams.get("search")?.trim() || "";
  let result;
  if (search) {
    result = await env.DB.prepare(
      `SELECT * FROM keys WHERE key LIKE ? OR username LIKE ? ORDER BY created_at DESC`
    )
      .bind(`%${search}%`, `%${search}%`)
      .all();
  } else {
    result = await env.DB.prepare(`SELECT * FROM keys ORDER BY created_at DESC`).all();
  }
  return json({
    keys: result.results.map((k) => ({
      key: k.key,
      username: k.username,
      plan: k.plan || "day",
      executed: k.executed === 1,
      last_execution: k.last_execution,
      created_at: k.created_at,
      expires_at: k.expires_at,
      revoked: k.revoked === 1,
      status: k.revoked === 1 ? "REVOKED" : k.expires_at <= now() ? "EXPIRED" : "ACTIVE",
    })),
  });
}
async function handleAdminRevoke(request, env) {
  if (!adminAuthorized(request, env)) return json({ success: false, reason: "unauthorized" }, 401);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ success: false, reason: "invalid_json" }, 400);
  }
  const key = typeof body.key === "string" ? body.key.trim() : "";
  if (!key) return json({ success: false, reason: "missing_key" }, 400);
  const result = await env.DB.prepare(`UPDATE keys SET revoked = 1 WHERE key = ?`).bind(key).run();
  if (!result.meta.changes) return json({ success: false, reason: "key_not_found" }, 404);
  return json({ success: true });
}
async function handleAdminKey(request, env, key) {
  if (!adminAuthorized(request, env)) return json({ error: "Unauthorized" }, 401);
  const record = await env.DB.prepare(`SELECT * FROM keys WHERE key = ? LIMIT 1`).bind(key).first();
  if (!record) return json({ error: "Key not found" }, 404);
  return json({
    key: record.key,
    username: record.username,
    plan: record.plan || "day",
    session_id: record.session_id,
    created_at: record.created_at,
    expires_at: record.expires_at,
    revoked: record.revoked === 1,
    executed: record.executed === 1,
    last_execution: record.last_execution,
    status: record.revoked === 1 ? "REVOKED" : record.expires_at <= now() ? "EXPIRED" : "ACTIVE",
  });
}
/** Discord bot / admin panel: create key with plan week|month|year|day */
async function handleAdminGenerate(request, env) {
  if (!adminAuthorized(request, env)) return json({ success: false, reason: "unauthorized" }, 401);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ success: false, reason: "invalid_json" }, 400);
  }
  const plan = typeof body.plan === "string" ? body.plan.trim().toLowerCase() : "month";
  if (!PLAN_TTL[plan]) return json({ success: false, reason: "invalid_plan", allowed: Object.keys(PLAN_TTL) }, 400);

  let username = typeof body.username === "string" ? body.username.trim() : "";
  if (username) {
    if (username.length < 3 || username.length > 20 || !/^[A-Za-z0-9_]+$/.test(username)) {
      return json({ success: false, reason: "invalid_username" }, 400);
    }
  }

  const key = generateKey();
  const timestamp = now();
  const expires = timestamp + planTtl(plan);
  const storedUser = username || ("pending_" + key.replace(/-/g, "").slice(0, 12));

  try {
    await env.DB.prepare(
      `INSERT INTO keys (key, username, session_id, created_at, expires_at, revoked, executed, last_execution, plan, activated)
       VALUES (?, ?, ?, ?, ?, 0, 0, NULL, ?, 0)`
    )
      .bind(key, storedUser, "admin:" + timestamp, timestamp, expires, plan)
      .run();
  } catch (e) {
    // D1 without activated column yet
    console.error("admin generate insert (activated):", String(e));
    try {
      await env.DB.prepare(
        `INSERT INTO keys (key, username, session_id, created_at, expires_at, revoked, executed, last_execution, plan)
         VALUES (?, ?, ?, ?, ?, 0, 0, NULL, ?)`
      )
        .bind(key, storedUser, "admin:" + timestamp, timestamp, expires, plan)
        .run();
    } catch (e2) {
      console.error("admin generate insert:", String(e2));
      return json({
        success: false,
        reason: "db_error",
        message: String(e2 && e2.message ? e2.message : e2),
      }, 500);
    }
  }

  return json({
    success: true,
    key,
    plan,
    expires_at: expires,
    username: username || null,
    pending: !username,
    activated: 0,
  });
}
/** Extend key by N days (un-revokes) */
async function handleAdminRenew(request, env) {
  if (!adminAuthorized(request, env)) return json({ success: false, reason: "unauthorized" }, 401);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ success: false, reason: "invalid_json" }, 400);
  }
  const key = typeof body.key === "string" ? body.key.trim() : "";
  const days = Math.max(1, Math.min(365, Number(body.days) || 0));
  if (!key || !days) return json({ success: false, reason: "missing_key_or_days" }, 400);

  const record = await env.DB.prepare(`SELECT * FROM keys WHERE key = ? LIMIT 1`).bind(key).first();
  if (!record) return json({ success: false, reason: "key_not_found" }, 404);

  const base = Math.max(Number(record.expires_at) || 0, now());
  const expires = base + days * 24 * 60 * 60;

  await env.DB.prepare(`UPDATE keys SET expires_at = ?, revoked = 0 WHERE key = ?`).bind(expires, key).run();

  return json({
    success: true,
    key,
    expires_at: expires,
    username: record.username,
    plan: record.plan || "day",
  });
}

/** Rewire username — GH-PAID-* keys only */
async function handleAdminRewire(request, env) {
  if (!adminAuthorized(request, env)) return json({ success: false, reason: "unauthorized" }, 401);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ success: false, reason: "invalid_json" }, 400);
  }
  const key = typeof body.key === "string" ? body.key.trim() : "";
  const username = typeof body.username === "string" ? body.username.trim() : "";
  if (!key) return json({ success: false, reason: "missing_key" }, 400);
  if (username.length < 3 || username.length > 20 || !/^[A-Za-z0-9_]+$/.test(username)) {
    return json({ success: false, reason: "invalid_username" }, 400);
  }
  if (!key.startsWith("GH-PAID-")) {
    return json({ success: false, reason: "rewire_only_paid", details: "Only GH-PAID-* keys can be rewired" }, 400);
  }

  const record = await env.DB.prepare(`SELECT * FROM keys WHERE key = ? LIMIT 1`).bind(key).first();
  if (!record) return json({ success: false, reason: "key_not_found" }, 404);
  if (record.revoked === 1) return json({ success: false, reason: "revoked" }, 400);
  if (Number(record.expires_at) <= now()) return json({ success: false, reason: "expired" }, 400);

  const previous = record.username;
  await env.DB.prepare(`UPDATE keys SET username = ? WHERE key = ?`).bind(username, key).run();

  return json({
    success: true,
    key,
    previous_username: previous,
    username,
    plan: record.plan || "paid",
    expires_at: record.expires_at,
  });
}

/** Key issuance stats (day / week / totals) */
async function handleAdminStats(request, env) {
  if (!adminAuthorized(request, env)) return json({ success: false, reason: "unauthorized" }, 401);
  const t = now();
  const dayAgo = t - 86400;
  const weekAgo = t - 7 * 86400;

  const row = async (sql, binds = []) => {
    const r = await env.DB.prepare(sql).bind(...binds).first();
    return Number(r && r.c != null ? r.c : 0);
  };

  const total = await row(`SELECT COUNT(*) AS c FROM keys`);
  const active = await row(
    `SELECT COUNT(*) AS c FROM keys WHERE revoked = 0 AND expires_at > ?`,
    [t]
  );
  const revoked = await row(`SELECT COUNT(*) AS c FROM keys WHERE revoked = 1`);
  const day = await row(`SELECT COUNT(*) AS c FROM keys WHERE created_at >= ?`, [dayAgo]);
  const week = await row(`SELECT COUNT(*) AS c FROM keys WHERE created_at >= ?`, [weekAgo]);
  const paid = await row(`SELECT COUNT(*) AS c FROM keys WHERE key LIKE 'GH-PAID-%'`);
  const paidActive = await row(
    `SELECT COUNT(*) AS c FROM keys WHERE key LIKE 'GH-PAID-%' AND revoked = 0 AND expires_at > ?`,
    [t]
  );
  const dayPaid = await row(
    `SELECT COUNT(*) AS c FROM keys WHERE created_at >= ? AND key LIKE 'GH-PAID-%'`,
    [dayAgo]
  );
  const weekPaid = await row(
    `SELECT COUNT(*) AS c FROM keys WHERE created_at >= ? AND key LIKE 'GH-PAID-%'`,
    [weekAgo]
  );

  return json({
    success: true,
    now: t,
    total,
    active,
    revoked,
    issued_day: day,
    issued_week: week,
    paid_total: paid,
    paid_active: paidActive,
    paid_day: dayPaid,
    paid_week: weekPaid,
  });
}

async function robloxUserIdFromUsername(username) {
  const headers = {
    "Content-Type": "application/json",
    Accept: "application/json",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  };
  try {
    const res = await fetch("https://users.roblox.com/v1/usernames/to-ids", {
      method: "POST",
      headers,
      body: JSON.stringify({
        usernames: [username],
        excludeBannedUsers: false,
      }),
    });
    const text = await res.text();
    let data = null;
    try { data = JSON.parse(text); } catch (_) {}
    if (res.status === 429) return { ok: false, reason: "roblox_users_http_429" };
    if (res.ok && data) {
      const row = (data.data || []).find((x) => {
        const a = String(x.requestedUsername || "").toLowerCase();
        const b = String(x.name || "").toLowerCase();
        const u = username.toLowerCase();
        return a === u || b === u;
      });
      if (row && row.id != null) {
        return { ok: true, userId: String(row.id), name: row.name || username };
      }
      if (Array.isArray(data.data) && data.data.length === 0) {
        return { ok: false, reason: "username_not_found" };
      }
    } else {
      console.error("to-ids status", res.status, (text || "").slice(0, 200));
    }
  } catch (e) {
    console.error("users.to-ids", e);
  }
  try {
    const q = encodeURIComponent(username);
    const res2 = await fetch(
      `https://users.roblox.com/v1/users/search?keyword=${q}&limit=10`,
      {
        headers: {
          Accept: "application/json",
          "User-Agent": headers["User-Agent"],
        },
      }
    );
    const text2 = await res2.text();
    let data2 = null;
    try { data2 = JSON.parse(text2); } catch (_) {}
    if (res2.status === 429) return { ok: false, reason: "roblox_users_http_429" };
    if (res2.ok && data2) {
      const row2 = (data2.data || []).find(
        (x) => String(x.name || "").toLowerCase() === username.toLowerCase()
      );
      if (row2 && row2.id != null) {
        return { ok: true, userId: String(row2.id), name: row2.name || username };
      }
      return { ok: false, reason: "username_not_found" };
    }
    return { ok: false, reason: "roblox_users_http_" + res2.status };
  } catch (e) {
    console.error("users.search", e);
    return { ok: false, reason: "roblox_users_network" };
  }
}
async function ownsGamePass(userId, gamePassId) {
  const url =
    `https://inventory.roblox.com/v1/users/${encodeURIComponent(userId)}` +
    `/items/GamePass/${encodeURIComponent(gamePassId)}`;
  const res = await fetch(url, {
    headers: {
      Accept: "application/json",
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    },
    cf: { cacheTtl: 0, cacheEverything: false },
  });
  if (res.status === 429) return { ok: false, reason: "inventory_http_429" };
  if (res.status === 403) return { ok: false, reason: "inventory_private" };
  if (res.status === 404) return { ok: true, owned: false };
  if (!res.ok) return { ok: false, reason: "inventory_http_" + res.status };
  const data = await res.json();
  const list = data.data || data;
  const owned = Array.isArray(list) && list.length > 0;
  return { ok: true, owned };
}
async function handleRedeemGamepass(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({
      success: false,
      reason: "invalid_json",
      support: REDEEM_SUPPORT_HINT,
      discord: DISCORD_REDEEM_CHANNEL,
    }, 400);
  }
  const plan = typeof body.plan === "string" ? body.plan.trim().toLowerCase() : "";
  const username = typeof body.username === "string" ? body.username.trim() : "";
  const inventoryPublic = body.inventory_public === true || body.inventoryPublic === true;
  if (!GAMEPASS_BY_PLAN[plan]) {
    return json({
      success: false,
      reason: "invalid_plan",
      allowed: Object.keys(GAMEPASS_BY_PLAN),
      support: REDEEM_SUPPORT_HINT,
      discord: DISCORD_REDEEM_CHANNEL,
    }, 400);
  }
  if (!username || username.length < 3 || username.length > 20 || !/^[A-Za-z0-9_]+$/.test(username)) {
    return json({
      success: false,
      reason: "invalid_username",
      support: REDEEM_SUPPORT_HINT,
      discord: DISCORD_REDEEM_CHANNEL,
    }, 400);
  }
  if (!inventoryPublic) {
    return json({
      success: false,
      reason: "inventory_checkbox_required",
      message: "Set Roblox inventory to Everyone and check the box.",
      support: REDEEM_SUPPORT_HINT,
      discord: DISCORD_REDEEM_CHANNEL,
    }, 400);
  }
  const gamepassId = GAMEPASS_BY_PLAN[plan];
  const byName = await env.DB.prepare(
    `SELECT key_value, plan, user_id FROM pass_redemptions
     WHERE lower(username) = lower(?) AND gamepass_id = ?
     LIMIT 1`
  )
    .bind(username, gamepassId)
    .first();
  if (byName) {
    return json({
      success: true,
      already_redeemed: true,
      key: byName.key_value,
      plan: byName.plan,
      message: "This Game Pass was already redeemed. Showing existing key.",
    });
  }
  const user = await robloxUserIdFromUsername(username);
  if (!user.ok) {
    const msg = String(user.reason || "").includes("429")
      ? "Roblox rate limit. Wait 1-2 minutes and try again."
      : "Could not resolve Roblox username.";
    return json({
      success: false,
      reason: user.reason,
      message: msg,
      support: REDEEM_SUPPORT_HINT,
      discord: DISCORD_REDEEM_CHANNEL,
    }, 400);
  }
  const byId = await env.DB.prepare(
    `SELECT key_value, plan FROM pass_redemptions
     WHERE user_id = ? AND gamepass_id = ? LIMIT 1`
  )
    .bind(user.userId, gamepassId)
    .first();
  if (byId) {
    return json({
      success: true,
      already_redeemed: true,
      key: byId.key_value,
      plan: byId.plan,
      message: "This Game Pass was already redeemed. Showing existing key.",
    });
  }
  const own = await ownsGamePass(user.userId, gamepassId);
  if (!own.ok) {
    let msg = "Could not check Game Pass ownership.";
    if (own.reason === "inventory_private") {
      msg = "Inventory is private. Set Who can see my inventory = Everyone, wait 1-2 min, retry.";
    } else if (String(own.reason).includes("429")) {
      msg = "Roblox rate limit. Wait 1-2 minutes and try again.";
    }
    return json({
      success: false,
      reason: own.reason,
      message: msg,
      support: REDEEM_SUPPORT_HINT,
      discord: DISCORD_REDEEM_CHANNEL,
    }, 400);
  }
  if (!own.owned) {
    return json({
      success: false,
      reason: "not_owned",
      message: "Game Pass not found on this account. Buy it, wait ~30s, retry.",
      store: GAMEPASS_STORE[plan],
      support: REDEEM_SUPPORT_HINT,
      discord: DISCORD_REDEEM_CHANNEL,
    }, 404);
  }
  const key = generateKey();
  const timestamp = now();
  const expires = timestamp + planTtl(plan);
  try {
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO keys (key, username, session_id, created_at, expires_at, revoked, executed, last_execution, plan, activated)
         VALUES (?, ?, ?, ?, ?, 0, 0, NULL, ?, 0)`
      ).bind(key, user.name || username, "pass:" + gamepassId, timestamp, expires, plan),
      env.DB.prepare(
        `INSERT INTO pass_redemptions (user_id, username, gamepass_id, plan, key_value, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`
      ).bind(user.userId, user.name || username, gamepassId, plan, key, timestamp),
    ]);
  } catch (e) {
    const again = await env.DB.prepare(
      `SELECT key_value, plan FROM pass_redemptions WHERE user_id = ? AND gamepass_id = ? LIMIT 1`
    )
      .bind(user.userId, gamepassId)
      .first();
    if (again) {
      return json({
        success: true,
        already_redeemed: true,
        key: again.key_value,
        plan: again.plan,
      });
    }
    console.error("redeem insert", e);
    return json({
      success: false,
      reason: "db_error",
      message: "Database error while creating key.",
      support: REDEEM_SUPPORT_HINT,
      discord: DISCORD_REDEEM_CHANNEL,
    }, 500);
  }
  return json({
    success: true,
    key,
    plan,
    expires_at: expires,
    username: user.name || username,
    user_id: user.userId,
  });
}

/* ===================== LUA PROXY ===================== */
async function proxyGithub(file) {
  const response = await fetch(`${GH}/${file}`, { cf: { cacheTtl: 0, cacheEverything: false } });
  if (!response.ok) return plain(`${file} not found`, 404);
  return plain(await response.text(), 200);
}

/* ===================== OBFUSCATOR v2 (Shamir layer + API + long-bracket) ===================== */
const PLUGIN_DEFS = [
  { key: "EncryptStrings", label: "Encrypt Strings", args: [100] },
  { key: "SwizzleLookups", label: "Swizzle Lookups / Table indirection", args: [100] },
  { key: "TableIndirection", label: "Table Indirection", args: [100] },
  { key: "EncryptFuncDeclaration", label: "Encrypt Func Declaration", args: [] },
  { key: "ControlFlowFlattenV1AllBlocks", label: "Control Flow Flatten V1", args: [75] },
  { key: "ControlFlowFlattenAllBlocks", label: "Control Flow Flatten (alt)", args: [75] },
  { key: "RevertAllIfStatements", label: "Revert If Statements", args: [50] },
  { key: "JunkifyAllIfStatements", label: "Junkify If Statements", args: [50] },
  { key: "MixedBooleanArithmetic", label: "Mixed Boolean Arithmetic", args: [75] },
  { key: "MutateAllLiterals", label: "Mutate Literals", args: [50] },
  { key: "DummyFunctionArgs", label: "Dummy Function Args", args: [1, 3] },
];

/** Safe API presets — Virtualize off by default (breaks Luau often) */
function presetConfig(preset) {
  if (preset === "basic" || preset === "light" || preset === "safe") {
    return {
      MinifiyAll: true,
      Virtualize: false,
      CustomPlugins: {
        SwizzleLookups: [100],
        EncryptStrings: [100],
        TableIndirection: [100],
      },
    };
  }
  if (preset === "medium" || preset === "standard" || preset === "shamir") {
    return {
      MinifiyAll: true,
      Virtualize: false,
      CustomPlugins: {
        SwizzleLookups: [100],
        EncryptStrings: [100],
        TableIndirection: [100],
        ControlFlowFlattenV1AllBlocks: [60],
        MutateAllLiterals: [35],
        JunkifyAllIfStatements: [30],
      },
    };
  }
  if (preset === "excellent") {
    return {
      MinifiyAll: true,
      Virtualize: true,
      CustomPlugins: {
        SwizzleLookups: [100],
        EncryptStrings: [100],
        TableIndirection: [100],
        ControlFlowFlattenV1AllBlocks: [75],
        MutateAllLiterals: [40],
        JunkifyAllIfStatements: [35],
        RevertAllIfStatements: [40],
      },
    };
  }
  if (preset === "full" || preset === "heavy") {
    return {
      MinifiyAll: true,
      Virtualize: false,
      CustomPlugins: {
        SwizzleLookups: [100],
        EncryptStrings: [100],
        TableIndirection: [100],
        EncryptFuncDeclaration: [],
        ControlFlowFlattenV1AllBlocks: [85],
        RevertAllIfStatements: [50],
        MixedBooleanArithmetic: [50],
        MutateAllLiterals: [50],
        JunkifyAllIfStatements: [40],
      },
    };
  }
  if (preset === "vm") {
    return {
      MinifiyAll: true,
      Virtualize: true,
      CustomPlugins: {
        SwizzleLookups: [100],
        EncryptStrings: [100],
        TableIndirection: [100],
        ControlFlowFlattenV1AllBlocks: [75],
      },
    };
  }
  return {
    MinifiyAll: true,
    Virtualize: false,
    CustomPlugins: {
      SwizzleLookups: [100],
      EncryptStrings: [100],
      TableIndirection: [100],
    },
  };
}

function buildConfigFromOptions(options) {
  const cfg = { MinifiyAll: true, Virtualize: !!options.Virtualize, CustomPlugins: {} };
  for (const def of PLUGIN_DEFS) {
    if (options[def.key]) {
      cfg.CustomPlugins[def.key] = def.args && def.args.length ? def.args : [];
    }
  }
  return cfg;
}

/** Minify to one line; preserve strings & long brackets */
function minifyOneLine(code) {
  if (typeof code !== "string") return "";
  let out = "";
  let i = 0;
  const n = code.length;
  while (i < n) {
    const c = code[i];
    // long string [=[...]=]
    if (c === "[" && code[i + 1] === "[") {
      let eq = 0;
      let j = i + 1;
      // actually [====[ form
    }
    if (c === "[") {
      let k = i + 1;
      let eqs = 0;
      while (k < n && code[k] === "=") {
        eqs++;
        k++;
      }
      if (k < n && code[k] === "[") {
        const open = code.slice(i, k + 1);
        const close = "]" + "=".repeat(eqs) + "]";
        const end = code.indexOf(close, k + 1);
        if (end !== -1) {
          out += code.slice(i, end + close.length);
          i = end + close.length;
          continue;
        }
      }
    }
    // single / double strings
    if (c === '"' || c === "'") {
      const q = c;
      out += c;
      i++;
      while (i < n) {
        out += code[i];
        if (code[i] === "\\" && i + 1 < n) {
          out += code[i + 1];
          i += 2;
          continue;
        }
        if (code[i] === q) {
          i++;
          break;
        }
        i++;
      }
      continue;
    }
    // line comments
    if (c === "-" && code[i + 1] === "-") {
      if (code[i + 2] === "[") {
        // block comment --[=[ ]=]
        let k = i + 2;
        let eqs = 0;
        if (code[k] === "[") {
          k++;
          while (k < n && code[k] === "=") {
            eqs++;
            k++;
          }
          if (code[k] === "[") {
            const close = "]" + "=".repeat(eqs) + "]";
            const end = code.indexOf(close, k + 1);
            if (end !== -1) {
              i = end + close.length;
              continue;
            }
          }
        }
      }
      // -- line
      while (i < n && code[i] !== "\n") i++;
      continue;
    }
    // whitespace collapse
    if (c === " " || c === "\t" || c === "\n" || c === "\r") {
      // keep single space only if needed between alnum
      const prev = out.length ? out[out.length - 1] : "";
      let j = i;
      while (j < n && /\s/.test(code[j])) j++;
      const next = j < n ? code[j] : "";
      if (/[A-Za-z0-9_]/.test(prev) && /[A-Za-z0-9_]/.test(next)) {
        out += " ";
      }
      i = j;
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

/** If script contains long-bracket literals, scramble/minify their *contents* */
function processLongBrackets(code) {
  let i = 0;
  let out = "";
  const n = code.length;
  while (i < n) {
    if (code[i] === "[") {
      let k = i + 1;
      let eqs = 0;
      while (k < n && code[k] === "=") {
        eqs++;
        k++;
      }
      if (k < n && code[k] === "[") {
        const close = "]" + "=".repeat(eqs) + "]";
        const contentStart = k + 1;
        const end = code.indexOf(close, contentStart);
        if (end !== -1) {
          let inner = code.slice(contentStart, end);
          // only touch if looks like code (has function/local/end)
          if (/\b(function|local|end|return)\b/.test(inner) && inner.length > 40) {
            inner = minifyOneLine(inner);
            // light string noise: wrap as still valid Lua code inside
            inner = localStringEncrypt(inner);
            inner = minifyOneLine(inner);
          } else {
            inner = minifyOneLine(inner);
          }
          out += code.slice(i, contentStart) + inner + close;
          i = end + close.length;
          continue;
        }
      }
    }
    out += code[i];
    i++;
  }
  return out;
}

/** Simple local string encrypt for offline layer */
function localStringEncrypt(code) {
  // replace "..." string literals with (_G[string.char(...)] pattern) — only plain double quotes, no escapes heavy
  return code.replace(/"([^"\\]{3,80})"/g, (m, s) => {
    const bytes = [];
    for (let i = 0; i < s.length; i++) bytes.push(s.charCodeAt(i));
    return `(string.char(${bytes.join(",")}))`;
  });
}

/** Shamir runtime (fixed) — reconstruct only; shares are compile-time constants */
const SHAMIR_RUNTIME = `
local __P=257
local function __modinv(a,m)a=a%m;local r0,r1,s0,s1=a,m,1,0;while r1~=0 do local q=math.floor(r0/r1);r0,r1=r1,r0-q*r1;s0,s1=s1,s0-q*s1 end;return s0%m end
local function __recon(points)local secret=0;for i=1,#points do local xi,yi=points[i][1],points[i][2];local num,den=1,1;for j=1,#points do if j~=i then local xj=points[j][1];num=(num*(-xj))%__P;den=(den*(xi-xj))%__P end end;secret=(secret+yi*num%__P*__modinv(den,__P))%__P end;return secret%__P end
`.replace(/\n+/g, " ");

/** Deterministic shares for small secrets (offline, no math.random in shipped code) */
function makeSharesDeterministic(secret, threshold, shareCount, seed) {
  const P = 257;
  const coeffs = [secret % P];
  let s = seed >>> 0;
  for (let i = 1; i < threshold; i++) {
    s = (s * 1664525 + 1013904223) >>> 0;
    coeffs.push((s % (P - 1)) + 1);
  }
  const shares = [];
  for (let x = 1; x <= shareCount; x++) {
    let y = 0;
    let xp = 1;
    for (let i = 0; i < coeffs.length; i++) {
      y = (y + coeffs[i] * xp) % P;
      xp = (xp * x) % P;
    }
    shares.push([x, y]);
  }
  return shares;
}

/**
 * Optional Shamir layer: rewrite simple numeric state assigns when safe.
 * Only touches patterns:  state = N  /  state=N  for small N (1..64)
 * Leaves logic equivalent via __recon(fixed shares)
 */
function applyShamirLayer(code) {
  let seed = 0xC0FFEE;
  const out = code.replace(
    /\b(state|_s|st)\s*=\s*(\d{1,2})\b/g,
    (m, name, num) => {
      const n = parseInt(num, 10);
      if (n < 1 || n > 64) return m;
      seed = (seed * 1103515245 + 12345) >>> 0;
      const shares = makeSharesDeterministic(n, 2, 3, seed);
      // use first 2 shares
      const a = shares[0];
      const b = shares[1];
      return `${name}=__recon({{${a[0]},${a[1]}},{${b[0]},${b[1]}}})`;
    }
  );
  if (out === code) {
    return SHAMIR_RUNTIME + "\n" + code;
  }
  return SHAMIR_RUNTIME + "\n" + out;
}

function localObfuscate(code, level) {
  level = level || 1;
  let c = String(code || "");
  c = processLongBrackets(c);
  if (level >= 1) {
    c = localStringEncrypt(c);
  }
  if (level >= 2) {
    c = applyShamirLayer(c);
  }
  c = minifyOneLine(c);
  return c;
}

function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, rej) => setTimeout(() => rej(new Error("timeout " + ms + "ms")), ms)),
  ]);
}

async function callLuaObfOnce(apiKey, code, cfg, ep) {
  const newRes = await fetch(ep.newscript, {
    method: "POST",
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      apikey: apiKey,
    },
    body: code,
  });
  const newText = await newRes.text();
  let newJson = null;
  try {
    newJson = JSON.parse(newText);
  } catch (_) {}
  const sessionId =
    (newJson && (newJson.sessionId || newJson.sessionid)) ||
    newRes.headers.get("sessionId") ||
    newRes.headers.get("sessionid");
  if (!sessionId) {
    return {
      ok: false,
      error: `newscript ${ep.newscript} HTTP ${newRes.status}: ${(newText || "").slice(0, 200)}`,
    };
  }
  const runRes = await fetch(ep.obfuscate, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      apikey: apiKey,
      sessionId: String(sessionId),
    },
    body: JSON.stringify(cfg),
  });
  const t = await runRes.text();
  let data = null;
  try {
    data = JSON.parse(t);
  } catch (_) {
    return { ok: false, error: `obfuscate invalid JSON HTTP ${runRes.status}: ${t.slice(0, 200)}` };
  }
  if (!runRes.ok) {
    return {
      ok: false,
      error: `obfuscate HTTP ${runRes.status}: ${String(data.message || data.error || t).slice(0, 280)}`,
    };
  }
  if (data.message && !data.code) {
    return { ok: false, error: String(data.message) };
  }
  if (!data.code || typeof data.code !== "string") {
    return { ok: false, error: "obfuscate: empty code" };
  }
  // Detect broken upstream VM (IronBrew / missing assemblies)
  const head = data.code.slice(0, 200);
  if (/IronBrew|FileNotFoundException|System\.IO\.Pipes/i.test(data.code) ||
      /IronBrew|FileNotFoundException|System\.IO\.Pipes/i.test(String(data.message || ""))) {
    return { ok: false, error: "upstream VM broken (IronBrew)" };
  }
  return { ok: true, code: data.code, sessionId: String(sessionId), endpoint: ep.newscript };
}

async function callLuaObf(apiKey, code, cfg) {
  // Prefer non-VM config when Virtualize fails upstream
  const attempts = [];
  attempts.push(cfg);
  if (cfg && cfg.Virtualize) {
    attempts.push({
      ...cfg,
      Virtualize: false,
      CustomPlugins: { ...(cfg.CustomPlugins || {}) },
    });
  }
  let lastErr = "no endpoints";
  for (const ep of LUAOBF_ENDPOINTS) {
    for (const tryCfg of attempts) {
      try {
        const r = await withTimeout(callLuaObfOnce(apiKey, code, tryCfg, ep), 28000);
        if (r.ok) {
          if (tryCfg.Virtualize === false && cfg.Virtualize) {
            r.note = "API without Virtualize (VM upstream broken)";
          }
          return r;
        }
        lastErr = r.error || lastErr;
      } catch (e) {
        lastErr = String(e && e.message ? e.message : e);
      }
    }
  }
  return { ok: false, error: lastErr };
}

/** Full pipeline used by /api/obfuscate */
async function runObfuscatePipeline(code, preset, apiKey, options) {
  // UI levels → internal modes
  if (preset === "minimum") preset = "local";
  else if (preset === "good") preset = "safe";
  else if (preset === "excellent") preset = "excellent"; // keep name → Virtualize on
  else if (preset === "all" || preset === "all_plugins") preset = "custom";
  // 1) always process long-bracket *contents* first (user request)
  let stage = processLongBrackets(code);

  // 2) local minify pass before API (smaller upload)
  const preMin = minifyOneLine(stage);

  if (preset === "local" || preset === "minify") {
    return {
      ok: true,
      code: minifyOneLine(localStringEncrypt(stage)),
      mode: "local_minify",
      note: "local one-line + string char encode; long-brackets processed",
    };
  }

  if (preset === "shamir_only") {
    return {
      ok: true,
      code: minifyOneLine(applyShamirLayer(processLongBrackets(code))),
      mode: "shamir_local",
      note: "Shamir reconstruct layer + long-brackets + one-line (no API)",
    };
  }

  const cfg =
    preset === "custom"
      ? buildConfigFromOptions(options || {})
      : presetConfig(preset);

  // VM only for explicit presets (excellent / vm / full)
  if (preset !== "vm" && preset !== "excellent" && preset !== "full") {
    cfg.Virtualize = false;
  }
  if (preset === "excellent" || preset === "vm" || preset === "full") {
    cfg.Virtualize = true;
  }
  cfg.MinifiyAll = true;

  try {
    const result = await withTimeout(callLuaObf(apiKey, preMin.length < 900000 ? preMin : stage, cfg), 25000);
    if (result && result.ok && result.code) {
      let finalCode = result.code;
      // 3) post: one-line + optional shamir wrapper on API output for "shamir" preset
      if (preset === "shamir" || preset === "standard") {
        // inject runtime only if not already minified heavily — still add reconstruct helper
        if (!finalCode.includes("__recon")) {
          finalCode = SHAMIR_RUNTIME + " " + finalCode;
        }
      }
      finalCode = minifyOneLine(finalCode);
      return {
        ok: true,
        code: finalCode,
        mode: preset,
        sessionId: result.sessionId,
        note: "API (" + preset + ") + long-brackets pre + one-line post",
      };
    }
    const err = (result && result.error) || "api failed";
    const short = String(err).replace(/\s+/g, " ").slice(0, 160);
    // Stronger local when API/VM is down
    return {
      ok: true,
      code: localObfuscate(code, 2),
      mode: preset + "_local",
      note: "API fail → local JS: " + short,
    };
  } catch (e) {
    return {
      ok: true,
      code: localObfuscate(code, 2),
      mode: preset + "_local",
      note: "API error → local JS: " + String(e && e.message ? e.message : e).slice(0, 160),
    };
  }
}

function obfuscatePage(siteName) {
  return siteShell("Obfuscator", "obfuscator", `
  <div class="badge">Tools</div>
  <h1>Lua Obfuscator</h1>
  <p class="sub">Long-bracket contents processed when present · safe API plugins · optional Shamir helper · one-line minify</p>
  <div class="card">
    <label class="f">Level</label>
    <select id="preset" class="f" style="width:100%;margin-bottom:12px;padding:10px;border-radius:8px;background:var(--bg2);color:var(--text);border:1px solid var(--border)">
      <option value="minimum">Minimum — minify + string encode (local)</option>
      <option value="good" selected>Good — API strings + table indirection + one-line</option>
      <option value="excellent">Excellent — API + control-flow + Virtual Machine + one-line</option>
      <option value="custom">All plugins + Custom</option>
    </select>
    <div id="customBox" style="display:none;margin-bottom:12px">
      <label class="f">Plugins</label>
      <div id="plugins" style="display:flex;flex-wrap:wrap;gap:10px;margin-top:6px"></div>
      <label style="display:flex;gap:8px;align-items:center;margin-top:8px;color:var(--muted);font-size:13px">
        <input type="checkbox" id="opt_vm"/> Include Virtualize (may break Luau)
      </label>
    </div>
    <label class="f">Source</label>
    <textarea id="code" class="f" style="width:100%;min-height:220px;margin-bottom:10px;padding:12px;border-radius:8px;background:var(--bg2);color:var(--text);border:1px solid var(--border);font-family:ui-monospace,monospace" placeholder="Paste Lua source"></textarea>
    <div style="display:flex;flex-wrap:wrap;gap:8px">
      <button type="button" class="btn btn-gold" id="go">Obfuscate</button>
      <button type="button" class="btn" id="copy">Copy output</button>
    </div>
    <p id="status" class="muted" style="margin-top:10px"></p>
    <label class="f" style="margin-top:12px">Output</label>
    <textarea id="out" readonly class="f" style="width:100%;min-height:180px;padding:12px;border-radius:8px;background:var(--bg2);color:var(--text);border:1px solid var(--border);font-family:ui-monospace,monospace"></textarea>
  </div>
  <script>
  (function(){
    const PLUGIN_DEFS = [
      {key:"EncryptStrings",label:"Encrypt Strings"},
      {key:"SwizzleLookups",label:"Swizzle Lookups"},
      {key:"TableIndirection",label:"Table Indirection"},
      {key:"ControlFlowFlattenV1AllBlocks",label:"Control-flow flatten"},
      {key:"RevertAllIfStatements",label:"Revert ifs"},
      {key:"JunkifyAllIfStatements",label:"Junkify ifs"},
      {key:"MixedBooleanArithmetic",label:"MBA"},
      {key:"MutateAllLiterals",label:"Mutate literals"},
      {key:"EncryptFuncDeclaration",label:"Encrypt func decl"},
      {key:"DummyFunctionArgs",label:"Dummy args"}
    ];
    const preset = document.getElementById("preset");
    const customBox = document.getElementById("customBox");
    const plugins = document.getElementById("plugins");
    PLUGIN_DEFS.forEach(function(p){
      const lab = document.createElement("label");
      lab.style.cssText = "display:flex;gap:6px;align-items:center;color:var(--muted);font-size:13px";
      lab.innerHTML = '<input type="checkbox" id="p_'+p.key+'" checked/> '+p.label;
      plugins.appendChild(lab);
    });
    preset.onchange = function(){
      customBox.style.display = preset.value === "custom" ? "block" : "none";
    };
    function collectOptions(){
      const o = { Virtualize: !!document.getElementById("opt_vm").checked };
      PLUGIN_DEFS.forEach(function(p){
        const el = document.getElementById("p_"+p.key);
        o[p.key] = !!(el && el.checked);
      });
      return o;
    }
    document.getElementById("go").onclick = async function(){
      const code = document.getElementById("code").value;
      const statusEl = document.getElementById("status");
      const out = document.getElementById("out");
      if (!code || code.trim().length < 2) {
        statusEl.className = "err";
        statusEl.textContent = "Empty source";
        return;
      }
      statusEl.className = "muted";
      statusEl.textContent = "Working...";
      out.value = "";
      try {
        const res = await fetch("/api/obfuscate", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ preset: preset.value, options: collectOptions(), code: code })
        });
        const data = await res.json();
        if (!data.ok) {
          statusEl.className = "err";
          statusEl.textContent = data.error || res.status;
          return;
        }
        out.value = data.code || "";
        statusEl.className = "ok";
        statusEl.textContent = "OK · " + (data.mode||"") + " · " + (data.code||"").length + " chars · " + (data.note||"");
      } catch (e) {
        statusEl.className = "err";
        statusEl.textContent = String(e);
      }
    };
    document.getElementById("copy").onclick = async function(){
      try {
        await navigator.clipboard.writeText(document.getElementById("out").value);
        document.getElementById("status").className = "ok";
        document.getElementById("status").textContent = "Copied";
      } catch (e) {}
    };
  })();
  </script>
`, true);
}

function siteNav(active) {
  const items = [
    ["home", "/home", "Home"],
    ["pricing", "/pricing", "Pricing"],
    ["obfuscator", "/obfuscator", "Obfuscator"],
    ["executors", "/executors", "Executors"],
    ["guide", "/guide", "Guide"],
    ["status", "/status", "Status"],
    ["tos", "/tos", "ToS"],
  ];
  return items
    .map(([id, href, label]) => {
      const cls = active === id ? ' class="active"' : "";
      return "<a href=\"" + href + "\"" + cls + ">" + label + "</a>";
    })
    .join("");
}

function siteShell(title, active, bodyHtml, wide = false) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${title} · Greedy Hudzell</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet"/>
<style>
:root{
  --bg:#0a0a0a;--bg2:#111;--card:#141414;--border:#2a2a2a;
  --text:#f2f2f2;--muted:#9a9a9a;--gold:#C9A227;--gold-soft:#E8C547;
  --ok:#4caf7a;--bad:#e85d5d;--radius:16px;
}
*{box-sizing:border-box;margin:0;padding:0}
body{
  font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);
  min-height:100vh;line-height:1.55;
  background-image:
    radial-gradient(ellipse 80% 50% at 50% -20%,rgba(201,162,39,.08),transparent),
    radial-gradient(ellipse 60% 40% at 100% 100%,rgba(255,255,255,.03),transparent);
}
a{color:var(--gold-soft);text-decoration:none}
a:hover{text-decoration:underline}
.wrap{width:min(980px,94vw);margin:0 auto;padding:28px 0 80px}
.wrap.wide{width:min(1100px,94vw)}
.top{
  position:sticky;top:0;z-index:50;backdrop-filter:blur(14px);
  background:rgba(10,10,10,.78);border-bottom:1px solid var(--border);
}
.top-inner{
  width:min(1100px,94vw);margin:0 auto;display:flex;align-items:center;
  justify-content:space-between;gap:16px;padding:14px 0;flex-wrap:wrap;
}
.brand{display:flex;align-items:center;gap:12px;font-weight:700;color:var(--text);text-decoration:none}
.brand:hover{text-decoration:none}
.brand-mark{
  width:34px;height:34px;border-radius:10px;
  background:linear-gradient(135deg,#1a1a1a,#2a2410);
  border:1px solid var(--gold);display:grid;place-items:center;
  color:var(--gold);font-size:14px;font-weight:700;
}
.nav{display:flex;flex-wrap:wrap;gap:6px}
.nav a{
  color:var(--muted);padding:8px 14px;border-radius:999px;
  border:1px solid transparent;font-size:13px;font-weight:500;text-decoration:none;
}
.nav a:hover{color:var(--text);border-color:var(--border);background:var(--card);text-decoration:none}
.nav a.active{color:#0a0a0a;background:var(--gold);border-color:var(--gold)}
.page-header{margin:28px 0 22px}
.page-header h1{font-size:1.85rem;font-weight:700;margin-bottom:6px}
.page-header .sub{color:var(--muted);font-size:14px}
.badge{
  display:inline-block;font-size:11px;font-weight:600;padding:2px 8px;
  border-radius:999px;background:rgba(201,162,39,.12);color:var(--gold);
  border:1px solid rgba(201,162,39,.25);margin-bottom:14px;
}
.card{
  background:var(--card);border:1px solid var(--border);border-radius:var(--radius);
  padding:18px;margin:12px 0;
}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:720px){.grid2{grid-template-columns:1fr}}
label.f{display:block;color:var(--muted);font-size:12px;margin:10px 0 6px;font-weight:600}
input,select,textarea{
  width:100%;border-radius:10px;border:1px solid var(--border);
  background:#0c0c0c;color:var(--text);padding:11px 12px;font-size:13px;
}
input:focus,select:focus,textarea:focus{outline:1px solid rgba(201,162,39,.4)}
.btn{
  display:inline-flex;align-items:center;justify-content:center;gap:8px;
  padding:11px 16px;border-radius:999px;border:1px solid var(--border);
  background:var(--bg2);color:var(--text);font-weight:600;font-size:13px;
  cursor:pointer;text-decoration:none;
}
.btn:hover{border-color:var(--gold);color:var(--gold-soft);text-decoration:none}
.btn-gold{
  background:linear-gradient(135deg,var(--gold),#a8841a);
  color:#0a0a0a;border-color:var(--gold);
}
.btn-gold:hover{color:#0a0a0a;filter:brightness(1.05);text-decoration:none}
.muted{color:var(--muted);font-size:13px}
.ok{color:var(--ok)}
.err{color:var(--bad)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--border)}
th{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.04em}
.hero-actions{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}
.price-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:18px 0}
@media(max-width:900px){.price-grid{grid-template-columns:1fr 1fr}}
@media(max-width:520px){.price-grid{grid-template-columns:1fr}}
.price-card{
  background:var(--card);border:1px solid var(--border);border-radius:var(--radius);
  padding:18px;display:flex;flex-direction:column;gap:8px;position:relative;
}
.price-card.featured{border-color:var(--gold);box-shadow:0 0 0 1px rgba(201,162,39,.2)}
.price-card .tag{
  position:absolute;top:12px;right:12px;font-size:10px;font-weight:700;
  background:var(--gold);color:#0a0a0a;padding:3px 8px;border-radius:999px;
}
.price-card h3{font-size:1rem;font-weight:600}
.price-card .amount{font-size:1.7rem;font-weight:700;color:var(--gold-soft)}
.price-card .amount span{font-size:12px;color:var(--muted);font-weight:500}
.price-card ul{list-style:none;padding:0;margin:6px 0;flex:1}
.price-card ul li{font-size:13px;color:#c8c8c8;padding:4px 0 4px 16px;position:relative}
.price-card ul li::before{content:"✓";position:absolute;left:0;color:var(--gold);font-size:12px}
.foot{margin-top:32px;text-align:center;color:#555;font-size:12px}
</style>
</head>
<body>
<header class="top">
  <div class="top-inner">
    <a class="brand" href="/home">
      <div class="brand-mark">GH</div>
      <span>Greedy Hudzell</span>
    </a>
    <nav class="nav">${siteNav(active)}</nav>
  </div>
</header>
<main class="wrap${wide ? " wide" : ""}">
${bodyHtml}
  <div class="foot">© Greedy Hudzell · <a href="${DISCORD_INVITE}">Discord</a> · Not affiliated with Roblox</div>
</main>
</body>
</html>`;
}

function fmtSunc(v) {
  if (v == null || v === "") return "—";
  if (typeof v === "number" || typeof v === "boolean") {
    return String(v) + (typeof v === "number" && !String(v).includes("%") ? "%" : "");
  }
  if (typeof v === "string") {
    const t = v.trim();
    if (!t) return "—";
    if (/^\d+(\.\d+)?$/.test(t)) return t + "%";
    return t;
  }
  if (typeof v === "object") {
    // weao.xyz: real score is suncPercentage / uncPercentage; `sunc` is metadata keys only
    if (v.suncPercentage != null) return fmtSunc(v.suncPercentage);
    if (v.uncPercentage != null) return fmtSunc(v.uncPercentage);
    if (v.percentage != null) return fmtSunc(v.percentage);
    if (v.percent != null) return fmtSunc(v.percent);
    if (v.score != null && typeof v.score !== "object") return fmtSunc(v.score);
    // ignore suncScrap / suncKey blobs
    if (v.suncScrap != null || v.suncKey != null) return "—";
    return "—";
  }
  return "—";
}

function homePage() {
  return siteShell("Home", "home", `
  <div class="badge">Official</div>
  <h1>Greedy Hudzell</h1>
  <p class="sub">Keys, loader, updates. Check your key status below.</p>
  <div class="hero-actions">
    <a class="btn btn-gold" href="${FREE_KEY_LINK}" target="_blank" rel="noopener">Get free key</a>
    <a class="btn" href="/pricing">Pricing</a>
    <a class="btn" href="${DISCORD_INVITE}" target="_blank" rel="noopener">Discord</a>
  </div>
  <div class="grid2">
    <div class="card">
      <h3 style="margin-bottom:8px">Key status</h3>
      <label class="f">Key</label>
      <input id="k_key" placeholder="GH-XXXX-XXXX-XXXX" autocomplete="off"/>
      <label class="f">Roblox username</label>
      <input id="k_user" placeholder="Not display name" autocomplete="off"/>
      <button class="btn btn-gold" style="margin-top:12px;width:100%" id="k_btn" type="button">Check key</button>
      <p id="k_out" class="muted" style="margin-top:12px;white-space:pre-wrap"></p>
    </div>
    <div class="card">
      <h3 style="margin-bottom:8px">Loader</h3>
      <p class="muted" style="word-break:break-all"><code>loadstring(game:HttpGet("https://greedyhudzell.xyz/loader.lua"))()</code></p>
      <p class="muted" style="margin-top:12px"><a href="/guide">Guide</a> · <a href="/executors">Executors</a> · <a href="/status">Status</a></p>
    </div>
  </div>
<script>
(function(){
  const out=document.getElementById('k_out');
  const btn=document.getElementById('k_btn');
  btn.onclick=async function(){
    const key=(document.getElementById('k_key').value||'').trim();
    const username=(document.getElementById('k_user').value||'').trim();
    if(!key||!username){out.className='err';out.textContent='Enter key and username.';return;}
    out.className='muted';out.textContent='Checking...';btn.disabled=true;
    try{
      const res=await fetch('/validate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key,username})});
      const data=await res.json();
      if(data.valid===true){
        out.className='ok';
        const exp=data.expires_at?new Date(Number(data.expires_at)*1000).toUTCString():'n/a';
        out.textContent='VALID\\nPlan: '+(data.plan||'n/a')+'\\nExpires: '+exp;
      }else{out.className='err';out.textContent='INVALID — '+(data.reason||res.status);}
    }catch(e){out.className='err';out.textContent=String(e);}
    btn.disabled=false;
  };
})();
</script>
`, true);
}

function statusPage() {
  return siteShell("Status", "status", `
  <div class="badge">Ops</div>
  <h1>Status</h1>
  <p class="sub">Public endpoints. For live incidents use Discord status channel.</p>
  <div class="card">
    <table>
      <tr><th>Component</th><th>Note</th></tr>
      <tr><td>Website</td><td>Online</td></tr>
      <tr><td>/validate</td><td>Key API</td></tr>
      <tr><td>/loader.lua</td><td>GitHub proxy</td></tr>
      <tr><td>Work.ink free keys</td><td>Third-party flow</td></tr>
      <tr><td>Discord bot</td><td>Keys / verify / updates</td></tr>
    </table>
  </div>
`);
}

function executorsPage() {
  // Client-side fetch + safe sUNC formatting
  return siteShell("Executors", "executors", `
  <div class="badge">Compatibility</div>
  <h1>Executors</h1>
  <p class="sub">Best-effort list. Prefer tools with HTTP, files, and queue_on_teleport.</p>
  <div class="card muted" id="ex_out">Loading…</div>
<script>
function fmtPct(v){
  if(v==null||v==="")return "—";
  if(typeof v==="number")return v+"%";
  if(typeof v==="boolean")return v?"yes":"no";
  if(typeof v==="string"){
    var t=v.trim();
    if(!t)return "—";
    if(/^\d+(\.\d+)?$/.test(t))return t+"%";
    return t;
  }
  return "—";
}
function pickSunc(x){
  if(!x||typeof x!=="object")return "—";
  // weao.xyz uses suncPercentage; sunc field is metadata keys only, not a score
  if(x.suncPercentage!=null)return fmtPct(x.suncPercentage);
  if(x.uncPercentage!=null)return fmtPct(x.uncPercentage);
  if(typeof x.sunc==="number"||typeof x.sunc==="string")return fmtPct(x.sunc);
  if(typeof x.sUNC==="number"||typeof x.sUNC==="string")return fmtPct(x.sUNC);
  if(x.percentage!=null)return fmtPct(x.percentage);
  if(x.percent!=null)return fmtPct(x.percent);
  if(x.unc!=null&&(typeof x.unc==="number"||typeof x.unc==="string"))return fmtPct(x.unc);
  return "—";
}
function fmtStatus(x){
  if(x.updateStatus===true||x.updateStatus==="true"||x.updateStatus==="Updated")return "Updated";
  if(x.updateStatus===false||x.updateStatus==="false")return "Not updated";
  if(x.updateStatus!=null&&typeof x.updateStatus!=="object")return String(x.updateStatus);
  if(x.status!=null&&typeof x.status!=="object")return String(x.status);
  if(x.updatedDate)return String(x.updatedDate);
  return "—";
}
function esc(s){return String(s==null?"":s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}
(async function(){
  const el=document.getElementById("ex_out");
  try{
    const res=await fetch(${JSON.stringify(WEAO_URL)},{headers:{Accept:"application/json"}});
    if(!res.ok)throw new Error("HTTP "+res.status);
    const data=await res.json();
    const list=Array.isArray(data)?data:(data.exploits||data.data||data.results||[]);
    if(!list.length){el.textContent="Empty list from weao.xyz";return;}
    const rows=list.slice(0,50).map(function(x){
      const name=x.title||x.name||x.executor||"?";
      const st=fmtStatus(x);
      const sunc=pickSunc(x);
      const unc=x.uncPercentage!=null?fmtPct(x.uncPercentage):"—";
      return "<tr><td>"+esc(name)+"</td><td>"+esc(st)+"</td><td>"+esc(sunc)+(unc!=="—"&&unc!==sunc?" · UNC "+esc(unc):"")+"</td></tr>";
    }).join("");
    el.className="card";
    el.innerHTML="<table><thead><tr><th>Executor</th><th>Status</th><th>sUNC %</th></tr></thead><tbody>"+rows+"</tbody></table>";
  }catch(e){
    el.textContent="Could not load weao.xyz ("+e+"). Use Discord recommendations.";
  }
})();
</script>
`);
}

function guidePage() {
  return siteShell("Guide", "guide", `
  <div class="badge">Docs</div>
  <h1>Guide</h1>
  <p class="sub">Free key → loader → hub.</p>
  <div class="card">
    <p><b>1.</b> Get a key (free Work.ink or paid on Discord).</p>
    <p style="margin-top:8px"><b>2.</b> Run: <code>loadstring(game:HttpGet("https://greedyhudzell.xyz/loader.lua"))()</code></p>
    <p style="margin-top:8px"><b>3.</b> Enter key. Check status anytime on <a href="/home">Home</a>.</p>
    <p style="margin-top:8px"><b>4.</b> Stack overflow after obfuscation → use light/raw, not Full/VM.</p>
  </div>
`);
}

function pricingPage() {
  return siteShell("Pricing", "pricing", `
  <div class="page-header">
    <div class="badge">USD</div>
    <h1>Pricing</h1>
    <p class="sub">Free day key via Work.ink · Paid plans include <b>account rewire</b></p>
  </div>
  <div class="price-grid">
    <article class="price-card">
      <h3>Free</h3>
      <div class="amount">$0 <span>/ 24h</span></div>
      <ul>
        <li>Full script access</li>
        <li>1 Roblox username</li>
        <li>Work.ink unlock</li>
        <li>No rewire</li>
      </ul>
      <a class="btn" href="${FREE_KEY_LINK}" target="_blank" rel="noopener">Get free key</a>
    </article>
    <article class="price-card">
      <h3>Week</h3>
      <div class="amount">$3.99 <span>/ 7 days</span></div>
      <ul>
        <li>Full script access</li>
        <li>Account rewire included</li>
        <li>Priority Discord support</li>
      </ul>
      <a class="btn" href="${DISCORD_INVITE}" target="_blank" rel="noopener">Buy on Discord</a>
    </article>
    <article class="price-card featured">
      <span class="tag">Popular</span>
      <h3>Month</h3>
      <div class="amount">$6.99 <span>/ 30 days</span></div>
      <ul>
        <li>Full script access</li>
        <li>Account rewire included</li>
        <li>Best balance price / time</li>
      </ul>
      <a class="btn btn-gold" href="${DISCORD_INVITE}" target="_blank" rel="noopener">Buy on Discord</a>
    </article>
    <article class="price-card">
      <h3>Year</h3>
      <div class="amount">$12.99 <span>/ 365 days</span></div>
      <ul>
        <li>Full script access</li>
        <li>Account rewire included</li>
        <li>Best long-term value</li>
      </ul>
      <a class="btn" href="${DISCORD_INVITE}" target="_blank" rel="noopener">Buy on Discord</a>
    </article>
  </div>
  <p class="muted">See <a href="/tos">Terms of Service</a> for rewire, refunds, and key rules.</p>

  <div class="card" style="margin-top:18px">
    <h3>Redeem Game Pass → key</h3>
    <p class="muted">1) Buy the pass · 2) Inventory = Everyone · 3) Redeem</p>
    <label class="field">Roblox username</label>
    <input id="rp_user" maxlength="20" placeholder="Username (not display name)" autocomplete="off"/>
    <label class="field">Plan</label>
    <select id="rp_plan">
      <option value="week">Week (310 R$)</option>
      <option value="month">Month (550 R$)</option>
      <option value="year">Year (1100 R$)</option>
    </select>
    <label class="field" style="display:flex;gap:8px;align-items:center;margin-top:12px">
      <input type="checkbox" id="rp_inv" style="width:auto"/>
      My inventory is set to Everyone
    </label>
    <div style="margin-top:12px;display:flex;flex-wrap:wrap;gap:8px">
      <a class="btn" id="rp_buy" href="https://www.roblox.com/game-pass/1963350769" target="_blank" rel="noopener">Open pass store</a>
      <button type="button" class="btn btn-gold" id="rp_go">Redeem</button>
    </div>
    <p id="rp_out" class="muted" style="margin-top:12px;white-space:pre-wrap"></p>
  </div>
  <script>
  (function(){
    const stores = {
      week: "https://www.roblox.com/game-pass/1963350769",
      month: "https://www.roblox.com/game-pass/1965054742",
      year: "https://www.roblox.com/game-pass/1966320456"
    };
    const planEl = document.getElementById("rp_plan");
    const buy = document.getElementById("rp_buy");
    if (planEl && buy) planEl.onchange = function(){ buy.href = stores[planEl.value] || stores.week; };
    const go = document.getElementById("rp_go");
    if (go) go.onclick = async function(){
      const out = document.getElementById("rp_out");
      const username = (document.getElementById("rp_user").value || "").trim();
      const plan = planEl.value;
      const inventory_public = document.getElementById("rp_inv").checked;
      out.className = "muted";
      out.textContent = "Checking...";
      try {
        const res = await fetch("/redeem/gamepass", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, plan, inventory_public })
        });
        const data = await res.json();
        if (data.success && data.key) {
          out.className = "ok";
          out.textContent = (data.already_redeemed ? "Already redeemed\\n" : "OK\\n")
            + "Key: " + data.key + "\\nPlan: " + (data.plan || plan);
        } else {
          out.className = "err";
          out.textContent = (data.message || data.reason || res.status) + (data.store ? "\\n" + data.store : "");
        }
      } catch (e) {
        out.className = "err";
        out.textContent = String(e);
      }
    };
  })();
  </script>
`, true);
}

function tosPage() {
  return siteShell("ToS", "tos", `
  <div class="badge">Legal</div>
  <h1>Terms of Service</h1>
  <p class="sub">August 2026</p>
  <div class="card muted">
    <p>Free = 24h, one username, no rewire. Paid (Week $3.99 / Month $6.99 / Year $12.99) includes fair-use rewire.</p>
    <p style="margin-top:8px">No resale of keys. Sales final after key delivery. Not affiliated with Roblox. Use at your own risk.</p>
    <p style="margin-top:8px"><a href="${DISCORD_INVITE}">Discord</a></p>
  </div>
`);
}

/* ===================== ROUTER ===================== */

/* ===================== DISCORD LINK (profile / verify-key / rewire) ===================== */
function isPaidPlan(plan, key) {
  const p = String(plan || "").toLowerCase();
  if (p === "week" || p === "month" || p === "year" || p === "paid") return true;
  if (typeof key === "string" && key.startsWith("GH-PAID-")) return true;
  return false;
}
function getDiscordBotToken(env) {
  return (
    env.DISCORD_BOT_TOKEN ||
    env.DISCORD_TOKEN ||
    env.BOT_TOKEN ||
    ""
  );
}
async function discordApi(env, method, path, body) {
  const token = getDiscordBotToken(env);
  if (!token) {
    return {
      ok: false,
      status: 500,
      data: {
        message: "DISCORD_BOT_TOKEN not set",
        hint: "Set secret DISCORD_BOT_TOKEN (or DISCORD_TOKEN) on the Worker that serves greedyhudzell.xyz",
      },
    };
  }
  const res = await fetch(`https://discord.com/api/v10${path}`, {
    method,
    headers: {
      Authorization: `Bot ${token}`,
      "Content-Type": "application/json",
      "User-Agent": "GreedyHudzellWorker (https://greedyhudzell.xyz, 1.0)",
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = null;
  const textBody = await res.text();
  try {
    data = textBody ? JSON.parse(textBody) : null;
  } catch {
    data = { raw: textBody };
  }
  return { ok: res.ok, status: res.status, data };
}
function avatarUrlFromUser(user) {
  if (!user || !user.id) return null;
  if (user.avatar) {
    const ext = user.avatar.startsWith("a_") ? "gif" : "png";
    return `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.${ext}?size=128`;
  }
  let idx = 0;
  try {
    if (user.discriminator && user.discriminator !== "0") {
      idx = Number(user.discriminator) % 5;
    } else {
      idx = Number((BigInt(user.id) >> 22n) % 6n);
    }
  } catch {
    idx = 0;
  }
  return `https://cdn.discordapp.com/embed/avatars/${idx}.png`;
}

async function handleDiscordDebug(request, env) {
  const token = getDiscordBotToken(env);
  return json({
    ok: true,
    has_token: Boolean(token),
    token_len: token ? token.length : 0,
    token_prefix: token ? String(token).slice(0, 4) + "…" : null,
    guild_id: env.DISCORD_GUILD_ID || "1422222409846620201",
    member_role: env.DISCORD_MEMBER_ROLE || "1445500571640402052",
    source_names_checked: ["DISCORD_BOT_TOKEN", "DISCORD_TOKEN", "BOT_TOKEN"],
  });
}

async function handleDiscordProfile(request, env) {
  if (request.method !== "POST") return json({ ok: false, error: "method_not_allowed" }, 405);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "invalid_json" }, 400);
  }
  const discordId = String(body.discord_id || body.discordId || "").replace(/\D/g, "");
  if (!discordId || discordId.length < 16) {
    return json({ ok: false, error: "invalid_discord_id" }, 400);
  }
  const token = getDiscordBotToken(env);
  // Without bot token: still return default embed avatar so client can test getcustomasset
  if (!token) {
    let idx = 0;
    try {
      idx = Number((BigInt(discordId) >> 22n) % 6n);
    } catch {
      idx = 0;
    }
    return json({
      ok: true,
      id: discordId,
      username: null,
      global_name: null,
      discriminator: "0",
      avatar_url: `https://cdn.discordapp.com/embed/avatars/${idx}.png`,
      partial: true,
      warning: "DISCORD_BOT_TOKEN not visible on this Worker — using default avatar only. Set secret on the Worker bound to greedyhudzell.xyz",
    });
  }
  const api = await discordApi(env, "GET", `/users/${discordId}`);
  if (!api.ok) {
    return json(
      {
        ok: false,
        error: "discord_users_http",
        status: api.status,
        details: api.data,
        hint:
          api.status === 401
            ? "Invalid DISCORD_BOT_TOKEN"
            : api.status === 404
              ? "Unknown Discord user id"
              : api.status === 429
                ? "Discord rate limited — retry later"
                : "Discord API rejected the request",
      },
      api.status === 404 ? 404 : 502
    );
  }
  const user = api.data;
  return json({
    ok: true,
    id: user.id,
    username: user.username,
    global_name: user.global_name || null,
    discriminator: user.discriminator || "0",
    avatar_url: avatarUrlFromUser(user),
    partial: false,
  });
}

/* ===== Discord OAuth (identify + guilds) for server verify =====
 * Secrets: DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_BOT_TOKEN (for role assign optional)
 * Vars: OAUTH_REDIRECT = https://greedyhudzell.xyz/api/discord/oauth/callback
 * D1: run migration discord_oauth table
 */
const OAUTH_SCOPES = "identify guilds";

function oauthRedirectUri(env, request) {
  if (env.OAUTH_REDIRECT) return env.OAUTH_REDIRECT;
  const u = new URL(request.url);
  return `${u.origin}/api/discord/oauth/callback`;
}

async function ensureOauthTable(env) {
  if (!env.DB) return;
  try {
    await env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS discord_oauth (
        discord_id TEXT PRIMARY KEY,
        guild_ids TEXT NOT NULL,
        access_token TEXT,
        updated_at INTEGER NOT NULL
      )`
    ).run();
  } catch (e) {
    console.error("oauth table:", e);
  }
}

async function handleOauthStart(request, env) {
  const url = new URL(request.url);
  // Prefer discord_id query; optional fallback from path
  let discordId = String(url.searchParams.get("discord_id") || "").replace(/\D/g, "");
  if (!discordId || discordId.length < 16) {
    return html(
      `<!doctype html><html><body style="font-family:system-ui;background:#0b0b0b;color:#eee;padding:2rem">
      <h1>Missing discord_id</h1>
      <p>Open this from the Discord bot Verify button.</p>
      </body></html>`,
      400
    );
  }
  const clientId = env.DISCORD_CLIENT_ID || env.CLIENT_ID || DEFAULT_DISCORD_CLIENT_ID;
  if (!clientId) {
    return html(`<h1>DISCORD_CLIENT_ID not set</h1><p>Set secret or use built-in default.</p>`, 500);
  }
  const redirect = oauthRedirectUri(env, request);
  const state = discordId;
  const auth = new URL("https://discord.com/api/oauth2/authorize");
  auth.searchParams.set("client_id", String(clientId));
  auth.searchParams.set("redirect_uri", redirect);
  auth.searchParams.set("response_type", "code");
  auth.searchParams.set("scope", OAUTH_SCOPES);
  auth.searchParams.set("state", state);
  auth.searchParams.set("prompt", "consent");
  return Response.redirect(auth.toString(), 302);
}

async function handleOauthCallback(request, env) {
  const url = new URL(request.url);
  // Discord returns ?code=...&state=...  (state is our discord_id)
  // Direct authorize links without state used to show "Missing code" — fixed.
  const code = url.searchParams.get("code");
  let state = String(url.searchParams.get("state") || "").replace(/\D/g, "");
  const err = url.searchParams.get("error");
  const errDesc = url.searchParams.get("error_description") || "";
  if (err) {
    return html(
      `<!doctype html><html><body style="font-family:system-ui;background:#0b0b0b;color:#eee;padding:2rem">
      <h1>Authorization failed</h1>
      <p><code>${err}</code> ${errDesc}</p>
      <p>Close this tab and press <b>Verify</b> again in Discord.</p>
      </body></html>`,
      400
    );
  }
  if (!code) {
    return html(
      `<!doctype html><html><body style="font-family:system-ui;background:#0b0b0b;color:#eee;padding:2rem">
      <h1>Missing authorization code</h1>
      <p>Open verification from Discord (Authorize bot), do not bookmark this URL.</p>
      <p>Expected: <code>/api/discord/oauth/start?discord_id=YOUR_ID</code></p>
      </body></html>`,
      400
    );
  }
  const clientId = env.DISCORD_CLIENT_ID || env.CLIENT_ID || DEFAULT_DISCORD_CLIENT_ID;
  const clientSecret = env.DISCORD_CLIENT_SECRET || env.CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    return html(`<h1>Server misconfigured</h1><p>DISCORD_CLIENT_ID / DISCORD_CLIENT_SECRET secrets required.</p>`, 500);
  }
  // redirect_uri MUST match Discord Developer Portal exactly (and the authorize request)
  const redirect = oauthRedirectUri(env, request);
  const body = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    grant_type: "authorization_code",
    code: code,
    redirect_uri: redirect,
  });
  const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  const tokenJson = await tokenRes.json().catch(() => ({}));
  if (!tokenRes.ok || !tokenJson.access_token) {
    return html(
      `<!doctype html><html><body style="font-family:system-ui;background:#0b0b0b;color:#eee;padding:2rem">
      <h1>Token exchange failed</h1>
      <p>Usually redirect_uri mismatch. Portal must have exactly:</p>
      <pre>${redirect}</pre>
      <pre>${JSON.stringify(tokenJson).slice(0, 500)}</pre>
      </body></html>`,
      502
    );
  }
  const access = tokenJson.access_token;
  const meRes = await fetch("https://discord.com/api/users/@me", {
    headers: { Authorization: `Bearer ${access}` },
  });
  const me = await meRes.json().catch(() => ({}));
  const meId = String(me.id || "").replace(/\D/g, "");
  if (!meId) {
    return html(`<h1>Could not read Discord user</h1>`, 502);
  }
  // If state was sent, it must match; if omitted (old links), trust /@me id
  if (state && state !== meId) {
    return html(
      `<h1>Account mismatch</h1>
      <p>Authorized account <code>${meId}</code> does not match the Discord user who started verify (<code>${state}</code>).</p>`,
      403
    );
  }
  state = meId;

  const gRes = await fetch("https://discord.com/api/users/@me/guilds", {
    headers: { Authorization: `Bearer ${access}` },
  });
  const guilds = await gRes.json().catch(() => []);
  const guildIds = Array.isArray(guilds)
    ? guilds.map((g) => String(g.id)).filter(Boolean)
    : [];

  await ensureOauthTable(env);
  if (env.DB) {
    await env.DB.prepare(
      `INSERT INTO discord_oauth (discord_id, guild_ids, access_token, updated_at)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(discord_id) DO UPDATE SET
         guild_ids = excluded.guild_ids,
         access_token = excluded.access_token,
         updated_at = excluded.updated_at`
    )
      .bind(state, JSON.stringify(guildIds), access, Math.floor(Date.now() / 1000))
      .run();
  }

  return html(
    `<!doctype html><html><body style="font-family:system-ui;background:#0b0b0b;color:#eee;padding:2rem;text-align:center">
    <h1 style="color:#d4af37">Connected</h1>
    <p>Discord <b>${me.username || state}</b> authorized.</p>
    <p>Servers seen: <b>${guildIds.length}</b></p>
    <p>Return to Discord and press <b>Verify</b> again.</p>
    <p style="opacity:.6;font-size:12px">You can close this tab.</p>
    <script>try{window.close()}catch(e){}</script>
    </body></html>`,
    200
  );
}

async function handleOauthStatus(request, env) {
  const url = new URL(request.url);
  const discordId = String(url.searchParams.get("discord_id") || "").replace(/\D/g, "");
  if (!discordId) return json({ ok: false, error: "missing_discord_id" }, 400);
  await ensureOauthTable(env);
  if (!env.DB) return json({ ok: false, authorized: false, error: "no_db" }, 500);
  const row = await env.DB.prepare(
    `SELECT discord_id, guild_ids, updated_at FROM discord_oauth WHERE discord_id = ? LIMIT 1`
  )
    .bind(discordId)
    .first();
  if (!row) return json({ ok: true, authorized: false, guild_ids: [] });
  let guild_ids = [];
  try {
    guild_ids = JSON.parse(row.guild_ids || "[]");
  } catch (_) {}
  return json({
    ok: true,
    authorized: true,
    guild_ids,
    updated_at: row.updated_at,
  });
}

async function handleDiscordVerifyKey(request, env) {
  if (request.method !== "POST") return json({ ok: false, error: "method_not_allowed" }, 405);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "invalid_json" }, 400);
  }
  const key = typeof body.key === "string" ? body.key.trim() : "";
  // Roblox username optional on Discord verify (bound later by loader /validate)
  const username =
    typeof body.roblox_username === "string"
      ? body.roblox_username.trim()
      : typeof body.username === "string"
        ? body.username.trim()
        : "";
  const discordId = String(body.discord_id || body.discordId || "").replace(/\D/g, "");
  if (!key) return json({ ok: false, error: "missing_key" }, 400);
  if (!discordId || discordId.length < 16) return json({ ok: false, error: "invalid_discord_id" }, 400);

  const record = await env.DB.prepare(`SELECT * FROM keys WHERE key = ? LIMIT 1`).bind(key).first();
  if (!record) return json({ ok: false, error: "invalid_key", reason: "invalid_key" });
  if (record.revoked === 1) return json({ ok: false, error: "revoked", reason: "revoked" });
  if (Number(record.expires_at) <= now()) return json({ ok: false, error: "expired", reason: "expired" });

  // Optional username bind (only if provided)
  if (username) {
    const isPending = String(record.username || "").startsWith("pending_");
    if (record.username && record.username !== username && !isPending) {
      return json({
        ok: false,
        error: "username_mismatch",
        reason: "username_mismatch",
        bound_username: record.username,
        message: "Key already bound to another Roblox user",
      }, 403);
    }
    if (isPending || !record.username) {
      try {
        await env.DB.prepare(`UPDATE keys SET username = ? WHERE key = ?`).bind(username, key).run();
      } catch (_) {}
    }
  }

  // Discord lock: key may only belong to one Discord account
  if (record.discord_id && String(record.discord_id) !== discordId) {
    return json({
      ok: false,
      error: "discord_mismatch",
      reason: "discord_mismatch",
      message: "Key already linked to another Discord account",
    }, 403);
  }

  // Always allow re-activation (same key or new key for same Discord).
  // activated can be flipped 0→1 any number of times for valid non-revoked keys.
  const ts = now();
  try {
    await env.DB.prepare(
      `UPDATE keys SET discord_id = ?, activated = 1, last_execution = ? WHERE key = ?`
    )
      .bind(discordId, ts, key)
      .run();
  } catch {
    try {
      await env.DB.prepare(
        `UPDATE keys SET activated = 1, last_execution = ? WHERE key = ?`
      )
        .bind(ts, key)
        .run();
    } catch {
      try {
        await env.DB.prepare(`UPDATE keys SET last_execution = ? WHERE key = ?`).bind(ts, key).run();
      } catch (_) {}
    }
  }

  // Member role: only grant if missing (first time)
  const guildId = env.DISCORD_GUILD_ID || "1422222409846620201";
  const roleId = env.DISCORD_MEMBER_ROLE || "1445500571640402052";
  let roleGiven = false;
  let roleAlready = false;
  let roleError = null;

  const memberGet = await discordApi(env, "GET", `/guilds/${guildId}/members/${discordId}`, null);
  if (memberGet.ok && memberGet.data && Array.isArray(memberGet.data.roles)) {
    roleAlready = memberGet.data.roles.map(String).includes(String(roleId));
  } else if (memberGet.status === 404) {
    roleError = {
      status: 404,
      hint: "User not in guild — join Discord first",
      details: memberGet.data,
    };
  }

  if (!roleAlready && !roleError) {
    const rolePut = await discordApi(
      env,
      "PUT",
      `/guilds/${guildId}/members/${discordId}/roles/${roleId}`,
      null
    );
    roleGiven = rolePut.ok || rolePut.status === 204;
    if (!roleGiven) {
      roleError = {
        status: rolePut.status,
        details: rolePut.data,
        hint:
          rolePut.status === 404
            ? "User not in guild — join Discord first"
            : rolePut.status === 403
              ? "Bot missing Manage Roles or role hierarchy"
              : "Discord API error",
      };
    }
  }

  const wasAlreadyActive = record.activated === 1 || record.activated === "1";
  return json({
    ok: true,
    success: true,
    valid: true,
    plan: record.plan || "day",
    expires_at: record.expires_at,
    role_given: roleGiven,
    role_already: roleAlready,
    role_error: roleError,
    activated: true,
    reactivated: wasAlreadyActive,
    paid: isPaidPlan(record.plan, key),
    message: roleGiven
      ? "Key activated. Member role granted (first time)."
      : roleAlready
        ? "Key activated. Member role already present."
        : "Key activated." + (roleError ? " Role not granted." : ""),
  });
}

async function handleDiscordRewire(request, env) {
  if (request.method !== "POST") return json({ ok: false, error: "method_not_allowed" }, 405);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "invalid_json" }, 400);
  }
  const key = typeof body.key === "string" ? body.key.trim() : "";
  const username =
    typeof body.roblox_username === "string"
      ? body.roblox_username.trim()
      : typeof body.username === "string"
        ? body.username.trim()
        : "";
  const discordId = String(body.discord_id || body.discordId || "").replace(/\D/g, "");
  if (!key) return json({ ok: false, error: "missing_key" }, 400);
  if (username.length < 3 || username.length > 20 || !/^[A-Za-z0-9_]+$/.test(username)) {
    return json({ ok: false, error: "invalid_username" }, 400);
  }
  const record = await env.DB.prepare(`SELECT * FROM keys WHERE key = ? LIMIT 1`).bind(key).first();
  if (!record) return json({ ok: false, error: "key_not_found" }, 404);
  if (record.revoked === 1) return json({ ok: false, error: "revoked" }, 400);
  if (Number(record.expires_at) <= now()) return json({ ok: false, error: "expired" }, 400);
  if (!isPaidPlan(record.plan, key)) {
    return json({
      ok: false,
      error: "rewire_only_paid",
      reason: "rewire_only_paid",
      message: "Rewire is only for week/month/year (or GH-PAID-*) keys",
    }, 403);
  }
  if (record.discord_id && discordId && String(record.discord_id) !== discordId) {
    return json({ ok: false, error: "discord_mismatch" }, 403);
  }
  const previous = record.username;
  try {
    if (discordId) {
      await env.DB.prepare(`UPDATE keys SET username = ?, discord_id = ? WHERE key = ?`)
        .bind(username, discordId, key)
        .run();
    } else {
      await env.DB.prepare(`UPDATE keys SET username = ? WHERE key = ?`).bind(username, key).run();
    }
  } catch {
    await env.DB.prepare(`UPDATE keys SET username = ? WHERE key = ?`).bind(username, key).run();
  }
  return json({
    ok: true,
    key,
    previous_username: previous,
    username,
    plan: record.plan || "paid",
    expires_at: record.expires_at,
    message: "Key rewired",
  });
}



/* ===================== BANS / KICKS / WEBHOOKS ===================== */
async function ensureBanTables(env) {
  if (!env.DB) return;
  try {
    await env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS bans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT,
        username TEXT,
        user_id TEXT,
        reason TEXT,
        by_discord TEXT,
        created_at INTEGER
      )`
    ).run();
    try {
      await env.DB.prepare(`ALTER TABLE bans ADD COLUMN user_id TEXT`).run();
    } catch (_) {}
    await env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS pending_kicks (
        user_id TEXT PRIMARY KEY,
        reason TEXT,
        created_at INTEGER
      )`
    ).run();
    await env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS webhooks_meta (
        webhook_id TEXT PRIMARY KEY,
        url TEXT,
        roblox_name TEXT,
        discord_id TEXT,
        created_at INTEGER
      )`
    ).run();
  } catch (e) {
    console.error("ensureBanTables", e);
  }
}

async function isBanned(env, key, username, userId) {
  await ensureBanTables(env);
  const k = (key || "").trim();
  const u = (username || "").trim().toLowerCase();
  const uid = String(userId || "").trim();
  try {
    if (k) {
      const row = await env.DB.prepare(`SELECT reason FROM bans WHERE key = ? LIMIT 1`).bind(k).first();
      if (row) return { banned: true, reason: row.reason || "banned" };
    }
    if (u) {
      const row = await env.DB.prepare(
        `SELECT reason FROM bans WHERE lower(username) = ? LIMIT 1`
      )
        .bind(u)
        .first();
      if (row) return { banned: true, reason: row.reason || "banned" };
    }
    if (uid) {
      const row = await env.DB.prepare(
        `SELECT reason FROM bans WHERE user_id = ? LIMIT 1`
      )
        .bind(uid)
        .first();
      if (row) return { banned: true, reason: row.reason || "banned" };
    }
  } catch (e) {
    console.error("isBanned", e);
  }
  return false;
}

async function handleAdminBan(request, env) {
  if (!adminAuthorized(request, env)) return json({ success: false, reason: "unauthorized" }, 401);
  await ensureBanTables(env);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ success: false, reason: "invalid_json" }, 400);
  }
  const key = typeof body.key === "string" ? body.key.trim() : "";
  const username = typeof body.username === "string" ? body.username.trim() : "";
  const userId = String(body.user_id || body.userId || body.roblox_id || "").trim();
  const reason = body.reason || "Banned from Greedy Hudzell";
  const by = String(body.by_discord || "");
  if (!key && !username && !userId) return json({ success: false, reason: "need key, username or user_id" }, 400);
  const ts = now();
  await env.DB.prepare(
    `INSERT INTO bans (key, username, user_id, reason, by_discord, created_at) VALUES (?, ?, ?, ?, ?, ?)`
  )
    .bind(key || null, username || null, userId || null, reason, by, ts)
    .run();
  if (key) {
    try {
      await env.DB.prepare(`UPDATE keys SET revoked = 1 WHERE key = ?`).bind(key).run();
    } catch (_) {}
  }
  // Immediate kick for online sessions
  if (userId) {
    try {
      await env.DB.prepare(
        `INSERT OR REPLACE INTO pending_kicks (user_id, reason, created_at) VALUES (?, ?, ?)`
      )
        .bind(userId, reason, ts)
        .run();
    } catch (_) {}
  }
  return json({ success: true, key: key || null, username: username || null, user_id: userId || null });
}

async function handleAdminUnban(request, env) {
  if (!adminAuthorized(request, env)) return json({ success: false, reason: "unauthorized" }, 401);
  await ensureBanTables(env);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ success: false, reason: "invalid_json" }, 400);
  }
  const key = typeof body.key === "string" ? body.key.trim() : "";
  const username = typeof body.username === "string" ? body.username.trim() : "";
  const userId = String(body.user_id || body.userId || body.roblox_id || "").trim();
  if (!key && !username && !userId) return json({ success: false, reason: "need key, username or user_id" }, 400);
  if (key) {
    await env.DB.prepare(`DELETE FROM bans WHERE key = ?`).bind(key).run();
    try {
      await env.DB.prepare(`UPDATE keys SET revoked = 0 WHERE key = ?`).bind(key).run();
    } catch (_) {}
  }
  if (username) {
    await env.DB.prepare(`DELETE FROM bans WHERE lower(username) = lower(?)`).bind(username).run();
  }
  if (userId) {
    await env.DB.prepare(`DELETE FROM bans WHERE user_id = ?`).bind(userId).run();
    await env.DB.prepare(`DELETE FROM pending_kicks WHERE user_id = ?`).bind(userId).run();
  }
  return json({ success: true });
}

async function handleAdminKick(request, env) {
  if (!adminAuthorized(request, env)) return json({ success: false, reason: "unauthorized" }, 401);
  await ensureBanTables(env);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ success: false, reason: "invalid_json" }, 400);
  }
  const userId = String(body.user_id || "");
  const reason = String(body.reason || "Kicked by moderator");
  if (!userId) return json({ success: false, reason: "user_id" }, 400);
  await env.DB.prepare(
    `INSERT OR REPLACE INTO pending_kicks (user_id, reason, created_at) VALUES (?, ?, ?)`
  )
    .bind(userId, reason, now())
    .run();
  return json({ success: true });
}

async function handleKickCheck(request, env, url) {
  await ensureBanTables(env);
  const userId = url.searchParams.get("userId") || "";
  const username = (url.searchParams.get("username") || "").trim();
  const key = (url.searchParams.get("key") || "").trim();
  if (!userId && !username && !key) return json({ kick: false, banned: false });

  // Live ban check (username / key / userId)
  const ban = await isBanned(env, key, username, userId);
  if (ban) {
    return json({
      kick: true,
      banned: true,
      reason: ban.reason || "You are banned from Greedy Hudzell",
    });
  }

  if (!userId) return json({ kick: false, banned: false });
  const row = await env.DB.prepare(`SELECT reason FROM pending_kicks WHERE user_id = ?`)
    .bind(userId)
    .first();
  if (!row) return json({ kick: false, banned: false });
  await env.DB.prepare(`DELETE FROM pending_kicks WHERE user_id = ?`).bind(userId).run();
  return json({ kick: true, banned: false, reason: row.reason });
}

async function handleWebhookRegister(request, env) {
  if (!adminAuthorized(request, env)) return json({ success: false, reason: "unauthorized" }, 401);
  await ensureBanTables(env);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ success: false, reason: "invalid_json" }, 400);
  }
  const webhookId = String(body.webhook_id || "");
  const whUrl = String(body.url || "");
  if (!webhookId || !whUrl) return json({ success: false, reason: "webhook_id+url" }, 400);
  await env.DB.prepare(
    `INSERT OR REPLACE INTO webhooks_meta (webhook_id, url, roblox_name, discord_id, created_at) VALUES (?, ?, ?, ?, ?)`
  )
    .bind(webhookId, whUrl, body.roblox_name || "", body.discord_id || "", now())
    .run();
  return json({ success: true });
}

async function handleCreateWebhook(request, env) {
  await ensureBanTables(env);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "invalid_json" }, 400);
  }
  const key = typeof body.key === "string" ? body.key.trim() : "";
  const username = typeof body.username === "string" ? body.username.trim() : "";
  if (!key || !username) return json({ ok: false, error: "key+username" }, 400);
  if (await isBanned(env, key, username, body.user_id || body.roblox_id)) return json({ ok: false, error: "banned" }, 403);
  const token = env.DISCORD_BOT_TOKEN || env.DISCORD_TOKEN;
  if (!token) return json({ ok: false, error: "no bot token" }, 500);
  const channelId = "1546938830333153321";
  const name = username.replace(/[^\w\- ]/g, "").slice(0, 80) || "gh-user";
  const res = await fetch(`https://discord.com/api/v10/channels/${channelId}/webhooks`, {
    method: "POST",
    headers: {
      Authorization: `Bot ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ name }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) return json({ ok: false, error: data }, 502);
  const urlWh = `https://discord.com/api/webhooks/${data.id}/${data.token}`;
  await env.DB.prepare(
    `INSERT OR REPLACE INTO webhooks_meta (webhook_id, url, roblox_name, discord_id, created_at) VALUES (?, ?, ?, ?, ?)`
  )
    .bind(String(data.id), urlWh, username, body.discord_id || "", now())
    .run();
  return json({ ok: true, url: urlWh });
}

async function handleSessionJoin(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "invalid_json" }, 400);
  }
  const token = env.DISCORD_BOT_TOKEN || env.DISCORD_TOKEN;
  if (!token) return json({ ok: false, error: "no bot token" }, 500);
  const ch = "1438999670075686912";
  const content =
    `**Session**\n` +
    `Roblox: \`${body.roblox_user || "?"}\` (${body.roblox_id || "?"})\n` +
    `Discord: \`${body.discord_name || "-"}\` (${body.discord_id || "-"})\n` +
    `Key: \`${body.key || "-"}\` plan=${body.plan || "-"} place=${body.place_id || "-"}`;
  try {
    await fetch(`https://discord.com/api/v10/channels/${ch}/messages`, {
      method: "POST",
      headers: {
        Authorization: `Bot ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ content }),
    });
  } catch (e) {
    console.error("session join post", e);
    return json({ ok: false, error: "discord_post_failed" }, 502);
  }
  return json({ ok: true });
}


export default {
  async fetch(request, env) {
    try {
      if (request.method === "OPTIONS") {
        return new Response(null, { status: 204, headers: corsHeaders });
      }
      
      const url = new URL(request.url);
      // нормализация: "/" и "" и иногда без слэша
      let path = url.pathname;
      if (path.length > 1 && path.endsWith("/")) path = path.slice(0, -1);
      if (path === "") path = "/";

      // РЕДИРЕКТ — сразу, до любого html на "/"
      if (request.method === "GET" && path === "/") {
        return Response.redirect(new URL("/home", request.url).toString(), 302);
      }

      // страницы
      if (request.method === "GET" && path === "/home") {
        return html(homePage());
      }
      if (request.method === "GET" && path === "/status") return html(statusPage());
      if (request.method === "GET" && path === "/executors") return html(executorsPage());
      if (request.method === "GET" && path === "/guide") return html(guidePage());
      if (request.method === "GET" && path === "/pricing") return html(pricingPage());
      if (request.method === "GET" && path === "/tos") return html(tosPage());

      // Lua proxies
      if (path === "/loader.lua") return proxyGithub("greedyloader.lua");
      if (path === "/script.lua") return proxyGithub("greedy.lua");
      if (path === "/library.lua") return proxyGithub("greedylibrary.lua");
      if (path === "/modules.lua") return proxyGithub("greedymodules.lua");
      
      // Obfuscator
      if (
        request.method === "GET" &&
        (path === "/obfuscate" || path === "/obfuscate/" || path === "/obfuscator" || path === "/obfuscator/")
      ) {
        return html(obfuscatePage(env.SITE_NAME || "Greedy Hudzell"));
      }
      if (request.method === "POST" && path === "/api/syntax-check") {
        let body;
        try {
          body = await request.json();
        } catch {
          return json({ ok: false, issues: ["invalid JSON"] }, 400);
        }
        const sc = syntaxCheck(body.code || "");
        if (!Array.isArray(sc.issues)) sc.issues = [];
        return json(sc);
      }
      if (request.method === "POST" && path === "/api/obfuscate") {
        let body;
        try {
          body = await request.json();
        } catch {
          return json({ ok: false, error: "invalid_json" }, 400);
        }
        const code = typeof body.code === "string" ? body.code : "";
        if (!code || code.length < 2) return json({ ok: false, error: "empty_code" }, 400);
        if (code.length > 1200000) return json({ ok: false, error: "code_too_large" }, 413);
        const preset = body.preset || "standard";
        const apiKey = env.LUAOBF_API_KEY || LUAOBF_FALLBACK;
        try {
          const result = await runObfuscatePipeline(code, preset, apiKey, body.options || {});
          return json(result, result.ok ? 200 : 502);
        } catch (e) {
          return json({
            ok: true,
            code: localObfuscate(code, 2),
            mode: "local_emergency",
            note: String(e && e.message ? e.message : e),
          });
        }
      }

            // KEY SYSTEM
      if (request.method === "GET" && path.startsWith("/get-key/token/")) {
        const token = decodeURIComponent(path.slice("/get-key/token/".length));
        return await handleGetKeyToken(request, env, token);
      }
      if (request.method === "GET" && path === "/step2") return await handleStep2(request, env);
      if (request.method === "GET" && path.startsWith("/finish/token/")) {
        const token = decodeURIComponent(path.slice("/finish/token/".length));
        return await handleFinish(request, env, token);
      }
      if (request.method === "GET" && path === "/finish") {
        const tok = extractWorkInkToken(request, url, null);
        return await handleFinish(request, env, tok);
      }
      if (request.method === "POST" && path === "/generate-key") return await handleGenerateKey(request, env);
      if (request.method === "POST" && path === "/validate") return await handleValidate(request, env);
      if (request.method === "POST" && path === "/redeem/gamepass") return await handleRedeemGamepass(request, env);
      
      // ADMIN
      const adminMatch = path.match(/^\/keys\/([^/]+)\/encrypted\/get-keys-all$/);
      if (request.method === "GET" && adminMatch) return await handleAdminKeys(request, env, adminMatch[1]);
      if (request.method === "POST" && path === "/admin/generate") return await handleAdminGenerate(request, env);
      if (request.method === "POST" && path === "/admin/renew") return await handleAdminRenew(request, env);
      if (request.method === "POST" && path === "/admin/revoke") return await handleAdminRevoke(request, env);
      if (request.method === "POST" && path === "/admin/ban") return await handleAdminBan(request, env);
      if (request.method === "POST" && path === "/admin/unban") return await handleAdminUnban(request, env);
      if (request.method === "POST" && path === "/admin/kick") return await handleAdminKick(request, env);
      if (request.method === "POST" && path === "/admin/webhook-register") return await handleWebhookRegister(request, env);
      if (request.method === "POST" && path === "/admin/rewire") return await handleAdminRewire(request, env);
      if (request.method === "GET" && path === "/api/session/kick-check") return await handleKickCheck(request, env, url);
      if (request.method === "POST" && path === "/api/discord/create-webhook") return await handleCreateWebhook(request, env);
      if (request.method === "POST" && path === "/api/session/join") return await handleSessionJoin(request, env);
      if (request.method === "GET" && path === "/admin/stats") return await handleAdminStats(request, env);
      const adminKeyMatch = path.match(/^\/admin\/key\/(.+)$/);
      if (request.method === "GET" && adminKeyMatch) {
        return await handleAdminKey(request, env, decodeURIComponent(adminKeyMatch[1]));
      }
      

      
      // DISCORD OAUTH (identify + guilds)
      if (request.method === "GET" && path === "/api/discord/oauth/start") {
        return await handleOauthStart(request, env);
      }
      if (request.method === "GET" && path === "/api/discord/oauth/callback") {
        return await handleOauthCallback(request, env);
      }
      if (request.method === "GET" && path === "/api/discord/oauth/status") {
        return await handleOauthStatus(request, env);
      }

      // DISCORD LINK
      if (request.method === "GET" && path === "/api/discord/debug") {
        return await handleDiscordDebug(request, env);
      }
      if (request.method === "POST" && path === "/api/discord/profile") {
        return await handleDiscordProfile(request, env);
      }
      if (request.method === "POST" && path === "/api/discord/verify-key") {
        return await handleDiscordVerifyKey(request, env);
      }
      if (request.method === "POST" && path === "/api/discord/rewire") {
        return await handleDiscordRewire(request, env);
      }

      return json({ error: "Not found" }, 404);
    } catch (error) {
      console.error("Worker error:", error);
      return json({ error: "Internal server error" }, 500);
    }
  },
};
