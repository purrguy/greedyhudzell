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
const WEAO_URL = "https://weao.xyz/api/exploits";

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

/* ===================== API KEYS + OBFUSCATOR QUOTA =====================
 * API keys inherit the plan of the license that created them. Quota for
 * /api/obfuscate resolves: api key > license key > anonymous IP. Work.ink
 * step1+step2 sessions grant +1/day. Admins top up licenses via grants.
 */
const OBF_PLAN_LIMITS = { free: 2, day: 2, week: 10, month: 30, year: 50, lifetime: 50, paid: 50 };
const OBF_ANON_LIMIT = 1;
const OBF_KEY_SCOPES = ["obfuscate", "validate", "stats"];
const OBF_MAX_KEYS_PER_LICENSE = 10;

function obfDay(t) {
  return new Date(t * 1000).toISOString().slice(0, 10);
}

let _obfMigrated = false;
async function ensureObfTables(env) {
  if (_obfMigrated) return;
  try {
    await env.DB.batch([
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS api_keys (
        id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', license_key TEXT,
        plan TEXT NOT NULL DEFAULT 'day', key_hash TEXT NOT NULL UNIQUE,
        prefix TEXT NOT NULL, scopes TEXT NOT NULL DEFAULT 'obfuscate,validate,stats',
        daily_limit INTEGER, expires_at INTEGER, revoked INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL, last_used_at INTEGER)`),
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS obf_usage (
        identity TEXT NOT NULL, endpoint TEXT NOT NULL DEFAULT '', day TEXT NOT NULL,
        used INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (identity, endpoint, day))`),
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS obf_grants (
        id TEXT PRIMARY KEY, license_key TEXT NOT NULL, amount INTEGER NOT NULL,
        expires_at INTEGER, granted_by TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL)`),
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS obf_cache (
        code_hash TEXT PRIMARY KEY, output TEXT NOT NULL, out_chars INTEGER NOT NULL,
        preset TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL)`),
    ]);
    try {
      await env.DB.prepare(`ALTER TABLE keys ADD COLUMN plan TEXT NOT NULL DEFAULT 'day'`).run();
    } catch {}
    try {
      await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_obf_grants_key ON obf_grants(license_key)`).run();
    } catch {}
    _obfMigrated = true;
  } catch {}
}

async function resolveApiKey(request, env, needScope) {
  const hdr = request.headers.get("X-API-Key") || "";
  const auth = request.headers.get("Authorization") || "";
  let supplied = hdr.trim();
  if (!supplied && auth.startsWith("Bearer ghsk_")) supplied = auth.slice(7).trim();
  if (!supplied) return null;
  const h = await sha256("ghsk|" + supplied);
  let row = null;
  try {
    row = await env.DB.prepare(`SELECT * FROM api_keys WHERE key_hash = ? LIMIT 1`).bind(h).first();
  } catch { return { error: "api_unavailable" }; }
  if (!row || row.revoked === 1) return { error: "bad_api_key" };
  if (row.expires_at && Number(row.expires_at) <= now()) return { error: "api_key_expired" };
  const scopes = String(row.scopes || "").split(",").map(s => s.trim()).filter(Boolean);
  if (needScope && !scopes.includes(needScope)) return { error: "scope_denied" };
  try {
    await env.DB.prepare(`UPDATE api_keys SET last_used_at = ? WHERE id = ?`).bind(now(), row.id).run();
  } catch {}
  return { row, scopes };
}

async function resolveObfIdentity(request, env, body) {
  // 1) API key (header X-API-Key / Bearer ghsk_... / body.api_key)
  let supplied = ((body && body.api_key) || "").trim();
  if (!supplied) {
    const hdr = request.headers.get("X-API-Key") || "";
    const auth = request.headers.get("Authorization") || "";
    supplied = hdr.trim() || (auth.startsWith("Bearer ghsk_") ? auth.slice(7).trim() : "");
  }
  if (supplied) {
    const h = await sha256("ghsk|" + supplied);
    let row = null;
    try {
      row = await env.DB.prepare(`SELECT * FROM api_keys WHERE key_hash = ? LIMIT 1`).bind(h).first();
    } catch { return { error: "api_unavailable", status: 500 }; }
    if (!row || row.revoked === 1) return { error: "bad_api_key", status: 401 };
    if (row.expires_at && Number(row.expires_at) <= now()) return { error: "api_key_expired", status: 403 };
    const scopes = String(row.scopes || "").split(",").map(s => s.trim()).filter(Boolean);
    if (!scopes.includes("obfuscate")) return { error: "scope_denied", status: 403 };
    try {
      await env.DB.prepare(`UPDATE api_keys SET last_used_at = ? WHERE id = ?`).bind(now(), row.id).run();
    } catch {}
    return { kind: "api", id: "api:" + row.id, plan: row.plan || "day", apiRow: row };
  }
  // 2) license key in body
  const lic = (body && body.license_key ? String(body.license_key) : "").trim();
  if (lic) {
    let rec = null;
    try {
      rec = await env.DB.prepare(`SELECT * FROM keys WHERE key = ? LIMIT 1`).bind(lic).first();
    } catch { return { error: "api_unavailable", status: 500 }; }
    if (!rec || rec.revoked === 1 || Number(rec.expires_at) <= now()) {
      return { error: "bad_license", status: 403 };
    }
    return { kind: "license", id: "lic:" + lic, plan: rec.plan || "day" };
  }
  // 3) anonymous IP
  const ip = getClientIP(request) || "?";
  return { kind: "ip", id: "ip:" + await sha256("ip|" + ip), plan: "free", anon: true };
}

async function obfAllowance(env, ident, request) {
  const t = now();
  const day = obfDay(t);
  let limit = ident.kind === "ip" ? OBF_ANON_LIMIT : (OBF_PLAN_LIMITS[ident.plan] ?? OBF_PLAN_LIMITS.day);
  if (ident.kind === "api" && ident.apiRow && ident.apiRow.daily_limit != null) {
    const cap = Number(ident.apiRow.daily_limit);
    if (Number.isFinite(cap) && cap > 0) limit = Math.min(limit, Math.floor(cap));
  }
  let bonus = 0, bonusReason = null;
  // Work.ink bonus: a session that completed both steps grants +1 today.
  try {
    const sid = getCookie(request, "GH_SESSION");
    if (sid && ident.kind !== "api") {
      const s = await env.DB.prepare(
        `SELECT step1, step2 FROM sessions WHERE session_id = ? LIMIT 1`
      ).bind(sid).first();
      if (s && Number(s.step1) === 1 && Number(s.step2) === 1) {
        bonus = 1; bonusReason = "workink";
      }
    }
  } catch {}
  let granted = 0;
  const grantKey = ident.kind === "api" ? (ident.apiRow.license_key || null)
    : ident.kind === "license" ? ident.id.slice(4) : null;
  if (grantKey) {
    try {
      const g = await env.DB.prepare(
        `SELECT COALESCE(SUM(amount),0) AS s FROM obf_grants WHERE license_key = ? AND (expires_at IS NULL OR expires_at > ?)`
      ).bind(grantKey, t).first();
      granted = Number(g?.s || 0);
    } catch {}
  }
  const total = limit + bonus + granted;
  let used = 0;
  try {
    const r = await env.DB.prepare(
      `SELECT used FROM obf_usage WHERE identity = ? AND endpoint = 'obfuscate' AND day = ?`
    ).bind(ident.id, day).first();
    used = Number(r?.used || 0);
  } catch {}
  if (used >= total) return { ok: false, limit: total, used, bonus: bonusReason, plan: ident.plan };
  return { ok: true, limit: total, used, left: total - used - 1, bonus: bonusReason, plan: ident.plan, day };
}

async function obfRecordUse(env, ident, day) {
  try {
    await env.DB.prepare(
      `INSERT INTO obf_usage (identity, endpoint, day, used) VALUES (?, 'obfuscate', ?, 1)
       ON CONFLICT(identity, endpoint, day) DO UPDATE SET used = used + 1`
    ).bind(ident.id, day).run();
  } catch {}
}

async function endpointQuota(env, endpoint, request, body, keyLimit, ipLimit) {
  // Optional API-key lane on validate/stats: counted generously per key,
  // strict per IP. Anonymous behavior is unchanged (no quota).
  let supplied = ((body && body.api_key) || "").trim();
  if (!supplied) {
    const hdr = request.headers.get("X-API-Key") || "";
    const auth = request.headers.get("Authorization") || "";
    supplied = hdr.trim() || (auth.startsWith("Bearer ghsk_") ? auth.slice(7).trim() : "");
  }
  if (!supplied) return { ok: true, keyed: false };
  const r = await resolveApiKey(request, env, endpoint);
  if (r && r.error) return { ok: false, error: r.error };
  if (!r) return { ok: true, keyed: false };
  const day = obfDay(now());
  const ident = "api:" + r.row.id;
  let used = 0;
  try {
    const q = await env.DB.prepare(
      `SELECT used FROM obf_usage WHERE identity = ? AND endpoint = ? AND day = ?`
    ).bind(ident, endpoint, day).first();
    used = Number(q?.used || 0);
  } catch {}
  if (used >= keyLimit) return { ok: false, error: "daily_limit" };
  try {
    await env.DB.prepare(
      `INSERT INTO obf_usage (identity, endpoint, day, used) VALUES (?, ?, ?, 1)
       ON CONFLICT(identity, endpoint, day) DO UPDATE SET used = used + 1`
    ).bind(ident, endpoint, day).run();
  } catch {}
  return { ok: true, keyed: true };
}

function newApiSecret() {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return "ghsk_" + [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function validLicenseForApi(env, lic) {
  if (!lic) return null;
  let rec = null;
  try {
    rec = await env.DB.prepare(`SELECT * FROM keys WHERE key = ? LIMIT 1`).bind(lic).first();
  } catch { return null; }
  if (!rec || rec.revoked === 1 || Number(rec.expires_at) <= now()) return null;
  return rec;
}

// POST /api/keys {license_key, name?, scopes?, daily_limit?, expires_at?}
async function handleApiKeyCreate(request, env) {
  await ensureObfTables(env);
  let body;
  try { body = await request.json(); } catch { return json({ ok: false, error: "invalid_json" }, 400); }
  const lic = String(body.license_key || "").trim();
  const rec = await validLicenseForApi(env, lic);
  if (!rec) return json({ ok: false, error: "bad_license" }, 403);
  const plan = rec.plan || "day";
  const planMax = OBF_PLAN_LIMITS[plan] ?? OBF_PLAN_LIMITS.day;
  let scopes = ["obfuscate", "validate", "stats"];
  if (Array.isArray(body.scopes) && body.scopes.length) {
    scopes = body.scopes.map(s => String(s).trim()).filter(s => OBF_KEY_SCOPES.includes(s));
    if (!scopes.length) return json({ ok: false, error: "bad_scopes" }, 400);
  }
  let dailyLimit = null;
  if (body.daily_limit != null && body.daily_limit !== "") {
    dailyLimit = Math.floor(Number(body.daily_limit));
    if (!Number.isFinite(dailyLimit) || dailyLimit < 1 || dailyLimit > planMax) {
      return json({ ok: false, error: "bad_limit", detail: `1..${planMax} on ${plan}` }, 400);
    }
  }
  let expiresAt = null;
  if (body.expires_at != null && body.expires_at !== "") {
    expiresAt = Math.floor(Number(body.expires_at));
    if (!Number.isFinite(expiresAt) || expiresAt <= now()) {
      return json({ ok: false, error: "bad_expiry" }, 400);
    }
  }
  try {
    const n = await env.DB.prepare(
      `SELECT COUNT(*) AS c FROM api_keys WHERE license_key = ? AND revoked = 0`
    ).bind(lic).first();
    if (Number(n?.c || 0) >= OBF_MAX_KEYS_PER_LICENSE) {
      return json({ ok: false, error: "too_many_keys" }, 400);
    }
  } catch {}
  const secret = newApiSecret();
  const id = randomString(8);
  const prefix = secret.slice(0, 13);
  const name = String(body.name || "api key").slice(0, 40) || "api key";
  try {
    await env.DB.prepare(
      `INSERT INTO api_keys (id, name, license_key, plan, key_hash, prefix, scopes, daily_limit, expires_at, revoked, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`
    ).bind(id, name, lic, plan, await sha256("ghsk|" + secret), prefix,
      scopes.join(","), dailyLimit, expiresAt, now()).run();
  } catch (e) {
    return json({ ok: false, error: "create_failed" }, 500);
  }
  return json({ ok: true, id, api_key: secret, prefix, plan, scopes,
    daily_limit: dailyLimit, expires_at: expiresAt });
}

// GET /api/keys?license_key=…
async function handleApiKeyList(request, env) {
  await ensureObfTables(env);
  const url = new URL(request.url);
  const lic = (url.searchParams.get("license_key") || "").trim();
  const rec = await validLicenseForApi(env, lic);
  if (!rec) return json({ ok: false, error: "bad_license" }, 403);
  let rows = [];
  try {
    const r = await env.DB.prepare(
      `SELECT id, name, plan, prefix, scopes, daily_limit, expires_at, revoked, created_at, last_used_at
       FROM api_keys WHERE license_key = ? ORDER BY created_at DESC`
    ).bind(lic).all();
    rows = r.results || [];
  } catch {}
  return json({ ok: true, plan: rec.plan || "day",
    plan_max: OBF_PLAN_LIMITS[rec.plan] ?? OBF_PLAN_LIMITS.day,
    keys: rows.map(k => ({ ...k })) });
}

async function handleApiKeyMute(request, env, mutate) {
  await ensureObfTables(env);
  let body;
  try { body = await request.json(); } catch { return json({ ok: false, error: "invalid_json" }, 400); }
  const lic = String(body.license_key || "").trim();
  const rec = await validLicenseForApi(env, lic);
  if (!rec) return json({ ok: false, error: "bad_license" }, 403);
  const id = String(body.id || "").trim();
  if (!id) return json({ ok: false, error: "missing_id" }, 400);
  let row = null;
  try {
    row = await env.DB.prepare(`SELECT * FROM api_keys WHERE id = ? AND license_key = ? LIMIT 1`).bind(id, lic).first();
  } catch {}
  if (!row) return json({ ok: false, error: "unknown_key" }, 404);
  const out = await mutate(env, row, body, rec);
  return out;
}

// POST /api/keys/revoke {license_key, id}
async function handleApiKeyRevoke(request, env) {
  return handleApiKeyMute(request, env, async (env2, row) => {
    await env2.DB.prepare(`UPDATE api_keys SET revoked = 1 WHERE id = ?`).bind(row.id).run();
    return json({ ok: true, id: row.id, revoked: true });
  });
}

// POST /api/keys/rules {license_key, id, daily_limit?, scopes?, expires_at?}
async function handleApiKeyRules(request, env) {
  return handleApiKeyMute(request, env, async (env2, row, body, rec) => {
    const planMax = OBF_PLAN_LIMITS[rec.plan] ?? OBF_PLAN_LIMITS.day;
    const patch = {};
    if (body.daily_limit !== undefined) {
      if (body.daily_limit === null || body.daily_limit === "") {
        patch.daily_limit = null;
      } else {
        const v = Math.floor(Number(body.daily_limit));
        if (!Number.isFinite(v) || v < 1 || v > planMax) {
          return json({ ok: false, error: "bad_limit", detail: `1..${planMax} on ${rec.plan}` }, 400);
        }
        patch.daily_limit = v;
      }
    }
    if (body.scopes !== undefined) {
      if (!Array.isArray(body.scopes) || !body.scopes.length) {
        return json({ ok: false, error: "bad_scopes" }, 400);
      }
      const scopes = body.scopes.map(s => String(s).trim()).filter(s => OBF_KEY_SCOPES.includes(s));
      if (!scopes.length) return json({ ok: false, error: "bad_scopes" }, 400);
      patch.scopes = scopes.join(",");
    }
    if (body.expires_at !== undefined) {
      if (body.expires_at === null || body.expires_at === "") {
        patch.expires_at = null;
      } else {
        const v = Math.floor(Number(body.expires_at));
        if (!Number.isFinite(v) || v <= now()) return json({ ok: false, error: "bad_expiry" }, 400);
        patch.expires_at = v;
      }
    }
    const keys = Object.keys(patch);
    if (!keys.length) return json({ ok: false, error: "nothing_to_change" }, 400);
    await env2.DB.prepare(
      `UPDATE api_keys SET ${keys.map(k => k + " = ?").join(", ")} WHERE id = ?`
    ).bind(...keys.map(k => patch[k]), row.id).run();
    return json({ ok: true, id: row.id, ...patch });
  });
}

// POST /admin/obf-grant {license_key, amount, days} — ADMIN_SECRET only.
// days = 0 (or omitted) means never expires.
async function handleAdminObfGrant(request, env) {
  if (!adminAuthorized(request, env)) return json({ error: "Unauthorized" }, 401);
  await ensureObfTables(env);
  let body;
  try { body = await request.json(); } catch { return json({ ok: false, error: "invalid_json" }, 400); }
  const lic = String(body.license_key || "").trim();
  const amount = Math.floor(Number(body.amount));
  if (!lic) return json({ ok: false, error: "missing_license" }, 400);
  if (!Number.isFinite(amount) || amount < 1 || amount > 10000) {
    return json({ ok: false, error: "bad_amount" }, 400);
  }
  let days = body.days === undefined ? 0 : Math.floor(Number(body.days));
  if (!Number.isFinite(days) || days < 0) return json({ ok: false, error: "bad_days" }, 400);
  const expires = days > 0 ? now() + days * 86400 : null;
  const id = randomString(8);
  try {
    await env.DB.prepare(
      `INSERT INTO obf_grants (id, license_key, amount, expires_at, granted_by, created_at)
       VALUES (?, ?, ?, ?, 'admin', ?)`
    ).bind(id, lic, amount, expires, now()).run();
  } catch (e) {
    return json({ ok: false, error: "grant_failed" }, 500);
  }
  return json({ ok: true, id, license_key: lic, amount, expires_at: expires });
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
      <p class="muted">Complete Work.ink Step 2 below — you will return here automatically and your key loads on its own.</p>
      <a href="${secondWorkInkLink}"><button>CONTINUE TO STEP 2</button></a>`
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
  } else {
    // No token in URL = step 2 was never completed (the skip button that
    // allowed this is gone). Send them back to do it properly.
    return html(
      pageShell(
        "Failed",
        `<div class="logo">${env.SITE_NAME}</div><h2>STEP 2 NOT DONE</h2><p>Finish Work.ink Step 2 first — press CONTINUE TO STEP 2 above and complete the unlock. You return here automatically.</p><p class="muted"><a href="/step2" style="color:var(--gold)">← Back to Step 2</a></p>`
      ),
      403
    );
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
  // Auto-generate on page load: one key per session, reused on revisit.
  // No username asked — the loader binds the real one (HWID) on first use.
  const timestamp = now();
  let keyRow = await env.DB.prepare(
    `SELECT key FROM keys WHERE session_id = ? LIMIT 1`
  ).bind(sessionId).first();
  let key = keyRow && keyRow.key;
  if (!key) {
    key = generateKey();
    try {
      await env.DB.prepare(
        `INSERT INTO keys (key, username, session_id, created_at, expires_at, revoked, executed, last_execution, plan, activated)
         VALUES (?, ?, ?, ?, ?, 0, 0, NULL, ?, 0)`
      ).bind(key, "", sessionId, timestamp, timestamp + KEY_TTL, "day").run();
    } catch (e) {
      await env.DB.prepare(
        `INSERT INTO keys (key, username, session_id, created_at, expires_at, revoked, executed, last_execution, plan)
         VALUES (?, ?, ?, ?, ?, 0, 0, NULL, ?)`
      ).bind(key, "", sessionId, timestamp, timestamp + KEY_TTL, "day").run();
    }
  }
  const loaderCode = `loadstring(game:HttpGet("https://greedyhudzell.xyz/loader.lua"))()`;
  return html(
    pageShell(
      "Your key",
      `<div class="logo">${env.SITE_NAME}</div>
      <div class="step ok">✓ KEY READY</div>
      <label>Your key — click to copy</label>
      <div class="keybox" id="kbox">${key}</div>
      <label style="margin-top:16px">Loader — tap the box to copy, run in your executor</label>
      <div class="codeblock" id="ld-block2">
        <div class="cb-head"><i></i><i></i><i></i><span>&#96;&#96;&#96;lua</span><button class="cb-copy" id="ld-copy2" type="button">Copy</button></div>
        <pre><code id="ld-code2">${loaderCode}</code></pre>
        <div class="cb-hint">press anywhere to copy</div>
      </div>
      <script>(function(){
        function wire(boxId, btnId, getText, btnLabel) {
          var box = document.getElementById(boxId);
          if (!box) return;
          function doCopy() {
            var t = getText();
            function done() {
              box.classList.add('copied');
              var b = btnId && document.getElementById(btnId);
              var old = b ? b.textContent : '';
              if (b) b.textContent = 'Copied!';
              setTimeout(function(){ box.classList.remove('copied'); if (b) b.textContent = old || 'Copy'; }, 1500);
            }
            if (navigator.clipboard && navigator.clipboard.writeText) {
              navigator.clipboard.writeText(t).then(done, function(){});
            }
          }
          box.addEventListener('click', doCopy);
          var b = btnId && document.getElementById(btnId);
          if (b) b.addEventListener('click', doCopy);
        }
        wire('kbox', null, function(){ return document.getElementById('kbox').textContent; });
        wire('ld-block2', 'ld-copy2', function(){ return document.getElementById('ld-code2').textContent; });
      })();</script>`
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
  const qv = await endpointQuota(env, "validate", request, body, 2000);
  if (!qv.ok) return json({ valid: false, reason: qv.error }, 429);
  const username = typeof body.username === "string" ? body.username.trim() : "";
  const discordId = String(body.discord_id || body.discordId || "").replace(/\D/g, "") || null;
  const hwid = typeof body.hwid === "string" ? body.hwid.trim().slice(0, 128) : "";
  // keys: explicit list wins, single key appended for old loaders
  let candidates = [];
  if (Array.isArray(body.keys)) candidates = body.keys.filter((k) => typeof k === "string").map((k) => k.trim()).filter(Boolean);
  if (typeof body.key === "string" && body.key.trim()) candidates.push(body.key.trim());
  candidates = [...new Set(candidates)].slice(0, 10);
  if (!username) return json({ valid: false, reason: "missing_key_or_username" });

  // ---- 5.2.1: key-required script. No keys = no script, no free session. ----
  if (candidates.length === 0) {
    return json({ valid: false, reason: "missing_key", message: "Incorrect key/caught bypassing" });
  }
  // ---- look up every candidate, keep usable ones ----
  // Key-only gate: revoked / expired rows are skipped here; if every known
  // row was expired (or revoked) we report that distinctly so the loader can
  // show "Key expired" instead of the generic incorrect-key message.
  const usable = [];
  let expiredFound = false;
  let revokedFound = false;
  for (const k of candidates) {
    const record = await env.DB.prepare(`SELECT * FROM keys WHERE key = ? LIMIT 1`).bind(k).first();
    if (!record) continue;
    if (record.revoked === 1) { revokedFound = true; continue; }
    if (Number(record.expires_at) <= now()) { expiredFound = true; continue; }
    const ban = await isBanned(env, k, username, body.user_id || body.userId || body.roblox_id, body.hwid);
    if (ban) return json({ valid: false, reason: "banned", message: ban.reason || "Banned from GH." });
    usable.push(record);
  }
  if (usable.length === 0) {
    if (expiredFound) {
      return json({ valid: false, reason: "expired", message: "Key expired" });
    }
    if (revokedFound) {
      return json({ valid: false, reason: "revoked", message: "Key revoked" });
    }
    return json({ valid: false, reason: "invalid_key", message: "Incorrect key/caught bypassing" });
  }

  // ---- highest status key wins ----
  usable.sort((a, b) => planRank(b.plan) - planRank(a.plan));
  const record = usable[0];
  const key = record.key;
  const hwidFree = Number(record.hwid_free) === 1; // universal key: works on all HWIDs

  // ---- HWID bind (first contact binds; then strict match; universal keys skip) ----
  let hwidBoundNow = false;
  if (!hwidFree && hwid) {
    if (!record.hwid) {
      try {
        await env.DB.prepare(`UPDATE keys SET hwid = ?, username = ? WHERE key = ?`).bind(hwid, username, key).run();
      } catch {
        return json({ valid: false, reason: "bind_failed" });
      }
      record.hwid = hwid;
      record.username = username;
      hwidBoundNow = true;
    } else if (record.hwid === hwid) {
      if (record.username !== username) {
        try { await env.DB.prepare(`UPDATE keys SET username = ? WHERE key = ?`).bind(username, key).run(); } catch (_) {}
        record.username = username;
      }
    } else {
      return json({ valid: false, reason: "hwid_mismatch", message: "Incorrect key/caught bypassing" });
    }
  }

  // Roblox username is informational only (HWID is the bind). Claim pending_*
  // once, otherwise refresh best-effort — never fail validation on it.
  if (String(record.username || "") !== username) {
    try {
      await env.DB.prepare(`UPDATE keys SET username = ? WHERE key = ?`).bind(username, key).run();
      record.username = username;
    } catch (_) {}
  }

  // Discord bind: informational only, first send attaches
  if (!record.discord_id && discordId) {
    try {
      await env.DB.prepare(`UPDATE keys SET discord_id = ? WHERE key = ?`).bind(discordId, key).run();
    } catch (_) {}
  }

  const timestamp = now();
  await env.DB.prepare(`UPDATE keys SET executed = 1, last_execution = ? WHERE key = ?`).bind(timestamp, key).run();
  // first HWID bind is logged to Discord (same logs channel as handshake
  // fails) with the FULL hwid so sellers can see which machine claimed it.
  // Awaited but fully guarded: logging must never break validation.
  if (hwidBoundNow) {
    try {
      const ch = env.DISCORD_LOGS_CHANNEL || "";
      if (ch) {
        const uid = String(body.user_id || body.userId || body.roblox_id || "").replace(/\D/g, "");
        const content = "HWID bind | key `" + key + "` | user `" + username + "`"
          + (uid ? " (" + uid + ")" : "")
          + " | plan `" + (record.plan || "?") + "`"
          + (hwidFree ? " | UNIVERSAL" : "")
          + " | HWID `" + hwid + "`";
        await discordApi(env, "POST", "/channels/" + ch + "/messages", { content: content.slice(0, 1900) });
      }
    } catch (_) {}
  }
  // explicit submit = fresh 24h entry (audit trail for re-entry policy)
  if (hwid) {
    try {
      await env.DB.prepare(
        `CREATE TABLE IF NOT EXISTS key_sessions (hwid TEXT NOT NULL, key TEXT NOT NULL, entered_at INTEGER NOT NULL, PRIMARY KEY (hwid, key))`
      ).run();
      await env.DB.prepare(
        `INSERT INTO key_sessions (hwid, key, entered_at) VALUES (?, ?, ?)
         ON CONFLICT(hwid, key) DO UPDATE SET entered_at = excluded.entered_at`
      ).bind(hwid, key, timestamp).run();
    } catch (_) {}
  }

  const testing = record.testing === 1;
  const paid = isPaidPlan(record.plan, key);
  const discordBound = record.discord_id || discordId || null;
  let verified = await isGuildMember(env, discordBound);
  if (!verified && hwid) {
    try {
      const link = await env.DB.prepare(`SELECT discord_id FROM hwid_discord WHERE hwid = ? LIMIT 1`).bind(hwid).first();
      if (link && link.discord_id) verified = true;
    } catch (_) {}
  }
  const script = await fetchSecretScript(env, testing);
  return json({
    valid: true,
    key,
    expires_at: record.expires_at,
    plan: record.plan || "day",
    username: username,
    discord_id: discordBound,
    discord_linked: Boolean(discordBound),
    member_verified: verified,
    paid,
    rewire_allowed: paid,
    testing,
    hwid_bound: Boolean(record.hwid),
    hwid_free: hwidFree,
    script: script.ok ? script.script : null,
    script_error: script.ok ? null : script.reason,
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
      discord_id: k.discord_id != null ? String(k.discord_id) : null,
      executed: k.executed === 1,
      last_execution: k.last_execution,
      created_at: k.created_at,
      expires_at: k.expires_at,
      revoked: k.revoked === 1,
      status: k.revoked === 1 ? "REVOKED" : k.expires_at <= now() ? "EXPIRED" : "ACTIVE",
    })),
  });
}

async function handleAdminKeysByDiscord(request, env) {
  if (!adminAuthorized(request, env)) return json({ error: "Unauthorized" }, 401);
  const url = new URL(request.url);
  const discordId = String(
    url.searchParams.get("discord_id") || url.searchParams.get("discordId") || ""
  ).replace(/\D/g, "");
  if (!discordId || discordId.length < 15) {
    return json({ ok: false, error: "missing_discord_id" }, 400);
  }
  let result;
  try {
    result = await env.DB.prepare(
      `SELECT * FROM keys WHERE CAST(discord_id AS TEXT) = ? ORDER BY created_at DESC`
    )
      .bind(discordId)
      .all();
  } catch (e) {
    return json(
      {
        ok: false,
        error: "discord_id_query_failed",
        hint: "ALTER TABLE keys ADD COLUMN discord_id TEXT;",
        details: String(e && e.message ? e.message : e),
      },
      500
    );
  }
  const rows = (result && result.results) || [];
  return json({
    ok: true,
    success: true,
    discord_id: discordId,
    keys: rows.map((k) => ({
      key: k.key,
      username: k.username,
      plan: k.plan || "day",
      discord_id: k.discord_id != null ? String(k.discord_id) : null,
      executed: k.executed === 1,
      activated: k.activated === 1 || k.executed === 1,
      last_execution: k.last_execution,
      created_at: k.created_at,
      expires_at: k.expires_at,
      revoked: k.revoked === 1,
      status:
        k.revoked === 1
          ? "REVOKED"
          : k.expires_at && k.expires_at <= now()
            ? "EXPIRED"
            : "ACTIVE",
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
    discord_id: record.discord_id != null ? String(record.discord_id) : null,
    session_id: record.session_id,
    created_at: record.created_at,
    expires_at: record.expires_at,
    revoked: record.revoked === 1,
    executed: record.executed === 1,
    last_execution: record.last_execution,
    testing: record.testing === 1,
    hwid: record.hwid || null,
    hwid_free: Number(record.hwid_free) === 1,
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

  const testing = body.testing === true || body.plan === "testing";
  // universal key: works on all HWIDs (optional, off by default).
  const hwidFree = body.hwid_free === true || body.hwidFree === true;
  // custom keys: seller types the literal string. Strict charset so keys stay
  // paste-safe and URL-safe; uniqueness enforced by PRIMARY KEY (duplicate
  // insert returns a clean `duplicate` reason instead of a 500).
  let key;
  let custom = false;
  if (typeof body.custom_key === "string" && body.custom_key.trim() !== "") {
    custom = true;
    key = body.custom_key.trim();
    if (key.length < 8 || key.length > 64 || !/^[A-Za-z0-9_\-]+$/.test(key)) {
      return json({ success: false, reason: "invalid_custom_key" }, 400);
    }
  } else {
    key = testing ? generateTestingKey() : generateKey();
  }
  const timestamp = now();
  const expires = timestamp + planTtl(testing ? "year" : plan);
  const storedUser = username || ("pending_" + key.replace(/-/g, "").slice(0, 12));

  // ensure the hwid_free column exists (older DBs predate migration 0006).
  try { await env.DB.prepare(`ALTER TABLE keys ADD COLUMN hwid_free INTEGER`).run(); } catch (_) {}
  try {
    await env.DB.prepare(
      `INSERT INTO keys (key, username, session_id, created_at, expires_at, revoked, executed, last_execution, plan, testing, hwid_free)
       VALUES (?, ?, ?, ?, ?, 0, 0, NULL, ?, ?, ?)`
    )
      .bind(key, storedUser, "admin:" + timestamp, timestamp, expires, testing ? "testing" : plan, testing ? 1 : 0, hwidFree ? 1 : 0)
      .run();
  } catch (e) {
    const msg = String((e && e.message) || e);
    if (custom && /UNIQUE|PRIMARY|duplicate|already exists/i.test(msg)) {
      return json({ success: false, reason: "duplicate", message: "That key string is already taken." }, 409);
    }
    console.error("admin generate insert:", msg);
    return json({
      success: false,
      reason: "db_error",
      message: msg,
    }, 500);
  }

  return json({
    success: true,
    key,
    custom,
    plan: testing ? "testing" : plan,
    testing,
    hwid_free: hwidFree,
    expires_at: expires,
    username: username || null,
    pending: !username,
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

/** Reset HWID bind — at most once per 7 days per key */
async function handleAdminResetHwid(request, env) {
  if (!adminAuthorized(request, env)) return json({ success: false, reason: "unauthorized" }, 401);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ success: false, reason: "invalid_json" }, 400);
  }
  const key = typeof body.key === "string" ? body.key.trim() : "";
  if (!key) return json({ success: false, reason: "missing_key" }, 400);
  const record = await env.DB.prepare(`SELECT * FROM keys WHERE key = ? LIMIT 1`).bind(key).first();
  if (!record) return json({ success: false, reason: "key_not_found" }, 404);
  if (!record.hwid) return json({ success: true, key, already_free: true });
  const paid = isPaidPlan(record.plan, key);
  const week = 7 * 24 * 60 * 60;
  const last = Number(record.hwid_reset_at) || 0;
  // 5.2.0: free keys get 1 rebind, paid keys rebind unlimited (no cooldown)
  if (last && !paid) {
    return json({ success: false, reason: "free_used", message: "Free keys get 1 HWID rebind. Paid keys rebind unlimited." }, 400);
  }
  await env.DB.prepare(`UPDATE keys SET hwid = NULL, hwid_reset_at = ? WHERE key = ?`).bind(now(), key).run();
  return json({ success: true, key, reset_at: now() });
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

/* 5.2.0: private gh-secret builds (loader + hub). Token never leaves the worker. */
async function proxySecret(env, file) {
  const token = env.GITHUB_TOKEN || "";
  if (!token) return plain("hub not published", 503);
  const repo = env.GH_SECRET_REPO || "purrguy/gh-secret";
  const res = await fetch(`https://api.github.com/repos/${repo}/contents/${file}`, {
    headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github.raw", "User-Agent": "greedyhudzell-worker" },
  });
  if (!res.ok) return plain(`${file} not found`, 404);
  const text = await res.text();
  if (!text || text.length < 40) return plain(`${file} empty`, 404);
  return plain(text, 200);
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
  <div style="margin:14px 0;padding:12px 16px;border:1px solid var(--gold,#f0b429);border-radius:10px;background:rgba(240,180,41,.08)">Greedy Hudzell obfuscator has been renamed to <b>lime</b>! Purchase it here: <a href="https://lime.greedyhudzell.xyz" style="color:var(--gold,#f0b429)">lime.greedyhudzell.xyz</a></div>
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
    <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center">
      <button type="button" class="btn btn-gold" id="go">Obfuscate</button>
      <button type="button" class="btn" id="copy">Copy output</button>
      <span id="quota" class="muted"></span>
    </div>
    <label class="f" style="margin-top:10px">License key <span class="muted">(optional — raises your daily limit)</span></label>
    <input type="text" id="lickey" placeholder="GH-XXXX-XXXX-XXXX" autocomplete="off" style="max-width:320px"/>
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
      const quotaEl = document.getElementById("quota");
      const out = document.getElementById("out");
      const licEl = document.getElementById("lickey");
      const lickey = licEl && licEl.value.trim() ? licEl.value.trim() : undefined;
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
          body: JSON.stringify({ preset: preset.value, options: collectOptions(), code: code, license_key: lickey })
        });
        const data = await res.json();
        if (!data.ok) {
          statusEl.className = "err";
          statusEl.textContent = data.error === "daily_limit"
            ? "Daily limit reached (" + (data.used || "?") + "/" + (data.limit || "?") + "). " + (data.reset_hint || "")
            : (data.error || res.status);
          return;
        }
        out.value = data.code || "";
        statusEl.className = "ok";
        statusEl.textContent = "OK · " + (data.mode||"") + " · " + (data.code||"").length + " chars · " + (data.note||"");
        if (data.left_today !== undefined) {
          quotaEl.textContent = data.left_today + " left today · plan " + (data.plan || "?")
            + (data.bonus ? " · +1 Work.ink bonus 🎁" : "");
        }
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
    ["api", "/api", "API"],
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
<link rel="icon" type="image/png" href="https://raw.githubusercontent.com/purrguy/greedyhudzell/main/logo.png"/>
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
.brand-logo{width:34px;height:34px;border-radius:10px;border:1px solid var(--gold);object-fit:cover;display:block}
/* golden code block, markdown-fence style */
.codeblock{background:#070707;border:1px solid var(--gold);border-radius:12px;overflow:hidden;margin-top:14px;max-width:100%;cursor:pointer}
.codeblock .cb-head{display:flex;align-items:center;gap:7px;padding:9px 13px;border-bottom:1px solid rgba(201,162,39,.4)}
.codeblock .cb-head i{width:11px;height:11px;border-radius:50%;background:#3a3a3a}
.codeblock .cb-head i:nth-child(1){background:#ff5f57}
.codeblock .cb-head i:nth-child(2){background:#febc2e}
.codeblock .cb-head i:nth-child(3){background:#28c840}
.codeblock .cb-head span{margin-left:6px;color:var(--muted);font-size:12px;font-family:ui-monospace,monospace}
.codeblock .cb-copy{margin-left:auto;background:var(--bg2);border:1px solid var(--gold);color:var(--gold-soft);border-radius:8px;padding:6px 14px;font-size:12px;font-weight:600;cursor:pointer;font-family:inherit}
.codeblock .cb-copy:hover{background:var(--gold);color:#0a0a0a}
.codeblock pre{padding:14px 15px;font-family:ui-monospace,monospace;font-size:12.5px;line-height:1.65;color:var(--gold-soft);white-space:pre-wrap;word-break:break-all;overflow-wrap:anywhere;overflow:hidden;margin:0;max-width:100%}
.codeblock code{overflow-wrap:anywhere;word-break:break-all}
.codeblock .cb-hint{font-size:11px;color:var(--muted);padding:0 15px 10px}
/* method modal */
.mback{position:fixed;inset:0;z-index:200;background:rgba(0,0,0,.68);backdrop-filter:blur(3px);display:flex;align-items:center;justify-content:center;padding:20px}
.mback[hidden]{display:none}
.modal{background:var(--card);border:1px solid var(--gold);border-radius:18px;box-shadow:0 24px 70px rgba(0,0,0,.6);max-width:400px;width:100%;padding:24px}
.m-title{font-size:17px;font-weight:700;margin-bottom:4px}
.m-sub{font-size:13px;color:var(--muted);margin-bottom:16px}
.dd{position:relative}
.dd-btn{width:100%;display:flex;align-items:center;justify-content:space-between;gap:10px;background:#0c0c0c;border:1px solid var(--gold);color:var(--text);border-radius:10px;padding:12px 14px;font-size:13px;font-weight:600;cursor:pointer;font-family:inherit}
.dd-btn .dd-chev{color:var(--gold);transition:transform .15s}
.dd.open .dd-btn .dd-chev{transform:rotate(180deg)}
.dd-list{position:absolute;top:calc(100% + 6px);left:0;right:0;background:#101010;border:1px solid var(--gold);border-radius:12px;overflow:hidden;z-index:5;box-shadow:0 16px 40px rgba(0,0,0,.55)}
.dd-list[hidden]{display:none}
.dd-opt{display:block;width:100%;text-align:left;background:transparent;border:none;border-bottom:1px solid var(--border);color:var(--text);padding:12px 14px;font-size:13px;cursor:pointer;font-family:inherit}
.dd-opt:last-child{border-bottom:none}
.dd-opt:not(.locked):hover{background:rgba(201,162,39,.1)}
.dd-opt .dd-sub{display:block;font-size:11px;color:var(--muted);margin-top:2px}
.dd-opt.locked{opacity:.55;cursor:not-allowed}
.dd-opt .dd-lock{color:var(--gold);font-size:11px;font-weight:700}
.m-note{font-size:12px;color:var(--gold-soft);min-height:18px;margin-top:12px;text-align:center}
.m-actions{display:flex;justify-content:flex-end;margin-top:8px}
/* key display box */
.keybox{font-family:ui-monospace,monospace;font-size:17px;font-weight:700;letter-spacing:1px;text-align:center;background:#070707;border:1px solid var(--gold);border-radius:12px;padding:16px 12px;cursor:pointer;user-select:all;color:var(--gold-soft);overflow-wrap:anywhere;word-break:break-word}
.keybox:hover{background:#0d0d09}
.keybox.copied{border-color:var(--ok);color:var(--ok)}
/* golden frames on commerce UI */
.price-card{border-color:rgba(201,162,39,.45)}
.price-card.featured{border-color:var(--gold)}
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
      <img class="brand-logo" src="https://raw.githubusercontent.com/purrguy/greedyhudzell/main/logo.png" alt="GH" onerror="this.outerHTML='<div class=&quot;brand-mark&quot;>GH</div>'"/>
      <span>Greedy Hudzell</span>
    </a>
    <nav class="nav">${siteNav(active)}</nav>
  </div>
</header>
<main class="wrap${wide ? " wide" : ""}">
${bodyHtml}
  <div class="foot">© Greedy Hudzell · <a href="${DISCORD_INVITE}">Discord</a> · Not affiliated with Roblox</div>
</main>
<div class="mback" id="gh-mback" hidden>
  <div class="modal">
    <div class="m-title" id="gh-mtitle">Select method</div>
    <div class="m-sub" id="gh-msub"></div>
    <div class="dd" id="gh-dd">
      <button class="dd-btn" id="gh-ddbtn" type="button"><span id="gh-ddlabel">Choose…</span><span class="dd-chev">▾</span></button>
      <div class="dd-list" id="gh-ddlist" hidden></div>
    </div>
    <div class="m-note" id="gh-mnote"></div>
    <div class="m-actions"><button class="btn" id="gh-mcancel" type="button">Cancel</button></div>
  </div>
</div>
<script>
(function(){
  var back = document.getElementById('gh-mback');
  if (!back) return;
  var dd = document.getElementById('gh-dd');
  var btn = document.getElementById('gh-ddbtn');
  var list = document.getElementById('gh-ddlist');
  var note = document.getElementById('gh-mnote');
  function close() { back.hidden = true; dd.classList.remove('open'); list.hidden = true; }
  back.addEventListener('click', function(e) { if (e.target === back) close(); });
  document.getElementById('gh-mcancel').addEventListener('click', close);
  document.addEventListener('keydown', function(e) { if (e.key === 'Escape') close(); });
  btn.addEventListener('click', function(e) {
    e.stopPropagation();
    dd.classList.toggle('open');
    list.hidden = !list.hidden;
  });
  document.addEventListener('click', function(e) {
    if (!dd.contains(e.target)) { dd.classList.remove('open'); list.hidden = true; }
  });
  window.ghMethods = function(title, sub, opts) {
    document.getElementById('gh-mtitle').textContent = title;
    document.getElementById('gh-msub').textContent = sub || '';
    note.textContent = '';
    list.innerHTML = '';
    opts.forEach(function(o) {
      var b = document.createElement('button');
      b.type = 'button';
      b.className = 'dd-opt' + (o.locked ? ' locked' : '');
      b.innerHTML = '<span>' + o.label + '</span>'
        + (o.locked ? ' <span class="dd-lock">🔒 ' + (o.lockNote || 'Locked') + '</span>' : '')
        + (o.sub ? '<span class="dd-sub">' + o.sub + '</span>' : '');
      b.addEventListener('click', function() {
        if (o.locked) { note.textContent = o.lockNote || 'Temporarily locked'; return; }
        close();
        if (o.href) window.open(o.href, '_blank', 'noopener');
      });
      list.appendChild(b);
    });
    document.getElementById('gh-ddlabel').textContent = 'Choose…';
    back.hidden = false;
  };
})();
</script>
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
  <img src="https://raw.githubusercontent.com/purrguy/greedyhudzell/main/GH%20banner.png" alt="Greedy Hudzell" style="width:100%;border-radius:12px;margin-bottom:14px" onerror="this.style.display='none'"/>
  <h1>Greedy Hudzell</h1>
  <p class="sub">Keys, loader, updates. Check your key status below.</p>
  <div class="hero-actions">
    <button class="btn btn-gold" id="m-free-btn" type="button">Select method</button>
    <a class="btn" href="/pricing">Pricing</a>
    <a class="btn" href="${DISCORD_INVITE}" target="_blank" rel="noopener">Discord</a>
  </div>
  <script>(function(){
    var b = document.getElementById('m-free-btn');
    if (b && window.ghMethods) b.addEventListener('click', function() {
      window.ghMethods('Get a free key', 'Pick where to complete the steps:', [
        { label: 'Work.Ink', sub: '24h key · already set up', href: '${FREE_KEY_LINK}' },
        { label: 'Linkvertise', sub: 'coming soon', locked: true, lockNote: 'Coming soon' }
      ]);
    });
  })();</script>
  <div class="grid2" style="margin-top:14px">
    <div class="card"><h3 style="margin-bottom:4px">Executions</h3><p class="muted" id="st_exec" style="font-size:22px">—</p></div>
    <div class="card"><h3 style="margin-bottom:4px">Levels farmed</h3><p class="muted" id="st_lvl" style="font-size:22px">—</p></div>
  </div>
  <script>(function(){fetch("/api/stats").then(function(r){return r.json()}).then(function(d){var e=document.getElementById("st_exec"),l=document.getElementById("st_lvl");if(e)e.textContent=d.executions||0;if(l)l.textContent=d.levels_farmed||0;}).catch(function(){});})();</script>
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
      <div class="codeblock" id="ld-block">
        <div class="cb-head"><i></i><i></i><i></i><span>&#96;&#96;&#96;lua</span><button class="cb-copy" id="ld-copy" type="button">Copy</button></div>
        <pre><code id="ld-code">loadstring(game:HttpGet("https://greedyhudzell.xyz/loader.lua"))()</code></pre>
        <div class="cb-hint">press anywhere to copy</div>
      </div>
      <p class="muted" style="margin-top:12px"><a href="/guide">Guide</a> · <a href="/executors">Executors</a> · <a href="/status">Status</a></p>
    </div>
  <script>(function(){
    var b = document.getElementById('ld-copy');
    var block = document.getElementById('ld-block');
    function doCopy() {
      var t = document.getElementById('ld-code').textContent;
      function done() { if (b) { b.textContent = 'Copied!'; setTimeout(function(){ b.textContent = 'Copy'; }, 1500); } }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(t).then(done, function() {});
      }
    }
    if (b) b.addEventListener('click', doCopy);
    if (block) block.addEventListener('click', doCopy);
  })();</script>
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
      <tr><td>/loader.lua</td><td>Private build v5.2.0 (key gate + hub in one)</td></tr>
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
    <p><b>1.</b> No key needed to run (free). Keys unlock paid; Member unlocks most features.</p>
    <p style="margin-top:8px"><b>2.</b> Run: <code>loadstring(game:HttpGet("https://greedyhudzell.xyz/loader.lua"))()</code></p>
    <p style="margin-top:8px"><b>3.</b> Enter key. Check status anytime on <a href="/home">Home</a>.</p>
    <p style="margin-top:8px"><b>4.</b> Stack overflow after obfuscation → use light/raw, not Full/VM.</p>
  </div>
`);
}

function apiPage() {
  return siteShell("API", "api", `
  <div class="badge">Developers</div>
  <h1>API access</h1>
  <p class="sub">Keys inherit your license plan (free: 2 obfuscations/day · week: 10 · month: 30 · year: 50). Complete both Work.ink steps for +1/day. Never expires unless you revoke it.</p>
  <div class="card">
    <h3 style="margin-bottom:8px">Your license key</h3>
    <p class="muted">Paste a valid license key to manage its API keys. The key itself is never stored — only checked.</p>
    <div class="key-input-group">
      <input type="text" id="api-lic" placeholder="GH-XXXX-XXXX-XXXX" autocomplete="off"/>
      <button id="api-load" type="button">Unlock</button>
    </div>
    <p id="api-plan" class="muted" style="margin-top:10px"></p>
  </div>
  <div class="card" id="api-mgr" hidden>
    <div class="panel-head"><h3>API keys</h3><span class="tag" id="api-plan-tag">plan</span></div>
    <div class="key-input-group">
      <input type="text" id="api-name" maxlength="40" placeholder="Key name (e.g. my bot)" autocomplete="off"/>
      <button id="api-create" type="button">Create key</button>
    </div>
    <p id="api-new" class="muted" style="margin-top:10px"></p>
    <div id="api-list" style="margin-top:12px"></div>
  </div>
  <div class="card">
    <h3 style="margin-bottom:8px">Docs</h3>
    <p class="muted">Send the key as <code>X-API-Key</code> header (or <code>Bearer ghsk_…</code>). Quotas reset midnight UTC.</p>
    <div class="codeblock"><div class="cb-head"><i></i><i></i><i></i><span>curl</span></div><pre><code>curl -X POST https://greedyhudzell.xyz/api/obfuscate \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: ghsk_YOUR_KEY" \\
  -d '{"code": "print(1)", "preset": "good"}'

curl -X POST https://greedyhudzell.xyz/validate \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: ghsk_YOUR_KEY" \\
  -d '{"key": "GH-XXXX-XXXX-XXXX", "username": "SomeName"}'</code></pre></div>
  </div>
  <script>(function(){
    var lic = "";
    var planMax = 2;
    function esc(s){ return String(s == null ? "" : s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); }
    function msg(t, ok){ var p = document.getElementById("api-plan"); p.className = ok ? "ok" : "muted"; p.textContent = t; }
    function copyText(t, done) {
      function ok2(){ done(); }
      if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(t).then(ok2, function(){}); }
    }
    async function refresh() {
      var box = document.getElementById("api-list");
      box.innerHTML = "<p class='muted'>Loading…</p>";
      try {
        var r = await fetch("/api/keys?license_key=" + encodeURIComponent(lic));
        var d = await r.json();
        if (!d.ok) { box.innerHTML = "<p class='err'>" + esc(d.error || "failed") + "</p>"; return; }
        document.getElementById("api-plan-tag").textContent = d.plan || "?";
        planMax = d.plan_max || 2;
        if (!d.keys.length) { box.innerHTML = "<p class='muted'>No API keys yet — create one above.</p>"; return; }
        var h = '<table><thead><tr><th>Name</th><th>Key</th><th>Rules</th><th></th></tr></thead><tbody>';
        d.keys.forEach(function(k) {
          var rules = (k.scopes || "") + (k.daily_limit ? " · ≤" + k.daily_limit + "/day" : "") + (k.expires_at ? " · exp " + new Date(k.expires_at * 1000).toLocaleDateString() : "") + (k.revoked ? " · REVOKED" : "");
          h += "<tr><td>" + esc(k.name) + "</td>"
            + "<td class='mono'>" + esc(k.prefix) + "…</td>"
            + "<td class='muted'>" + esc(rules) + "</td>"
            + "<td style='white-space:nowrap'><button class='btn' data-gear='" + esc(k.id) + "' type='button' title='rules'>⚙</button> "
            + (k.revoked ? "" : "<button class='btn' data-revoke='" + esc(k.id) + "' type='button'>Revoke</button>") + "</td></tr>"
            + "<tr class='gear-row' data-gearrow='" + esc(k.id) + "' hidden><td colspan='4'>"
            + "daily cap <input data-f-limit style='width:90px;display:inline-block' type='number' min='1' max='" + planMax + "' value='" + (k.daily_limit || "") + "' placeholder='" + planMax + "'/> "
            + "expires <input data-f-exp style='width:150px;display:inline-block' type='date'/> "
            + "<label style='display:inline'><input data-f-s-obf type='checkbox'" + ((k.scopes || "").indexOf("obfuscate") >= 0 ? " checked" : "") + "/> obfuscate</label> "
            + "<label style='display:inline'><input data-f-s-val type='checkbox'" + ((k.scopes || "").indexOf("validate") >= 0 ? " checked" : "") + "/> validate</label> "
            + "<label style='display:inline'><input data-f-s-stats type='checkbox'" + ((k.scopes || "").indexOf("stats") >= 0 ? " checked" : "") + "/> stats</label> "
            + "<button class='btn btn-gold' data-save='" + esc(k.id) + "' type='button'>Save</button></td></tr>";
        });
        box.innerHTML = h + "</tbody></table>";
      } catch (e) { box.innerHTML = "<p class='err'>Network error.</p>"; }
    }
    document.getElementById("api-load").addEventListener("click", async function() {
      lic = (document.getElementById("api-lic").value || "").trim();
      if (!lic) { msg("Enter your license key first.", false); return; }
      msg("Checking…", true);
      try {
        var r = await fetch("/api/keys?license_key=" + encodeURIComponent(lic));
        var d = await r.json();
        if (!d.ok) { msg("License rejected: " + (d.error || r.status), false); return; }
        document.getElementById("api-mgr").hidden = false;
        msg("Unlocked · plan " + (d.plan || "?") + " · up to " + (d.plan_max || 2) + "/day per key", true);
        refresh();
      } catch (e) { msg("Network error.", false); }
    });
    document.getElementById("api-create").addEventListener("click", async function() {
      var name = (document.getElementById("api-name").value || "").trim() || "api key";
      var out = document.getElementById("api-new");
      out.className = "muted"; out.textContent = "Creating…";
      try {
        var r = await fetch("/api/keys", { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ license_key: lic, name: name }) });
        var d = await r.json();
        if (!d.ok) { out.className = "err"; out.textContent = "Failed: " + (d.detail || d.error); return; }
        out.className = "ok";
        out.innerHTML = "Copy it NOW — shown once:<br><code id='api-fresh'>" + esc(d.api_key) + "</code> "
          + "<button class='btn' id='api-fresh-copy' type='button'>Copy</button>";
        document.getElementById("api-fresh-copy").addEventListener("click", function() {
          copyText(d.api_key, function() { out.textContent = "Copied! " + d.api_key.slice(0, 13) + "…"; });
        });
        refresh();
      } catch (e) { out.className = "err"; out.textContent = "Network error."; }
    });
    document.getElementById("api-list").addEventListener("click", async function(e) {
      var g = e.target.closest ? e.target.closest("[data-gear]") : null;
      var rv = e.target.closest ? e.target.closest("[data-revoke]") : null;
      var sv = e.target.closest ? e.target.closest("[data-save]") : null;
      if (g) {
        var row = document.querySelector('[data-gearrow="' + g.dataset.gear + '"]');
        if (row) row.hidden = !row.hidden;
        return;
      }
      if (rv) {
        if (!confirm("Revoke this API key? Existing integrations break immediately.")) return;
        try {
          var r = await fetch("/api/keys/revoke", { method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ license_key: lic, id: rv.dataset.revoke }) });
          var d = await r.json();
          if (!d.ok) { alert("Failed: " + (d.error || r.status)); return; }
          refresh();
        } catch (err) { alert("Network error."); }
        return;
      }
      if (sv) {
        var row2 = document.querySelector('[data-gearrow="' + sv.dataset.save + '"]');
        var lim = row2.querySelector("[data-f-limit]").value;
        var exp = row2.querySelector("[data-f-exp]").value;
        var sc = [];
        if (row2.querySelector("[data-f-s-obf]").checked) sc.push("obfuscate");
        if (row2.querySelector("[data-f-s-val]").checked) sc.push("validate");
        if (row2.querySelector("[data-f-s-stats]").checked) sc.push("stats");
        var payload = { license_key: lic, id: sv.dataset.save, scopes: sc };
        payload.daily_limit = lim === "" ? null : Number(lim);
        payload.expires_at = exp === "" ? null : Math.floor(new Date(exp + "T00:00:00Z").getTime() / 1000);
        try {
          var r2 = await fetch("/api/keys/rules", { method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload) });
          var d2 = await r2.json();
          if (!d2.ok) { alert("Failed: " + (d2.detail || d2.error)); return; }
          refresh();
        } catch (err) { alert("Network error."); }
      }
    });
  })();</script>
`, true);
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
      <button class="btn" id="m-free-paid" type="button">Select method</button>
    </article>
    <article class="price-card">
      <h3>Week</h3>
      <div class="amount">$3.99 <span>/ 7 days</span></div>
      <ul>
        <li>Full script access</li>
        <li>Account rewire included</li>
        <li>Priority Discord support</li>
      </ul>
      <button class="btn m-paid-btn" type="button">Select method</button>
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
      <button class="btn btn-gold m-paid-btn" type="button">Select method</button>
    </article>
    <article class="price-card">
      <h3>Year</h3>
      <div class="amount">$12.99 <span>/ 365 days</span></div>
      <ul>
        <li>Full script access</li>
        <li>Account rewire included</li>
        <li>Best long-term value</li>
      </ul>
      <button class="btn m-paid-btn" type="button">Select method</button>
    </article>
  </div>
  <p class="muted">See <a href="/tos">Terms of Service</a> for rewire, refunds, and key rules.</p>
  <script>
  (function(){
    function freeModal() {
      if (!window.ghMethods) return;
      window.ghMethods('Get a free key', 'Pick where to complete the steps:', [
        { label: 'Work.Ink', sub: '24h key · already set up', href: '${FREE_KEY_LINK}' },
        { label: 'Linkvertise', sub: 'coming soon', locked: true, lockNote: 'Coming soon' }
      ]);
    }
    function paidModal() {
      if (!window.ghMethods) return;
      window.ghMethods('Choose payment', 'Paid plans, week / month / year:', [
        { label: 'Roblox Gamepass', sub: 'pay with Robux', locked: true, lockNote: 'Temporary locked' },
        { label: 'Card payment', sub: 'via Discord ticket', href: '${DISCORD_INVITE}' }
      ]);
    }
    var f = document.getElementById('m-free-paid');
    if (f) f.addEventListener('click', freeModal);
    document.querySelectorAll('.m-paid-btn').forEach(function(b) {
      b.addEventListener('click', paidModal);
    });
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

/* ===================== 5.2.0 KEY AUTH ===================== */
// plan rank: highest valid key wins (year > month > week > day; free = -1)
function planRank(plan) {
  const p = String(plan || "").toLowerCase();
  if (p === "year") return 3;
  if (p === "month") return 2;
  if (p === "week") return 1;
  if (p === "day") return 0;
  return -1;
}
// long testing keys: GHT- + 48 chars, unmistakable vs normal GH- keys
function generateTestingKey() {
  const bytes = new Uint8Array(36);
  crypto.getRandomValues(bytes);
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  let value = "";
  for (const byte of bytes) value += alphabet[byte % alphabet.length];
  return `GHT-${value}`;
}
// Discord Member check: linked discord_id must hold the Member role
async function isGuildMember(env, discordId) {
  const id = String(discordId || "").replace(/\D/g, "");
  if (!id) return false;
  // fast path: web-verify members table (written on authorize)
  try {
    const row = await env.DB.prepare(`SELECT discord_id FROM members WHERE discord_id = ? LIMIT 1`).bind(id).first();
    if (row) return true;
  } catch (_) {}
  const guildId = env.DISCORD_GUILD_ID || "1422222409846620201";
  const roleId = env.DISCORD_MEMBER_ROLE || "1445500571640402052";
  try {
    const r = await discordApi(env, "GET", `/guilds/${guildId}/members/${id}`, null);
    if (!r.ok || !r.data || !Array.isArray(r.data.roles)) return false;
    return r.data.roles.map(String).includes(String(roleId));
  } catch {
    return false;
  }
}
// private repo script fetch (gh-secret). Needs GITHUB_TOKEN secret.
// normal key -> greedy.lua, testing key -> greedytesting.lua
async function fetchSecretScript(env, testing) {
  const token = env.GITHUB_TOKEN || "";
  if (!token) return { ok: false, reason: "no_github_token" };
  const repo = env.GH_SECRET_REPO || "purrguy/gh-secret";
  const file = testing ? (env.GH_SECRET_TESTING_FILE || "greedytesting.lua")
                       : (env.GH_SECRET_FILE || "greedy.lua");
  try {
    const res = await fetch(`https://api.github.com/repos/${repo}/contents/${file}`, {
      headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github.raw", "User-Agent": "greedyhudzell-worker" },
    });
    if (!res.ok) return { ok: false, reason: "github_" + res.status };
    const text = await res.text();
    if (!text || text.length < 40) return { ok: false, reason: "empty_script" };
    return { ok: true, script: text, file };
  } catch (e) {
    return { ok: false, reason: "fetch_failed" };
  }
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
const OAUTH_SCOPES = "identify guilds guilds.join";

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

/* 5.2.0: keyless web verify. Copy the link from the hub, authorize,
   worker auto-joins the guild + grants Member + stores you in members. */
/* 5.2.0: per-client verify links. Hub requests a fresh token every execute
   (old tokens for the HWID are revoked), user opens it, authorizes, gets the
   Verified role + HWID link. No refresh button needed. */
async function handleVerifyLink(request, env) {
  if (request.method !== "POST") return json({ ok: false }, 405);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false }, 400);
  }
  const hwid = typeof body.hwid === "string" ? body.hwid.trim().slice(0, 128) : "";
  if (!hwid) return json({ ok: false, reason: "missing_hwid" }, 400);
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  const token = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  try {
    await env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS verify_links (token TEXT PRIMARY KEY, hwid TEXT NOT NULL, created_at INTEGER NOT NULL)`
    ).run();
    await env.DB.prepare(`DELETE FROM verify_links WHERE hwid = ?`).bind(hwid).run();
    await env.DB.prepare(
      `INSERT INTO verify_links (token, hwid, created_at) VALUES (?, ?, ?)`
    ).bind(token, hwid, now()).run();
  } catch {
    return json({ ok: false, reason: "db_error" }, 500);
  }
  return json({ ok: true, url: "https://greedyhudzell.xyz/verify/key/discord/" + token });
}

async function handleVerifyToken(request, env, token) {
  token = String(token || "").slice(0, 140);
  if (!/^[0-9a-f]{4,128}$/.test(token)) {
    return html(`<h1>Bad verify link</h1><p>Copy a fresh link from the hub.</p>`, 400);
  }
  let row = null;
  try {
    await env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS verify_links (token TEXT PRIMARY KEY, hwid TEXT NOT NULL, created_at INTEGER NOT NULL)`
    ).run();
    row = await env.DB.prepare(`SELECT hwid FROM verify_links WHERE token = ? LIMIT 1`).bind(token).first();
  } catch (_) {}
  if (!row) {
    return html(`<h1>Link expired or used</h1><p>Copy a fresh link from the hub (new one every execute).</p>`, 400);
  }
  const clientId = env.DISCORD_CLIENT_ID || env.CLIENT_ID || DEFAULT_DISCORD_CLIENT_ID;
  if (!clientId) return html(`<h1>Server misconfigured</h1>`, 500);
  const redirect = oauthRedirectUri(env, request);
  const auth = new URL("https://discord.com/api/oauth2/authorize");
  auth.searchParams.set("client_id", String(clientId));
  auth.searchParams.set("redirect_uri", redirect);
  auth.searchParams.set("response_type", "code");
  auth.searchParams.set("scope", OAUTH_SCOPES);
  auth.searchParams.set("state", "vfy:" + token);
  auth.searchParams.set("prompt", "consent");
  return Response.redirect(auth.toString(), 302);
}

async function handleWebVerify(request, env) {
  const clientId = env.DISCORD_CLIENT_ID || env.CLIENT_ID || DEFAULT_DISCORD_CLIENT_ID;
  if (!clientId) {
    return html(`<h1>Server misconfigured</h1><p>DISCORD_CLIENT_ID secret required.</p>`, 500);
  }
  const redirect = oauthRedirectUri(env, request);
  const auth = new URL("https://discord.com/api/oauth2/authorize");
  auth.searchParams.set("client_id", String(clientId));
  auth.searchParams.set("redirect_uri", redirect);
  auth.searchParams.set("response_type", "code");
  auth.searchParams.set("scope", OAUTH_SCOPES);
  auth.searchParams.set("state", "web");
  auth.searchParams.set("prompt", "consent");
  return Response.redirect(auth.toString(), 302);
}

async function handleOauthCallback(request, env) {
  const url = new URL(request.url);
  // Discord returns ?code=...&state=...  (state is our discord_id)
  // Direct authorize links without state used to show "Missing code" — fixed.
  const code = url.searchParams.get("code");
  const rawState = String(url.searchParams.get("state") || "");
  const webFlow = rawState === "web";
  let state = rawState.replace(/\D/g, "");
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
  // 5.2.0 key-verify flow: state vfy:<token> links this Discord to a client HWID
  let keyFlow = null;
  if (rawState.startsWith("vfy:")) {
    const token = rawState.slice(4, 140);
    try {
      await env.DB.prepare(
        `CREATE TABLE IF NOT EXISTS verify_links (token TEXT PRIMARY KEY, hwid TEXT NOT NULL, created_at INTEGER NOT NULL)`
      ).run();
      const row = await env.DB.prepare(`SELECT hwid FROM verify_links WHERE token = ? LIMIT 1`).bind(token).first();
      if (row && row.hwid) {
        keyFlow = { token, hwid: String(row.hwid).slice(0, 128) };
        try { await env.DB.prepare(`DELETE FROM verify_links WHERE token = ?`).bind(token).run(); } catch (_) {}
      }
    } catch (_) {}
  }

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

  // Auto-join our guild straight from OAuth (needs guilds.join scope).
  let joined = false, joinErr = null;
  let memberGiven = false, memberErr = null;
  const joinGuild = env.DISCORD_GUILD_ID || "1422222409846620201";
  const memberRole = env.DISCORD_MEMBER_ROLE || "1445500571640402052";
  try {
    const jr = await discordApi(env, "PUT", `/guilds/${joinGuild}/members/${state}`, { access_token: access });
    joined = jr.ok || jr.status === 201 || jr.status === 204;
    if (!joined) joinErr = "discord_" + jr.status;
  } catch (e) {
    joinErr = String((e && e.message) || e).slice(0, 80);
  }
  // 5.2.0 web flow: Member role right here (no key needed), stored in members.
  // key flow piggybacks the same grant, then links HWID <-> Discord.
  if (webFlow || keyFlow) {
    try {
      const rr = await discordApi(env, "PUT", `/guilds/${joinGuild}/members/${state}/roles/${memberRole}`, null);
      memberGiven = rr.ok || rr.status === 204;
      if (!memberGiven) memberErr = "discord_" + rr.status;
    } catch (e) {
      memberErr = String((e && e.message) || e).slice(0, 80);
    }
    try {
      await env.DB.prepare(
        `CREATE TABLE IF NOT EXISTS members (discord_id TEXT PRIMARY KEY, username TEXT, verified_at INTEGER NOT NULL)`
      ).run();
      await env.DB.prepare(
        `INSERT INTO members (discord_id, username, verified_at) VALUES (?, ?, ?)
         ON CONFLICT(discord_id) DO UPDATE SET username = excluded.username, verified_at = excluded.verified_at`
      ).bind(state, String(me.username || me.global_name || ""), Math.floor(Date.now() / 1000)).run();
    } catch (_) {}
    if (keyFlow) {
      try {
        await env.DB.prepare(
          `CREATE TABLE IF NOT EXISTS hwid_discord (hwid TEXT PRIMARY KEY, discord_id TEXT NOT NULL, verified_at INTEGER NOT NULL)`
        ).run();
        await env.DB.prepare(
          `INSERT INTO hwid_discord (hwid, discord_id, verified_at) VALUES (?, ?, ?)
           ON CONFLICT(hwid) DO UPDATE SET discord_id = excluded.discord_id, verified_at = excluded.verified_at`
        ).bind(keyFlow.hwid, state, Math.floor(Date.now() / 1000)).run();
      } catch (_) {}
    }
  }

  return html(
    `<!doctype html><html><body style="font-family:system-ui;background:#0b0b0b;color:#eee;padding:2rem;text-align:center">
    <h1 style="color:#d4af37">Connected</h1>
    <p>Discord <b>${me.username || state}</b> authorized.</p>
    <p>Servers seen: <b>${guildIds.length}</b></p>
    <p>${joined ? "Joined the Greedy Hudzell server." : "Auto-join: " + (joinErr || "already a member") + ". If you are not in, use the invite."}</p>
    ${(webFlow || keyFlow)
      ? `<p>${memberGiven ? "Verified role granted. This machine is now verified — features unlock in the hub." : "Verified role: " + (memberErr || "already present") + ". This machine is linked."}</p>`
      : `<p>Return to Discord and press <b>Verify</b> again.</p>`}
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



/* ===================== ADMIN MESSAGES (popup queue) ===================== */
async function ensureMessagesTable(env) {
  if (!env.DB) return;
  try {
    await env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT,
        discord_id TEXT,
        user_id TEXT,
        text TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        delivered INTEGER NOT NULL DEFAULT 0
      )`
    ).run();
  } catch (_) {}
}

/** Queue a popup for a key / discord user / roblox user. Admin only. */
async function handleAdminMessage(request, env) {
  if (!adminAuthorized(request, env)) return json({ success: false, reason: "unauthorized" }, 401);
  await ensureMessagesTable(env);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ success: false, reason: "invalid_json" }, 400);
  }
  const key = typeof body.key === "string" ? body.key.trim() : "";
  const discordId = String(body.discord_id || body.discordId || "").replace(/\D/g, "");
  const userId = String(body.user_id || body.userId || body.roblox_id || "").replace(/\D/g, "");
  const text = typeof body.text === "string" ? body.text.trim().slice(0, 300) : "";
  if (!text) return json({ success: false, reason: "missing_text" }, 400);
  if (!key && !discordId && !userId) return json({ success: false, reason: "missing_target" }, 400);
  const r = await env.DB.prepare(
    `INSERT INTO messages (key, discord_id, user_id, text, created_at, delivered)
     VALUES (?, ?, ?, ?, ?, 0)`
  ).bind(key || null, discordId || null, userId || null, text, now()).run();
  return json({ success: true, id: Number(r.meta.last_row_id) || null });
}

/** Client poll: pending popups for this key/user/discord. Marks delivered. */
async function handleMessageCheck(request, env, url) {
  await ensureMessagesTable(env);
  const key = (url.searchParams.get("key") || "").trim();
  const userId = (url.searchParams.get("userId") || "").trim();
  const discordId = (url.searchParams.get("discordId") || "").trim();
  if (!key && !userId && !discordId) return json({ messages: [] });
  const rows = await env.DB.prepare(
    `SELECT id, text FROM messages
     WHERE delivered = 0 AND (key = ? OR user_id = ? OR discord_id = ?)
     ORDER BY id ASC LIMIT 10`
  ).bind(key, userId, discordId).all();
  const list = (rows.results || []).map((m) => ({ id: m.id, text: m.text }));
  if (list.length) {
    const ids = list.map((m) => m.id);
    await env.DB.prepare(
      `UPDATE messages SET delivered = 1 WHERE id IN (${ids.map(() => "?").join(",")})`
    ).bind(...ids).run();
  }
  return json({ messages: list });
}

/* ===================== USAGE STATS (execs + levels) ===================== */
async function ensureStatsTable(env) {
  if (!env.DB) return;
  try {
    await env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS exec_stats (
        key TEXT PRIMARY KEY, username TEXT,
        execs INTEGER NOT NULL DEFAULT 0,
        max_level INTEGER NOT NULL DEFAULT 0,
        updated_at INTEGER NOT NULL
      )`
    ).run();
  } catch (_) {}
}

/** Loader calls once per execution. */
async function handleSessionExec(request, env) {
  await ensureStatsTable(env);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ success: false, reason: "invalid_json" }, 400);
  }
  const key = typeof body.key === "string" ? body.key.trim().slice(0, 64) : "";
  const username = typeof body.username === "string" ? body.username.trim().slice(0, 20) : "";
  if (!key) return json({ success: false, reason: "missing_key" }, 400);
  try {
    await env.DB.prepare(
      `INSERT INTO exec_stats (key, username, execs, max_level, updated_at)
       VALUES (?, ?, 1, 0, ?)
       ON CONFLICT(key) DO UPDATE SET
         execs = execs + 1, username = excluded.username, updated_at = excluded.updated_at`
    ).bind(key, username, now()).run();
  } catch (_) {}
  return json({ success: true });
}

/** Hub reports level-ups. */
async function handleSessionLevel(request, env) {
  await ensureStatsTable(env);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ success: false, reason: "invalid_json" }, 400);
  }
  const key = typeof body.key === "string" ? body.key.trim().slice(0, 64) : "";
  const level = Math.max(0, Math.floor(Number(body.level) || 0));
  if (!key || !level) return json({ success: false, reason: "missing_key_or_level" }, 400);
  try {
    await env.DB.prepare(
      `INSERT INTO exec_stats (key, username, execs, max_level, updated_at)
       VALUES (?, ?, 0, ?, ?)
       ON CONFLICT(key) DO UPDATE SET
         max_level = MAX(max_level, excluded.max_level), updated_at = excluded.updated_at`
    ).bind(key, typeof body.username === "string" ? body.username.trim().slice(0, 20) : "", level, now()).run();
  } catch (_) {}
  return json({ success: true });
}

/** Public totals for the site. */
async function handlePublicStats(request, env) {
  const qs = await endpointQuota(env, "stats", request, null, 2000);
  if (!qs.ok) return json({ error: "daily_limit" }, 429);
  await ensureStatsTable(env);
  try {
    const r = await env.DB.prepare(
      `SELECT COUNT(*) AS keys, COALESCE(SUM(execs),0) AS execs, COALESCE(SUM(max_level),0) AS levels FROM exec_stats`
    ).first();
    return json({
      keys: Number(r.keys) || 0,
      executions: Number(r.execs) || 0,
      levels_farmed: Number(r.levels) || 0,
    });
  } catch (_) {
    return json({ keys: 0, executions: 0, levels_farmed: 0 });
  }
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
    try {
      // HWID bans: ban a whole machine (+ every key bound to it). Prefix
      // searchable so mods can paste the 16-char HWID from Discord logs.
      await env.DB.prepare(`ALTER TABLE bans ADD COLUMN hwid TEXT`).run();
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

async function isBanned(env, key, username, userId, hwid) {
  await ensureBanTables(env);
  const k = (key || "").trim();
  const u = (username || "").trim().toLowerCase();
  const uid = String(userId || "").trim();
  const hw = String(hwid || "").trim().slice(0, 128);
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
    // HWID ban: exact match, or >=8-char prefix match (mods paste the
    // 16-char HWID prefix from Discord logs). Catches fresh keys/alts
    // on the same machine at validate time.
    if (hw && hw.length >= 8) {
      const row = await env.DB.prepare(
        `SELECT reason FROM bans WHERE hwid = ? OR (hwid IS NOT NULL AND ? LIKE hwid || '%' AND length(hwid) >= 8) OR (length(?) >= 8 AND hwid LIKE ? || '%') LIMIT 1`
      )
        .bind(hw, hw, hw, hw)
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
  const hwid = String(body.hwid || "").trim().slice(0, 128);
  const reason = body.reason || "Banned from Greedy Hudzell";
  const by = String(body.by_discord || "");
  if (!key && !username && !userId && !hwid) return json({ success: false, reason: "need key, username, user_id or hwid" }, 400);
  if (hwid && hwid.length < 8) return json({ success: false, reason: "hwid_too_short", message: "HWID needs 8+ chars (paste full or 16-char prefix from logs)" }, 400);
  const ts = now();
  // HWID ban = whole machine: revoke every key bound to it, ban each key +
  // every known user_id/username on it, so alts and fresh keys die too.
  let keysRevoked = 0;
  const kickIds = new Set();
  if (hwid) {
    try {
      const rows = await env.DB.prepare(`SELECT key, username FROM keys WHERE hwid = ? OR hwid LIKE ? || '%'`).bind(hwid, hwid).all();
      for (const r of (rows.results || [])) {
        if (r && r.key) {
          await env.DB.prepare(`UPDATE keys SET revoked = 1 WHERE key = ?`).bind(r.key).run();
          await env.DB.prepare(
            `INSERT INTO bans (key, username, user_id, hwid, reason, by_discord, created_at) VALUES (?, ?, NULL, ?, ?, ?, ?)`
          ).bind(r.key, r.username || null, hwid, reason, by, ts).run();
          keysRevoked++;
        }
      }
    } catch (e) {
      console.error("hwid ban revoke:", String((e && e.message) || e));
    }
  }
  await env.DB.prepare(
    `INSERT INTO bans (key, username, user_id, hwid, reason, by_discord, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(key || null, username || null, userId || null, hwid || null, reason, by, ts)
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
    kickIds.add(userId);
  }
  if (hwid) {
    // kick every user_id ever seen on this HWID (works in any server,
    // including private — the client poll is plain HTTP)
    try {
      const execRows = await env.DB.prepare(
        `SELECT DISTINCT user_id FROM security_events WHERE hwid = ? AND user_id IS NOT NULL AND user_id != ''`
      ).bind(hwid).all();
      for (const r of (execRows.results || [])) {
        if (r && r.user_id) {
          await env.DB.prepare(
            `INSERT OR REPLACE INTO pending_kicks (user_id, reason, created_at) VALUES (?, ?, ?)`
          ).bind(String(r.user_id), reason, ts).run();
          kickIds.add(String(r.user_id));
        }
      }
    } catch (_) {}
  }
  return json({ success: true, key: key || null, username: username || null, user_id: userId || null, hwid: hwid || null, keys_revoked: keysRevoked, kicks_queued: kickIds.size });
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
  const hwid = String(body.hwid || "").trim().slice(0, 128);
  if (!key && !username && !userId && !hwid) return json({ success: false, reason: "need key, username, user_id or hwid" }, 400);
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
  if (hwid) {
    // lift HWID rows (exact + prefix rows); keys stay revoked — re-issue or
    // /admin/renew path if the machine should come back.
    await env.DB.prepare(`DELETE FROM bans WHERE hwid = ? OR hwid LIKE ? || '%' OR ? LIKE hwid || '%'`).bind(hwid, hwid, hwid).run();
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
  const hwid = (url.searchParams.get("hwid") || "").trim().slice(0, 128);
  if (!userId && !username && !key && !hwid) return json({ kick: false, banned: false });

  // Live ban check (hwid / username / key / userId)
  const ban = await isBanned(env, key, username, userId, hwid);
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
  if (await isBanned(env, key, username, body.user_id || body.roblox_id, body.hwid)) return json({ ok: false, error: "banned" }, 403);
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

/* 5.2.0: handshake-failure log. Client keeps running (script is free),
   but the attempt is recorded + forwarded to the Discord logs channel. */
async function handleHandshakeFail(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false }, 400);
  }
  const hwid = typeof body.hwid === "string" ? body.hwid.trim().slice(0, 128) : "";
  const username = typeof body.username === "string" ? body.username.trim().slice(0, 32) : "";
  const userId = String(body.user_id || body.userId || body.roblox_id || "").replace(/\D/g, "").slice(0, 20);
  const reason = typeof body.reason === "string" ? body.reason.trim().slice(0, 128) : "unknown";
  const key = typeof body.key === "string" ? body.key.trim().slice(0, 80) : "";
  try {
    await env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS security_events (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, hwid TEXT, username TEXT, key TEXT, reason TEXT, created_at INTEGER NOT NULL)`
    ).run();
    try { await env.DB.prepare(`ALTER TABLE security_events ADD COLUMN user_id TEXT`).run(); } catch (_) {}
    await env.DB.prepare(
      `INSERT INTO security_events (kind, hwid, username, key, reason, created_at, user_id) VALUES ('handshake_fail', ?, ?, ?, ?, ?, ?)`
    ).bind(hwid, username, key, reason, now(), userId).run();
  } catch (_) {}
  try {
    const ch = env.DISCORD_LOGS_CHANNEL || "";
    if (ch && (env.DISCORD_BOT_TOKEN || env.DISCORD_TOKEN || env.BOT_TOKEN)) {
      const content = "Handshake fail | user `" + (username || "?") + "` (" + (userId || "?") + ")"
        + " | key `" + (key || "none") + "` | HWID `" + (hwid || "?").slice(0, 16) + "` | " + reason;
      await discordApi(env, "POST", "/channels/" + ch + "/messages", { content: content.slice(0, 1900) });
    }
  } catch (_) {}
  return json({ ok: true });
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
      if (request.method === "GET" && path === "/verify") return await handleWebVerify(request, env);
      if (request.method === "POST" && path === "/api/verify-link") return await handleVerifyLink(request, env);
      const vfyMatch = path.match(/^\/verify\/key\/discord\/([0-9a-f]{4,128})$/);
      if (request.method === "GET" && vfyMatch) return await handleVerifyToken(request, env, vfyMatch[1]);
      if (request.method === "GET" && (path === "/executors" || path === "/executor")) return html(executorsPage());
      if (request.method === "GET" && path === "/guide") return html(guidePage());
      if (request.method === "GET" && path === "/pricing") return html(pricingPage());
      if (request.method === "GET" && path === "/tos") return html(tosPage());
      if (request.method === "GET" && path === "/api") return html(apiPage());

      // Lua proxies
      if (path === "/loader.lua") return proxySecret(env, "greedyloader.lua");
      if (path === "/script.lua") return plain("gone: hub ships inside /validate since 5.2.0", 410);
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
        await ensureObfTables(env);
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
        // --- quota: api key > license key > anonymous IP ---
        const ident = await resolveObfIdentity(request, env, body);
        if (ident.error) return json({ ok: false, error: ident.error }, ident.status);
        const allow = await obfAllowance(env, ident, request);
        if (!allow.ok) {
          return json({ ok: false, error: "daily_limit", limit: allow.limit, used: allow.used,
            reset_hint: "quota resets midnight UTC" + (allow.bonus ? "" : " · finish Work.ink steps for +1") }, 429);
        }
        // --- result cache: identical code+preset never bills twice ---
        const chash = await sha256("obf1|" + preset + "|" + code);
        try {
          const hit = await env.DB.prepare(
            `SELECT output, out_chars FROM obf_cache WHERE code_hash = ? LIMIT 1`
          ).bind(chash).first();
          if (hit && hit.output) {
            await obfRecordUse(env, ident, allow.day);
            return json({ ok: true, code: hit.output, mode: "cache", cached: true,
              seed: null, left_today: allow.left, plan: allow.plan, bonus: allow.bonus || null });
          }
        } catch {}
        const apiKey = env.LUAOBF_API_KEY || LUAOBF_FALLBACK;
        try {
          const result = await runObfuscatePipeline(code, preset, apiKey, body.options || {});
          if (result && result.ok) {
            await obfRecordUse(env, ident, allow.day);
            try {
              await env.DB.prepare(
                `INSERT INTO obf_cache (code_hash, output, out_chars, preset, created_at) VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT(code_hash) DO NOTHING`
              ).bind(chash, result.code, String(result.code || "").length, preset, now()).run();
              await env.DB.prepare(
                `DELETE FROM obf_cache WHERE code_hash NOT IN (SELECT code_hash FROM obf_cache ORDER BY created_at DESC LIMIT 2000)`
              ).run();
            } catch {}
          }
          return json({ ...result, left_today: allow.left, plan: allow.plan, bonus: allow.bonus || null },
            result.ok ? 200 : 502);
        } catch (e) {
          return json({
            ok: true,
            code: localObfuscate(code, 2),
            mode: "local_emergency",
            note: String(e && e.message ? e.message : e),
          });
        }
      }
      if (request.method === "POST" && path === "/api/keys") return await handleApiKeyCreate(request, env);
      if (request.method === "GET" && path === "/api/keys") return await handleApiKeyList(request, env);
      if (request.method === "POST" && path === "/api/keys/revoke") return await handleApiKeyRevoke(request, env);
      if (request.method === "POST" && path === "/api/keys/rules") return await handleApiKeyRules(request, env);
      if (request.method === "POST" && path === "/admin/obf-grant") return await handleAdminObfGrant(request, env);
      if (request.method === "GET" && path === "/api") return html(apiPage());

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
      if (request.method === "POST" && path === "/admin/reset-hwid") return await handleAdminResetHwid(request, env);
      if (request.method === "GET" && path === "/api/session/kick-check") return await handleKickCheck(request, env, url);
      if (request.method === "GET" && path === "/api/session/message-check") return await handleMessageCheck(request, env, url);
      if (request.method === "POST" && path === "/api/session/exec") return await handleSessionExec(request, env);
      if (request.method === "POST" && path === "/api/session/level") return await handleSessionLevel(request, env);
      if (request.method === "GET" && path === "/api/stats") return await handlePublicStats(request, env);
      if (request.method === "POST" && path === "/admin/message") return await handleAdminMessage(request, env);
      if (request.method === "POST" && path === "/api/discord/create-webhook") return await handleCreateWebhook(request, env);
      if (request.method === "POST" && path === "/api/session/join") return await handleSessionJoin(request, env);
      if (request.method === "POST" && path === "/api/session/handshake-fail") return await handleHandshakeFail(request, env);
      if (request.method === "GET" && path === "/admin/stats") return await handleAdminStats(request, env);
      if (request.method === "GET" && (path === "/admin/keys-by-discord" || path === "/admin/keys")) {
        return await handleAdminKeysByDiscord(request, env);
      }
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
