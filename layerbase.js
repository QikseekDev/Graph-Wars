import { randomBytes, createHash } from "node:crypto";

/*
 * Graphwar rooms proxy.
 *
 * The browser never sends SQL. It sends an action and the server builds the query:
 *   init                          create the table (once)
 *   list                          public room list (no secrets)
 *   get     { code }              one room (no secret)
 *   create  { peer_id, host }     makes a room, returns { code, secret } to its creator ONLY
 *   delete  { code, secret }      removes a room, only if the secret matches
 *   update  { code, secret, players, max }  refreshes player list + room lifetime (host only)
 *   ping                          init + schema check, returns { ok, rooms }
 *   chat_get  { since }           public chat: one row holds { ver, last 40 msgs }; returns nothing if ver unchanged
 *   chat_post { name, text, cid } appends one message to that row
 *
 * Every room gets its own random secret. Only a SHA-256 hash is stored, and the hash
 * column is never selected, so no endpoint can ever return it. The raw secret exists
 * in exactly one response: the reply to "create", which goes to the host.
 */

const TABLE = "graphwar_rooms_v2"; // v2 adds secret_hash. The old graphwar_rooms table can be dropped.
const ROOM_TTL = 60 * 60 * 1000;
const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no 0/O/1/I
const CODE_LEN = 6;
const MAX_ACTIVE_ROOMS = 500;
const CHAT = "graphwar_chat_v1";
const CHAT_MAX = 40;
const chatRate = new Map(); // best-effort per-instance spam limit
const cleanChat = (v, max) => String(v ?? "").replace(/[\u0000-\u001f\u007f\\]/g, "").replace(/"/g, "'").replace(/\s+/g, " ").trim().slice(0, max);
const parseMsgs = (t) => { try { const a = JSON.parse(t); return Array.isArray(a) ? a : []; } catch { return []; } };

const json = (res, status, data) => {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(data));
};

/* ---------- SQL building (inputs are validated first, then escaped) ---------- */

// Free text is stripped of backslashes, double quotes (they'd need JSON escaping), <>, NUL and
// control characters, so nothing can break out of a SQL literal on any dialect or inject HTML.
// Single quotes are doubled by lit().
const clean = (v, max) =>
  String(v ?? "").replace(/[\u0000-\u001f\u007f\\"<>]/g, "").replace(/\s+/g, " ").trim().slice(0, max);
const lit = (v) => "'" + String(v).replace(/'/g, "''") + "'";

const CODE_RE = new RegExp(`^[${CODE_ALPHABET}]{${CODE_LEN}}$`);
const isCode = (v) => typeof v === "string" && CODE_RE.test(v);
const isPeerId = (v) => typeof v === "string" && /^[A-Za-z0-9_-]{1,100}$/.test(v);
const isSecret = (v) => typeof v === "string" && /^[a-f0-9]{48}$/.test(v);

const hashSecret = (secret) => createHash("sha256").update(secret).digest("hex");

const newCode = () => {
  const bytes = randomBytes(CODE_LEN);
  let out = "";
  for (let i = 0; i < CODE_LEN; i++) out += CODE_ALPHABET[bytes[i] % CODE_ALPHABET.length];
  return out;
};

const cutoff = (now) => Math.floor(now - ROOM_TTL);

const Q = {
  initChat: () => `CREATE TABLE IF NOT EXISTS ${CHAT} (id VARCHAR(16) PRIMARY KEY, ver BIGINT, data TEXT)`,
  chatVer: () => `SELECT ver FROM ${CHAT} WHERE id = 'global' LIMIT 1`,
  chatData: () => `SELECT ver, data FROM ${CHAT} WHERE id = 'global' LIMIT 1`,
  chatInsert: (js) => `INSERT INTO ${CHAT} (id, ver, data) VALUES ('global', 1, ${lit(js)})`,
  // Optimistic lock: only succeeds if nobody else bumped ver since we read it.
  chatUpdate: (ver, js) => `UPDATE ${CHAT} SET ver = ${ver + 1}, data = ${lit(js)} WHERE id = 'global' AND ver = ${ver}`,
  update: (code, h, players, now) => `UPDATE ${TABLE} SET players = ${lit(players)}, created = ${Math.floor(now)} WHERE code = ${lit(code)} AND secret_hash = ${lit(h)}`,
  init: () =>
    `CREATE TABLE IF NOT EXISTS ${TABLE} ` +
    `(code VARCHAR(8) PRIMARY KEY, peer_id TEXT, host TEXT, created BIGINT, players TEXT, secret_hash VARCHAR(64))`,
  list: (now) =>
    `SELECT code, peer_id, host, created, players FROM ${TABLE} ` +
    `WHERE created > ${cutoff(now)} ORDER BY created DESC LIMIT 50`,
  get: (code, now) =>
    `SELECT code, peer_id, host, created, players FROM ${TABLE} ` +
    `WHERE code = ${lit(code)} AND created > ${cutoff(now)} LIMIT 1`,
  create: (r) =>
    `INSERT INTO ${TABLE} (code, peer_id, host, created, players, secret_hash) VALUES (` +
    [lit(r.code), lit(r.peer_id), lit(r.host), Math.floor(r.created), lit(r.players), lit(r.secret_hash)].join(", ") + `)`,
  // The secret hash is part of the WHERE clause: without the right secret nothing matches.
  remove: (code, secretHash) => `DELETE FROM ${TABLE} WHERE code = ${lit(code)} AND secret_hash = ${lit(secretHash)}`,
  sweep: (now) => `DELETE FROM ${TABLE} WHERE created < ${cutoff(now)}`,
  count: (now) => `SELECT COUNT(*) AS n FROM ${TABLE} WHERE created > ${cutoff(now)}`
};

/* ---------- upstream ---------- */

let target, apiKey;
function configure() {
  const url = process.env.LAYERBASE_URL;
  const key = process.env.LAYERBASE_API_KEY;
  if (!url || !key) throw new Error("Layerbase environment variables are not configured");
  const t = new URL(url);
  if (t.protocol !== "https:" || !/(^|\.)layerbase\.dev$/i.test(t.hostname) || !t.pathname.includes("/databases/")) {
    throw new Error("Invalid Layerbase endpoint configuration");
  }
  target = t;
  apiKey = key;
}

async function run(query) {
  const upstream = await fetch(target.toString(), {
    method: "POST",
    headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
    body: JSON.stringify({ query }),
    signal: AbortSignal.timeout(8000)
  });
  const text = await upstream.text();
  if (!upstream.ok) {
    console.error("Layerbase error", upstream.status, text.slice(0, 500));
    const err = new Error("Database error");
    err.upstream = true;
    err.status = upstream.status;
    throw err;
  }
  try { return JSON.parse(text); } catch { return text; }
}

// Same tolerant row reader the game used, so any Layerbase response shape works.
function rowsOf(data) {
  if (!data) return [];
  let rows = Array.isArray(data) ? data : (data.rows ?? data.data ?? data.result ?? data.results ?? []);
  if (rows && !Array.isArray(rows)) rows = rows.rows ?? [];
  if (rows.length && Array.isArray(rows[0])) {
    const cols = (data.columns || data.fields || []).map((c) => (typeof c === "string" ? c : c.name || c));
    return rows.map((r) => Object.fromEntries(cols.map((c, i) => [c, r[i]])));
  }
  return rows;
}

// Explicit allowlist of fields sent to browsers. secret_hash can never be in here.
const publicRoom = (r) => ({
  code: String(r.code),
  peer_id: String(r.peer_id),
  host: String(r.host),
  created: Number(r.created),
  players: String(r.players)
});

// If the chat table does not exist yet (older deployments), create it once and retry.
const chatSafe = async (fn) => { try { return await fn(); } catch { await run(Q.initChat()); return await fn(); } };

/* ---------- request helpers ---------- */

function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try { return new URL(origin).host === req.headers.host; } catch { return false; }
}

function readBody(req) {
  let raw = req.body;
  if (Buffer.isBuffer(raw)) raw = raw.toString("utf8");
  return typeof raw === "string" ? JSON.parse(raw) : raw;
}

/* ---------- handler ---------- */

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return json(res, 405, { error: "POST only" });
  }
  if (!sameOrigin(req)) return json(res, 403, { error: "Forbidden" });
  if (Number(req.headers["content-length"] || 0) > 4 * 1024) return json(res, 413, { error: "Request too large" });

  try { configure(); } catch (e) { return json(res, 500, { error: e.message }); }

  let body;
  try { body = readBody(req); } catch { return json(res, 400, { error: "Invalid JSON body" }); }
  if (!body || typeof body !== "object" || typeof body.action !== "string") {
    return json(res, 400, { error: "Expected { action }" });
  }

  const now = Date.now();

  try {
    switch (body.action) {
      case "init":
      case "ping": {
        await run(Q.init());
        await run(Q.initChat());
        // An older table without secret_hash would make every create fail silently: repair it.
        try { await run(`SELECT secret_hash FROM ${TABLE} LIMIT 1`); }
        catch { await run(`ALTER TABLE ${TABLE} ADD COLUMN secret_hash VARCHAR(64)`); }
        const n = Number(rowsOf(await run(Q.count(now)))[0]?.n ?? 0);
        return json(res, 200, { ok: true, rooms: n });
      }

      case "list": {
        const rooms = rowsOf(await run(Q.list(now))).map(publicRoom);
        return json(res, 200, { rooms });
      }

      case "get": {
        if (!isCode(body.code)) return json(res, 400, { error: "Bad room code" });
        const rooms = rowsOf(await run(Q.get(body.code, now))).map(publicRoom);
        return json(res, 200, { rooms });
      }

      case "create": {
        if (!isPeerId(body.peer_id)) return json(res, 400, { error: "Bad peer id" });
        const host = clean(body.host, 30) || "Player";

        // Occasional cleanup of expired rooms + a global cap so the table can't be flooded.
        if (Math.random() < 0.2) {
          await run(Q.sweep(now)).catch(() => {});
          const n = Number(rowsOf(await run(Q.count(now)).catch(() => []))[0]?.n ?? 0);
          if (n >= MAX_ACTIVE_ROOMS) return json(res, 429, { error: "Too many active rooms, try again soon" });
        }

        const secret = randomBytes(24).toString("hex"); // 48 hex chars, unique per room
        const max = Math.max(2, Math.min(4, Math.floor(Number(body.max)) || 2));
        const players = JSON.stringify({ p: [host], m: max });

        // Codes are random; on the rare collision (primary key) retry with a new code.
        for (let attempt = 0; attempt < 3; attempt++) {
          const code = newCode();
          try {
            await run(Q.create({ code, peer_id: body.peer_id, host, created: now, players, secret_hash: hashSecret(secret) }));
            // The ONLY place a secret ever leaves the server: the reply to the creator.
            return json(res, 200, { code, secret, room: publicRoom({ code, peer_id: body.peer_id, host, created: now, players }) });
          } catch (e) {
            if (attempt === 2) throw e;
          }
        }
        return json(res, 500, { error: "Could not create room" });
      }

      case "delete": {
        if (!isCode(body.code) || !isSecret(body.secret)) return json(res, 400, { error: "Bad request" });
        // Wrong secret = no row matches = nothing happens (and the caller can't tell why).
        await run(Q.remove(body.code, hashSecret(body.secret)));
        return json(res, 200, { ok: true });
      }

      case "update": {
        if (!isCode(body.code) || !isSecret(body.secret) || !Array.isArray(body.players)) return json(res, 400, { error: "Bad request" });
        const names = body.players.slice(0, 4).map((n) => clean(n, 30) || "Player");
        const max = Math.max(2, Math.min(4, Math.floor(Number(body.max)) || 2));
        await run(Q.update(body.code, hashSecret(body.secret), JSON.stringify({ p: names, m: max }), now));
        return json(res, 200, { ok: true });
      }

      case "chat_get": {
        const since = Number(body.since) || 0;
        const first = await chatSafe(() => run(Q.chatVer()));
        const ver = Number(rowsOf(first)[0]?.ver ?? 0);
        if (ver === since || !rowsOf(first).length) return json(res, 200, { ver, unchanged: true });
        const row = rowsOf(await run(Q.chatData()))[0];
        return json(res, 200, { ver: Number(row?.ver ?? ver), messages: parseMsgs(row?.data) });
      }

      case "chat_post": {
        const ip = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "?";
        if (now - (chatRate.get(ip) || 0) < 2000) return json(res, 429, { error: "Slow down" });
        chatRate.set(ip, now);
        if (chatRate.size > 500) chatRate.clear();
        const text = cleanChat(body.text, 200);
        const name = cleanChat(body.name, 30) || "Player";
        if (!text || typeof body.cid !== "string" || !/^[A-Za-z0-9]{8,24}$/.test(body.cid)) return json(res, 400, { error: "Bad message" });
        const msg = { i: body.cid, t: now, n: name, m: text };
        for (let attempt = 0; attempt < 4; attempt++) {
          const row = rowsOf(await chatSafe(() => run(Q.chatData())))[0];
          if (!row) { try { await run(Q.chatInsert(JSON.stringify([msg]))); return json(res, 200, { ok: true, ver: 1 }); } catch { continue; } }
          const ver = Number(row.ver);
          const msgs = parseMsgs(row.data);
          if (msgs.some((x) => x.i === msg.i)) return json(res, 200, { ok: true, ver });
          msgs.push(msg);
          await run(Q.chatUpdate(ver, JSON.stringify(msgs.slice(-CHAT_MAX))));
          const chk = rowsOf(await run(Q.chatData()))[0];
          if (parseMsgs(chk?.data).some((x) => x.i === msg.i)) return json(res, 200, { ok: true, ver: Number(chk.ver) });
        }
        return json(res, 409, { error: "Chat busy, try again" });
      }

      default:
        return json(res, 400, { error: "Unknown action" });
    }
  } catch (err) {
    if (err && err.upstream) return json(res, 502, { error: "Database error", detail: err.status ? "upstream " + err.status : undefined });
    console.error("Proxy error", err && err.name);
    return json(res, 502, { error: "Database server unreachable" });
  }
}
