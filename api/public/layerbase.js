const TABLE = "graphwar_rooms";

const json = (res, status, data) => {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(data));
};

function normalizeQuery(query) {
  return query.trim().replace(/\s+/g, " ").replace(/;+\s*$/, "");
}

function isSafeQuery(input) {
  const q = normalizeQuery(input);

  // No SQL batching or comments.
  if (q.includes(";") || /--|\/\*|\*\//.test(q)) return false;

  if (/^SELECT 1$/i.test(q)) return true;

  if (new RegExp(
    `^CREATE TABLE IF NOT EXISTS ${TABLE} ` +
    `\\(code VARCHAR\\(8\\) PRIMARY KEY, peer_id TEXT, host TEXT, created BIGINT, players TEXT\\)$`,
    "i"
  ).test(q)) return true;

  if (new RegExp(
    `^SELECT code, peer_id, host, created, players FROM ${TABLE} ` +
    `WHERE created > [0-9]+ ORDER BY created DESC LIMIT 50$`,
    "i"
  ).test(q)) return true;

  if (new RegExp(
    `^SELECT code, peer_id, host, created, players FROM ${TABLE} ` +
    `WHERE code = '(?:''|[^'])*' LIMIT 1$`,
    "i"
  ).test(q)) return true;

  if (new RegExp(
    `^DELETE FROM ${TABLE} WHERE created < [0-9]+ OR code = '(?:''|[^'])*'$`,
    "i"
  ).test(q)) return true;

  if (new RegExp(
    `^DELETE FROM ${TABLE} WHERE code = '(?:''|[^'])*'$`,
    "i"
  ).test(q)) return true;

  if (new RegExp(
    `^INSERT INTO ${TABLE} ` +
    `\\(code, peer_id, host, created, players\\) VALUES ` +
    `\\('(?!')(?:(?:'')|[^'])*', ` +
    `'(?:''|[^'])*', ` +
    `'(?:''|[^'])*', ` +
    `[0-9]+, ` +
    `'(?:''|[^'])*'\\)$`,
    "i"
  ).test(q)) return true;

  return false;
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return json(res, 405, { error: "POST only" });
  }

  const contentLength = Number(req.headers["content-length"] || 0);
  if (contentLength > 16 * 1024) {
    return json(res, 413, { error: "Request too large" });
  }

  const url = process.env.LAYERBASE_URL;
  const key = process.env.LAYERBASE_API_KEY;

  if (!url || !key) {
    return json(res, 500, {
      error: "Layerbase environment variables are not configured"
    });
  }

  let target;
  try {
    target = new URL(url);
  } catch {
    return json(res, 500, {
      error: "Invalid LAYERBASE_URL"
    });
  }

  if (
    target.protocol !== "https:" ||
    !/(^|\.)layerbase\.dev$/i.test(target.hostname) ||
    !target.pathname.includes("/databases/")
  ) {
    return json(res, 500, {
      error: "Invalid Layerbase endpoint configuration"
    });
  }

  let body;
  try {
    body =
      typeof req.body === "string"
        ? JSON.parse(req.body)
        : req.body;
  } catch {
    return json(res, 400, {
      error: "Invalid JSON body"
    });
  }

  if (!body || typeof body.query !== "string") {
    return json(res, 400, {
      error: "Expected { query }"
    });
  }

  const query = normalizeQuery(body.query);

  if (query.length > 4000) {
    return json(res, 413, {
      error: "Query too large"
    });
  }

  if (!isSafeQuery(query)) {
    return json(res, 403, {
      error: "Query not permitted"
    });
  }

  try {
    const upstream = await fetch(target.toString(), {
      method: "POST",
      headers: {
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ query })
    });

    const text = await upstream.text();

    res.statusCode = upstream.status;
    res.setHeader(
      "Content-Type",
      upstream.headers.get("content-type") || "application/json"
    );
    res.setHeader("Cache-Control", "no-store");
    res.end(text);
  } catch {
    return json(res, 502, {
      error: "Database server unreachable"
    });
  }
}
