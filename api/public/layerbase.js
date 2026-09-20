// Layerbase query proxy for Vercel.
// Drop this file into your Vercel project as: api/public/layerbase.js
// Vercel serves it at /api/public/layerbase — the exact path the game
// already calls, so no changes to graphwar.html are needed.

const json = (res, status, data) => {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(data));
};

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return json(res, 405, { error: "POST only" });
  }

  let body;
  try {
    body = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
  } catch {
    return json(res, 400, { error: "Invalid JSON body" });
  }

  const { url, key, query } = body ?? {};
  if (typeof url !== "string" || typeof key !== "string" || typeof query !== "string" || !url || !key || !query) {
    return json(res, 400, { error: "Expected { url, key, query }" });
  }

  let target;
  try {
    target = new URL(url);
  } catch {
    return json(res, 400, { error: "Invalid url" });
  }

  // Only allow forwarding to Layerbase query endpoints.
  const hostOk = target.protocol === "https:" && /(^|\.)layerbase\.dev$/.test(target.hostname);
  if (!hostOk || !target.pathname.includes("/databases/")) {
    return json(res, 400, { error: "Only https Layerbase database query URLs are allowed" });
  }

  try {
    const upstream = await fetch(target.toString(), {
      method: "POST",
      headers: {
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ query }),
    });
    const text = await upstream.text();
    res.statusCode = upstream.status;
    res.setHeader("Content-Type", upstream.headers.get("content-type") ?? "application/json");
    res.setHeader("Cache-Control", "no-store");
    res.end(text);
  } catch {
    return json(res, 502, { error: "Database server unreachable" });
  }
}
