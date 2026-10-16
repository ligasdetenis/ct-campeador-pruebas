import { buildPushPayload } from "@block65/webcrypto-web-push";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Cache-Control": "no-store",
};

const json = (data, status = 200) => new Response(JSON.stringify(data, null, 2), {
  status,
  headers: { "content-type": "application/json; charset=utf-8", ...cors },
});

function authorized(request, env) {
  const token = String(env.TEST_TOKEN || "");
  if (!token) return false;
  return (request.headers.get("authorization") || "") === `Bearer ${token}`;
}

async function subscriptionKey(endpoint) {
  const bytes = new TextEncoder().encode(String(endpoint || ""));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return "sub:" + [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function allSubscriptions(env) {
  const out = [];
  let cursor;
  do {
    const page = await env.PUSH_DATA.list({ prefix: "sub:", cursor });
    for (const key of page.keys || []) {
      const raw = await env.PUSH_DATA.get(key.name, "json");
      if (raw?.subscription?.endpoint) out.push({ key: key.name, ...raw });
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return out;
}

async function sendTo(subscription, env, message) {
  const vapid = {
    subject: env.VAPID_SUBJECT,
    publicKey: env.VAPID_PUBLIC_KEY,
    privateKey: env.VAPID_PRIVATE_KEY,
  };
  const payload = await buildPushPayload(
    { data: JSON.stringify(message), options: { ttl: 60 } },
    subscription,
    vapid
  );
  return fetch(subscription.endpoint, payload);
}

function normalizeName(value) {
  return String(value || "").trim().toLocaleLowerCase("es");
}

async function sendRows(rows, env, incoming = {}) {
  const message = {
    title: String(incoming.title || "🎾 CT Campeador · PRUEBAS").slice(0, 100),
    body: String(incoming.body || "Aviso de prueba.").slice(0, 300),
    url: String(incoming.url || "https://ligasdetenis.github.io/ct-campeador-pruebas/"),
    tag: String(incoming.tag || "ct-campeador-test").slice(0, 100),
  };

  let sent = 0;
  let removed = 0;
  const failed = [];
  const delivered = [];

  for (const row of rows) {
    try {
      const res = await sendTo(row.subscription, env, message);
      if (res.ok || res.status === 201) {
        sent++;
        delivered.push({ userName: row.userName || "", status: res.status });
      } else if (res.status === 404 || res.status === 410) {
        await env.PUSH_DATA.delete(row.key);
        removed++;
      } else {
        failed.push({ userName: row.userName || "", status: res.status, text: await res.text().catch(() => "") });
      }
    } catch (e) {
      failed.push({ userName: row.userName || "", error: e?.message || String(e) });
    }
  }

  return { ok: failed.length === 0, sent, removed, failed, delivered };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });

    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/health")) {
      return json({
        ok: true,
        service: "CT Campeador Push TEST",
        environment: "test",
        vapidPublicKey: String(env.VAPID_PUBLIC_KEY || ""),
        vapidConfigured: !!(env.VAPID_PUBLIC_KEY && env.VAPID_PRIVATE_KEY && env.VAPID_SUBJECT),
      });
    }

    if (request.method === "POST" && url.pathname === "/subscribe") {
      if (!authorized(request, env)) return json({ ok: false, error: "No autorizado." }, 401);
      const body = await request.json().catch(() => ({}));
      const subscription = body.subscription || body;
      const userName = String(body.userName || "").trim();
      if (!subscription?.endpoint || !subscription?.keys?.p256dh || !subscription?.keys?.auth) {
        return json({ ok: false, error: "Suscripción incompleta." }, 400);
      }
      const key = await subscriptionKey(subscription.endpoint);
      const previous = await env.PUSH_DATA.get(key, "json");
      const record = { subscription, userName, updatedAt: new Date().toISOString() };
      await env.PUSH_DATA.put(key, JSON.stringify(record));
      const unchanged = !!previous && previous.userName === userName && JSON.stringify(previous.subscription) === JSON.stringify(subscription);
      return json({ ok: true, created: !previous, updated: !!previous && !unchanged, unchanged });
    }

    if (request.method === "POST" && url.pathname === "/send") {
      if (!authorized(request, env)) return json({ ok: false, error: "No autorizado." }, 401);
      const incoming = await request.json().catch(() => ({}));
      const rows = await allSubscriptions(env);
      const result = await sendRows(rows, env, incoming);
      return json({ ...result, total: rows.length, matchedUsers: new Set(rows.map(r => normalizeName(r.userName)).filter(Boolean)).size });
    }

    if (request.method === "POST" && url.pathname === "/admin/send") {
      if (!authorized(request, env)) return json({ ok: false, error: "No autorizado." }, 401);
      const incoming = await request.json().catch(() => ({}));
      const recipients = new Set((incoming.recipients || []).map(normalizeName).filter(Boolean));
      const all = await allSubscriptions(env);
      const rows = recipients.size ? all.filter(r => recipients.has(normalizeName(r.userName))) : [];
      const result = await sendRows(rows, env, incoming);
      return json({ ...result, total: rows.length, matchedUsers: new Set(rows.map(r => normalizeName(r.userName)).filter(Boolean)).size });
    }

    if (request.method === "POST" && url.pathname === "/admin/devices") {
      if (!authorized(request, env)) return json({ ok: false, error: "No autorizado." }, 401);
      const rows = await allSubscriptions(env);
      const grouped = new Map();
      for (const row of rows) {
        const label = String(row.userName || "").trim();
        const key = normalizeName(label) || "__sin_identificar__";
        const g = grouped.get(key) || { userName: label, count: 0, lastUpdated: "" };
        g.count++;
        if (String(row.updatedAt || "") > g.lastUpdated) g.lastUpdated = String(row.updatedAt || "");
        grouped.set(key, g);
      }
      const users = [...grouped.values()].sort((a, b) => String(a.userName).localeCompare(String(b.userName), "es"));
      return json({ ok: true, total: rows.length, users });
    }

    if (request.method === "POST" && url.pathname === "/admin/remove-user") {
      if (!authorized(request, env)) return json({ ok: false, error: "No autorizado." }, 401);
      const body = await request.json().catch(() => ({}));
      const target = normalizeName(body.userName);
      if (!target) return json({ ok: false, error: "Falta el usuario." }, 400);
      const rows = await allSubscriptions(env);
      let removed = 0;
      for (const row of rows) {
        if (normalizeName(row.userName) === target) {
          await env.PUSH_DATA.delete(row.key);
          removed++;
        }
      }
      return json({ ok: true, removed });
    }

    return json({ ok: false, error: "Ruta no encontrada." }, 404);
  },
};
