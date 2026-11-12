var __defProp = Object.defineProperty;

var __name = (target, value) => __defProp(target, "name", { value, configurable: true });



// node_modules/@mmmike/web-push/dist/vapid.mjs

var urlBase64ToUint8Array = /* @__PURE__ */ __name((base64String) => {

  if (!base64String) return /* @__PURE__ */ new Uint8Array(0);

  const base64 = (base64String + "=".repeat((4 - base64String.length % 4) % 4)).replace(/-/g, "+").replace(/_/g, "/");

  const rawData = atob(base64);

  const outputArray = new Uint8Array(rawData.length);

  for (let i = 0; i < rawData.length; ++i) outputArray[i] = rawData.charCodeAt(i);

  return outputArray;

}, "urlBase64ToUint8Array");

var uint8ArrayToUrlBase64 = /* @__PURE__ */ __name((array) => {

  let binary = "";

  const chunkSize = 32768;

  for (let i = 0; i < array.length; i += chunkSize) binary += String.fromCharCode(...array.subarray(i, i + chunkSize));

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

}, "uint8ArrayToUrlBase64");

var encodeJwtSegment = /* @__PURE__ */ __name((segment) => uint8ArrayToUrlBase64(new TextEncoder().encode(JSON.stringify(segment))), "encodeJwtSegment");

var importSigningKey = /* @__PURE__ */ __name((publicKey, privateKey) => {

  const publicKeyArray = urlBase64ToUint8Array(publicKey);

  const privateKeyArray = urlBase64ToUint8Array(privateKey);

  if (publicKeyArray.length !== 65 || publicKeyArray[0] !== 4) throw new Error("VAPID public key must be a 65-byte uncompressed P-256 point");

  if (privateKeyArray.length !== 32) throw new Error("VAPID private key must be a 32-byte P-256 scalar");

  const jwk = {

    kty: "EC",

    crv: "P-256",

    x: uint8ArrayToUrlBase64(publicKeyArray.slice(1, 33)),

    y: uint8ArrayToUrlBase64(publicKeyArray.slice(33)),

    d: uint8ArrayToUrlBase64(privateKeyArray)

  };

  return crypto.subtle.importKey("jwk", jwk, {

    name: "ECDSA",

    namedCurve: "P-256"

  }, false, ["sign"]);

}, "importSigningKey");

var createVapidJwt = /* @__PURE__ */ __name(async (options) => {

  const { audience, subject, publicKey, privateKey, expiration = 43200 } = options;

  if (expiration <= 0 || expiration > 86400) throw new Error("VAPID JWT expiration must be between 1 and 86400 seconds (24 hours)");

  if (!/^(mailto:|https:\/\/)/.test(subject)) throw new Error("VAPID subject must be a 'mailto:' or 'https\://' URI");

  const unsignedToken = [{

    typ: "JWT",

    alg: "ES256"

  }, {

    aud: audience,

    exp: Math.floor(Date.now() / 1e3) + expiration,

    sub: subject

  }].map(encodeJwtSegment).join(".");

  const signingKey = await importSigningKey(publicKey, privateKey);

  const signature = await crypto.subtle.sign({

    name: "ECDSA",

    hash: "SHA-256"

  }, signingKey, new TextEncoder().encode(unsignedToken));

  return `${unsignedToken}.${uint8ArrayToUrlBase64(new Uint8Array(signature))}`;

}, "createVapidJwt");



// node_modules/@mmmike/web-push/dist/send-Tzby4YPa.mjs

var SALT_LENGTH = 16;

var KEY_ID_LENGTH = 65;

var PADDING_DELIMITER = 2;

var UNCOMPRESSED_POINT_TAG = 4;

var HEADER_LENGTH = 86;

var RECORD_SIZE = 4096;

var MAX_PAYLOAD_BYTES = 3993;

var encoder = new TextEncoder();

var assertPayloadWithinLimit = /* @__PURE__ */ __name((payload) => {

  if (payload.length > MAX_PAYLOAD_BYTES) throw new Error(`Payload too large: ${payload.length} bytes exceeds the ${MAX_PAYLOAD_BYTES}-byte single-record limit`);

}, "assertPayloadWithinLimit");

var concat = /* @__PURE__ */ __name((...parts) => {

  const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));

  let offset = 0;

  for (const part of parts) {

    out.set(part, offset);

    offset += part.length;

  }

  return out;

}, "concat");

var validatePushInputs = /* @__PURE__ */ __name((payload, p256dhKey, authSecret) => {

  assertPayloadWithinLimit(payload);

  const clientPublicKeyBytes = urlBase64ToUint8Array(p256dhKey);

  if (clientPublicKeyBytes.length !== KEY_ID_LENGTH || clientPublicKeyBytes[0] !== UNCOMPRESSED_POINT_TAG) throw new Error("Invalid subscription p256dh key: expected a 65-byte uncompressed P-256 public key");

  const authSecretBytes = urlBase64ToUint8Array(authSecret);

  if (authSecretBytes.length < 16) throw new Error("Invalid subscription auth secret: expected at least 16 bytes");

  return {

    clientPublicKeyBytes,

    authSecretBytes

  };

}, "validatePushInputs");

var importClientPublicKey = /* @__PURE__ */ __name((rawKey) => crypto.subtle.importKey("raw", rawKey, {

  name: "ECDH",

  namedCurve: "P-256"

}, false, []), "importClientPublicKey");

var deriveSharedSecret = /* @__PURE__ */ __name(async (serverPrivateKey, clientPublicKey) => new Uint8Array(await crypto.subtle.deriveBits({

  name: "ECDH",

  public: clientPublicKey

}, serverPrivateKey, 256)), "deriveSharedSecret");

var exportRawPublicKey = /* @__PURE__ */ __name(async (key) => new Uint8Array(await crypto.subtle.exportKey("raw", key)), "exportRawPublicKey");

var importHkdfKey = /* @__PURE__ */ __name((bytes) => crypto.subtle.importKey("raw", bytes, "HKDF", false, ["deriveBits", "deriveKey"]), "importHkdfKey");

var hkdfInfo = /* @__PURE__ */ __name((label, ...context) => concat(encoder.encode(label), new Uint8Array([0]), ...context), "hkdfInfo");

var deriveInputKeyingMaterial = /* @__PURE__ */ __name(async (sharedSecret, authSecret, clientPublicKey, serverPublicKey) => new Uint8Array(await crypto.subtle.deriveBits({

  name: "HKDF",

  hash: "SHA-256",

  salt: authSecret,

  info: hkdfInfo("WebPush: info", clientPublicKey, serverPublicKey)

}, await importHkdfKey(sharedSecret), 256)), "deriveInputKeyingMaterial");

var deriveContentEncryptionKey = /* @__PURE__ */ __name((ikmKey, salt) => crypto.subtle.deriveKey({

  name: "HKDF",

  hash: "SHA-256",

  salt,

  info: hkdfInfo("Content-Encoding: aes128gcm")

}, ikmKey, {

  name: "AES-GCM",

  length: 128

}, false, ["encrypt"]), "deriveContentEncryptionKey");

var deriveNonce = /* @__PURE__ */ __name(async (ikmKey, salt) => new Uint8Array(await crypto.subtle.deriveBits({

  name: "HKDF",

  hash: "SHA-256",

  salt,

  info: hkdfInfo("Content-Encoding: nonce")

}, ikmKey, 96)), "deriveNonce");

var padPayload = /* @__PURE__ */ __name((payload) => concat(payload, new Uint8Array([PADDING_DELIMITER])), "padPayload");

var contentCodingHeader = /* @__PURE__ */ __name((salt, keyId) => {

  const header = new Uint8Array(HEADER_LENGTH);

  header.set(salt, 0);

  new DataView(header.buffer).setUint32(SALT_LENGTH, RECORD_SIZE, false);

  header[20] = KEY_ID_LENGTH;

  header.set(keyId, 21);

  return header;

}, "contentCodingHeader");

var encryptPayload = /* @__PURE__ */ __name(async (payload, p256dhKey, authSecret) => {

  const serverKeyPair = await crypto.subtle.generateKey({

    name: "ECDH",

    namedCurve: "P-256"

  }, true, ["deriveBits"]);

  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));

  return encryptRecord(payload, p256dhKey, authSecret, serverKeyPair, salt);

}, "encryptPayload");

var encryptRecord = /* @__PURE__ */ __name(async (payload, p256dhKey, authSecret, serverKeyPair, salt) => {

  const { clientPublicKeyBytes, authSecretBytes } = validatePushInputs(payload, p256dhKey, authSecret);

  const clientPublicKey = await importClientPublicKey(clientPublicKeyBytes);

  const sharedSecret = await deriveSharedSecret(serverKeyPair.privateKey, clientPublicKey);

  const serverPublicKey = await exportRawPublicKey(serverKeyPair.publicKey);

  const ikm = await deriveInputKeyingMaterial(sharedSecret, authSecretBytes, clientPublicKeyBytes, serverPublicKey);

  const ikmKey = await importHkdfKey(ikm);

  const contentEncryptionKey = await deriveContentEncryptionKey(ikmKey, salt);

  const nonce = await deriveNonce(ikmKey, salt);

  const ciphertext = await crypto.subtle.encrypt({

    name: "AES-GCM",

    iv: nonce

  }, contentEncryptionKey, padPayload(payload));

  return concat(contentCodingHeader(salt, serverPublicKey), new Uint8Array(ciphertext));

}, "encryptRecord");

var parseRetryAfterMs = /* @__PURE__ */ __name((retryAfter) => {

  if (retryAfter === null) return null;

  const trimmed = retryAfter.trim();

  if (/^\d+$/.test(trimmed)) return Number(trimmed) * 1e3;

  const date = Date.parse(trimmed);

  return Number.isNaN(date) ? null : Math.max(0, date - Date.now());

}, "parseRetryAfterMs");

var WebPushError = class extends Error {

  static {

    __name(this, "WebPushError");

  }

  statusCode;

  body;

  /**

 * The full subscription endpoint, a capability URL: anyone holding it can

 * push to the device. Route on it, but keep it out of logs; serializers

 * that honor `toJSON` get a truncated one.

*  */

  endpoint;

  /** The `Retry-After` header verbatim: delta-seconds or an HTTP-date */

  retryAfter;

  /** `Retry-After` as milliseconds from now; `null` when absent or unparseable */

  retryAfterMs;

  constructor(message, statusCode, body, endpoint, retryAfter = null) {

    super(message);

    this.name = "WebPushError";

    this.statusCode = statusCode;

    this.body = body;

    this.endpoint = endpoint;

    this.retryAfter = retryAfter;

    this.retryAfterMs = parseRetryAfterMs(retryAfter);

  }

  /**

 * Truncates `endpoint` and `body` for serialization. Without this,

 * `JSON.stringify` on the error would emit every enumerable field,

 * persisting the full capability URL into any structured log.

*  */

  toJSON() {

    return {

      name: this.name,

      message: this.message,

      statusCode: this.statusCode,

      endpoint: this.endpoint.slice(0, 50),

      body: this.body.slice(0, 200),

      retryAfter: this.retryAfter,

      retryAfterMs: this.retryAfterMs

    };

  }

};

var RawBytes = class {

  static {

    __name(this, "RawBytes");

  }

  #bytes;

  constructor(bytes) {

    this.#bytes = bytes;

  }

  get bytes() {

    return this.#bytes;

  }

};

var encodePayload = /* @__PURE__ */ __name((payload) => payload instanceof RawBytes ? payload.bytes : new TextEncoder().encode(JSON.stringify(payload)), "encodePayload");

var assertValidTopic = /* @__PURE__ */ __name((topic) => {

  if (topic !== void 0 && !/^[A-Za-z0-9\\-_]{1,32}$/.test(topic)) throw new Error("Topic must be 1-32 URL-safe base64 characters");

}, "assertValidTopic");

var pushServiceOrigin = /* @__PURE__ */ __name((endpoint) => {

  const url = new URL(endpoint);

  if (url.protocol !== "https:") throw new Error("Invalid subscription endpoint: must be an https: URL (RFC 8030 \xA73)");

  return `${url.protocol}//${url.host}`;

}, "pushServiceOrigin");

var isSubscriptionGone = /* @__PURE__ */ __name((status) => status === 404 || status === 410, "isSubscriptionGone");

var DEFAULT_TIMEOUT_MS = 3e4;

var assertValidTimeout = /* @__PURE__ */ __name((timeoutMs) => {

  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new Error("timeoutMs must be a positive number of milliseconds");

}, "assertValidTimeout");

var requestSignal = /* @__PURE__ */ __name((signal, timeoutMs) => signal ? AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)]) : AbortSignal.timeout(timeoutMs), "requestSignal");

var buildPushHeaders = /* @__PURE__ */ __name(({ jwt, vapidPublicKey, ttl, urgency, topic }) => {

  const headers = {

    Authorization: `vapid t=${jwt}, k=${vapidPublicKey}`,

    "Content-Encoding": "aes128gcm",

    "Content-Type": "application/octet-stream",

    TTL: String(ttl)

  };

  if (urgency) headers.Urgency = urgency;

  if (topic) headers.Topic = topic;

  return headers;

}, "buildPushHeaders");

var postToPushService = /* @__PURE__ */ __name(async (subscription, payloadBytes, jwt, vapidPublicKey, options) => {

  const { logger, ttl = 86400, urgency, topic, signal, timeoutMs = DEFAULT_TIMEOUT_MS } = options;

  const encryptedPayload = await encryptPayload(payloadBytes, subscription.keys.p256dh, subscription.keys.auth);

  const response = await fetch(subscription.endpoint, {

    method: "POST",

    headers: buildPushHeaders({

      jwt,

      vapidPublicKey,

      ttl,

      urgency,

      topic

    }),

    body: encryptedPayload,

    signal: requestSignal(signal, timeoutMs)

  });

  const responseText = await response.text();

  logger?.debug?.("Push response", {

    endpoint: subscription.endpoint.slice(0, 50),

    status: response.status,

    statusText: response.statusText,

    body: responseText.slice(0, 200)

  });

  if (response.ok) return true;

  if (isSubscriptionGone(response.status)) return false;

  throw new WebPushError(response.status === 429 ? `Push rate limit exceeded: ${response.statusText}` : `Push service error: ${response.status} ${response.statusText}`, response.status, responseText, subscription.endpoint, response.headers.get("retry-after"));

}, "postToPushService");

var sendPushNotification = /* @__PURE__ */ __name(async (subscription, payload, vapid, options = {}) => {

  assertValidTopic(options.topic);

  assertValidTimeout(options.timeoutMs ?? DEFAULT_TIMEOUT_MS);

  const payloadBytes = encodePayload(payload);

  validatePushInputs(payloadBytes, subscription.keys.p256dh, subscription.keys.auth);

  const jwt = await createVapidJwt({

    audience: pushServiceOrigin(subscription.endpoint),

    subject: vapid.subject,

    publicKey: vapid.publicKey,

    privateKey: vapid.privateKey,

    expiration: options.vapidExpiration ?? 43200

  });

  return postToPushService(subscription, payloadBytes, jwt, vapid.publicKey, options);

}, "sendPushNotification");



// src/index.js

var PREFIX = "v1:device:";

var cors = {

  "Access-Control-Allow-Origin": "*",

  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",

  "Access-Control-Allow-Headers": "Content-Type,Authorization",

  "Cache-Control": "no-store"

};

function json(data, status = 200) {

  return new Response(JSON.stringify(data, null, 2), {

    status,

    headers: { "content-type": "application/json; charset=utf-8", ...cors }

  });

}

__name(json, "json");

function clean(v) {

  return String(v ?? "").trim().replace(/^["']|["']$/g, "");

}

__name(clean, "clean");

function testTokenOK(request, env) {

  const got = request.headers.get("authorization") || "";

  return !!env.TEST_TOKEN && got === `Bearer ${env.TEST_TOKEN}`;

}

__name(testTokenOK, "testTokenOK");

function normalizeName(value) {

  return String(value || "").trim().normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLocaleLowerCase("es").replace(/\s+/g, " ");

}

__name(normalizeName, "normalizeName");

function internalTokenOK(request, env) {

  const got = request.headers.get("authorization") || "";

  return !!env.TEST_TOKEN && got === `Bearer ${env.TEST_TOKEN}`;

}

__name(internalTokenOK, "internalTokenOK");

function requireInternal(request, env) {

  if (!internalTokenOK(request, env)) {

    throw new Response(JSON.stringify({ ok: false, error: "Servicio interno no autorizado." }), {

      status: 401,

      headers: { "content-type": "application/json; charset=utf-8", ...cors }

    });

  }

  return true;

}

__name(requireInternal, "requireInternal");

function validSubscription(s) {

  return !!(s?.endpoint && s?.keys?.p256dh && s?.keys?.auth);

}

__name(validSubscription, "validSubscription");

function requireAdmin(request) {

  const origin = request.headers.get("Origin") || "";

  const allowed = origin === "https\://ligasdetenis.github.io";

  if (!allowed) {

    throw new Response(JSON.stringify({

      ok: false,

      error: "Petici\xF3n de administraci\xF3n no autorizada."

    }), {

      status: 403,

      headers: { "content-type": "application/json; charset=utf-8", ...cors }

    });

  }

  return true;

}

__name(requireAdmin, "requireAdmin");

async function listDevices(env) {

  const listed = await env.PUSH_DATA.list({ prefix: PREFIX });

  const out = [];

  for (const k of listed.keys) {

    const item = await env.PUSH_DATA.get(k.name, "json");

    if (item?.subscription?.endpoint) out.push({ key: k.name, ...item });

  }

  out.sort((a, b) => String(b.updatedAt || "").localeCompare(String(a.updatedAt || "")));

  return out;

}

__name(listDevices, "listDevices");

async function sendAll(env, payload, recipients = null) {

  let rows = await listDevices(env);

  let matchedUsers = 0;

  if (Array.isArray(recipients)) {

    const wanted = new Set(recipients.map(normalizeName).filter(Boolean));

    rows = rows.filter((row) => wanted.has(normalizeName(row.userName)));

    matchedUsers = new Set(rows.map((row) => normalizeName(row.userName)).filter(Boolean)).size;

  } else {

    matchedUsers = new Set(rows.map((row) => normalizeName(row.userName)).filter(Boolean)).size;

  }

  const vapid = {

    publicKey: clean(env.VAPID_PUBLIC_KEY),

    privateKey: clean(env.VAPID_PRIVATE_KEY),

    subject: clean(env.VAPID_SUBJECT || "mailto:ctcampeador.push\@example.com")

  };

  if (!vapid.publicKey || !vapid.privateKey) {

    throw new Error("Faltan VAPID_PUBLIC_KEY o VAPID_PRIVATE_KEY.");

  }

  let sent = 0, removed = 0;

  const failed = [];

  for (const row of rows) {

    try {

      const result = await sendPushNotification(row.subscription, payload, vapid);

      if (result === true || result?.ok === true || result?.status === 201 || result?.status === 200) {

        sent++;

      } else {

        const status = result?.status ?? null;

        if (status === 404 || status === 410) {

          await env.PUSH_DATA.delete(row.key);

          removed++;

        } else {

          failed.push({

            deviceId: row.deviceId,

            userName: row.userName || "",

            status,

            result: String(result)

          });

        }

      }

    } catch (e) {

      const message = e?.message || String(e);

      if (/\b(404|410)\b|gone|not found/i.test(message)) {

        await env.PUSH_DATA.delete(row.key);

        removed++;

      } else {

        failed.push({ deviceId: row.deviceId, userName: row.userName || "", error: message });

      }

    }

  }

  return { total: rows.length, matchedUsers, sent, removed, failed };

}

__name(sendAll, "sendAll");

var testSw = String.raw`

self.addEventListener("push", event => {

  let data = {};

  try { data = event.data ? event.data.json() : {}; }

  catch (_) { data = { body: event.data ? event.data.text() : "" }; }

  event.waitUntil(self.registration.showNotification(data.title || "CT Campeador", {

    body: data.body || "Prueba de notificación",

    tag: data.tag || "ctc-push-v1",

    data: { url: data.url || "/" }

  }));

});

self.addEventListener("notificationclick", event => {

  event.notification.close();

  const url = event.notification?.data?.url || "/";

  event.waitUntil(clients.openWindow ? clients.openWindow(url) : Promise.resolve());

});

`;

function testPage(publicKey) {

  return `<!doctype html>

<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">

<title>CT Campeador \xB7 Push V1</title>

<style>body{font-family:system-ui;background:#101114;color:#fff;margin:0;padding:22px}.card{max-width:620px;margin:auto;background:#1b1d22;border:1px solid #343740;border-radius:18px;padding:20px}h1{font-size:22px;margin:0 0 8px}p{color:#c6c9d0;line-height:1.4}input,button{width:100%;box-sizing:border-box;border-radius:11px;padding:12px;margin-top:9px;font:inherit}input{background:#111318;color:#fff;border:1px solid #454955}button{border:0;background:#e5b72c;color:#201800;font-weight:800;cursor:pointer}button.secondary{background:#353944;color:#fff}pre{white-space:pre-wrap;word-break:break-word;background:#0f1115;border:1px solid #343740;padding:12px;border-radius:11px;min-height:90px}.ok{color:#75e09b}.bad{color:#ff9a9a}</style>

</head><body><div class="card">

<h1>\u{1F3BE} CT Campeador \xB7 Push V1</h1>

<p>Prueba aislada del sistema Push.</p>

<input id="name" placeholder="Nombre">

<button id="activate">\u{1F514} Activar este dispositivo</button>

<button id="status" class="secondary">\u{1F4F1} Ver estado</button>

<pre id="log">Esperando\u2026</pre>

</div>

<script>

const PUBLIC_KEY=${JSON.stringify(publicKey || "")};

const logEl=document.getElementById("log");

const log=(s,ok=null)=>{logEl.textContent=String(s);logEl.className=ok===true?"ok":ok===false?"bad":""};

function b64u(s){const p="=".repeat((4-s.length%4)%4);const b=(s+p).replace(/-/g,"+").replace(/_/g,"/");const raw=atob(b),out=new Uint8Array(raw.length);for(let i=0;i<raw.length;i++)out[i]=raw.charCodeAt(i);return out}

function deviceId(){let id=localStorage.getItem("ctc_push_v1_device");if(!id){id=crypto.randomUUID?crypto.randomUUID():"dev-"+Date.now()+"-"+Math.random().toString(36).slice(2);localStorage.setItem("ctc_push_v1_device",id)}return id}

async function registration(){await navigator.serviceWorker.register("/sw.js",{scope:"/"});return navigator.serviceWorker.ready}

document.getElementById("activate").onclick=async()=>{try{

  if(!PUBLIC_KEY)throw new Error("Falta VAPID_PUBLIC_KEY.");

  const permission=await Notification.requestPermission();

  if(permission!=="granted")throw new Error("Permiso de notificaciones: "+permission);

  const reg=await registration();

  let old=await reg.pushManager.getSubscription();

  if(old)await old.unsubscribe().catch(()=>{});

  const sub=await reg.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:b64u(PUBLIC_KEY)});

  const res=await fetch("/subscribe-test",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({deviceId:deviceId(),userName:document.getElementById("name").value.trim(),subscription:sub.toJSON()})});

  const j=await res.json();if(!res.ok||j.ok===false)throw new Error(j.error||("HTTP "+res.status));

  log("\u2705 Dispositivo registrado correctamente.\\\n\\\nDevice ID: "+j.deviceId,true);

}catch(e){log("\u274C "+(e?.message||e),false)}};

document.getElementById("status").onclick=async()=>{const r=await fetch("/status",{cache:"no-store"});const j=await r.json();log(JSON.stringify(j,null,2),r.ok&&j.ok!==false)};

<\/script></body></html>`;

}

__name(testPage, "testPage");

var index_default = {

  async fetch(request, env) {

    const url = new URL(request.url);

    if (request.method === "OPTIONS") {

      return new Response(null, { status: 204, headers: cors });

    }

    if (request.method === "GET" && url.pathname === "/") {

      return new Response(testPage(clean(env.VAPID_PUBLIC_KEY)), {

        headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" }

      });

    }

    if (request.method === "GET" && url.pathname === "/sw.js") {

      return new Response(testSw, {

        headers: {

          "content-type": "application/javascript; charset=utf-8",

          "service-worker-allowed": "/",

          "cache-control": "no-store"

        }

      });

    }

    if (request.method === "GET" && url.pathname === "/public-key") {

      return json({ ok: true, publicKey: clean(env.VAPID_PUBLIC_KEY) });

    }

    if (request.method === "GET" && url.pathname === "/health") {
      return json({ok:true, vapidPublicKey:clean(env.VAPID_PUBLIC_KEY), vapidConfigured:!!(env.VAPID_PUBLIC_KEY&&env.VAPID_PRIVATE_KEY)});
    }
    if (request.method === "GET" && url.pathname === "/status") {

      const rows = await listDevices(env);

      return json({ ok: true, version: "PUSH_FINAL_V1", devices: rows.length });

    }

    if (request.method === "POST" && url.pathname === "/subscribe-test") {
      if(!testTokenOK(request,env)) return json({ok:false,error:"No autorizado"},401);


      const body = await request.json().catch(() => ({}));

      const deviceId = clean(body.deviceId);

      const userName = clean(body.userName);

      const subscription = body.subscription;

      if (!deviceId) return json({ ok: false, error: "Falta deviceId." }, 400);

      if (!validSubscription(subscription)) return json({ ok: false, error: "Suscripci\xF3n incompleta." }, 400);

      await env.PUSH_DATA.put(PREFIX + deviceId, JSON.stringify({

        deviceId,

        userName,

        subscription,

        updatedAt: (/* @__PURE__ */ new Date()).toISOString()

      }));

      return json({ ok: true, deviceId });

    }

    if (request.method === "POST" && url.pathname === "/subscribe") {
      try { await requireInternal(request, env); }
      catch (response) { return response; }


      const body = await request.json().catch(() => ({}));

      const deviceId = clean(body.deviceId);

      const userName = clean(body.userName);

      const subscription = body.subscription;

      if (!deviceId) return json({ ok: false, error: "Falta deviceId." }, 400);

      if (!userName) return json({ ok: false, error: "Falta userName." }, 400);

      if (!validSubscription(subscription)) return json({ ok: false, error: "Suscripci\xF3n incompleta." }, 400);

      await env.PUSH_DATA.put(PREFIX + deviceId, JSON.stringify({

        deviceId,

        userName,

        subscription,

        updatedAt: (/* @__PURE__ */ new Date()).toISOString()

      }));

      return json({ ok: true, deviceId, userName });

    }

    if (request.method === "POST" && url.pathname === "/admin/devices") {
      try { await requireInternal(request, env); } catch(response) { return response; }

      const rows = await listDevices(env);

      const grouped = /* @__PURE__ */ new Map();

      for (const row of rows) {

        const name = clean(row.userName) || "Sin identificar";

        const g = grouped.get(name) || { userName: name, count: 0, lastUpdated: "" };

        g.count++;

        if (row.updatedAt && (!g.lastUpdated || row.updatedAt > g.lastUpdated)) g.lastUpdated = row.updatedAt;

        grouped.set(name, g);

      }

      const users = [...grouped.values()].sort((a, b) => a.userName.localeCompare(b.userName, "es"));

      return json({ ok: true, total: rows.length, users });

    }

    if (request.method === "POST" && url.pathname === "/admin/remove-user") {
      try { await requireInternal(request, env); } catch(response) { return response; }

      const body = await request.json().catch(() => ({}));

      const target = clean(body.userName);

      if (!target) return json({ ok: false, error: "Falta userName." }, 400);

      const rows = await listDevices(env);

      let removed = 0;

      for (const row of rows) {

        if (clean(row.userName) === target) {

          await env.PUSH_DATA.delete(row.key);

          removed++;

        }

      }

      return json({ ok: true, removed });

    }

    if (request.method === "POST" && url.pathname === "/admin/send") {

      try {

        await requireInternal(request, env);

      } catch (response) {

        return response;

      }

      const body = await request.json().catch(() => ({}));

      const recipients = Array.isArray(body.recipients) ? [...new Set(body.recipients.map(clean).filter(Boolean))].slice(0, 250) : [];

      if (!recipients.length) return json({ ok: false, error: "No hay destinatarios." }, 400);

      const payload = {

        title: clean(body.title) || "\u{1F3BE} CT Campeador",

        body: clean(body.body) || "Tienes un nuevo aviso.",

        url: clean(body.url) || "https\://ligasdetenis.github.io/ct-campeador-pruebas/",

        tag: clean(body.tag) || `ctc-admin-${Date.now()}`

      };

      try {

        const result = await sendAll(env, payload, recipients);

        return json({ ok: result.failed.length === 0, ...result });

      } catch (e) {

        return json({ ok: false, error: e?.message || String(e) }, 500);

      }

    }

    if (request.method === "POST" && url.pathname === "/send") {

      try {

        await requireInternal(request, env);

      } catch (response) {

        return response;

      }

      const body = await request.json().catch(() => ({}));

      try {

        const result = await sendAll(env, {

          title: clean(body.title) || "\u{1F3BE} CT Campeador",

          body: clean(body.body) || "Tienes un nuevo aviso.",

          url: clean(body.url) || "https\://ligasdetenis.github.io/ct-campeador-pruebas/",

          tag: clean(body.tag) || "ctc-general"

        });

        return json({ ok: result.failed.length === 0, ...result });

      } catch (e) {

        return json({ ok: false, error: e?.message || String(e) }, 500);

      }

    }

    if (request.method === "POST" && url.pathname === "/send-availability") {
      try { await requireInternal(request, env); }
      catch (response) { return response; }

      const body = await request.json().catch(() => ({}));

      const weekLabel = clean(body.weekLabel) || clean(body.weekId) || "esta semana";

      const targetUrl = clean(body.url) || "https\://ligasdetenis.github.io/ct-campeador-pruebas/";

      try {

        const result = await sendAll(env, {

          title: "\u{1F3BE} CT Campeador",

          body: `Ya est\xE1n disponibles las pistas para ${weekLabel}. Entra en la app para reservar.`,

          url: targetUrl,

          tag: "ctc-disponibilidad"

        });

        return json({ ok: result.failed.length === 0, ...result });

      } catch (e) {

        return json({ ok: false, error: e?.message || String(e) }, 500);

      }

    }

    if (request.method === "POST" && url.pathname === "/send-test") {

      if (!testTokenOK(request, env)) return json({ ok: false, error: "No autorizado." }, 401);

      const body = await request.json().catch(() => ({}));

      try {

        const result = await sendAll(env, {

          title: clean(body.title) || "\u{1F3BE} CT Campeador",

          body: clean(body.body) || "Push funcionando",

          url: clean(body.url) || "https\://ligasdetenis.github.io/ct-campeador-pruebas/",

          tag: clean(body.tag) || "ctc-push-test"

        });

        return json({ ok: result.failed.length === 0, ...result });

      } catch (e) {

        return json({ ok: false, error: e?.message || String(e) }, 500);

      }

    }

    return json({ ok: false, error: "Ruta no encontrada.", path: url.pathname }, 404);

  }

};

export {

  index_default as default

};


