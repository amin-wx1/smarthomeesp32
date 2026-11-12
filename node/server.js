"use strict";

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const mqtt = require("mqtt");
const path = require("path");
const crypto = require("crypto");

// ---------- پیکربندی از متغیرهای محیطی (بدون مقدار پیش‌فرض برای رمزها) ----------
function requireEnv(name) {
  const value = process.env[name];
  if (!value) {
    console.error(`متغیر محیطی ${name} تنظیم نشده است. به .env.example نگاه کنید.`);
    process.exit(1);
  }
  return value;
}

const MQTT_URL = requireEnv("MQTT_URL");
const MQTT_USER = requireEnv("MQTT_USER");
const MQTT_PASS = requireEnv("MQTT_PASS");
const PORT = Number(process.env.PORT) || 3000;
const REQUEST_TIMEOUT_MS = Number(process.env.REQUEST_TIMEOUT_MS) || 6000;
const TRUST_PROXY = process.env.TRUST_PROXY === undefined ? 1 : Number(process.env.TRUST_PROXY);
const MAX_PENDING = 20;

const TOPIC_REQ = "smarthome/api/request";
const TOPIC_RES = "smarthome/api/response";
const TOPIC_STATUS = "smarthome/status";

// ---------- فهرست مجاز مسیر و متد (هر چیز دیگر هرگز به برد نمی‌رسد) ----------
const ALLOWED = new Set([
  "GET /api/setup-status",
  "POST /api/setup",
  "POST /api/login",
  "POST /api/logout",
  "POST /api/auth/password",
  "GET /api/auth/sessions",
  "POST /api/auth/logout-others",
  "GET /api/status",
  "GET /api/history",
  "POST /api/relay",
  "POST /api/security/mode",
  "POST /api/security/reset",
  "POST /api/automation/smart-mode",
  "POST /api/gas/open",
]);

const TOKEN_RE = /^[0-9a-f]{32}$/;

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", TRUST_PROXY);

// داشبورد یک فایل HTML با اسکریپت و استایل inline است، پس 'unsafe-inline' لازم است.
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        scriptSrcAttr: ["'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'none'"],
      },
    },
  })
);

app.use(express.json({ limit: "2kb" }));
app.use(express.static(path.join(__dirname, "public")));

// ---------- Rate limit ----------
function jsonLimiter(options) {
  return rateLimit({
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) =>
      res.status(429).json({ success: false, message: "تعداد درخواست‌ها زیاد است. کمی بعد دوباره تلاش کنید." }),
    ...options,
  });
}

// عمومی: داشبورد هر ثانیه status می‌گیرد (۶۰ در دقیقه)، پس سقف بالاتر است.
const generalLimiter = jsonLimiter({ windowMs: 60 * 1000, limit: 180 });
// ورود و تنظیم اولیه: تلاش‌های زیاد از یک IP را قبل از رسیدن به برد قطع می‌کند.
const authLimiter = jsonLimiter({ windowMs: 60 * 1000, limit: 5 });
const passwordLimiter = jsonLimiter({ windowMs: 60 * 1000, limit: 5 });

app.use("/api/", generalLimiter);
app.use("/api/login", authLimiter);
app.use("/api/setup", authLimiter);
app.use("/api/auth/password", passwordLimiter);

// ---------- اتصال MQTT و وضعیت برد ----------
const pendingRequests = new Map();
let boardOnline = null; // null = هنوز پیام وضعیت نرسیده

const client = mqtt.connect(MQTT_URL, {
  username: MQTT_USER,
  password: MQTT_PASS,
  reconnectPeriod: 3000,
  clean: true,
});

function failAllPending(status, message) {
  for (const [reqId, pending] of pendingRequests) {
    clearTimeout(pending.timer);
    pendingRequests.delete(reqId);
    if (!pending.res.headersSent) pending.res.status(status).json({ success: false, message });
  }
}

client.on("connect", () => {
  console.log("Connected to MQTT broker");
  client.subscribe([TOPIC_RES, TOPIC_STATUS], { qos: 1 }, (err) => {
    if (err) console.error("Subscribe failed:", err.message);
  });
});

client.on("close", () => {
  boardOnline = null;
  failAllPending(503, "اتصال سرور به بروکر MQTT قطع شد");
});

client.on("error", (err) => console.error("MQTT error:", err.message));

client.on("message", (topic, message) => {
  if (topic === TOPIC_STATUS) {
    const text = message.toString().trim();
    boardOnline = text === "online";
    console.log(`Board status: ${text}`);
    if (!boardOnline) failAllPending(503, "برد آفلاین شد");
    return;
  }

  if (topic !== TOPIC_RES) return;
  try {
    const data = JSON.parse(message.toString());
    const pending = pendingRequests.get(data.reqId);
    if (!pending) return;
    clearTimeout(pending.timer);
    pendingRequests.delete(data.reqId);
    pending.res
      .status(Number(data.status) || 200)
      .type("application/json")
      .send(typeof data.payload === "string" ? data.payload : "{}");
  } catch (err) {
    console.error("Invalid MQTT response:", err.message);
  }
});

// ---------- عبور درخواست‌ها به برد ----------
function reject(res, status, message) {
  return res.status(status).json({ success: false, message });
}

app.all("/api/*", (req, res) => {
  const key = `${req.method} ${req.path}`;
  if (!ALLOWED.has(key)) return reject(res, 404, "Endpoint not found");

  if (!client.connected) return reject(res, 503, "عدم اتصال سرور به بروکر MQTT");
  if (boardOnline === false) return reject(res, 503, "برد آفلاین است. اتصال اینترنت و برق ESP32 را بررسی کنید.");
  if (pendingRequests.size >= MAX_PENDING) return reject(res, 503, "سرور مشغول است. کمی بعد دوباره تلاش کنید.");

  let body = null;
  if (req.method === "POST") {
    if (req.body === null || typeof req.body !== "object" || Array.isArray(req.body)) {
      return reject(res, 400, "Invalid JSON");
    }
    body = req.body;
  }

  const authHeader = req.headers["authorization"] || "";
  let token = "";
  if (authHeader.startsWith("Bearer ")) {
    token = authHeader.substring(7).trim();
    if (!TOKEN_RE.test(token)) token = ""; // توکن بدشکل هرگز به برد نمی‌رسد
  }

  const reqId = crypto.randomUUID();
  const timer = setTimeout(() => {
    pendingRequests.delete(reqId);
    if (!res.headersSent) {
      reject(res, 504, "برد پاسخ نداد. اتصال اینترنت ESP32 را بررسی کنید.");
    }
  }, REQUEST_TIMEOUT_MS);

  pendingRequests.set(reqId, { res, timer });
  res.on("close", () => {
    // کاربر قبل از پاسخ قطع کرد
    if (!res.writableEnded && pendingRequests.has(reqId)) {
      clearTimeout(timer);
      pendingRequests.delete(reqId);
    }
  });

  const payload = JSON.stringify({ reqId, path: req.path, method: req.method, token, body });
  client.publish(TOPIC_REQ, payload, { qos: 0 }, (err) => {
    if (err && pendingRequests.has(reqId)) {
      clearTimeout(timer);
      pendingRequests.delete(reqId);
      if (!res.headersSent) reject(res, 502, "ارسال درخواست به بروکر ناموفق بود");
    }
  });
});

// خطای JSON خراب یا بدنه‌ی بزرگ
app.use((err, req, res, next) => {
  if (err && (err.type === "entity.parse.failed" || err.type === "entity.too.large")) {
    return reject(res, err.status || 400, "Invalid request body");
  }
  console.error(err);
  return reject(res, 500, "Internal error");
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`SmartHome Web Panel running on port ${PORT}`);
});
