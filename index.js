// index.js
import path4 from "node:path";
import express from "express";
import cors from "cors";

// server/db/index.js
import fs2 from "node:fs";
import path2 from "node:path";
import Database from "better-sqlite3";
import bcrypt from "bcryptjs";

// server/config/store.js
import fs from "node:fs";
import path from "node:path";

// server/security/crypto.js
import crypto2 from "node:crypto";

// server/security/keyPartA.js
var keyPartA = "a1f7c9d4e8b2";

// server/security/keyPartB.js
var keyPartB = "73aa91fe22c4";

// server/security/keyPartC.js
var keyPartC = "54bc0de61f98";

// server/security/crypto.js
var masterMaterial = `${keyPartA}:${keyPartB}:${keyPartC}:v1`;
var masterKey = crypto2.createHash("sha256").update(masterMaterial).digest();
function encryptJson(data) {
  const iv = crypto2.randomBytes(12);
  const cipher = crypto2.createCipheriv("aes-256-gcm", masterKey, iv);
  const plaintext = Buffer.from(JSON.stringify(data), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return JSON.stringify({
    version: 1,
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    data: ciphertext.toString("base64")
  });
}
function decryptJson(payload) {
  const parsed = JSON.parse(payload);
  const iv = Buffer.from(parsed.iv, "base64");
  const tag = Buffer.from(parsed.tag, "base64");
  const data = Buffer.from(parsed.data, "base64");
  const decipher = crypto2.createDecipheriv("aes-256-gcm", masterKey, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(data), decipher.final()]);
  return JSON.parse(plaintext.toString("utf8"));
}

// server/config/store.js
var dataDir = path.resolve(process.cwd(), "data");
var configPath = path.join(dataDir, "monitor.dat");
var defaultConfig = {
  server: {
    port: 3e3
  },
  database: {
    path: "./data/monitor.db",
    initialAdminPassword: "admin123"
  },
  auth: {
    jwtSecret: "replace-this-secret-in-admin-config"
  },
  monitoring: {
    maxConcurrentChecks: 5,
    defaultTimeoutSeconds: 30,
    alertConsecutiveFailures: 2,
    recoveryConsecutiveSuccesses: 2,
    alertCooldownMinutes: 10,
    webhookMaxRetries: 3,
    webhookRetryDelayMs: 1e3,
    checkHistoryDays: 30
  },
  binary: {
    path: "/app",
    targetPort: 31e3,
    url: "",
    moduleName: "",
    autoStart: false
  }
};
var cache = null;
function deepMerge(base, patch) {
  if (!patch || typeof patch !== "object") {
    return base;
  }
  const output = Array.isArray(base) ? [...base] : { ...base };
  for (const [key, value] of Object.entries(patch)) {
    const current = output[key];
    if (value && typeof value === "object" && !Array.isArray(value) && current && typeof current === "object" && !Array.isArray(current)) {
      output[key] = deepMerge(current, value);
    } else {
      output[key] = value;
    }
  }
  return output;
}
function ensureDataDir() {
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }
}
function validateConfig(config) {
  const port = Number(config.server?.port);
  if (!Number.isFinite(port) || port < 1 || port > 65535) {
    throw new Error("invalid server.port");
  }
  const maxConcurrentChecks = Number(config.monitoring?.maxConcurrentChecks);
  if (!Number.isFinite(maxConcurrentChecks) || maxConcurrentChecks < 1 || maxConcurrentChecks > 100) {
    throw new Error("invalid monitoring.maxConcurrentChecks");
  }
  const defaultTimeoutSeconds = Number(config.monitoring?.defaultTimeoutSeconds);
  if (!Number.isFinite(defaultTimeoutSeconds) || defaultTimeoutSeconds < 5 || defaultTimeoutSeconds > 120) {
    throw new Error("invalid monitoring.defaultTimeoutSeconds");
  }
  const alertConsecutiveFailures = Number(config.monitoring?.alertConsecutiveFailures);
  if (!Number.isFinite(alertConsecutiveFailures) || alertConsecutiveFailures < 1 || alertConsecutiveFailures > 10) {
    throw new Error("invalid monitoring.alertConsecutiveFailures");
  }
  const recoveryConsecutiveSuccesses = Number(config.monitoring?.recoveryConsecutiveSuccesses);
  if (!Number.isFinite(recoveryConsecutiveSuccesses) || recoveryConsecutiveSuccesses < 1 || recoveryConsecutiveSuccesses > 10) {
    throw new Error("invalid monitoring.recoveryConsecutiveSuccesses");
  }
  const alertCooldownMinutes = Number(config.monitoring?.alertCooldownMinutes);
  if (!Number.isFinite(alertCooldownMinutes) || alertCooldownMinutes < 0 || alertCooldownMinutes > 1440) {
    throw new Error("invalid monitoring.alertCooldownMinutes");
  }
  const webhookMaxRetries = Number(config.monitoring?.webhookMaxRetries);
  if (!Number.isFinite(webhookMaxRetries) || webhookMaxRetries < 1 || webhookMaxRetries > 10) {
    throw new Error("invalid monitoring.webhookMaxRetries");
  }
  const webhookRetryDelayMs = Number(config.monitoring?.webhookRetryDelayMs);
  if (!Number.isFinite(webhookRetryDelayMs) || webhookRetryDelayMs < 100 || webhookRetryDelayMs > 6e4) {
    throw new Error("invalid monitoring.webhookRetryDelayMs");
  }
  const checkHistoryDays = Number(config.monitoring?.checkHistoryDays);
  if (!Number.isFinite(checkHistoryDays) || checkHistoryDays < 1 || checkHistoryDays > 3650) {
    throw new Error("invalid monitoring.checkHistoryDays");
  }
  const binaryPath = `${config.binary?.path || ""}`.trim();
  if (!binaryPath || !binaryPath.startsWith("/")) {
    throw new Error("invalid binary.path");
  }
  const binaryTargetPort = Number(config.binary?.targetPort);
  if (!Number.isFinite(binaryTargetPort) || binaryTargetPort < 1 || binaryTargetPort > 65535) {
    throw new Error("invalid binary.targetPort");
  }
  const binaryModuleName = `${config.binary?.moduleName || ""}`.trim();
  if (binaryModuleName.length > 120) {
    throw new Error("invalid binary.moduleName length");
  }
  const binaryUrl = `${config.binary?.url || ""}`.trim();
  if (binaryUrl && binaryUrl.length > 2048) {
    throw new Error("invalid binary.url length");
  }
  if (binaryUrl && !/^https?:\/\//i.test(binaryUrl)) {
    throw new Error("invalid binary.url");
  }
  const binaryAutoStart = Number(config.binary?.autoStart ? 1 : 0);
  if (![0, 1].includes(binaryAutoStart)) {
    throw new Error("invalid binary.autoStart");
  }
  const dbPath2 = `${config.database?.path || ""}`.trim();
  if (!dbPath2) {
    throw new Error("invalid database.path");
  }
  const adminPassword = `${config.database?.initialAdminPassword || ""}`;
  if (adminPassword.length < 6 || adminPassword.length > 128) {
    throw new Error("invalid database.initialAdminPassword length");
  }
  const jwtSecret = `${config.auth?.jwtSecret || ""}`;
  if (jwtSecret.length < 16 || jwtSecret.length > 256) {
    throw new Error("invalid auth.jwtSecret length");
  }
}
function writeEncryptedConfig(config) {
  ensureDataDir();
  const encrypted = encryptJson(config);
  fs.writeFileSync(configPath, encrypted, "utf8");
}
function getConfigPath() {
  return configPath;
}
function loadConfig() {
  if (cache) {
    return cache;
  }
  ensureDataDir();
  if (!fs.existsSync(configPath)) {
    validateConfig(defaultConfig);
    writeEncryptedConfig(defaultConfig);
    cache = structuredClone(defaultConfig);
    return cache;
  }
  const encrypted = fs.readFileSync(configPath, "utf8");
  const parsed = decryptJson(encrypted);
  const merged = deepMerge(defaultConfig, parsed);
  validateConfig(merged);
  cache = merged;
  return cache;
}
function saveConfig(nextConfig) {
  validateConfig(nextConfig);
  writeEncryptedConfig(nextConfig);
  cache = structuredClone(nextConfig);
  return cache;
}
function patchConfig(partial) {
  const current = loadConfig();
  const merged = deepMerge(current, partial);
  return saveConfig(merged);
}

// server/db/index.js
var SCHEMA_SQL_FALLBACK = `CREATE TABLE IF NOT EXISTS admin_credentials (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS monitors (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  public_name TEXT,
  is_public INTEGER NOT NULL DEFAULT 1,
  url TEXT NOT NULL,
  check_interval_mode TEXT NOT NULL DEFAULT 'fixed',
  check_interval INTEGER NOT NULL DEFAULT 5,
  check_interval_min INTEGER,
  check_interval_max INTEGER,
  check_type TEXT NOT NULL DEFAULT 'http',
  check_method TEXT NOT NULL DEFAULT 'GET',
  check_timeout INTEGER NOT NULL DEFAULT 30,
  cert_expiry_days INTEGER NOT NULL DEFAULT 15,
  expected_status_codes TEXT DEFAULT '200,201,204,301,302',
  expected_keyword TEXT,
  forbidden_keyword TEXT,
  webhook_url TEXT,
  webhook_content_type TEXT DEFAULT 'application/json',
  webhook_headers TEXT,
  webhook_body TEXT,
  webhook_username TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  consecutive_successes INTEGER NOT NULL DEFAULT 0,
  last_status TEXT,
  last_alert_at TEXT,
  last_recovery_at TEXT,
  last_checked_at TEXT,
  next_check_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS monitor_checks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  monitor_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('up', 'down')),
  failure_reason TEXT,
  response_time INTEGER NOT NULL,
  status_code INTEGER,
  error_message TEXT,
  checked_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (monitor_id) REFERENCES monitors(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  monitor_id TEXT NOT NULL,
  started_at TEXT NOT NULL DEFAULT (datetime('now')),
  resolved_at TEXT,
  duration_seconds INTEGER,
  notified INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (monitor_id) REFERENCES monitors(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_monitor_checks_monitor_id ON monitor_checks(monitor_id);
CREATE INDEX IF NOT EXISTS idx_monitor_checks_checked_at ON monitor_checks(checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_monitor_checks_monitor_time ON monitor_checks(monitor_id, checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_monitor_id ON incidents(monitor_id);
CREATE INDEX IF NOT EXISTS idx_incidents_unresolved ON incidents(monitor_id, resolved_at) WHERE resolved_at IS NULL;`;
var appConfig = loadConfig();
var dbPath = appConfig.database.path || "./data/monitor.db";
var absoluteDbPath = path2.isAbsolute(dbPath) ? dbPath : path2.resolve(process.cwd(), dbPath);
var dbDir = path2.dirname(absoluteDbPath);
if (!fs2.existsSync(dbDir)) {
  fs2.mkdirSync(dbDir, { recursive: true });
}
var db = new Database(absoluteDbPath);
db.pragma("journal_mode = WAL");
function shouldIgnoreSchemaError(statement, error) {
  const sql = `${statement || ""}`.toLowerCase();
  const message = `${error?.message || ""}`.toLowerCase();
  if (sql.startsWith("create index") && message.includes("no such column")) {
    return true;
  }
  if (sql.startsWith("alter table") && (message.includes("duplicate column name") || message.includes("already exists"))) {
    return true;
  }
  return false;
}
function execSchemaSafely(schemaSql) {
  const statements = schemaSql.split(";").map((line) => line.trim()).filter((line) => line.length > 0);
  for (const statement of statements) {
    try {
      db.exec(`${statement};`);
    } catch (error) {
      if (shouldIgnoreSchemaError(statement, error)) {
        continue;
      }
      throw error;
    }
  }
}
function initDatabase() {
  const schemaPath = path2.resolve(process.cwd(), "server/db/schema.sql");
  const schemaSql = fs2.existsSync(schemaPath) ? fs2.readFileSync(schemaPath, "utf8") : SCHEMA_SQL_FALLBACK;
  execSchemaSafely(schemaSql);
  const columns = db.prepare("PRAGMA table_info(monitors)").all();
  const columnNames = new Set(columns.map((col) => col.name));
  if (!columnNames.has("check_interval_mode")) {
    db.exec("ALTER TABLE monitors ADD COLUMN check_interval_mode TEXT NOT NULL DEFAULT 'fixed'");
  }
  if (!columnNames.has("check_interval_min")) {
    db.exec("ALTER TABLE monitors ADD COLUMN check_interval_min INTEGER");
  }
  if (!columnNames.has("check_interval_max")) {
    db.exec("ALTER TABLE monitors ADD COLUMN check_interval_max INTEGER");
  }
  if (!columnNames.has("next_check_at")) {
    db.exec("ALTER TABLE monitors ADD COLUMN next_check_at TEXT");
  }
  if (!columnNames.has("cert_expiry_days")) {
    db.exec("ALTER TABLE monitors ADD COLUMN cert_expiry_days INTEGER NOT NULL DEFAULT 15");
  }
  if (!columnNames.has("consecutive_failures")) {
    db.exec("ALTER TABLE monitors ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0");
  }
  if (!columnNames.has("consecutive_successes")) {
    db.exec("ALTER TABLE monitors ADD COLUMN consecutive_successes INTEGER NOT NULL DEFAULT 0");
  }
  if (!columnNames.has("last_status")) {
    db.exec("ALTER TABLE monitors ADD COLUMN last_status TEXT");
  }
  if (!columnNames.has("last_alert_at")) {
    db.exec("ALTER TABLE monitors ADD COLUMN last_alert_at TEXT");
  }
  if (!columnNames.has("last_recovery_at")) {
    db.exec("ALTER TABLE monitors ADD COLUMN last_recovery_at TEXT");
  }
  const checkColumns = db.prepare("PRAGMA table_info(monitor_checks)").all();
  const checkColumnNames = new Set(checkColumns.map((col) => col.name));
  if (!checkColumnNames.has("failure_reason")) {
    db.exec("ALTER TABLE monitor_checks ADD COLUMN failure_reason TEXT");
  }
  db.exec("CREATE INDEX IF NOT EXISTS idx_monitor_checks_monitor_time ON monitor_checks(monitor_id, checked_at DESC)");
  db.exec("CREATE INDEX IF NOT EXISTS idx_monitor_checks_failure_reason ON monitor_checks(monitor_id, failure_reason, checked_at DESC)");
  const row = db.prepare("SELECT id FROM admin_credentials WHERE id = 1").get();
  if (!row) {
    const adminPassword = appConfig.database.initialAdminPassword || "admin123";
    const passwordHash = bcrypt.hashSync(adminPassword, 10);
    db.prepare(
      "INSERT INTO admin_credentials (id, password_hash, created_at, updated_at) VALUES (1, ?, datetime('now'), datetime('now'))"
    ).run(passwordHash);
  }
}

// server/routes/auth.js
import { Router } from "express";
import bcrypt2 from "bcryptjs";
import jwt2 from "jsonwebtoken";

// server/middleware/auth.js
import jwt from "jsonwebtoken";
function requireAuth(req, res, next) {
  const authHeader = req.header("Authorization") || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  try {
    const secret = loadConfig().auth.jwtSecret;
    const payload = jwt.verify(token, secret);
    if (payload.role !== "admin") {
      return res.status(403).json({ error: "Forbidden" });
    }
    return next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// server/middleware/rateLimit.js
function createRateLimiter(options) {
  const buckets = /* @__PURE__ */ new Map();
  return function rateLimit(req, res, next) {
    const now = Date.now();
    const key = `${req.ip || "unknown"}:${req.path}`;
    const current = buckets.get(key);
    if (!current || now > current.resetAt) {
      buckets.set(key, { count: 1, resetAt: now + options.windowMs });
      return next();
    }
    current.count += 1;
    if (current.count > options.max) {
      const retryAfterSeconds = Math.ceil((current.resetAt - now) / 1e3);
      res.setHeader("Retry-After", String(Math.max(retryAfterSeconds, 1)));
      return res.status(429).json({ error: "Too many requests" });
    }
    return next();
  };
}

// server/routes/auth.js
var authRouter = Router();
var loginRateLimit = createRateLimiter({ windowMs: 6e4, max: 10 });
authRouter.post("/login", loginRateLimit, (req, res) => {
  const { password } = req.body || {};
  if (!password) {
    return res.status(400).json({ error: "password required" });
  }
  const row = db.prepare("SELECT password_hash FROM admin_credentials WHERE id = 1").get();
  if (!row) {
    return res.status(500).json({ error: "admin credentials not initialized" });
  }
  const valid = bcrypt2.compareSync(password, row.password_hash);
  if (!valid) {
    return res.status(401).json({ error: "invalid password" });
  }
  const secret = loadConfig().auth.jwtSecret;
  const token = jwt2.sign({ role: "admin" }, secret, { expiresIn: "24h" });
  return res.json({ token });
});
authRouter.post("/change-password", requireAuth, (req, res) => {
  const { new_password } = req.body || {};
  if (!new_password) {
    return res.status(400).json({ error: "new_password required" });
  }
  if (new_password.length < 6 || new_password.length > 128) {
    return res.status(400).json({ error: "new password length must be 6-128" });
  }
  const newHash = bcrypt2.hashSync(new_password, 10);
  db.prepare("UPDATE admin_credentials SET password_hash = ?, updated_at = datetime('now') WHERE id = 1").run(newHash);
  return res.json({ success: true });
});

// server/routes/public.js
import { Router as Router2 } from "express";

// server/services/monitor.js
import net from "node:net";
import tls from "node:tls";
function nowIso() {
  return (/* @__PURE__ */ new Date()).toISOString();
}
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
function classifyFailure(checkType, statusCode, errorMessage) {
  const message = `${errorMessage || ""}`.toLowerCase();
  if (!message) {
    if (statusCode && statusCode >= 400) return "http_status";
    return "unknown";
  }
  if (message.includes("timeout") || message.includes("timed out") || message.includes("abort")) return "timeout";
  if (message.includes("dns") || message.includes("enotfound") || message.includes("name or service not known")) return "dns";
  if (message.includes("refused") || message.includes("econnrefused")) return "connection_refused";
  if (message.includes("reset") || message.includes("econnreset")) return "connection_reset";
  if (message.includes("forbidden keyword")) return "forbidden_keyword";
  if (message.includes("expected keyword")) return "expected_keyword_missing";
  if (message.includes("status code")) return "http_status";
  if (message.includes("certificate") || message.includes("tls") || message.includes("ssl")) return "tls";
  if (checkType === "https_cert" && (message.includes("expired") || message.includes("expiry") || message.includes("days"))) return "certificate_expiry";
  return "network";
}
function checkHttpsCert(monitor) {
  const start = Date.now();
  const timeoutSeconds = Number(monitor.check_timeout || loadConfig().monitoring.defaultTimeoutSeconds || 30);
  const timeoutMs = timeoutSeconds * 1e3;
  const thresholdDays = Math.max(1, Number(monitor.cert_expiry_days || 15));
  let host;
  let port = 443;
  try {
    const parsed = monitor.url.startsWith("http://") || monitor.url.startsWith("https://") ? new URL(monitor.url) : new URL(`https://${monitor.url}`);
    host = parsed.hostname;
    port = parsed.port ? Number(parsed.port) : 443;
    if (!host) {
      throw new Error("Invalid host");
    }
  } catch {
    return Promise.resolve({
      monitor_id: monitor.id,
      status: "down",
      failure_reason: classifyFailure("https_cert", 0, "Invalid URL for certificate check"),
      response_time: Date.now() - start,
      status_code: 0,
      error_message: "Invalid URL for certificate check",
      checked_at: nowIso()
    });
  }
  return new Promise((resolve) => {
    let finished = false;
    const done = (status, message, daysLeft = null) => {
      if (finished) return;
      finished = true;
      resolve({
        monitor_id: monitor.id,
        status,
        failure_reason: status === "down" ? classifyFailure("https_cert", 0, message) : null,
        response_time: Date.now() - start,
        status_code: status === "up" ? 200 : 0,
        error_message: message,
        checked_at: nowIso(),
        cert_days_left: daysLeft
      });
    };
    const socket = tls.connect({
      host,
      port,
      servername: host,
      rejectUnauthorized: false,
      timeout: timeoutMs
    });
    socket.once("secureConnect", () => {
      const cert = socket.getPeerCertificate();
      socket.end();
      if (!cert || !cert.valid_to) {
        done("down", "Certificate information unavailable");
        return;
      }
      const expiryMs = new Date(cert.valid_to).getTime();
      if (!Number.isFinite(expiryMs)) {
        done("down", "Invalid certificate expiry date");
        return;
      }
      const daysLeft = Math.floor((expiryMs - Date.now()) / 864e5);
      if (daysLeft < thresholdDays) {
        done("down", `Certificate expires in ${daysLeft} day(s)`, daysLeft);
      } else {
        done("up", "", daysLeft);
      }
    });
    socket.once("timeout", () => {
      socket.destroy();
      done("down", `TLS timeout (${timeoutSeconds}s)`);
    });
    socket.once("error", (error) => {
      done("down", error?.message || "TLS connection failed");
    });
  });
}
function parseExpectedCodes(expected) {
  return expected.split(",").map((s) => Number(s.trim())).filter((n) => Number.isFinite(n));
}
function replaceVariables(template, variables) {
  let value = template;
  for (const [key, replacement] of Object.entries(variables)) {
    value = value.replaceAll(`{{${key}}}`, replacement);
  }
  return value;
}
function processWebhookBody(value, variables) {
  if (typeof value === "string") {
    return replaceVariables(value, variables);
  }
  if (Array.isArray(value)) {
    return value.map((item) => processWebhookBody(item, variables));
  }
  if (value && typeof value === "object") {
    const output = {};
    for (const [key, item] of Object.entries(value)) {
      output[key] = processWebhookBody(item, variables);
    }
    return output;
  }
  return value;
}
async function sendWebhookNotification(monitor, check, type) {
  if (!monitor.webhook_url) {
    return { success: false, error: "no webhook_url configured" };
  }
  const variables = {
    monitor_name: monitor.name,
    monitor_url: monitor.url,
    status: type,
    error: check.error_message,
    timestamp: check.checked_at,
    response_time: String(check.response_time),
    status_code: String(check.status_code)
  };
  let payload = {
    monitor: monitor.name,
    url: monitor.url,
    status: type,
    timestamp: check.checked_at,
    response_time: check.response_time,
    status_code: check.status_code,
    error: check.error_message
  };
  if (monitor.webhook_body) {
    try {
      const parsed = JSON.parse(monitor.webhook_body);
      payload = processWebhookBody(parsed, variables);
    } catch {
      payload = { ...payload, message: "Invalid webhook_body JSON in monitor config" };
    }
  }
  let headers = {
    "Content-Type": monitor.webhook_content_type || "application/json"
  };
  if (monitor.webhook_headers) {
    try {
      const parsedHeaders = JSON.parse(monitor.webhook_headers);
      headers = { ...headers, ...parsedHeaders };
    } catch {
      return { success: false, error: "invalid webhook_headers JSON" };
    }
  }
  if (monitor.webhook_username) {
    headers.Authorization = `Basic ${Buffer.from(`${monitor.webhook_username}:`).toString("base64")}`;
  }
  try {
    const response = await fetch(monitor.webhook_url, {
      method: "POST",
      headers,
      body: JSON.stringify(payload)
    });
    return {
      success: response.ok,
      statusCode: response.status,
      error: response.ok ? void 0 : `webhook responded ${response.status}`
    };
  } catch (error) {
    return { success: false, error: error?.message || "webhook request failed" };
  }
}
async function sendWebhookNotificationWithRetry(monitor, check, type) {
  const monitoringConfig = loadConfig().monitoring || {};
  const maxRetries = Number(monitoringConfig.webhookMaxRetries || 3);
  const baseDelayMs = Number(monitoringConfig.webhookRetryDelayMs || 1e3);
  const attempts = Math.max(1, maxRetries);
  let lastResult = { success: false, error: "webhook failed" };
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    lastResult = await sendWebhookNotification(monitor, check, type);
    if (lastResult.success) {
      return { ...lastResult, attempts: attempt };
    }
    if (attempt < attempts) {
      const delay = Math.min(baseDelayMs * 2 ** (attempt - 1), 3e4);
      await sleep(delay);
    }
  }
  return { ...lastResult, attempts };
}
async function checkHTTP(monitor) {
  const start = Date.now();
  const timeoutSeconds = Number(monitor.check_timeout || loadConfig().monitoring.defaultTimeoutSeconds || 30);
  const timeout = timeoutSeconds * 1e3;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(monitor.url, {
      method: monitor.check_method || "GET",
      signal: controller.signal,
      redirect: "follow",
      headers: { "User-Agent": "NodeUptimeMonitor/1.0" }
    });
    clearTimeout(timeoutId);
    let body = "";
    const needBody = (monitor.expected_keyword || monitor.forbidden_keyword) && monitor.check_method !== "HEAD";
    if (needBody) {
      body = await response.text().catch(() => "");
    }
    const expected = parseExpectedCodes(monitor.expected_status_codes || "200,201,204,301,302");
    let status = expected.includes(response.status) ? "up" : "down";
    let errorMessage = "";
    if (status === "up" && monitor.forbidden_keyword && body.includes(monitor.forbidden_keyword)) {
      status = "down";
      errorMessage = `Detected forbidden keyword: ${monitor.forbidden_keyword}`;
    }
    if (status === "up" && monitor.expected_keyword && !body.includes(monitor.expected_keyword)) {
      status = "down";
      errorMessage = `Expected keyword missing: ${monitor.expected_keyword}`;
    }
    if (status === "down" && !errorMessage && !expected.includes(response.status)) {
      errorMessage = `Status code ${response.status} not expected`;
    }
    return {
      monitor_id: monitor.id,
      status,
      failure_reason: status === "down" ? classifyFailure("http", response.status, errorMessage) : null,
      response_time: Date.now() - start,
      status_code: response.status,
      error_message: errorMessage,
      checked_at: nowIso()
    };
  } catch (error) {
    clearTimeout(timeoutId);
    return {
      monitor_id: monitor.id,
      status: "down",
      failure_reason: classifyFailure("http", 0, error?.name === "AbortError" ? `Timeout (${timeoutSeconds}s)` : error?.message || "Request failed"),
      response_time: Date.now() - start,
      status_code: 0,
      error_message: error?.name === "AbortError" ? `Timeout (${timeoutSeconds}s)` : error?.message || "Request failed",
      checked_at: nowIso()
    };
  }
}
function checkTCP(monitor) {
  const start = Date.now();
  const timeoutSeconds = Number(monitor.check_timeout || loadConfig().monitoring.defaultTimeoutSeconds || 30);
  const timeout = timeoutSeconds * 1e3;
  let host = monitor.url;
  let port = 443;
  try {
    if (host.startsWith("http://") || host.startsWith("https://")) {
      const parsed = new URL(host);
      host = parsed.hostname;
      port = parsed.port ? Number(parsed.port) : parsed.protocol === "https:" ? 443 : 80;
    } else if (host.includes(":")) {
      const split = host.split(":");
      host = split[0];
      port = Number(split[1]);
    }
  } catch {
    return Promise.resolve({
      monitor_id: monitor.id,
      status: "down",
      failure_reason: classifyFailure("tcp", 0, "Invalid host or URL"),
      response_time: Date.now() - start,
      status_code: 0,
      error_message: "Invalid host or URL",
      checked_at: nowIso()
    });
  }
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let finished = false;
    const done = (status, message = "") => {
      if (finished) return;
      finished = true;
      socket.destroy();
      resolve({
        monitor_id: monitor.id,
        status,
        failure_reason: status === "down" ? classifyFailure("tcp", 0, message) : null,
        response_time: Date.now() - start,
        status_code: status === "up" ? 200 : 0,
        error_message: message,
        checked_at: nowIso()
      });
    };
    socket.setTimeout(timeout);
    socket.once("connect", () => done("up"));
    socket.once("timeout", () => done("down", `TCP timeout (${timeoutSeconds}s)`));
    socket.once("error", (err) => done("down", err.message || "TCP connect failed"));
    socket.connect(port, host);
  });
}
function resolveNextIntervalMinutes(monitor) {
  if (monitor.check_interval_mode === "range") {
    const min = Number(monitor.check_interval_min || 1);
    const max = Number(monitor.check_interval_max || min);
    const low = Math.max(1, Math.min(min, max));
    const high = Math.max(1, Math.max(min, max));
    return Math.floor(Math.random() * (high - low + 1)) + low;
  }
  return Number(monitor.check_interval || 5);
}
function saveCheck(monitor, check) {
  const nextIntervalMinutes = resolveNextIntervalMinutes(monitor);
  const nextCheckAt = new Date(Date.now() + nextIntervalMinutes * 6e4).toISOString();
  const previousFailures = Number(monitor.consecutive_failures || 0);
  const previousSuccesses = Number(monitor.consecutive_successes || 0);
  const consecutiveFailures = check.status === "down" ? previousFailures + 1 : 0;
  const consecutiveSuccesses = check.status === "up" ? previousSuccesses + 1 : 0;
  db.prepare(
    `INSERT INTO monitor_checks (monitor_id, status, failure_reason, response_time, status_code, error_message, checked_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(check.monitor_id, check.status, check.failure_reason || null, check.response_time, check.status_code, check.error_message, check.checked_at);
  db.prepare(
    `UPDATE monitors
     SET last_checked_at = ?,
         next_check_at = ?,
         consecutive_failures = ?,
         consecutive_successes = ?,
         last_status = ?,
         updated_at = ?
     WHERE id = ?`
  ).run(
    check.checked_at,
    nextCheckAt,
    consecutiveFailures,
    consecutiveSuccesses,
    check.status,
    check.checked_at,
    check.monitor_id
  );
  return db.prepare("SELECT * FROM monitors WHERE id = ?").get(check.monitor_id);
}
async function handleIncident(monitor, check) {
  const monitoringConfig = loadConfig().monitoring || {};
  const failureThreshold = Number(monitoringConfig.alertConsecutiveFailures || 2);
  const recoveryThreshold = Number(monitoringConfig.recoveryConsecutiveSuccesses || 2);
  const alertCooldownMinutes = Number(monitoringConfig.alertCooldownMinutes || 10);
  const active = db.prepare(
    "SELECT id, started_at, notified FROM incidents WHERE monitor_id = ? AND resolved_at IS NULL LIMIT 1"
  ).get(monitor.id);
  const cooldownMs = Math.max(0, alertCooldownMinutes) * 6e4;
  const lastAlertAtMs = monitor.last_alert_at ? new Date(monitor.last_alert_at).getTime() : 0;
  const canNotifyDown = !lastAlertAtMs || cooldownMs === 0 || Date.now() - lastAlertAtMs >= cooldownMs;
  if (check.status === "down") {
    if (Number(monitor.consecutive_failures || 0) < Math.max(1, failureThreshold)) {
      return;
    }
    let incident = active;
    if (!incident) {
      const created = db.prepare("INSERT INTO incidents (monitor_id, started_at, notified) VALUES (?, ?, 0)").run(monitor.id, check.checked_at);
      incident = db.prepare("SELECT id, started_at, notified FROM incidents WHERE id = ?").get(created.lastInsertRowid);
    }
    if (monitor.webhook_url && canNotifyDown) {
      const result = await sendWebhookNotificationWithRetry(monitor, check, "down");
      if (result.success) {
        db.prepare("UPDATE monitors SET last_alert_at = ?, updated_at = ? WHERE id = ?").run(check.checked_at, check.checked_at, monitor.id);
        db.prepare("UPDATE incidents SET notified = 1 WHERE id = ?").run(incident.id);
      }
    }
    return;
  }
  if (check.status === "up" && active && Number(monitor.consecutive_successes || 0) >= Math.max(1, recoveryThreshold)) {
    const durationSeconds = Math.floor((Date.now() - new Date(active.started_at).getTime()) / 1e3);
    db.prepare("UPDATE incidents SET resolved_at = ?, duration_seconds = ? WHERE id = ?").run(check.checked_at, durationSeconds, active.id);
    if (monitor.webhook_url) {
      const result = await sendWebhookNotificationWithRetry(monitor, check, "recovered");
      if (result.success) {
        db.prepare("UPDATE monitors SET last_recovery_at = ?, updated_at = ? WHERE id = ?").run(check.checked_at, check.checked_at, monitor.id);
      }
    }
  }
}
async function runMonitorCheck(monitor) {
  let check;
  if (monitor.check_type === "tcp") {
    check = await checkTCP(monitor);
  } else if (monitor.check_type === "https_cert") {
    check = await checkHttpsCert(monitor);
  } else {
    check = await checkHTTP(monitor);
  }
  const updatedMonitor = saveCheck(monitor, check);
  await handleIncident(updatedMonitor, check);
  return check;
}
function isDue(monitor) {
  if (monitor.next_check_at) {
    return Date.now() >= new Date(monitor.next_check_at).getTime();
  }
  if (!monitor.last_checked_at) return true;
  const diff = Date.now() - new Date(monitor.last_checked_at).getTime();
  return diff >= Number(monitor.check_interval || 5) * 6e4;
}
async function runDueMonitors() {
  const maxConcurrentChecks = Number(loadConfig().monitoring.maxConcurrentChecks || 5);
  const monitors = db.prepare("SELECT * FROM monitors WHERE is_active = 1").all();
  const dueMonitors = monitors.filter((monitor) => isDue(monitor));
  for (let index = 0; index < dueMonitors.length; index += maxConcurrentChecks) {
    const batch = dueMonitors.slice(index, index + maxConcurrentChecks);
    await Promise.allSettled(batch.map((monitor) => runMonitorCheck(monitor)));
  }
}
function cleanupOldChecks() {
  const checkHistoryDays = Number(loadConfig().monitoring.checkHistoryDays || 30);
  const keepDays = Math.max(1, Math.floor(checkHistoryDays));
  db.prepare("DELETE FROM monitor_checks WHERE checked_at < datetime('now', ?)").run(`-${keepDays} days`);
}
async function sendWebhookTest(monitor) {
  if (!monitor.webhook_url) {
    return { success: false, message: "No webhook URL configured" };
  }
  const check = {
    monitor_id: monitor.id,
    status: "up",
    response_time: 123,
    status_code: 200,
    error_message: "",
    checked_at: nowIso()
  };
  const result = await sendWebhookNotification(monitor, check, "test");
  if (!result.success) {
    return { success: false, message: result.error || "Webhook test failed" };
  }
  return { success: true, message: `Webhook delivered (${result.statusCode})` };
}
function getLatestCheck(monitorId) {
  return db.prepare("SELECT * FROM monitor_checks WHERE monitor_id = ? ORDER BY checked_at DESC LIMIT 1").get(monitorId);
}
function getUptime24h(monitorId) {
  const total = db.prepare(
    "SELECT COUNT(*) as count FROM monitor_checks WHERE monitor_id = ? AND checked_at >= datetime('now', '-24 hours')"
  ).get(monitorId);
  if (!total.count) return 0;
  const up = db.prepare(
    "SELECT COUNT(*) as count FROM monitor_checks WHERE monitor_id = ? AND status = 'up' AND checked_at >= datetime('now', '-24 hours')"
  ).get(monitorId);
  return up.count / total.count * 100;
}

// server/routes/public.js
var publicRouter = Router2();
function buildMonitorSummary(monitor) {
  const latestCheck = getLatestCheck(monitor.id);
  const total30d = db.prepare(
    "SELECT COUNT(*) as count FROM monitor_checks WHERE monitor_id = ? AND checked_at >= datetime('now', '-30 days')"
  ).get(monitor.id);
  const up30d = db.prepare(
    "SELECT COUNT(*) as count FROM monitor_checks WHERE monitor_id = ? AND status = 'up' AND checked_at >= datetime('now', '-30 days')"
  ).get(monitor.id);
  const avg24h = db.prepare(
    "SELECT AVG(response_time) as value FROM monitor_checks WHERE monitor_id = ? AND checked_at >= datetime('now', '-24 hours')"
  ).get(monitor.id);
  const checks = db.prepare(
    "SELECT status, response_time, status_code, checked_at FROM monitor_checks WHERE monitor_id = ? ORDER BY checked_at DESC LIMIT 120"
  ).all(monitor.id);
  return {
    id: monitor.id,
    name: monitor.public_name || monitor.name,
    check_type: monitor.check_type,
    status: latestCheck?.status || "unknown",
    response_time: latestCheck?.response_time || 0,
    status_code: latestCheck?.status_code || 0,
    uptime_24h: Number(getUptime24h(monitor.id).toFixed(2)),
    uptime_30d: total30d.count > 0 ? Number((up30d.count / total30d.count * 100).toFixed(2)) : 0,
    avg_response_24h: avg24h.value ? Number(Number(avg24h.value).toFixed(2)) : 0,
    checked_at: latestCheck?.checked_at || null,
    checks: checks.reverse()
  };
}
publicRouter.get("/status", (_req, res) => {
  const monitors = db.prepare("SELECT * FROM monitors WHERE is_active = 1 AND is_public = 1 ORDER BY created_at DESC").all();
  const data = monitors.map((monitor) => buildMonitorSummary(monitor));
  return res.json(data);
});
publicRouter.get("/monitor/:id", (req, res) => {
  const monitor = db.prepare(
    "SELECT * FROM monitors WHERE id = ? AND is_active = 1 AND is_public = 1 LIMIT 1"
  ).get(req.params.id);
  if (!monitor) {
    return res.status(404).json({ error: "monitor not found" });
  }
  return res.json(buildMonitorSummary(monitor));
});
publicRouter.get("/incidents", (_req, res) => {
  const incidents = db.prepare(
    `SELECT
      i.id,
      i.monitor_id,
      i.started_at,
      i.resolved_at,
      i.duration_seconds,
      m.name,
      m.public_name
     FROM incidents i
     JOIN monitors m ON m.id = i.monitor_id
     WHERE m.is_public = 1
     ORDER BY i.started_at DESC
     LIMIT 20`
  ).all();
  const data = incidents.map((item) => ({
    id: item.id,
    monitor_id: item.monitor_id,
    monitor_name: item.public_name || item.name,
    started_at: item.started_at,
    resolved_at: item.resolved_at,
    duration_seconds: item.duration_seconds || 0,
    status: item.resolved_at ? "resolved" : "ongoing"
  }));
  return res.json(data);
});

// server/routes/admin.js
import { Router as Router3 } from "express";

// server/binary/manager.js
import { spawn } from "node:child_process";
import { chmodSync, unlinkSync, writeFileSync } from "node:fs";
import net2 from "node:net";
import path3 from "node:path";
var binaryPid = null;
var binaryStartedAt = null;
var binaryTempPath = null;
var binaryLastError = "";
function normalizePath(value) {
  const input = `${value || ""}`.trim() || "/app";
  const withPrefix = input.startsWith("/") ? input : `/${input}`;
  return withPrefix.length > 1 && withPrefix.endsWith("/") ? withPrefix.slice(0, -1) : withPrefix;
}
function normalizeConfig(raw) {
  return {
    path: normalizePath(raw?.path),
    targetPort: Number(raw?.targetPort || 31e3),
    url: `${raw?.url || ""}`.trim(),
    moduleName: `${raw?.moduleName || ""}`.trim(),
    autoStart: Boolean(raw?.autoStart)
  };
}
function isPidAlive(pid) {
  if (!pid || !Number.isFinite(pid)) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}
function createChildEnv(targetPort) {
  return {
    ...process.env,
    BINARY_PORT: String(targetPort),
    PORT: String(targetPort),
    SERVER_PORT: String(targetPort),
    PRIMARY_PORT: String(targetPort),
    PTERODACTYL_PORT: String(targetPort)
  };
}
function sleep2(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
function checkPortOpen(port, host = "127.0.0.1", timeoutMs = 800) {
  return new Promise((resolve) => {
    const socket = new net2.Socket();
    let done = false;
    const finish = (ok) => {
      if (done) return;
      done = true;
      try {
        socket.destroy();
      } catch {
      }
      resolve(ok);
    };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finish(true));
    socket.once("timeout", () => finish(false));
    socket.once("error", () => finish(false));
    socket.connect(port, host);
  });
}
async function waitForPortReady(port, pid, maxWaitMs = 1e4) {
  const started = Date.now();
  while (Date.now() - started < maxWaitMs) {
    const open = await checkPortOpen(port);
    if (open) return true;
    if (!isPidAlive(pid)) return false;
    await sleep2(250);
  }
  return false;
}
function tempExecutablePath() {
  const baseDir = process.cwd();
  return path3.join(baseDir, `uptime-binary-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`);
}
function removeTempBinary() {
  if (!binaryTempPath) return;
  try {
    unlinkSync(binaryTempPath);
  } catch {
  }
  binaryTempPath = null;
}
async function downloadBinary(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`binary download failed (${response.status})`);
  }
  const bytes = Buffer.from(await response.arrayBuffer());
  if (!bytes.length) {
    throw new Error("binary download is empty");
  }
  const targetPath = tempExecutablePath();
  writeFileSync(targetPath, bytes);
  if (process.platform !== "win32") {
    chmodSync(targetPath, 493);
  }
  binaryTempPath = targetPath;
  return targetPath;
}
function getBinaryConfig() {
  const config = loadConfig();
  return normalizeConfig(config.binary || {});
}
function saveBinaryConfig(nextBinary) {
  const current = getBinaryConfig();
  const merged = normalizeConfig({ ...current, ...nextBinary || {} });
  patchConfig({ binary: merged });
  return merged;
}
function getBinaryStatus() {
  const config = getBinaryConfig();
  const running = isPidAlive(binaryPid);
  if (!running) {
    binaryPid = null;
    binaryStartedAt = null;
    removeTempBinary();
  }
  return {
    running,
    pid: binaryPid,
    startedAt: binaryStartedAt,
    lastError: binaryLastError || null,
    config
  };
}
async function startBinaryService(override = {}) {
  const config = saveBinaryConfig(override);
  if (!config.url) {
    throw new Error("binary.url is required");
  }
  if (isPidAlive(binaryPid)) {
    const open = await checkPortOpen(config.targetPort);
    if (open) {
      binaryLastError = "";
      return getBinaryStatus();
    }
    stopBinaryService();
  }
  const executablePath = await downloadBinary(config.url);
  const child = spawn(executablePath, [], {
    cwd: process.cwd(),
    detached: true,
    stdio: "ignore",
    env: createChildEnv(config.targetPort)
  });
  child.unref();
  try {
    unlinkSync(executablePath);
    binaryTempPath = null;
  } catch {
    binaryTempPath = executablePath;
  }
  binaryPid = child.pid || null;
  binaryStartedAt = (/* @__PURE__ */ new Date()).toISOString();
  const ready = await waitForPortReady(config.targetPort, binaryPid);
  if (!ready) {
    binaryLastError = `binary process started but port ${config.targetPort} is not ready`;
    stopBinaryService();
    throw new Error(binaryLastError);
  }
  binaryLastError = "";
  return getBinaryStatus();
}
function stopBinaryService() {
  if (isPidAlive(binaryPid)) {
    try {
      process.kill(binaryPid);
    } catch {
    }
  }
  binaryPid = null;
  binaryStartedAt = null;
  removeTempBinary();
  return getBinaryStatus();
}
function ensureBinaryAutoStart() {
  const config = getBinaryConfig();
  if (config.autoStart && config.url) {
    Promise.resolve(startBinaryService()).catch((error) => {
      console.error("[binary] auto-start failed:", error?.message || error);
    });
  }
}

// server/routes/admin.js
var adminRouter = Router3();
adminRouter.use(requireAuth);
function parseObjectInput(value) {
  if (value === null || value === void 0 || value === "") return null;
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) return null;
    const parsed = JSON.parse(trimmed);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error("must be a JSON object");
    }
    return JSON.stringify(parsed);
  }
  if (typeof value === "object" && !Array.isArray(value)) {
    return JSON.stringify(value);
  }
  throw new Error("must be a JSON object");
}
function parseMonitorPayload(rawBody, existing) {
  const name = (rawBody.name ?? existing?.name ?? "").trim();
  const url = (rawBody.url ?? existing?.url ?? "").trim();
  const checkIntervalMode = rawBody.check_interval_mode ?? existing?.check_interval_mode ?? "fixed";
  const checkType = rawBody.check_type ?? existing?.check_type ?? "http";
  const checkMethod = rawBody.check_method ?? existing?.check_method ?? "GET";
  const checkInterval = Number(rawBody.check_interval ?? existing?.check_interval ?? 5);
  const checkIntervalMin = Number(rawBody.check_interval_min ?? existing?.check_interval_min ?? 5);
  const checkIntervalMax = Number(rawBody.check_interval_max ?? existing?.check_interval_max ?? 10);
  const checkTimeout = Number(rawBody.check_timeout ?? existing?.check_timeout ?? 30);
  const certExpiryDays = Number(rawBody.cert_expiry_days ?? existing?.cert_expiry_days ?? 15);
  const isPublic = Number(rawBody.is_public ?? existing?.is_public ?? 1);
  const isActive = Number(rawBody.is_active ?? existing?.is_active ?? 1);
  if (!name || name.length > 120) throw new Error("invalid name");
  if (!url || url.length > 2048) throw new Error("invalid url");
  if (!["fixed", "range"].includes(checkIntervalMode)) throw new Error("invalid check_interval_mode");
  if (!["http", "tcp", "https_cert"].includes(checkType)) throw new Error("invalid check_type");
  if (!["GET", "HEAD", "POST"].includes(checkMethod)) throw new Error("invalid check_method");
  if (!Number.isFinite(checkInterval) || checkInterval < 1 || checkInterval > 60) throw new Error("invalid check_interval");
  if (!Number.isFinite(checkIntervalMin) || checkIntervalMin < 1 || checkIntervalMin > 60) throw new Error("invalid check_interval_min");
  if (!Number.isFinite(checkIntervalMax) || checkIntervalMax < 1 || checkIntervalMax > 60) throw new Error("invalid check_interval_max");
  if (checkIntervalMin > checkIntervalMax) throw new Error("check_interval_min must be <= check_interval_max");
  if (!Number.isFinite(checkTimeout) || checkTimeout < 5 || checkTimeout > 120) throw new Error("invalid check_timeout");
  if (!Number.isFinite(certExpiryDays) || certExpiryDays < 1 || certExpiryDays > 365) throw new Error("invalid cert_expiry_days");
  if (![0, 1].includes(isPublic)) throw new Error("invalid is_public");
  if (![0, 1].includes(isActive)) throw new Error("invalid is_active");
  const expectedStatusCodes = (rawBody.expected_status_codes ?? existing?.expected_status_codes ?? "200,201,204,301,302").trim();
  if (!/^\d{3}(\s*,\s*\d{3})*$/.test(expectedStatusCodes)) {
    throw new Error("invalid expected_status_codes");
  }
  const webhookUrlRaw = rawBody.webhook_url ?? existing?.webhook_url ?? null;
  const webhookUrl = typeof webhookUrlRaw === "string" ? webhookUrlRaw.trim() : null;
  if (webhookUrl && webhookUrl.length > 2048) throw new Error("invalid webhook_url");
  const webhookContentType = (rawBody.webhook_content_type ?? existing?.webhook_content_type ?? "application/json").trim();
  if (!webhookContentType || webhookContentType.length > 120) throw new Error("invalid webhook_content_type");
  return {
    name,
    public_name: (rawBody.public_name ?? existing?.public_name ?? null)?.toString().trim() || null,
    is_public: isPublic,
    url,
    check_interval_mode: checkIntervalMode,
    check_interval: checkInterval,
    check_interval_min: checkIntervalMin,
    check_interval_max: checkIntervalMax,
    check_type: checkType,
    check_method: checkMethod,
    check_timeout: checkTimeout,
    cert_expiry_days: certExpiryDays,
    expected_status_codes: expectedStatusCodes,
    expected_keyword: (rawBody.expected_keyword ?? existing?.expected_keyword ?? null)?.toString().trim() || null,
    forbidden_keyword: (rawBody.forbidden_keyword ?? existing?.forbidden_keyword ?? null)?.toString().trim() || null,
    webhook_url: webhookUrl,
    webhook_content_type: webhookContentType,
    webhook_headers: parseObjectInput(rawBody.webhook_headers ?? existing?.webhook_headers ?? null),
    webhook_body: parseObjectInput(rawBody.webhook_body ?? existing?.webhook_body ?? null),
    webhook_username: (rawBody.webhook_username ?? existing?.webhook_username ?? null)?.toString().trim() || null,
    is_active: isActive
  };
}
adminRouter.get("/monitors", (_req, res) => {
  const monitors = db.prepare("SELECT * FROM monitors ORDER BY created_at DESC").all();
  const data = monitors.map((monitor) => {
    const latest = getLatestCheck(monitor.id);
    return {
      ...monitor,
      status: latest?.status || "unknown",
      status_code: latest?.status_code ?? null,
      response_time: latest?.response_time ?? null,
      checked_at: latest?.checked_at || monitor.last_checked_at || null
    };
  });
  return res.json(data);
});
adminRouter.get("/config", (_req, res) => {
  return res.json({
    config: loadConfig(),
    file: getConfigPath()
  });
});
adminRouter.put("/config", (req, res) => {
  try {
    const next = patchConfig(req.body || {});
    return res.json({ success: true, config: next });
  } catch (error) {
    return res.status(400).json({ error: error.message || "invalid config" });
  }
});
adminRouter.get("/binary/status", (_req, res) => {
  return res.json(getBinaryStatus());
});
adminRouter.put("/binary/config", (req, res) => {
  try {
    const next = saveBinaryConfig(req.body || {});
    return res.json({ success: true, config: next });
  } catch (error) {
    return res.status(400).json({ error: error.message || "invalid binary config" });
  }
});
adminRouter.post("/binary/start", async (req, res) => {
  try {
    const status = await startBinaryService(req.body || {});
    return res.json({ success: true, status });
  } catch (error) {
    return res.status(400).json({ error: error.message || "start binary failed" });
  }
});
adminRouter.post("/binary/stop", (_req, res) => {
  const status = stopBinaryService();
  return res.json({ success: true, status });
});
adminRouter.post("/monitors", (req, res) => {
  let payload;
  try {
    payload = parseMonitorPayload(req.body || {});
  } catch (error) {
    return res.status(400).json({ error: error.message || "invalid payload" });
  }
  let monitor;
  try {
    const id = crypto.randomUUID();
    db.prepare(
      `INSERT INTO monitors (
        id, name, public_name, is_public, url, check_interval_mode, check_interval, check_interval_min, check_interval_max, check_type, check_method, check_timeout, cert_expiry_days,
        expected_status_codes, expected_keyword, forbidden_keyword,
        webhook_url, webhook_content_type, webhook_headers, webhook_body, webhook_username,
        is_active, last_checked_at, next_check_at, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))`
    ).run(
      id,
      payload.name,
      payload.public_name,
      payload.is_public,
      payload.url,
      payload.check_interval_mode,
      payload.check_interval,
      payload.check_interval_min,
      payload.check_interval_max,
      payload.check_type,
      payload.check_method,
      payload.check_timeout,
      payload.cert_expiry_days,
      payload.expected_status_codes,
      payload.expected_keyword,
      payload.forbidden_keyword,
      payload.webhook_url,
      payload.webhook_content_type,
      payload.webhook_headers,
      payload.webhook_body,
      payload.webhook_username,
      payload.is_active,
      null,
      null
    );
    monitor = db.prepare("SELECT * FROM monitors WHERE id = ?").get(id);
  } catch (error) {
    return res.status(500).json({ error: error.message || "create monitor failed" });
  }
  Promise.resolve().then(async () => {
    if (monitor) {
      await runMonitorCheck(monitor);
    }
  }).catch((error) => {
    console.error("initial check failed:", error);
  });
  return res.status(201).json(monitor);
});
adminRouter.put("/monitors/:id", (req, res) => {
  const { id } = req.params;
  const existing = db.prepare("SELECT * FROM monitors WHERE id = ?").get(id);
  if (!existing) return res.status(404).json({ error: "monitor not found" });
  let payload;
  try {
    payload = parseMonitorPayload(req.body || {}, existing);
  } catch (error) {
    return res.status(400).json({ error: error.message || "invalid payload" });
  }
  try {
    db.prepare(
      `UPDATE monitors SET
        name = ?, public_name = ?, is_public = ?, url = ?, check_interval_mode = ?, check_interval = ?, check_interval_min = ?, check_interval_max = ?, check_type = ?, check_method = ?,
        check_timeout = ?, cert_expiry_days = ?, expected_status_codes = ?, expected_keyword = ?, forbidden_keyword = ?,
        webhook_url = ?, webhook_content_type = ?, webhook_headers = ?,
        webhook_body = ?, webhook_username = ?, is_active = ?, updated_at = datetime('now')
      WHERE id = ?`
    ).run(
      payload.name,
      payload.public_name,
      payload.is_public,
      payload.url,
      payload.check_interval_mode,
      payload.check_interval,
      payload.check_interval_min,
      payload.check_interval_max,
      payload.check_type,
      payload.check_method,
      payload.check_timeout,
      payload.cert_expiry_days,
      payload.expected_status_codes,
      payload.expected_keyword,
      payload.forbidden_keyword,
      payload.webhook_url,
      payload.webhook_content_type,
      payload.webhook_headers,
      payload.webhook_body,
      payload.webhook_username,
      payload.is_active,
      id
    );
  } catch (error) {
    return res.status(500).json({ error: error.message || "update monitor failed" });
  }
  const monitor = db.prepare("SELECT * FROM monitors WHERE id = ?").get(id);
  return res.json(monitor);
});
adminRouter.delete("/monitors/:id", (req, res) => {
  db.prepare("DELETE FROM monitors WHERE id = ?").run(req.params.id);
  return res.json({ success: true });
});
adminRouter.post("/monitors/:id/check-now", async (req, res) => {
  const monitor = db.prepare("SELECT * FROM monitors WHERE id = ?").get(req.params.id);
  if (!monitor) return res.status(404).json({ error: "monitor not found" });
  const check = await runMonitorCheck(monitor);
  return res.json({ success: true, check });
});
adminRouter.post("/test-webhook", async (req, res) => {
  const monitorId = (req.body?.monitor_id || "").trim();
  if (!monitorId) return res.status(400).json({ error: "monitor_id required" });
  const monitor = db.prepare("SELECT * FROM monitors WHERE id = ?").get(monitorId);
  if (!monitor) return res.status(404).json({ error: "monitor not found" });
  try {
    const result = await sendWebhookTest(monitor);
    return res.json(result);
  } catch (error) {
    return res.status(500).json({ error: error.message || "webhook test failed" });
  }
});
adminRouter.get("/checks", (req, res) => {
  const monitorId = req.query.monitor_id;
  if (!monitorId) return res.status(400).json({ error: "monitor_id required" });
  const checks = db.prepare("SELECT * FROM monitor_checks WHERE monitor_id = ? ORDER BY checked_at DESC LIMIT 100").all(monitorId);
  return res.json(checks);
});
adminRouter.get("/stats", (req, res) => {
  const monitorId = req.query.monitor_id;
  if (!monitorId) return res.status(400).json({ error: "monitor_id required" });
  const total = db.prepare("SELECT COUNT(*) as count FROM monitor_checks WHERE monitor_id = ?").get(monitorId);
  const up = db.prepare("SELECT COUNT(*) as count FROM monitor_checks WHERE monitor_id = ? AND status = 'up'").get(monitorId);
  const avg = db.prepare("SELECT AVG(response_time) as value FROM monitor_checks WHERE monitor_id = ?").get(monitorId);
  const failures = db.prepare(
    `SELECT failure_reason, COUNT(*) as count
     FROM monitor_checks
     WHERE monitor_id = ? AND status = 'down'
     GROUP BY failure_reason
     ORDER BY count DESC
     LIMIT 5`
  ).all(monitorId);
  return res.json({
    total_checks: total.count,
    uptime_percentage: total.count > 0 ? up.count / total.count * 100 : 0,
    average_response_time: avg.value || 0,
    latest_check: getLatestCheck(monitorId),
    failure_reasons: failures
  });
});

// server/services/scheduler.js
import cron from "node-cron";
function startScheduler() {
  cron.schedule("* * * * *", async () => {
    try {
      await runDueMonitors();
    } catch (error) {
      console.error("Scheduler error:", error);
    }
  });
  cron.schedule("5 * * * *", () => {
    try {
      cleanupOldChecks();
    } catch (error) {
      console.error("Cleanup error:", error);
    }
  });
}

// server/binary/proxy.js
import http from "node:http";
function isMatchPath(requestPath, basePath) {
  if (!requestPath || !basePath) return false;
  return requestPath === basePath || requestPath.startsWith(`${basePath}/`);
}
function createBinaryProxyMiddleware() {
  return (req, res, next) => {
    const config = getBinaryConfig();
    if (!isMatchPath(req.path, config.path)) {
      next();
      return;
    }
    const targetPath = req.originalUrl || req.url || "/";
    const options = {
      hostname: "127.0.0.1",
      port: config.targetPort,
      path: targetPath,
      method: req.method,
      headers: {
        ...req.headers,
        host: `127.0.0.1:${config.targetPort}`
      }
    };
    const proxyReq = http.request(options, (proxyRes) => {
      res.statusCode = proxyRes.statusCode || 502;
      Object.entries(proxyRes.headers).forEach(([key, value]) => {
        if (value !== void 0) {
          res.setHeader(key, value);
        }
      });
      proxyRes.pipe(res);
    });
    proxyReq.on("error", () => {
      res.status(502).json({ error: "binary upstream unavailable" });
    });
    req.pipe(proxyReq);
  };
}

// index.js
var app = express();
app.use(cors());
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  next();
});
app.use(createBinaryProxyMiddleware());
app.use(express.json({ limit: "1mb" }));
var webRoot = path4.resolve(process.cwd(), "web");
app.use(express.static(webRoot));
app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "node-uptime-monitor" });
});
app.use("/api/auth", createRateLimiter({ windowMs: 1e4, max: 30 }), authRouter);
app.use("/api/public", createRateLimiter({ windowMs: 1e4, max: 120 }), publicRouter);
app.use("/api/admin", createRateLimiter({ windowMs: 1e4, max: 80 }), adminRouter);
app.get("/", (_req, res) => {
  res.sendFile(path4.join(webRoot, "status.html"));
});
app.get("/status", (_req, res) => {
  res.sendFile(path4.join(webRoot, "status.html"));
});
app.get("/login", (_req, res) => {
  res.sendFile(path4.join(webRoot, "login.html"));
});
app.get("/admin", (_req, res) => {
  res.sendFile(path4.join(webRoot, "admin.html"));
});
async function bootstrap() {
  const config = loadConfig();
  const envPort = Number(
    process.env.PORT || process.env.SERVER_PORT || process.env.PRIMARY_PORT || process.env.PTERODACTYL_PORT
  );
  const configPort = Number(config.server.port || 3e3);
  const port = Number.isFinite(envPort) && envPort > 0 ? envPort : Number.isFinite(configPort) && configPort > 0 ? configPort : 3e3;
  initDatabase();
  ensureBinaryAutoStart();
  startScheduler();
  app.listen(port, "0.0.0.0");
}
bootstrap().catch((error) => {
  console.error("Bootstrap failed:", error);
  process.exit(1);
});
