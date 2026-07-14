import "dotenv/config";
import express from "express";
import cors from "cors";
import compression from "compression";
import { initDatabase } from "../src/db/database";
import authRoutes from "../src/routes/auth";
import syncRoutes from "../src/routes/sync";
import ocrRoutes from "../src/routes/ocr";
import resetRoutes from "../src/routes/reset";
import verifyRouter from "../src/routes/verify";
import subscriptionRouter from "../src/routes/subscription";
import { authRequired } from "../src/middleware/auth";
import ocrProxyRouter from "../src/routes/ocrProxy";
import inviteRoutes from "../src/routes/invite";
import secretaryAccountRoutes from "../src/routes/secretaryAccounts";
import cabinetRoutes from "../src/routes/cabinet";
import medicationRoutes from "../src/routes/medications";
import bookingRoutes from "../src/routes/booking";
import smsRoutes from "../src/routes/sms";
import pushRoutes from "../src/routes/push";
import adminRoutes from "../src/routes/admin";
import eventsRoutes from "../src/routes/events";
import accountRoutes from "../src/routes/account";
import { rateLimit } from "../src/middleware/rateLimit";
import { isCipherActive } from "../src/crypto/dataCipher";

// Give the platform a function timeout ABOVE the code's own 25s request deadline
// (REQUEST_DEADLINE_MS below), so our graceful 503 fires first instead of the
// platform killing the invocation at its ~10-15s default (leaving the client with
// a bare 504). Read by @vercel/node at build time. (vercel.json can't use the
// `functions` key here because it already uses `builds`.)
export const maxDuration = 30;

const app = express();

// Security headers on every response (helmet-equivalent, hand-rolled to avoid a
// dependency for a JSON-only API). The API never returns rendered HTML to a
// browser context, so a strict CSP + frame denial + nosniff are safe and close
// the "no security headers" gap without touching CORS (handled below).
app.use((_req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-DNS-Prefetch-Control", "off");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
  res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
  next();
});

// gzip/brotli every response big enough to matter. The sync pulls are large
// JSON payloads, so this is a major cut in Fast Origin Transfer (bytes served
// out of the function) — the metric that got the project disabled.
app.use(compression());
// exposedHeaders: the web app is a different origin, so the browser only lets
// JS read the ETag (needed for conditional sync pulls) if we expose it.
// maxAge: Bearer auth forces a CORS preflight OPTIONS before every API call;
// caching it (browsers cap ~2–24h) removes that second request+invocation on
// every poll/push — a large cut to Edge Requests and Function Invocations.
// Lock CORS to the app's own origins. Auth is a Bearer token (a stolen token
// works from anywhere regardless), but this stops a hostile website from
// scripting the API inside a logged-in user's browser. Requests with NO Origin
// header — the native mobile app, server-to-server, curl — are allowed, since
// CORS is a browser-only control and those clients aren't subject to it.
const ALLOWED_ORIGINS = new Set([
  "https://www.blackpinecap.com",
  "https://blackpinecap.com",
]);
app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);                                   // native app / server-to-server
    if (ALLOWED_ORIGINS.has(origin)) return cb(null, true);               // production web
    if (/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) return cb(null, true); // local dev
    if (/^https:\/\/blackpine-[a-z0-9-]+-hamza-derkaouis-projects\.vercel\.app$/.test(origin)) return cb(null, true); // Vercel previews
    return cb(null, false);                                               // unknown origin → no ACAO, browser blocks
  },
  exposedHeaders: ["ETag"],
  maxAge: 86400,
}));

// Every response here is per-user (keyed by the Bearer token, not the URL).
// Without this a browser or CDN could reuse ONE account's cached GET for a
// DIFFERENT account on the same machine — showing "another account's data".
// no-store defeats caching entirely; Vary: Authorization is belt-and-suspenders
// for any intermediary. Our conditional sync pulls still work: the client sends
// If-None-Match explicitly, so 304s are unaffected by no-store.
app.use((_req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Vary", "Authorization");
  next();
});
app.use(express.json({ limit: "20mb" }));

// Now keyed on the real client IP (see rateLimit). Limits are per-IP; a clinic
// behind one NAT shares an IP and the web client auto-retries, so keep /auth
// generous enough not to lock out a legitimate desk.
app.use("/auth", rateLimit(30, 15 * 60 * 1000), authRoutes);
app.use("/reset", rateLimit(8, 15 * 60 * 1000), resetRoutes);
app.use("/verify", rateLimit(10, 10 * 60 * 1000), verifyRouter);
app.use("/subscription", rateLimit(10, 15 * 60 * 1000), subscriptionRouter);
// OCR relay uses the owner's paid OCR key → require auth + rate-limit so it can't
// be used as an open, uncapped proxy that burns the key. (Mobile already sends
// the Bearer token; the web uses the authenticated /ocr route.)
app.use("/ocr-proxy", rateLimit(20, 15 * 60 * 1000), authRequired, ocrProxyRouter);

app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "blackpine-backend", encryption: isCipherActive() });
});

app.use("/sync", authRequired, syncRoutes);
app.use("/ocr", authRequired, ocrRoutes);
app.use("/invite", rateLimit(10, 15 * 60 * 1000), inviteRoutes);
app.use("/secretary-accounts", rateLimit(20, 15 * 60 * 1000), secretaryAccountRoutes);
app.use("/cabinet", cabinetRoutes);
app.use("/medications", medicationRoutes);
// Public booking endpoints are unauthenticated → rate-limit per IP.
app.use("/booking", rateLimit(30, 15 * 60 * 1000), bookingRoutes);
// SMS reminder config (auth) + cron-protected daily sender.
app.use("/sms", rateLimit(60, 15 * 60 * 1000), smsRoutes);
// Push-token registration (auth).
app.use("/push", rateLimit(30, 15 * 60 * 1000), pushRoutes);
// Owner-only usage analytics.
app.use("/admin", rateLimit(60, 15 * 60 * 1000), adminRoutes);
// Behavioural analytics ingestion (auth).
app.use("/events", rateLimit(120, 15 * 60 * 1000), eventsRoutes);
// Self-service account + data deletion (auth, GDPR / Play requirement).
app.use("/account", rateLimit(10, 15 * 60 * 1000), authRequired, accountRoutes);

// De-duplicate initialization across concurrent cold-start requests: they all
// await the same promise instead of each running the full schema sweep. If init
// fails (transient Turso hiccup), reset so the next request can retry cleanly.
let initPromise: Promise<void> | null = null;

// Hard ceiling on how long a request will wait for the DB to come up. Without
// it, an unresponsive Turso makes initDatabase() hang until Vercel's 300s
// function timeout — so EVERY request (even /health and CORS preflights, which
// don't need the DB) 504s and the function's keep-warm pings pile up. The
// normal cold-start path is a single ~1s SELECT (schema_meta fast-path), so a
// generous timeout never trips in healthy operation.
const DB_INIT_TIMEOUT_MS = 15_000;

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("DB_INIT_TIMEOUT")), ms);
    p.then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); },
    );
  });
}

// Absolute ceiling on how long ANY request may run before we force a response.
// This is the ultimate backstop against a mid-request DB hang (a warm instance
// whose Turso connection dies after init has a route query with no init-gate to
// stop it): without this such a request rides Vercel's 300s function timeout and
// piles up invocations, turning a brief Turso blip into a full outage. Normal
// requests finish in well under a second, so this never trips in healthy
// operation. Kept above DB_INIT_TIMEOUT_MS so the clearer 503 wins on cold init.
const REQUEST_DEADLINE_MS = 25_000;

const handler = async (req: any, res: any) => {
  // Force a 503 if nothing has responded within the deadline, so no request can
  // hang to the 300s function ceiling. Cleared as soon as the response is sent.
  const deadline = setTimeout(() => {
    if (!res.headersSent) {
      console.error("[REQ] Deadline exceeded:", req.method, req.url);
      res.statusCode = 503;
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Retry-After", "5");
      res.end(JSON.stringify({ error: "request_timeout" }));
    }
  }, REQUEST_DEADLINE_MS);
  res.on("finish", () => clearTimeout(deadline));
  res.on("close", () => clearTimeout(deadline));

  // Health checks and CORS preflights must NEVER wait on the database: the
  // uptime monitor keeps the function warm, and the browser preflights every
  // authenticated call. Serve them straight from the app (cors + /health touch
  // no DB) so a slow/unavailable Turso can't take the whole API down.
  const url: string = req.url || "";
  if (req.method === "OPTIONS" || url === "/health" || url.startsWith("/health?")) {
    // Warm the DB connection in the BACKGROUND on health pings (the uptime
    // monitor hits /health every ~5 min). Once an instance has a live DB
    // connection, real requests on it skip the cold connect and are instant.
    // Fire-and-forget — never await — so /health stays fast and DB-independent.
    if (url.startsWith("/health") && !initPromise) {
      initPromise = initDatabase().catch(() => { initPromise = null; });
    }
    return app(req, res);
  }

  if (!initPromise) {
    initPromise = initDatabase().catch((err) => {
      initPromise = null; // allow a fresh attempt on the next request
      throw err;
    });
  }
  try {
    await withTimeout(initPromise, DB_INIT_TIMEOUT_MS);
  } catch (err: any) {
    // Fail fast with a clear 503 instead of hanging for 300s. The client's
    // retry (and the next request) will re-attempt once Turso responds again.
    if (err?.message === "DB_INIT_TIMEOUT") initPromise = null; // don't cache a hung attempt
    console.error("[INIT] Database unavailable:", err?.message || err);
    res.statusCode = 503;
    res.setHeader("Content-Type", "application/json");
    res.setHeader("Retry-After", "5");
    return res.end(JSON.stringify({ error: "database_unavailable" }));
  }
  return app(req, res);
};

export default handler;
