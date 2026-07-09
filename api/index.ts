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

const app = express();

// gzip/brotli every response big enough to matter. The sync pulls are large
// JSON payloads, so this is a major cut in Fast Origin Transfer (bytes served
// out of the function) — the metric that got the project disabled.
app.use(compression());
// exposedHeaders: the web app is a different origin, so the browser only lets
// JS read the ETag (needed for conditional sync pulls) if we expose it.
app.use(cors({ exposedHeaders: ["ETag"] }));
app.use(express.json({ limit: "20mb" }));

app.use("/auth", rateLimit(10, 15 * 60 * 1000), authRoutes);
app.use("/reset", rateLimit(5, 15 * 60 * 1000), resetRoutes);
app.use("/verify", rateLimit(5, 10 * 60 * 1000), verifyRouter);
app.use("/subscription", rateLimit(10, 15 * 60 * 1000), subscriptionRouter);
app.use("/ocr-proxy", ocrProxyRouter);

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

const handler = async (req: any, res: any) => {
  if (!initPromise) {
    initPromise = initDatabase().catch((err) => {
      initPromise = null; // allow a fresh attempt on the next request
      throw err;
    });
  }
  await initPromise;
  return app(req, res);
};

export default handler;
