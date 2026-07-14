/**
 * Behavioural analytics ingestion.
 *
 *   POST /events            (doctor auth)     { events: [{ name }], platform? }
 *   POST /events/secretary  (secretary token) { events: [{ name }] }
 *
 * Only short, sanitized event NAMES are stored (e.g. "page:/agenda",
 * "action:create_rdv") — never any patient data. Best-effort; cheap.
 *
 * Secretary events are attributed to the OWNER doctor's user_id (so they count
 * toward that cabinet's activity) and tagged platform="mobile-secretary"; the
 * mobile client also prefixes their names (sec/…, sec_…) so the supervision
 * dashboard can tell secretary behaviour apart from the doctor's own.
 */
import { Router, Request, Response } from "express";
import { getDb } from "../db/database";
import { authRequired, JWT_SECRET } from "../middleware/auth";
import jwt from "jsonwebtoken";
import crypto from "crypto";

const router = Router();

const MAX_BATCH = 50;
const NAME_RE = /^[a-z0-9:_/.-]{1,80}$/i;

/** Validate + clamp the incoming event names. */
function sanitizeNames(body: any): string[] {
  const raw = Array.isArray(body?.events) ? body.events : [];
  return raw
    .map((e: any) => String(e?.name ?? "").trim())
    .filter((n: string) => NAME_RE.test(n))
    .slice(0, MAX_BATCH);
}

/** Country (ISO-2) of the request, from Vercel's geo header. Null off-Vercel. */
function reqCountry(req: Request): string | null {
  const c = String(req.headers["x-vercel-ip-country"] ?? "").trim().toUpperCase();
  return /^[A-Z]{2}$/.test(c) ? c : null;
}

/** Insert a batch of event rows for one user. */
async function storeEvents(userId: string, names: string[], platform: string, country: string | null): Promise<void> {
  const db = getDb();
  const now = new Date().toISOString();
  for (const name of names) {
    await db.execute({
      sql: "INSERT INTO analytics_events (id, user_id, name, platform, created_at, ip_country) VALUES (?, ?, ?, ?, ?, ?)",
      args: ["ev_" + crypto.randomBytes(8).toString("hex"), userId, name, platform, now, country],
    });
  }
  // Opportunistic retention prune (~2% of writes) so analytics_events can't grow
  // unbounded. 400 days keeps a full year of history (year-over-year usage) plus
  // slack. Best-effort — never blocks ingestion; the created_at index makes it cheap.
  if (Math.random() < 0.02) {
    const cutoff = new Date(Date.now() - 400 * 86400000).toISOString();
    db.execute({ sql: "DELETE FROM analytics_events WHERE created_at < ?", args: [cutoff] }).catch(() => { /* best-effort */ });
  }
}

// ── Doctor (and web) events ───────────────────────────────────────────────────
router.post("/", authRequired, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user.userId;
    const platform = String(req.body?.platform ?? "web").slice(0, 16);
    const names = sanitizeNames(req.body);
    if (names.length === 0) return res.json({ ok: true, stored: 0 });
    await storeEvents(userId, names, platform, reqCountry(req));
    return res.json({ ok: true, stored: names.length });
  } catch (err: any) {
    console.error("[EVENTS] ingest error:", err.message);
    return res.status(500).json({ error: "Erreur" });
  }
});

// ── Secretary events (attributed to the owner doctor) ─────────────────────────
router.post("/secretary", async (req: Request, res: Response) => {
  try {
    const header = req.headers.authorization;
    if (!header || !header.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Token manquant" });
    }
    let decoded: any;
    try {
      decoded = jwt.verify(header.slice(7), JWT_SECRET, { algorithms: ["HS256"] });
    } catch {
      return res.status(401).json({ error: "Token invalide ou expiré" });
    }
    if (decoded?.type !== "secretary" || !decoded?.ownerUserId) {
      return res.status(401).json({ error: "Token invalide" });
    }
    // Confirm the session is still active (mirrors cabinet secretaryAuthRequired).
    const db = getDb();
    const sess = await db.execute({
      sql: "SELECT revoked FROM secretary_sessions WHERE id = ?",
      args: [decoded.secretaryId],
    });
    if (sess.rows.length === 0 || (sess.rows[0].revoked as number) === 1) {
      return res.status(401).json({ error: "Accès révoqué" });
    }

    const names = sanitizeNames(req.body);
    if (names.length === 0) return res.json({ ok: true, stored: 0 });
    await storeEvents(decoded.ownerUserId, names, "mobile-secretary", reqCountry(req));
    return res.json({ ok: true, stored: names.length });
  } catch (err: any) {
    console.error("[EVENTS] secretary ingest error:", err.message);
    return res.status(500).json({ error: "Erreur" });
  }
});

export default router;
