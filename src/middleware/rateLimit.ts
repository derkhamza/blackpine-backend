import { getDb } from "../db/database";

// Real client IP. On Vercel `req.ip` is the platform proxy address (the SAME for
// every user), so keying on it makes the limiter global. Vercel's edge sets the
// true client IP on `x-real-ip` / the left-most `x-forwarded-for`.
// We only accept an IP-shaped value: an attacker who can inject these headers
// could otherwise pass a unique random string per request and fragment the
// limiter into unlimited single-use buckets (defeating it entirely). Format
// validation caps that; per-account throttling (see hitLimit) is the real
// backstop for brute force, since it doesn't rely on IP at all.
function ipish(v: unknown): string | null {
  if (typeof v !== "string") return null;
  const ip = v.split(",")[0].trim();
  return /^[0-9a-fA-F:.]{3,45}$/.test(ip) ? ip : null;
}
function clientIp(req: any): string {
  return ipish(req.headers?.["x-real-ip"])
      ?? ipish(req.headers?.["x-forwarded-for"])
      ?? (typeof req.ip === "string" ? req.ip : null)
      ?? req.socket?.remoteAddress
      ?? "unknown";
}

// Imperative limiter for keying on something OTHER than the client IP — e.g. the
// target account — so a spoofable/rotated IP can't bypass a per-account cap.
// Returns true when the caller is now OVER the limit. Fails OPEN on a DB hiccup.
export async function hitLimit(bucketKey: string, maxAttempts: number, windowMs: number): Promise<boolean> {
  try {
    const nowIso  = new Date().toISOString();
    const resetAt = new Date(Date.now() + windowMs).toISOString();
    const r = await getDb().execute({
      sql: `INSERT INTO rate_limits (bucket, count, reset_at) VALUES (?, 1, ?)
            ON CONFLICT (bucket) DO UPDATE SET
              count    = CASE WHEN rate_limits.reset_at <= ? THEN 1 ELSE rate_limits.count + 1 END,
              reset_at = CASE WHEN rate_limits.reset_at <= ? THEN excluded.reset_at ELSE rate_limits.reset_at END
            RETURNING count`,
      args: [bucketKey, resetAt, nowIso, nowIso],
    });
    return Number(r.rows[0]?.count ?? 1) > maxAttempts;
  } catch {
    return false; // fail open
  }
}

// Clear a bucket — call after a SUCCESSFUL auth so a user who mistyped a few
// times then signed in correctly isn't left throttled.
export async function clearLimit(bucketKey: string): Promise<void> {
  try {
    await getDb().execute({ sql: "DELETE FROM rate_limits WHERE bucket = ?", args: [bucketKey] });
  } catch { /* best-effort */ }
}

// Durable, cross-instance limiter backed by the DB. Serverless functions do NOT
// share memory, so the previous in-process Map only ever counted the requests
// that happened to land on the same warm lambda — the limit was effectively
// (instances × maxAttempts), which barely throttled a brute-force. One atomic
// upsert per call maintains a per-(ip, route) sliding window shared by every
// instance. Fails OPEN on a DB error so a limiter hiccup can't lock out real
// users (a truly down DB already 503s the request upstream in api/index.ts).
export function rateLimit(maxAttempts: number, windowMs: number) {
  return async (req: any, res: any, next: any) => {
    try {
      const bucket   = clientIp(req) + ":" + req.path;
      const nowIso   = new Date().toISOString();
      const resetAt  = new Date(Date.now() + windowMs).toISOString();
      const db       = getDb();

      // Atomic: insert a fresh window, or increment; roll the window over when the
      // stored one has elapsed. RETURNING gives us the post-increment count.
      const r = await db.execute({
        sql: `INSERT INTO rate_limits (bucket, count, reset_at) VALUES (?, 1, ?)
              ON CONFLICT (bucket) DO UPDATE SET
                count    = CASE WHEN rate_limits.reset_at <= ? THEN 1 ELSE rate_limits.count + 1 END,
                reset_at = CASE WHEN rate_limits.reset_at <= ? THEN excluded.reset_at ELSE rate_limits.reset_at END
              RETURNING count`,
        args: [bucket, resetAt, nowIso, nowIso],
      });
      const count = Number(r.rows[0]?.count ?? 1);

      // Opportunistically prune expired buckets so the table stays tiny.
      if (count === 1 && Math.random() < 0.05) {
        db.execute({ sql: "DELETE FROM rate_limits WHERE reset_at <= ?", args: [nowIso] }).catch(() => { /* best-effort */ });
      }

      if (count > maxAttempts) {
        return res.status(429).json({ error: "Trop de tentatives. Réessayez dans quelques minutes." });
      }
      next();
    } catch (err: any) {
      console.error("[RATELIMIT]", err?.message || err);
      next(); // fail open
    }
  };
}
