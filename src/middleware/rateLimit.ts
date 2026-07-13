import { getDb } from "../db/database";

// Real client IP. On Vercel `req.ip` is the platform proxy address (the SAME for
// every user), so keying on it makes the limiter global. Vercel's edge sets the
// true client IP on `x-real-ip` / the left-most `x-forwarded-for`.
function clientIp(req: any): string {
  const realIp = req.headers?.["x-real-ip"];
  if (typeof realIp === "string" && realIp.trim()) return realIp.trim();

  const xff = req.headers?.["x-forwarded-for"];
  const xffStr = Array.isArray(xff) ? xff[0] : xff;
  if (typeof xffStr === "string" && xffStr.trim()) return xffStr.split(",")[0].trim();

  return req.ip || req.socket?.remoteAddress || "unknown";
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
