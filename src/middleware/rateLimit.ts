const attempts = new Map<string, { count: number; resetAt: number }>();

// Real client IP. On Vercel `req.ip` is the platform's proxy address — the SAME
// for every user — so keying on it makes the limiter GLOBAL (10 logins across
// ALL doctors in 15 min would lock everyone out). Vercel sets the true client IP
// on `x-real-ip` / the left-most `x-forwarded-for`, so prefer those.
function clientIp(req: any): string {
  const realIp = req.headers?.["x-real-ip"];
  if (typeof realIp === "string" && realIp.trim()) return realIp.trim();

  const xff = req.headers?.["x-forwarded-for"];
  const xffStr = Array.isArray(xff) ? xff[0] : xff;
  if (typeof xffStr === "string" && xffStr.trim()) return xffStr.split(",")[0].trim();

  return req.ip || req.socket?.remoteAddress || "unknown";
}

export function rateLimit(maxAttempts: number, windowMs: number) {
  return (req: any, res: any, next: any) => {
    const key = clientIp(req) + ":" + req.path;
    const now = Date.now();
    const entry = attempts.get(key);

    if (entry && now < entry.resetAt) {
      if (entry.count >= maxAttempts) {
        return res.status(429).json({
          error: "Trop de tentatives. Réessayez dans quelques minutes.",
        });
      }
      entry.count++;
    } else {
      attempts.set(key, { count: 1, resetAt: now + windowMs });
    }

    next();
  };
}
