const attempts = new Map<string, { count: number; resetAt: number }>();

export function rateLimit(maxAttempts: number, windowMs: number) {
  return (req: any, res: any, next: any) => {
    const key = req.ip + ":" + req.path;
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