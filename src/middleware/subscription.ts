import { Request, Response, NextFunction } from "express";
import { getDb } from "../db/database";

const TRIAL_DAYS = 30;

export async function subscriptionRequired(req: Request, res: Response, next: NextFunction) {
  try {
    const user = (req as any).user;
    const db = getDb();
    const result = await db.execute({
      sql: "SELECT trial_start, subscription_plan, subscription_expires_at FROM users WHERE id = ?",
      args: [user.userId],
    });

    if (result.rows.length === 0) return res.status(401).json({ error: "Utilisateur non trouvé" });

    const row = result.rows[0];
    const plan = (row.subscription_plan as string) || "free_trial";

    if (plan === "lifetime") return next();

    if (plan !== "free_trial") {
      const expiresAt = row.subscription_expires_at as string | null;
      if (expiresAt && new Date(expiresAt) > new Date()) return next();
      return res.status(403).json({ error: "subscription_expired", plan });
    }

    const trialStart = row.trial_start as string | null;
    if (!trialStart) return res.status(403).json({ error: "subscription_expired" });

    const daysElapsed = Math.floor((Date.now() - new Date(trialStart).getTime()) / (1000 * 60 * 60 * 24));
    if (daysElapsed < TRIAL_DAYS) return next();

    return res.status(403).json({ error: "subscription_expired", daysLeft: 0 });
  } catch (err: any) {
    console.error("[SUBSCRIPTION] Check failed:", err.message);
    next();
  }
}
