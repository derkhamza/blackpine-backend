import { Request, Response, NextFunction } from "express";
import { getDb } from "../db/database";

const TRIAL_DAYS = 30;

export async function subscriptionRequired(req: Request, res: Response, next: NextFunction) {
  try {
    // Gate on the ACCOUNT OWNER: a doctor authenticates as req.user; a secretary
    // authenticates as req.secretary and acts on the owning doctor's cabinet, so
    // her writes are governed by that doctor's subscription.
    const userId = (req as any).user?.userId ?? (req as any).secretary?.ownerUserId;
    if (!userId) return next(); // no identity resolved (auth already ran) — don't block
    const db = getDb();
    const result = await db.execute({
      sql: "SELECT trial_start, subscription_plan, subscription_expires_at FROM users WHERE id = ?",
      args: [userId],
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

    let trialStart = row.trial_start as string | null;

    // Backfill NULL trial_start for accounts created before trial tracking was added.
    // Give them a fresh 30-day window from today rather than blocking immediately.
    if (!trialStart) {
      trialStart = new Date().toISOString();
      try {
        await db.execute({
          sql: "UPDATE users SET trial_start = ? WHERE id = ?",
          args: [trialStart, userId],
        });
      } catch (updateErr: any) {
        console.error("[SUBSCRIPTION] Failed to backfill trial_start:", updateErr.message);
      }
    }

    const daysElapsed = Math.floor((Date.now() - new Date(trialStart).getTime()) / (1000 * 60 * 60 * 24));
    if (daysElapsed < TRIAL_DAYS) return next();

    // Return trialStart so the client can correct its local state
    return res.status(403).json({ error: "subscription_expired", trialStart, daysLeft: 0 });
  } catch (err: any) {
    console.error("[SUBSCRIPTION] Check failed:", err.message);
    next();
  }
}
