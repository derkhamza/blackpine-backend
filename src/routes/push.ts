/**
 * Expo push-token registration.
 *
 *   POST /push/register    (auth) { token }  → store this device's Expo token
 *   POST /push/unregister  (auth) { token }  → remove it (e.g. on logout)
 *
 * Tokens are used by other routes (e.g. booking) to notify the doctor's device.
 */
import { Router, Request, Response } from "express";
import { getDb } from "../db/database";
import { authRequired } from "../middleware/auth";

const router = Router();

router.post("/register", authRequired, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user.userId;
    const token = String(req.body?.token ?? "").trim();
    if (!token.startsWith("ExponentPushToken")) return res.status(400).json({ error: "Token invalide" });
    const db = getDb();
    await db.execute({
      sql: `INSERT INTO push_tokens (token, owner_user_id, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(token) DO UPDATE SET owner_user_id = excluded.owner_user_id, updated_at = excluded.updated_at`,
      args: [token, userId, new Date().toISOString()],
    });
    return res.json({ ok: true });
  } catch (err: any) {
    console.error("[PUSH] register error:", err.message);
    return res.status(500).json({ error: "Erreur" });
  }
});

router.post("/unregister", authRequired, async (req: Request, res: Response) => {
  try {
    const token = String(req.body?.token ?? "").trim();
    if (!token) return res.json({ ok: true });
    const ownerUserId = (req as any).user.userId;
    const db = getDb();
    // Scope to the caller's own tokens so one doctor can't unregister another's
    // device (notification denial-of-service).
    await db.execute({ sql: "DELETE FROM push_tokens WHERE token = ? AND owner_user_id = ?", args: [token, ownerUserId] });
    return res.json({ ok: true });
  } catch (err: any) {
    console.error("[PUSH] unregister error:", err.message);
    return res.status(500).json({ error: "Erreur" });
  }
});

export default router;
