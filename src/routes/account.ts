/**
 * Self-service account deletion.
 *
 * A signed-in doctor can permanently delete their own account and ALL associated
 * data (profile, cabinet snapshots + backups, transactions, booking link, SMS/
 * push config, secretary accounts, analytics…). Irreversible. Required for the
 * Google Play / GDPR "users can request account deletion" obligation.
 *
 * Safety: must re-type the account email to confirm; the deletion runs as a
 * single atomic batch (all-or-nothing).
 */
import { Router, Request, Response } from "express";
import { getDb } from "../db/database";
import { USER_TABLES } from "./admin";

const router = Router();

// DELETE /account — delete the *caller's own* account + all data.
router.delete("/", async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user.userId;
    const email  = String((req as any).user.email ?? "");

    // A secretary session must not be able to wipe the doctor's account.
    if ((req as any).user.type === "secretary") {
      return res.status(403).json({ error: "Action réservée au titulaire du compte" });
    }

    const confirm = String(req.body?.confirmEmail ?? "").trim().toLowerCase();
    if (!confirm || confirm !== email.toLowerCase()) {
      return res.status(400).json({ error: "Veuillez confirmer votre adresse e-mail." });
    }

    const db = getDb();
    const stmts = USER_TABLES.map(({ table, col }) => ({
      sql: `DELETE FROM ${table} WHERE ${col} = ?`,
      args: [userId],
    }));
    stmts.push({ sql: "DELETE FROM users WHERE id = ?", args: [userId] });
    await db.batch(stmts, "write");   // atomic: all-or-nothing

    console.warn(`[ACCOUNT] ${email} (${userId}) self-deleted account + all data`);
    return res.json({ ok: true });
  } catch (err: any) {
    console.error("[ACCOUNT] self-delete error:", err.message);
    return res.status(500).json({ error: "Erreur lors de la suppression" });
  }
});

export default router;
