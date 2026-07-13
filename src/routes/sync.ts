import { Router, Request, Response } from "express";
import { getDb } from "../db/database";
import { encryptField, decryptField } from "../crypto/dataCipher";
import { subscriptionRequired } from "../middleware/subscription";

const router = Router();

router.get("/pull", async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user.userId;
    const db = getDb();

    const userResult = await db.execute({
      sql: "SELECT trial_start, subscription_plan, subscription_expires_at FROM users WHERE id = ?",
      args: [userId],
    });

    const profileResult = await db.execute({
      sql: "SELECT data, updated_at FROM profiles WHERE user_id = ?",
      args: [userId],
    });

    const txResult = await db.execute({
      sql: "SELECT id, data, updated_at FROM transactions WHERE user_id = ? ORDER BY created_at",
      args: [userId],
    });

    const profileRow = profileResult.rows[0];
    const transactionRows = txResult.rows;
      const profileData = profileRow ? JSON.parse(decryptField(profileRow.data as string)) : null;
    const assets = profileData?._assets || [];
    const recurringRules = profileData?._recurringRules || [];
    if (profileData) {
      delete profileData._assets;
      delete profileData._recurringRules;
    }
    const userRow = userResult.rows[0];
    return res.json({
      // profileData is the decrypted profile with the embedded _assets /
      // _recurringRules already stripped (see above).
      profile: profileData,
      profileUpdatedAt: profileRow?.updated_at ?? null,
      transactions: transactionRows.map((r: any) => ({
        ...JSON.parse(decryptField(r.data as string)),
        id: r.id,
      })),
      transactionsUpdatedAt:
        transactionRows.length > 0
          ? transactionRows[transactionRows.length - 1].updated_at
          : null,
      // Assets & recurring rules are TOP-LEVEL fields the client reads as
      // data.assets / data.recurringRules (previously nested inside each
      // transaction by mistake, so they never round-tripped).
      assets,
      recurringRules,
      subscription: userRow ? {
        trialStart: userRow.trial_start,
        plan: userRow.subscription_plan || "free_trial",
        expiresAt: userRow.subscription_expires_at || null,
      } : null,
    });
  } catch (err: any) {
    console.error("[SYNC] Pull error:", err.message);
    return res.status(500).json({ error: "Erreur de synchronisation" });
  }
});

router.post("/push", subscriptionRequired, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user.userId;
    const { profile, transactions, assets, recurringRules } = req.body;
    if (!profile) {
      return res.status(400).json({ error: "Profile requis" });
    }

    const now = new Date().toISOString();
    const db = getDb();

    // Upsert profile
// Upsert assets
// Upsert profile (includes assets)
const profileWithExtras = { ...profile, _assets: assets || [], _recurringRules: recurringRules || [] };
    await db.execute({
      sql: `INSERT INTO profiles (user_id, data, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id)
            DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`,
      args: [userId, encryptField(JSON.stringify(profileWithExtras)), now],
    });

    // Delete old transactions
    await db.execute({
      sql: "DELETE FROM transactions WHERE user_id = ?",
      args: [userId],
    });

    // Insert new transactions
    for (const tx of transactions || []) {
      await db.execute({
        sql: `INSERT INTO transactions (id, user_id, data, created_at, updated_at) VALUES (?, ?, ?, ?, ?)
              ON CONFLICT (id) DO UPDATE SET user_id = EXCLUDED.user_id, data = EXCLUDED.data,
                created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at`,
        args: [tx.id, userId, encryptField(JSON.stringify(tx)), now, now],
      });
    }

    console.log(
      `[SYNC] User ${userId} pushed: profile + ${(transactions || []).length} transactions`
    );

    return res.json({ success: true, syncedAt: now });
  } catch (err: any) {
    console.error("[SYNC] Push error:", err.message);
    return res.status(500).json({ error: "Erreur de synchronisation" });
  }
});

export default router;