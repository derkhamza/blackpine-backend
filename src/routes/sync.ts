import { Router, Request, Response } from "express";
import { getDb } from "../db/database";

const router = Router();

router.get("/pull", async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user.userId;
    const db = getDb();

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
const profileData = profileRow ? JSON.parse(profileRow.data as string) : null;
    const assets = profileData?._assets || [];
    if (profileData) delete profileData._assets;
    
    return res.json({
      profile: profileRow ? JSON.parse(profileRow.data as string) : null,
      profileUpdatedAt: profileRow?.updated_at ?? null,
      transactions: transactionRows.map((r: any) => ({
        ...JSON.parse(r.data as string),
        id: r.id,
        assets
      })),
      transactionsUpdatedAt:
        transactionRows.length > 0
          ? transactionRows[transactionRows.length - 1].updated_at
          : null,
    });
  } catch (err: any) {
    console.error("[SYNC] Pull error:", err.message);
    return res.status(500).json({ error: "Erreur de synchronisation" });
  }
});

router.post("/push", async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user.userId;
    const { profile, transactions, assets } = req.body;

    if (!profile) {
      return res.status(400).json({ error: "Profile requis" });
    }

    const now = new Date().toISOString();
    const db = getDb();

    // Upsert profile
// Upsert assets
// Upsert profile (includes assets)
    const profileWithAssets = { ...profile, _assets: assets || [] };
    await db.execute({
      sql: `INSERT INTO profiles (user_id, data, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id)
            DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`,
      args: [userId, JSON.stringify(profileWithAssets), now],
    });

    // Delete old transactions
    await db.execute({
      sql: "DELETE FROM transactions WHERE user_id = ?",
      args: [userId],
    });

    // Insert new transactions
    for (const tx of transactions || []) {
      await db.execute({
        sql: "INSERT OR REPLACE INTO transactions (id, user_id, data, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        args: [tx.id, userId, JSON.stringify(tx), now, now],
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