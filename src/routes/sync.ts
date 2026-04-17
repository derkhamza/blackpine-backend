import { Router, Request, Response } from "express";
import db from "../db/database";

const router = Router();

// All routes here are protected by authRequired middleware

// GET /sync/pull — fetch all user data
router.get("/pull", (req: Request, res: Response) => {
  const userId = (req as any).user.userId;

  const profileRow = db
    .prepare("SELECT data, updated_at FROM profiles WHERE user_id = ?")
    .get(userId) as any;

  const transactionRows = db
    .prepare("SELECT id, data, updated_at FROM transactions WHERE user_id = ? ORDER BY created_at")
    .all(userId) as any[];

  return res.json({
    profile: profileRow ? JSON.parse(profileRow.data) : null,
    profileUpdatedAt: profileRow?.updated_at ?? null,
    transactions: transactionRows.map((r: any) => ({
      ...JSON.parse(r.data),
      id: r.id,
    })),
    transactionsUpdatedAt:
      transactionRows.length > 0
        ? transactionRows[transactionRows.length - 1].updated_at
        : null,
  });
});

// POST /sync/push — overwrite all user data
// Simple "last write wins" for v1. Conflict resolution comes later.
router.post("/push", (req: Request, res: Response) => {
  const userId = (req as any).user.userId;
  const { profile, transactions } = req.body;

  if (!profile) {
    return res.status(400).json({ error: "Profile requis" });
  }

  const now = new Date().toISOString();

  // Use a transaction for atomicity
  const pushAll = db.transaction(() => {
    // Upsert profile
    db.prepare(
      `INSERT INTO profiles (user_id, data, updated_at)
       VALUES (?, ?, ?)
       ON CONFLICT(user_id)
       DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`
    ).run(userId, JSON.stringify(profile), now);

    // Replace all transactions: delete old, insert new
    db.prepare("DELETE FROM transactions WHERE user_id = ?").run(userId);

    const insert = db.prepare(
    "INSERT OR REPLACE INTO transactions (id, user_id, data, created_at, updated_at) VALUES (?, ?, ?, ?, ?)"
    );

    for (const tx of transactions || []) {
      insert.run(tx.id, userId, JSON.stringify(tx), now, now);
    }
  });

  pushAll();

  console.log(
    `[SYNC] User ${userId} pushed: profile + ${(transactions || []).length} transactions`
  );

  return res.json({ success: true, syncedAt: now });
});

export default router;