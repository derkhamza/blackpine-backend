import { Router } from "express";
import { getDb, logSubEvent } from "../db/database";
import { authRequired } from "../middleware/auth";

function generateActivationCode(): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let code = "BP-";
  for (let i = 0; i < 8; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return code;
}

const router = Router();

router.post("/generate-code", async (req, res) => {
  try {
    const { adminSecret, plan, durationDays, customerEmail, customerName } = req.body;
    if (adminSecret !== process.env.ADMIN_SECRET) {
      return res.status(403).json({ error: "Non autorisé" });
    }

    const code = generateActivationCode();
    const db = getDb();
    await db.execute({
      sql: "INSERT INTO activation_codes (code, plan, duration_days, customer_email, customer_name, created_at, used) VALUES (?, ?, ?, ?, ?, ?, 0)",
      args: [code, plan, durationDays, customerEmail || null, customerName || null, new Date().toISOString()],
    });

    res.json({ code, plan, durationDays });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Validate and consume a code — requires auth so we can tie the plan to the user
router.post("/validate-code", authRequired, async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: "Code requis" });

    const userId = (req as any).user.userId;
    const db = getDb();
    const result = await db.execute({
      sql: "SELECT * FROM activation_codes WHERE code = ? AND used = 0",
      args: [code.toUpperCase().trim()],
    });

    if (result.rows.length === 0) {
      return res.status(400).json({ error: "Code invalide ou déjà utilisé" });
    }

    const row = result.rows[0];
    const now = new Date().toISOString();

    const expiresAt = row.duration_days
      ? new Date(Date.now() + (row.duration_days as number) * 24 * 60 * 60 * 1000).toISOString()
      : null;

    await db.execute({
      sql: "UPDATE activation_codes SET used = 1, used_at = ? WHERE code = ?",
      args: [now, code.toUpperCase().trim()],
    });

    await db.execute({
      sql: "UPDATE users SET subscription_plan = ?, subscription_expires_at = ? WHERE id = ?",
      args: [row.plan, expiresAt, userId],
    });
    void logSubEvent({ userId, type: "convert", toPlan: String(row.plan), durationDays: (row.duration_days as number) ?? null, source: "code" });

    console.log(`[SUB] User ${userId} activated plan=${row.plan} expires=${expiresAt}`);

    res.json({ valid: true, plan: row.plan, durationDays: row.duration_days, expiresAt });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/codes", async (req, res) => {
  try {
    const { adminSecret } = req.query;
    if (adminSecret !== process.env.ADMIN_SECRET) {
      return res.status(403).json({ error: "Non autorisé" });
    }
    const db = getDb();
    const result = await db.execute("SELECT * FROM activation_codes ORDER BY created_at DESC LIMIT 50");
    res.json({ codes: result.rows });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

export default router;
