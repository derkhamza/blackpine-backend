import { Router } from "express";
import { getDb } from "../db/database";
import crypto from "crypto";

const router = Router();

function generateActivationCode(): string {
  return "BP-" + crypto.randomBytes(4).toString("hex").toUpperCase();
}

// Admin endpoint: generate codes (protect with a secret)
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

// Validate and consume a code
router.post("/validate-code", async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: "Code requis" });

    const db = getDb();
    const result = await db.execute({
      sql: "SELECT * FROM activation_codes WHERE code = ? AND used = 0",
      args: [code.toUpperCase().trim()],
    });

    if (result.rows.length === 0) {
      return res.status(400).json({ error: "Code invalide ou déjà utilisé" });
    }

    const row = result.rows[0];

    // Mark as used
    await db.execute({
      sql: "UPDATE activation_codes SET used = 1, used_at = ? WHERE code = ?",
      args: [new Date().toISOString(), code.toUpperCase().trim()],
    });

    res.json({
      valid: true,
      plan: row.plan,
      durationDays: row.duration_days,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// List codes (admin)
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