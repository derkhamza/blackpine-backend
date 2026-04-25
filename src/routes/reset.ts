import { Router, Request, Response } from "express";
import bcrypt from "bcryptjs";
import { getDb } from "../db/database";
import { sendResetCode } from "../email/emailService";
import crypto from "crypto";
const uuid = () => crypto.randomUUID();

const router = Router();

function generateCode(): string {
  return String(Math.floor(100000 + Math.random() * 900000));
}

// POST /reset/request — send a reset code to email
router.post("/request", async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: "Email requis" });
    }

    const db = getDb();
    const userResult = await db.execute({
      sql: "SELECT id FROM users WHERE email = ?",
      args: [email.toLowerCase().trim()],
    });

    if (userResult.rows.length === 0) {
      // Don't reveal whether email exists
      return res.json({ success: true });
    }

    const userId = userResult.rows[0].id as string;
    const code = generateCode();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    // Invalidate previous codes for this user
    await db.execute({
      sql: "UPDATE reset_codes SET used = 1 WHERE user_id = ? AND used = 0",
      args: [userId],
    });

    // Store new code
    await db.execute({
      sql: "INSERT INTO reset_codes (id, user_id, code, expires_at) VALUES (?, ?, ?, ?)",
      args: [uuid(), userId, code, expiresAt],
    });

    // Send email
    await sendResetCode(email.toLowerCase().trim(), code);

    console.log(`[RESET] Code sent to ${email}`);
    return res.json({ success: true });
  } catch (err: any) {
    console.error("[RESET] Request error:", err.message);
    return res.status(500).json({ error: "Erreur interne" });
  }
});

// POST /reset/verify — verify code and set new password
router.post("/verify", async (req: Request, res: Response) => {
  try {
    const { email, code, newPassword } = req.body;

    if (!email || !code || !newPassword) {
      return res.status(400).json({ error: "Email, code et nouveau mot de passe requis" });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ error: "Le mot de passe doit contenir au moins 6 caractères" });
    }

    const db = getDb();

    // Find the user
    const userResult = await db.execute({
      sql: "SELECT id FROM users WHERE email = ?",
      args: [email.toLowerCase().trim()],
    });

    if (userResult.rows.length === 0) {
      return res.status(400).json({ error: "Code invalide ou expiré" });
    }

    const userId = userResult.rows[0].id as string;

    // Find valid code
    const codeResult = await db.execute({
      sql: "SELECT id, expires_at FROM reset_codes WHERE user_id = ? AND code = ? AND used = 0",
      args: [userId, code.trim()],
    });

    if (codeResult.rows.length === 0) {
      return res.status(400).json({ error: "Code invalide ou expiré" });
    }

    const resetRow = codeResult.rows[0];
    const expiresAt = new Date(resetRow.expires_at as string);

    if (expiresAt < new Date()) {
      return res.status(400).json({ error: "Code expiré. Demandez un nouveau code." });
    }

    // Mark code as used
    await db.execute({
      sql: "UPDATE reset_codes SET used = 1 WHERE id = ?",
      args: [resetRow.id as string],
    });

    // Update password
    const passwordHash = await bcrypt.hash(newPassword, 12);
    await db.execute({
      sql: "UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?",
      args: [passwordHash, userId],
    });

    console.log(`[RESET] Password updated for ${email}`);
    return res.json({ success: true });
  } catch (err: any) {
    console.error("[RESET] Verify error:", err.message);
    return res.status(500).json({ error: "Erreur interne" });
  }
});

export default router;