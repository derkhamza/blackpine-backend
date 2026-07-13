import { Router, Request, Response } from "express";
import bcrypt from "bcryptjs";
import { getDb } from "../db/database";
import { sendResetCode } from "../email/emailService";
import crypto from "crypto";
const uuid = () => crypto.randomUUID();

const router = Router();

// Cryptographically secure 6-digit code (Math.random is predictable → forgeable).
function generateCode(): string {
  return String(crypto.randomInt(100000, 1000000));
}

// Guesses allowed per issued code before it is burned. Small enough that a
// 6-digit code can't be brute-forced (≈8 / 900000), large enough for typos.
const MAX_CODE_ATTEMPTS = 8;

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
    if (newPassword.length < 8) {
      return res.status(400).json({ error: "Le mot de passe doit contenir au moins 8 caractères" });
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

    // Look up the ACTIVE code by user (not by the submitted value) so a wrong
    // guess still burns an attempt — otherwise the 6-digit space is brute-forceable.
    const codeResult = await db.execute({
      sql: "SELECT id, code, expires_at, attempts FROM reset_codes WHERE user_id = ? AND used = 0 ORDER BY created_at DESC LIMIT 1",
      args: [userId],
    });

    if (codeResult.rows.length === 0) {
      return res.status(400).json({ error: "Code invalide ou expiré" });
    }

    const resetRow = codeResult.rows[0];

    if (new Date(resetRow.expires_at as string) < new Date()) {
      return res.status(400).json({ error: "Code expiré. Demandez un nouveau code." });
    }

    // Too many wrong guesses on this code → burn it, force a fresh request.
    if (Number(resetRow.attempts ?? 0) >= MAX_CODE_ATTEMPTS) {
      await db.execute({ sql: "UPDATE reset_codes SET used = 1 WHERE id = ?", args: [resetRow.id as string] });
      return res.status(429).json({ error: "Trop de tentatives. Demandez un nouveau code." });
    }

    // Count this attempt before comparing (so wrong guesses count too).
    await db.execute({ sql: "UPDATE reset_codes SET attempts = attempts + 1 WHERE id = ?", args: [resetRow.id as string] });

    if (String(resetRow.code) !== String(code).trim()) {
      return res.status(400).json({ error: "Code invalide ou expiré" });
    }

    // Match → consume the code.
    await db.execute({
      sql: "UPDATE reset_codes SET used = 1 WHERE id = ?",
      args: [resetRow.id as string],
    });

    // Update password AND revoke every existing session: a reset is exactly the
    // "someone had my password" case, so all tokens issued before now are killed.
    const passwordHash = await bcrypt.hash(newPassword, 12);
    await db.execute({
      sql: "UPDATE users SET password_hash = ?, tokens_valid_after = ?, updated_at = datetime('now') WHERE id = ?",
      args: [passwordHash, new Date().toISOString(), userId],
    });

    console.log(`[RESET] Password updated + sessions revoked for ${email}`);
    return res.json({ success: true });
  } catch (err: any) {
    console.error("[RESET] Verify error:", err.message);
    return res.status(500).json({ error: "Erreur interne" });
  }
});

export default router;