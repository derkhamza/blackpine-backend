import { Router, Request, Response } from "express";
import { getDb } from "../db/database";
import { sendVerificationCode } from "../email/emailService";
import crypto from "crypto";

const uuid = () => crypto.randomUUID();
const generateCode = () => String(Math.floor(100000 + Math.random() * 900000));

const router = Router();

// POST /verify/send-code — send a signup verification code to an email.
// Codes are stored in the DB (durable across serverless cold starts).
router.post("/send-code", async (req: Request, res: Response) => {
  try {
    const email = String(req.body?.email || "").toLowerCase().trim();
    if (!email) return res.status(400).json({ error: "Email requis" });

    const db = getDb();

    // Refuse to re-verify an address that already has an account, so the user is
    // told to log in instead of walking through a signup that would 409 anyway.
    const existing = await db.execute({
      sql: "SELECT id FROM users WHERE email = ?",
      args: [email],
    });
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: "Un compte existe déjà avec cet email" });
    }

    const code = generateCode();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    // Invalidate any previous pending codes for this email.
    await db.execute({
      sql: "UPDATE email_verifications SET used = 1 WHERE email = ? AND used = 0",
      args: [email],
    });
    await db.execute({
      sql: "INSERT INTO email_verifications (id, email, code, expires_at) VALUES (?, ?, ?, ?)",
      args: [uuid(), email, code, expiresAt],
    });

    await sendVerificationCode(email, code);

    res.json({ success: true });
  } catch (err: any) {
    console.error("[VERIFY] Send code error:", err.message);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// POST /verify/check-code — validate a code WITHOUT consuming it (instant UI
// feedback). The authoritative consume happens in /auth/signup.
router.post("/check-code", async (req: Request, res: Response) => {
  try {
    const email = String(req.body?.email || "").toLowerCase().trim();
    const code = String(req.body?.code || "").trim();
    if (!email || !code) return res.status(400).json({ error: "Email et code requis" });

    const valid = await isVerificationCodeValid(email, code);
    if (!valid) return res.status(400).json({ error: "Code incorrect ou expiré" });

    res.json({ verified: true });
  } catch (err: any) {
    console.error("[VERIFY] Check code error:", err.message);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// Shared helper: is there an unused, unexpired code matching this email?
export async function isVerificationCodeValid(email: string, code: string): Promise<boolean> {
  const db = getDb();
  const result = await db.execute({
    sql: "SELECT id, expires_at FROM email_verifications WHERE email = ? AND code = ? AND used = 0",
    args: [email.toLowerCase().trim(), code.trim()],
  });
  if (result.rows.length === 0) return false;
  const expiresAt = new Date(result.rows[0].expires_at as string);
  return expiresAt >= new Date();
}

// Shared helper: consume (mark used) all pending codes for an email once signup
// succeeds. Returns true if a valid code existed and was consumed.
export async function consumeVerificationCode(email: string, code: string): Promise<boolean> {
  const db = getDb();
  const e = email.toLowerCase().trim();
  const result = await db.execute({
    sql: "SELECT id, expires_at FROM email_verifications WHERE email = ? AND code = ? AND used = 0",
    args: [e, code.trim()],
  });
  if (result.rows.length === 0) return false;
  const expiresAt = new Date(result.rows[0].expires_at as string);
  if (expiresAt < new Date()) return false;
  await db.execute({
    sql: "UPDATE email_verifications SET used = 1 WHERE email = ?",
    args: [e],
  });
  return true;
}

export default router;
