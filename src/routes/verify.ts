import { Router, Request, Response } from "express";
import { getDb } from "../db/database";
import { sendVerificationCode, sendAccountExistsNotice } from "../email/emailService";
import crypto from "crypto";

const uuid = () => crypto.randomUUID();
// Cryptographically secure 6-digit code (Math.random is predictable → forgeable).
const generateCode = () => String(crypto.randomInt(100000, 1000000));

// Guesses allowed per issued code before it is burned (brute-force cap).
const MAX_CODE_ATTEMPTS = 8;

type CodeCheck = "ok" | "invalid" | "locked";

// Look up the ACTIVE code for an email (not by the submitted value) so every
// call — right or wrong — burns an attempt; burn the code after MAX_CODE_ATTEMPTS
// so the 6-digit space can't be brute-forced.
async function verifyCodeAttempt(email: string, code: string): Promise<CodeCheck> {
  const db = getDb();
  const e = email.toLowerCase().trim();
  const r = await db.execute({
    sql: "SELECT id, code, expires_at, attempts FROM email_verifications WHERE email = ? AND used = 0 ORDER BY created_at DESC LIMIT 1",
    args: [e],
  });
  if (r.rows.length === 0) return "invalid";
  const row = r.rows[0];
  if (new Date(row.expires_at as string) < new Date()) return "invalid";
  if (Number(row.attempts ?? 0) >= MAX_CODE_ATTEMPTS) {
    await db.execute({ sql: "UPDATE email_verifications SET used = 1 WHERE id = ?", args: [row.id as string] });
    return "locked";
  }
  await db.execute({ sql: "UPDATE email_verifications SET attempts = attempts + 1 WHERE id = ?", args: [row.id as string] });
  return String(row.code) === String(code).trim() ? "ok" : "invalid";
}

const router = Router();

// POST /verify/send-code — send a signup verification code to an email.
// Codes are stored in the DB (durable across serverless cold starts).
router.post("/send-code", async (req: Request, res: Response) => {
  try {
    const email = String(req.body?.email || "").toLowerCase().trim();
    if (!email) return res.status(400).json({ error: "Email requis" });

    const db = getDb();

    // Privacy: never reveal via the API response whether an address is already
    // registered (that was an enumeration oracle). If it is, email the owner a
    // "you already have an account" notice (no code) and return the SAME success
    // as a fresh signup — the existence hint only ever reaches their own inbox.
    const existing = await db.execute({
      sql: "SELECT id FROM users WHERE email = ?",
      args: [email],
    });
    if (existing.rows.length > 0) {
      try { await sendAccountExistsNotice(email); }
      catch (e: any) { console.error("[VERIFY] account-exists notice failed:", e.message); }
      return res.json({ success: true });
    }

    const code = generateCode();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    // Invalidate any previous pending codes for this email.
    await db.execute({
      sql: "UPDATE email_verifications SET used = 1 WHERE email = ? AND used = 0",
      args: [email],
    });
    const rowId = uuid();
    await db.execute({
      sql: "INSERT INTO email_verifications (id, email, code, expires_at) VALUES (?, ?, ?, ?)",
      args: [rowId, email, code, expiresAt],
    });

    // Send the mail. If the provider rejects it (unverified domain, bad key,
    // test-mode recipient limit…) surface a clear, email-specific error rather
    // than a generic 500 — and drop the just-inserted code so it can't be used.
    try {
      await sendVerificationCode(email, code);
    } catch (mailErr: any) {
      console.error("[VERIFY] Verification email could not be sent:", mailErr.message);
      await db.execute({
        sql: "UPDATE email_verifications SET used = 1 WHERE id = ?",
        args: [rowId],
      });
      return res.status(502).json({ error: "L'email de vérification n'a pas pu être envoyé. Réessayez dans un instant." });
    }

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

    const result = await verifyCodeAttempt(email, code);
    if (result === "locked") return res.status(429).json({ error: "Trop de tentatives. Demandez un nouveau code." });
    if (result !== "ok")     return res.status(400).json({ error: "Code incorrect ou expiré" });

    res.json({ verified: true });
  } catch (err: any) {
    console.error("[VERIFY] Check code error:", err.message);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// Shared helper: consume (mark used) all pending codes for an email once signup
// succeeds. Goes through the same attempt-limited check, so a signup that guesses
// codes is throttled just like /verify/check-code. Returns true only on a match.
export async function consumeVerificationCode(email: string, code: string): Promise<boolean> {
  const e = email.toLowerCase().trim();
  const result = await verifyCodeAttempt(e, code);
  if (result !== "ok") return false;
  await getDb().execute({
    sql: "UPDATE email_verifications SET used = 1 WHERE email = ?",
    args: [e],
  });
  return true;
}

export default router;
