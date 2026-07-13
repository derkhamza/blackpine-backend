import { Router, Request, Response } from "express";
import bcrypt from "bcryptjs";
import { getDb } from "../db/database";
import { generateToken } from "../middleware/auth";
import { consumeVerificationCode } from "./verify";
import crypto from "crypto";
const uuid = () => crypto.randomUUID();

const router = Router();

// A real cost-12 hash to compare against when the email is unknown, so login
// takes the same time whether the email exists or not (defeats timing-based
// account enumeration). Computed once at startup.
const DUMMY_HASH = bcrypt.hashSync("blackpine-timing-equalizer", 12);

router.post("/signup", async (req: Request, res: Response) => {
  try {
    const { email, password, code } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email et mot de passe requis" });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: "Le mot de passe doit contenir au moins 8 caractères" });
    }
    if (!code) {
      return res.status(400).json({ error: "Code de vérification requis" });
    }

    const db = getDb();

    // Verify the emailed code BEFORE checking existence, so an attacker without a
    // valid code gets the same "code incorrect" answer whether or not the email is
    // registered (no enumeration). A signup for an existing email never holds a
    // valid code anyway — send-code issues none for addresses that already exist.
    const verified = await consumeVerificationCode(email, code);
    if (!verified) {
      return res.status(400).json({ error: "Code de vérification incorrect ou expiré" });
    }

    const existing = await db.execute({
      sql: "SELECT id FROM users WHERE email = ?",
      args: [email.toLowerCase().trim()],
    });

    if (existing.rows.length > 0) {
      return res.status(409).json({ error: "Un compte existe déjà avec cet email" });
    }

    const id = uuid();
    const passwordHash = await bcrypt.hash(password, 12);
    const trialStart = new Date().toISOString();

    await db.execute({
      sql: "INSERT INTO users (id, email, password_hash, trial_start) VALUES (?, ?, ?, ?)",
      args: [id, email.toLowerCase().trim(), passwordHash, trialStart],
    });

    const token = generateToken({ userId: id, email });
    console.log(`[AUTH] New user registered: ${email}`);

    return res.status(201).json({
      token,
      user: { id, email, trialStart, subscriptionPlan: "free_trial", subscriptionExpiresAt: null },
    });
  } catch (err: any) {
    console.error("[AUTH] Signup error:", err.message);
    return res.status(500).json({ error: "Erreur interne" });
  }
});

router.post("/login", async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email et mot de passe requis" });
    }

    const db = getDb();

    const result = await db.execute({
      sql: "SELECT id, email, password_hash, trial_start, subscription_plan, subscription_expires_at FROM users WHERE email = ?",
      args: [email.toLowerCase().trim()],
    });

    if (result.rows.length === 0) {
      // Spend the same time as a real bcrypt check so an unknown email can't be
      // distinguished from a wrong password by response time.
      await bcrypt.compare(password, DUMMY_HASH);
      return res.status(401).json({ error: "Email ou mot de passe incorrect" });
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash as string);

    if (!valid) {
      return res.status(401).json({ error: "Email ou mot de passe incorrect" });
    }

    const token = generateToken({ userId: user.id as string, email: user.email as string });
    console.log(`[AUTH] User logged in: ${email}`);

    return res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        trialStart: user.trial_start,
        subscriptionPlan: user.subscription_plan || "free_trial",
        subscriptionExpiresAt: user.subscription_expires_at || null,
      },
    });
  } catch (err: any) {
    console.error("[AUTH] Login error:", err.message);
    return res.status(500).json({ error: "Erreur interne" });
  }
});

router.get("/me", (req: Request, res: Response) => {
  const user = (req as any).user;
  return res.json({ user });
});

// NOTE: the old GET /trial-status?email= endpoint was removed — it was unused by
// the apps and was an unauthenticated account-enumeration oracle (404 vs 200, with
// the email exposed in the URL/logs). Trial state already rides in the /auth/login
// and /auth/me responses for the authenticated user.

export default router;
