import { Router, Request, Response } from "express";
import bcrypt from "bcryptjs";
import { getDb } from "../db/database";
import { generateToken } from "../middleware/auth";
import crypto from "crypto";
const uuid = () => crypto.randomUUID();

const router = Router();

router.post("/signup", async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email et mot de passe requis" });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: "Le mot de passe doit contenir au moins 6 caractères" });
    }

    const db = getDb();

    const existing = await db.execute({
      sql: "SELECT id FROM users WHERE email = ?",
      args: [email.toLowerCase().trim()],
    });

    if (existing.rows.length > 0) {
      return res.status(409).json({ error: "Un compte existe déjà avec cet email" });
    }

    const id = uuid();
    const passwordHash = await bcrypt.hash(password, 12);

    await db.execute({
      sql: "INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)",
      args: [id, email.toLowerCase().trim(), passwordHash],
    });

    // After: await db.execute({ sql: "INSERT INTO users ...", args: [...] });
// Add:
await db.execute({
  sql: "UPDATE users SET trial_start = ? WHERE email = ?",
  args: [new Date().toISOString(), email.toLowerCase().trim()],
});

    const token = generateToken({ userId: id, email });
    console.log(`[AUTH] New user registered: ${email}`);

    return res.status(201).json({
      token,
      user: { id, email },
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
      sql: "SELECT id, email, password_hash FROM users WHERE email = ?",
      args: [email.toLowerCase().trim()],
    });

    if (result.rows.length === 0) {
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
      user: { id: user.id, email: user.email },
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

router.get("/trial-status", async (req: Request, res: Response) => {
  try {
    const { email } = req.query;
    if (!email) return res.status(400).json({ error: "Email requis" });

    const db = getDb();
    const result = await db.execute({
      sql: "SELECT trial_start FROM users WHERE email = ?",
      args: [String(email).toLowerCase().trim()],
    });

    if (result.rows.length === 0) return res.status(404).json({ error: "Utilisateur non trouvé" });

    const trialStart = result.rows[0].trial_start as string;
    const startDate = new Date(trialStart);
    const now = new Date();
    const daysElapsed = Math.floor((now.getTime() - startDate.getTime()) / (1000 * 60 * 60 * 24));
    const daysLeft = Math.max(0, 30 - daysElapsed);

    res.json({ trialStart, daysElapsed, daysLeft, expired: daysLeft <= 0 });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});
export default router;