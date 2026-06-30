/**
 * Persistent secretary login accounts.
 *
 * A doctor creates named secretary accounts (username + password). The secretary
 * logs in with those credentials and receives a 365-day secretary token — the
 * same token shape the existing /cabinet/* endpoints already accept, so login
 * just creates a secretary_sessions row (which the secretary middleware validates
 * and which the doctor can revoke). No expiry; fully revocable by the doctor.
 */
import { Router, Request, Response } from "express";
import { getDb } from "../db/database";
import { authRequired } from "../middleware/auth";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import { decryptField } from "../crypto/dataCipher";

const router = Router();
const JWT_SECRET = process.env.JWT_SECRET || "blackpine-dev-secret-change-in-production";

const normUser = (s: string) => s.trim().toLowerCase();

async function ownerDisplayName(db: ReturnType<typeof getDb>, ownerUserId: string): Promise<string> {
  try {
    const r = await db.execute({ sql: "SELECT data FROM profiles WHERE user_id = ?", args: [ownerUserId] });
    const p = r.rows[0] ? JSON.parse(decryptField(r.rows[0].data as string)) : {};
    if (p?.firstName && p?.lastName) return `Dr. ${p.firstName} ${p.lastName}`;
    return p?.practiceName || "Cabinet médical";
  } catch {
    return "Cabinet médical";
  }
}

// ── Doctor: create a secretary account ────────────────────────────────────────
router.post("/", authRequired, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user.userId;
    const { username, password, name } = req.body ?? {};
    if (!username || !password) return res.status(400).json({ error: "Identifiant et mot de passe requis" });
    const u = normUser(String(username));
    if (u.length < 3) return res.status(400).json({ error: "Identifiant trop court (min. 3)" });
    if (String(password).length < 6) return res.status(400).json({ error: "Mot de passe trop court (min. 6)" });

    const db = getDb();
    const existing = await db.execute({ sql: "SELECT id FROM secretary_accounts WHERE username = ?", args: [u] });
    if (existing.rows.length > 0) return res.status(409).json({ error: "Cet identifiant est déjà utilisé" });

    const id = crypto.randomUUID();
    const passwordHash = await bcrypt.hash(String(password), 12);
    const now = new Date().toISOString();
    await db.execute({
      sql: `INSERT INTO secretary_accounts (id, owner_user_id, username, password_hash, name, created_at, revoked)
            VALUES (?, ?, ?, ?, ?, ?, 0)`,
      args: [id, userId, u, passwordHash, name ? String(name).trim() : null, now],
    });
    console.log(`[SEC-ACCT] Doctor ${userId} created secretary account ${u}`);
    return res.json({ id, username: u, name: name ?? null, createdAt: now, revoked: 0 });
  } catch (err: any) {
    console.error("[SEC-ACCT] create error", err);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// ── Doctor: list their secretary accounts ─────────────────────────────────────
router.get("/", authRequired, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user.userId;
    const db = getDb();
    const r = await db.execute({
      sql: "SELECT id, username, name, created_at, revoked FROM secretary_accounts WHERE owner_user_id = ? ORDER BY created_at DESC",
      args: [userId],
    });
    return res.json({
      accounts: r.rows.map((row) => ({
        id: row.id, username: row.username, name: row.name,
        createdAt: row.created_at, revoked: (row.revoked as number) === 1,
      })),
    });
  } catch (err: any) {
    console.error("[SEC-ACCT] list error", err);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// ── Doctor: revoke (disable) a secretary account ──────────────────────────────
router.delete("/:id", authRequired, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user.userId;
    const id = String(req.params.id);
    const db = getDb();
    // Only the owning doctor may revoke; also kill any active sessions from it.
    const r = await db.execute({
      sql: "UPDATE secretary_accounts SET revoked = 1 WHERE id = ? AND owner_user_id = ?",
      args: [id, userId],
    });
    if (r.rowsAffected === 0) return res.status(404).json({ error: "Compte introuvable" });
    await db.execute({ sql: "UPDATE secretary_sessions SET revoked = 1 WHERE account_id = ?", args: [id] });
    console.log(`[SEC-ACCT] Doctor ${userId} revoked secretary account ${id}`);
    return res.json({ ok: true });
  } catch (err: any) {
    console.error("[SEC-ACCT] revoke error", err);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

// ── Secretary: log in with username + password (public) ───────────────────────
router.post("/login", async (req: Request, res: Response) => {
  try {
    const { username, password } = req.body ?? {};
    if (!username || !password) return res.status(400).json({ error: "Identifiant et mot de passe requis" });
    const u = normUser(String(username));

    const db = getDb();
    const r = await db.execute({
      sql: "SELECT * FROM secretary_accounts WHERE username = ?",
      args: [u],
    });
    const acct = r.rows[0];
    if (!acct || (acct.revoked as number) === 1) {
      return res.status(401).json({ error: "Identifiants invalides ou accès révoqué" });
    }
    const ok = await bcrypt.compare(String(password), acct.password_hash as string);
    if (!ok) return res.status(401).json({ error: "Identifiants invalides" });

    const ownerUserId = acct.owner_user_id as string;
    const accountId = acct.id as string;
    const secretaryId = crypto.randomUUID();
    const now = new Date().toISOString();
    const secretaryToken = jwt.sign(
      { type: "secretary", ownerUserId, secretaryId, accountId },
      JWT_SECRET,
      { expiresIn: "365d" },
    );
    // A session row makes the token revocable via the existing secretary middleware.
    await db.execute({
      sql: `INSERT INTO secretary_sessions (id, code, owner_user_id, token, created_at, revoked, account_id)
            VALUES (?, ?, ?, ?, ?, 0, ?)`,
      args: [secretaryId, `ACCT:${u}`, ownerUserId, secretaryToken, now, accountId],
    });
    const ownerName = await ownerDisplayName(db, ownerUserId);
    console.log(`[SEC-ACCT] Secretary ${u} logged in → session ${secretaryId}`);
    return res.json({
      secretaryToken,
      ownerUserId,
      ownerName,
      name: acct.name ?? null,
      username: u,
      linkedAt: now,
    });
  } catch (err: any) {
    console.error("[SEC-ACCT] login error", err);
    return res.status(500).json({ error: "Erreur serveur" });
  }
});

export default router;
