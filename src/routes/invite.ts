import { Router, Request, Response } from "express";
import { getDb } from "../db/database";
import { authRequired, JWT_SECRET } from "../middleware/auth";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { decryptField } from "../crypto/dataCipher";

const router = Router();

function generateCode(): string {
  // Unambiguous chars (no 0/O, 1/I/L)
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let code = "";
  for (let i = 0; i < 6; i++) {
    code += chars[Math.floor(Math.random() * chars.length)];
  }
  return code;
}

// POST /invite/create — doctor generates a secretary invite code
router.post("/create", authRequired, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user.userId;
    const db = getDb();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 48 * 60 * 60 * 1000).toISOString(); // 48 h

    // Invalidate previous unused codes for this doctor
    await db.execute({
      sql: "UPDATE invite_codes SET used = 1 WHERE owner_user_id = ? AND used = 0",
      args: [userId],
    });

    // Generate a unique code (retry up to 10× on collision)
    let code = generateCode();
    for (let attempt = 0; attempt < 10; attempt++) {
      const existing = await db.execute({
        sql: "SELECT code FROM invite_codes WHERE code = ? AND used = 0",
        args: [code],
      });
      if (existing.rows.length === 0) break;
      code = generateCode();
    }

    await db.execute({
      sql: "INSERT INTO invite_codes (code, owner_user_id, expires_at, created_at, used) VALUES (?, ?, ?, ?, 0)",
      args: [code, userId, expiresAt, now.toISOString()],
    });

    console.log(`[INVITE] Doctor ${userId} created code ${code}`);
    return res.json({ code, expiresAt });
  } catch (err: any) {
    console.error("[INVITE] Create error:", err.message);
    return res.status(500).json({ error: "Erreur lors de la création du code" });
  }
});

// POST /invite/redeem — secretary redeems code and receives a token (public)
router.post("/redeem", async (req: Request, res: Response) => {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: "Code requis" });

    const db = getDb();
    const now = new Date().toISOString();
    const upperCode = (code as string).toUpperCase().trim();

    // Look up a valid, unexpired code
    const result = await db.execute({
      sql: "SELECT * FROM invite_codes WHERE code = ? AND used = 0 AND expires_at > ?",
      args: [upperCode, now],
    });

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Code invalide ou expiré" });
    }

    const invite = result.rows[0];
    const ownerUserId = invite.owner_user_id as string;

    // Fetch doctor's display name from their profile
    const profileResult = await db.execute({
      sql: "SELECT data FROM profiles WHERE user_id = ?",
      args: [ownerUserId],
    });
    const profileData =
      profileResult.rows[0]
        ? JSON.parse(decryptField(profileResult.rows[0].data as string))
        : {};
    const ownerName =
      profileData?.firstName && profileData?.lastName
        ? `Dr. ${profileData.firstName} ${profileData.lastName}`
        : profileData?.practiceName || "Cabinet médical";

    // Create secretary JWT (type distinguishes it from doctor tokens)
    const secretaryId = crypto.randomUUID();
    const secretaryToken = jwt.sign(
      { type: "secretary", ownerUserId, secretaryId, code: upperCode },
      JWT_SECRET,
      { expiresIn: "365d", algorithm: "HS256" },
    );

    // Persist the session so we can revoke it later
    await db.execute({
      sql: `INSERT INTO secretary_sessions
              (id, code, owner_user_id, token, created_at, revoked)
            VALUES (?, ?, ?, ?, ?, 0)
            ON CONFLICT (id) DO UPDATE SET
              code = EXCLUDED.code, owner_user_id = EXCLUDED.owner_user_id,
              token = EXCLUDED.token, created_at = EXCLUDED.created_at, revoked = EXCLUDED.revoked`,
      args: [secretaryId, upperCode, ownerUserId, secretaryToken, now],
    });

    console.log(`[INVITE] Code ${upperCode} redeemed → session ${secretaryId}`);
    return res.json({
      secretaryToken,
      ownerUserId,
      ownerName,
      inviteCode: upperCode,
      linkedAt: now,
    });
  } catch (err: any) {
    console.error("[INVITE] Redeem error:", err.message);
    return res.status(500).json({ error: "Erreur lors de l'activation du code" });
  }
});

// DELETE /invite/revoke — doctor revokes all active secretary sessions
router.delete("/revoke", authRequired, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user.userId;
    const db = getDb();

    await db.execute({
      sql: "UPDATE invite_codes SET used = 1 WHERE owner_user_id = ? AND used = 0",
      args: [userId],
    });

    await db.execute({
      sql: "UPDATE secretary_sessions SET revoked = 1 WHERE owner_user_id = ?",
      args: [userId],
    });

    console.log(`[INVITE] Doctor ${userId} revoked all secretary access`);
    return res.json({ success: true });
  } catch (err: any) {
    console.error("[INVITE] Revoke error:", err.message);
    return res.status(500).json({ error: "Erreur lors de la révocation" });
  }
});

export default router;
