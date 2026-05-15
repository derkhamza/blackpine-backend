import { Router, Request, Response, NextFunction } from "express";
import { getDb } from "../db/database";
import { authRequired } from "../middleware/auth";
import jwt from "jsonwebtoken";

const router = Router();
const JWT_SECRET = process.env.JWT_SECRET || "blackpine-dev-secret-change-in-production";

// ── Secretary auth middleware ────────────────────────────────────────────────

async function secretaryAuthRequired(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Token manquant" });
  }

  const token = header.slice(7);
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    if (decoded.type !== "secretary") {
      return res.status(401).json({ error: "Token invalide" });
    }

    // Verify the session hasn't been revoked
    const db = getDb();
    const result = await db.execute({
      sql: "SELECT revoked FROM secretary_sessions WHERE id = ?",
      args: [decoded.secretaryId],
    });

    if (result.rows.length === 0 || (result.rows[0].revoked as number) === 1) {
      return res.status(401).json({ error: "Accès révoqué" });
    }

    (req as any).secretary = decoded;
    next();
  } catch {
    return res.status(401).json({ error: "Token invalide ou expiré" });
  }
}

// ── Doctor routes ────────────────────────────────────────────────────────────

// POST /cabinet/push — doctor pushes a full snapshot before sharing the code
router.post("/push", authRequired, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user.userId;
    const { appointments, patients, doctorProfile } = req.body;
    const db = getDb();
    const now = new Date().toISOString();

    await db.execute({
      sql: `INSERT INTO cabinet_snapshots
              (owner_user_id, appointments, patients, doctor_profile, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(owner_user_id)
            DO UPDATE SET
              appointments   = excluded.appointments,
              patients       = excluded.patients,
              doctor_profile = excluded.doctor_profile,
              updated_at     = excluded.updated_at`,
      args: [
        userId,
        JSON.stringify(appointments ?? []),
        JSON.stringify(patients ?? []),
        JSON.stringify(doctorProfile ?? {}),
        now,
      ],
    });

    console.log(`[CABINET] Doctor ${userId} pushed snapshot`);
    return res.json({ success: true, updatedAt: now });
  } catch (err: any) {
    console.error("[CABINET] Push error:", err.message);
    return res.status(500).json({ error: "Erreur lors de la sauvegarde" });
  }
});

// ── Secretary routes ─────────────────────────────────────────────────────────

// GET /cabinet/pull — secretary pulls the latest cabinet snapshot
router.get("/pull", secretaryAuthRequired, async (req: Request, res: Response) => {
  try {
    const { ownerUserId } = (req as any).secretary;
    const db = getDb();

    const result = await db.execute({
      sql: "SELECT appointments, patients, doctor_profile FROM cabinet_snapshots WHERE owner_user_id = ?",
      args: [ownerUserId],
    });

    if (result.rows.length === 0) {
      return res.json({ appointments: [], patients: [], doctorProfile: {} });
    }

    const row = result.rows[0];
    return res.json({
      appointments: JSON.parse(row.appointments as string),
      patients: JSON.parse(row.patients as string),
      doctorProfile: JSON.parse(row.doctor_profile as string),
    });
  } catch (err: any) {
    console.error("[CABINET] Pull error:", err.message);
    return res.status(500).json({ error: "Erreur lors de la récupération" });
  }
});

// POST /cabinet/appointments — secretary updates only the appointments slice
router.post(
  "/appointments",
  secretaryAuthRequired,
  async (req: Request, res: Response) => {
    try {
      const { ownerUserId } = (req as any).secretary;
      const { appointments } = req.body;
      const db = getDb();
      const now = new Date().toISOString();

      // Ensure a snapshot row exists first (upsert with empty defaults)
      await db.execute({
        sql: `INSERT OR IGNORE INTO cabinet_snapshots
                (owner_user_id, appointments, patients, doctor_profile, updated_at)
              VALUES (?, ?, '[]', '{}', ?)`,
        args: [ownerUserId, JSON.stringify(appointments ?? []), now],
      });

      await db.execute({
        sql: "UPDATE cabinet_snapshots SET appointments = ?, updated_at = ? WHERE owner_user_id = ?",
        args: [JSON.stringify(appointments ?? []), now, ownerUserId],
      });

      return res.json({ success: true, updatedAt: now });
    } catch (err: any) {
      console.error("[CABINET] Appointments update error:", err.message);
      return res.status(500).json({ error: "Erreur lors de la mise à jour" });
    }
  },
);

// POST /cabinet/patients — secretary updates only the patients slice
router.post(
  "/patients",
  secretaryAuthRequired,
  async (req: Request, res: Response) => {
    try {
      const { ownerUserId } = (req as any).secretary;
      const { patients } = req.body;
      const db = getDb();
      const now = new Date().toISOString();

      // Ensure a snapshot row exists first
      await db.execute({
        sql: `INSERT OR IGNORE INTO cabinet_snapshots
                (owner_user_id, appointments, patients, doctor_profile, updated_at)
              VALUES (?, '[]', ?, '{}', ?)`,
        args: [ownerUserId, JSON.stringify(patients ?? []), now],
      });

      await db.execute({
        sql: "UPDATE cabinet_snapshots SET patients = ?, updated_at = ? WHERE owner_user_id = ?",
        args: [JSON.stringify(patients ?? []), now, ownerUserId],
      });

      return res.json({ success: true, updatedAt: now });
    } catch (err: any) {
      console.error("[CABINET] Patients update error:", err.message);
      return res.status(500).json({ error: "Erreur lors de la mise à jour" });
    }
  },
);

export default router;
