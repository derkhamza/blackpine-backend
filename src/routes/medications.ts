import { Router, Request, Response } from "express";
import { getDb } from "../db/database";
import { authRequired } from "../middleware/auth";
import { normalizeText } from "../util/normalizeText";

const router = Router();

// GET /medications/search?q=...  — search the official DMP/CNOPS reference.
// Doctor-authenticated. Prefix matches rank above mid-word matches.
router.get("/search", authRequired, async (req: Request, res: Response) => {
  try {
    const raw = String(req.query.q ?? "").trim();
    if (raw.length < 2) return res.json({ medications: [] });

    const q = normalizeText(raw);
    if (!q) return res.json({ medications: [] });

    const db = getDb();
    const result = await db.execute({
      sql: `SELECT code, nom, dci, dosage, unite, forme, presentation,
                   ppv, ph, prix_br, type, taux_remboursement
            FROM medications
            WHERE search LIKE ?
            ORDER BY
              CASE WHEN search LIKE ? THEN 0 ELSE 1 END,  -- prefix matches first
              length(nom),
              nom
            LIMIT 30`,
      args: [`%${q}%`, `${q}%`],
    });

    return res.json({
      medications: result.rows.map(r => ({
        code:              r.code as string,
        nom:               r.nom as string,
        dci:               r.dci as string,
        dosage:            r.dosage as string,
        unite:             r.unite as string,
        forme:             r.forme as string,
        presentation:      r.presentation as string,
        ppv:               r.ppv as number,
        ph:                r.ph as number,
        prixBR:            r.prix_br as number,
        type:              r.type as string,
        tauxRemboursement: r.taux_remboursement as string,
      })),
    });
  } catch (err: any) {
    console.error("[MEDS] Search error:", err.message);
    return res.status(500).json({ error: "Erreur lors de la recherche" });
  }
});

// GET /medications/count — quick health/coverage check (auth).
router.get("/count", authRequired, async (_req: Request, res: Response) => {
  try {
    const db = getDb();
    const r = await db.execute("SELECT COUNT(*) AS n FROM medications");
    return res.json({ count: Number(r.rows[0].n) });
  } catch (err: any) {
    console.error("[MEDS] Count error:", err.message);
    return res.status(500).json({ error: "Erreur" });
  }
});

export default router;
