/**
 * Import the official Moroccan DMP/CNOPS medication reference into the
 * `medications` table. Idempotent (INSERT OR REPLACE by code) — safe to re-run
 * when a newer dataset is published.
 *
 * Source: data.gov.ma "Référentiel des médicaments" (CNOPS, ODbL license).
 * Usage:  npx tsx scripts/importMedications.ts [path-to.xlsx]
 *         (defaults to data/dmp-medicaments.xlsx; loads Turso creds from .env)
 */
import "dotenv/config";
import * as XLSX from "xlsx";
import { initDatabase, getDb } from "../src/db/database";
import { normalizeText } from "../src/util/normalizeText";

const num = (v: any): number | null => {
  if (v === "" || v == null) return null;
  const n = typeof v === "number" ? v : parseFloat(String(v).replace(",", "."));
  return Number.isFinite(n) ? n : null;
};
const str = (v: any): string => (v == null ? "" : String(v).trim());

async function main() {
  const file = process.argv[2] || "data/dmp-medicaments.xlsx";
  console.log(`[IMPORT] Reading ${file} …`);

  const wb = XLSX.readFile(file);
  const ws = wb.Sheets[wb.SheetNames[0]];
  const rows = XLSX.utils.sheet_to_json<Record<string, any>>(ws, { defval: "" });
  console.log(`[IMPORT] ${rows.length} rows in sheet.`);

  await initDatabase();
  const db = getDb();

  const stmts = rows
    .map((r) => {
      const code = str(r.CODE);
      const nom = str(r.NOM);
      if (!code || !nom) return null; // skip incomplete rows
      const dci = str(r.DCI1);
      return {
        sql: `INSERT OR REPLACE INTO medications
                (code, nom, dci, dosage, unite, forme, presentation,
                 ppv, ph, prix_br, type, taux_remboursement, search)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        args: [
          code, nom, dci,
          str(r.DOSAGE1), str(r.UNITE_DOSAGE1), str(r.FORME), str(r.PRESENTATION),
          num(r.PPV), num(r.PH), num(r.PRIX_BR),
          str(r.PRINCEPS_GENERIQUE), str(r.TAUX_REMBOURSEMENT),
          normalizeText(`${nom} ${dci}`),
        ],
      };
    })
    .filter((s): s is NonNullable<typeof s> => s !== null);

  console.log(`[IMPORT] Upserting ${stmts.length} medications …`);
  const BATCH = 200;
  let done = 0;
  for (let i = 0; i < stmts.length; i += BATCH) {
    await db.batch(stmts.slice(i, i + BATCH), "write");
    done += Math.min(BATCH, stmts.length - i);
    process.stdout.write(`\r[IMPORT] ${done}/${stmts.length}`);
  }
  process.stdout.write("\n");

  const count = await db.execute("SELECT COUNT(*) AS n FROM medications");
  console.log(`[IMPORT] Done. medications table now holds ${Number(count.rows[0].n)} rows.`);
}

main().catch((err) => {
  console.error("[IMPORT] Failed:", err);
  process.exit(1);
});
