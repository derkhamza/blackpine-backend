import { Router, Request, Response, NextFunction } from "express";
import { getDb } from "../db/database";
import { authRequired } from "../middleware/auth";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import type { Client } from "@libsql/client";
import { encryptField, decryptField } from "./../crypto/dataCipher";

const router = Router();
const JWT_SECRET = process.env.JWT_SECRET || "blackpine-dev-secret-change-in-production";

// ── Automatic backups ─────────────────────────────────────────────────────────
// Keep a rolling history of daily snapshots so a doctor can recover from an
// accidental deletion or corruption that normal sync would otherwise propagate.

const BACKUP_THROTTLE_MS = 20 * 60 * 60 * 1000; // ≈ once per day
const BACKUP_KEEP        = 14;                   // retain the newest N per user

/**
 * Capture a backup of the doctor's current snapshot, throttled to ~once/day
 * (unless `force`). Prunes to the newest BACKUP_KEEP. Best-effort: never throws
 * into the caller's request path.
 */
async function maybeCreateBackup(
  db: Client,
  ownerUserId: string,
  reason: "auto" | "pre-restore" = "auto",
  force = false,
): Promise<void> {
  try {
    if (!force) {
      const last = await db.execute({
        sql: "SELECT created_at FROM cabinet_backups WHERE owner_user_id = ? ORDER BY created_at DESC LIMIT 1",
        args: [ownerUserId],
      });
      if (last.rows.length > 0) {
        const lastMs = new Date(last.rows[0].created_at as string).getTime();
        if (new Date().getTime() - lastMs < BACKUP_THROTTLE_MS) return;
      }
    }

    const snap = await db.execute({
      sql: "SELECT appointments, patients, doctor_profile, extra_data FROM cabinet_snapshots WHERE owner_user_id = ?",
      args: [ownerUserId],
    });
    if (snap.rows.length === 0) return;
    const row = snap.rows[0];

    await db.execute({
      sql: `INSERT INTO cabinet_backups
              (id, owner_user_id, created_at, reason, appointments, patients, doctor_profile, extra_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [
        crypto.randomUUID(),
        ownerUserId,
        new Date().toISOString(),
        reason,
        row.appointments as string,
        row.patients as string,
        row.doctor_profile as string,
        (row.extra_data as string) ?? "{}",
      ],
    });

    // Prune older backups beyond the retention window.
    await db.execute({
      sql: `DELETE FROM cabinet_backups
            WHERE owner_user_id = ?
              AND id NOT IN (
                SELECT id FROM cabinet_backups
                WHERE owner_user_id = ?
                ORDER BY created_at DESC
                LIMIT ?
              )`,
      args: [ownerUserId, ownerUserId, BACKUP_KEEP],
    });
  } catch (err: any) {
    console.error("[CABINET] Backup error:", err.message);
  }
}

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

// ── Legal pages ─────────────────────────────────────────────────────────────

const LEGAL_HTML_SHELL = (title: string, body: string) => `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} — Blackpine Cabinet</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    background: #F7F9F8;
    color: #1A1F1B;
    line-height: 1.75;
  }
  header {
    background: #1F3A2E;
    padding: 18px 24px;
    display: flex;
    align-items: baseline;
    gap: 10px;
  }
  .brand { color: #fff; font-size: 15px; font-weight: 800; letter-spacing: 3px; }
  .brand-sub { color: #C9A84C; font-size: 10px; font-weight: 600; letter-spacing: 3px; }
  main { max-width: 720px; margin: 0 auto; padding: 48px 24px 80px; }
  h1 { color: #1F3A2E; font-size: 26px; font-weight: 800; margin-bottom: 6px; }
  .meta { color: #888; font-size: 13px; margin-bottom: 40px; }
  h2 { color: #1F3A2E; font-size: 16px; font-weight: 700; margin-top: 36px; margin-bottom: 8px; }
  p { margin-bottom: 12px; font-size: 15px; }
  strong { font-weight: 600; }
  a { color: #1F3A2E; }
  nav { margin-top: 56px; padding-top: 24px; border-top: 1px solid #E0E6E2; display: flex; gap: 24px; }
  nav a { font-size: 13px; color: #1F3A2E; font-weight: 600; text-decoration: none; }
  nav a:hover { text-decoration: underline; }
</style>
</head>
<body>
<header>
  <span class="brand">BLACKPINE</span>
  <span class="brand-sub">CABINET</span>
</header>
<main>
${body}
<nav>
  <a href="/cabinet/privacy">Politique de confidentialité</a>
  <a href="/cabinet/terms">Conditions d'utilisation</a>
</nav>
</main>
</body>
</html>`;

router.get("/privacy", (_req: Request, res: Response) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(LEGAL_HTML_SHELL("Politique de Confidentialité", `
<h1>Politique de Confidentialité</h1>
<p class="meta">Dernière mise à jour : avril 2026</p>

<h2>1. Responsable du traitement</h2>
<p>Blackpine Capital Advisory SARL, basée à Oujda, Maroc, est responsable du traitement des données personnelles collectées via l'application Blackpine Cabinet.</p>

<h2>2. Données collectées</h2>
<p>Nous collectons : adresse email, mot de passe (chiffré), informations fiscales du profil professionnel (spécialité, commune, situation familiale, date de début d'activité), transactions financières (recettes et charges), et photos de justificatifs.</p>

<h2>3. Finalité du traitement</h2>
<p>Vos données sont utilisées exclusivement pour : le calcul de vos estimations fiscales, la synchronisation entre vos appareils, la génération de rapports fiscaux (PDF/Excel), et l'amélioration de l'application.</p>

<h2>4. Base légale</h2>
<p>Le traitement est fondé sur votre consentement et sur l'exécution du contrat de service. Conformément à la loi marocaine 09-08 relative à la protection des personnes physiques à l'égard du traitement des données à caractère personnel.</p>

<h2>5. Stockage et sécurité</h2>
<p>Vos données sont stockées sur des serveurs sécurisés. Les mots de passe sont chiffrés avec bcrypt. Les communications sont protégées par HTTPS. Les photos de justificatifs sont stockées localement sur votre appareil.</p>

<h2>6. Partage des données</h2>
<p>Nous ne vendons, ne louons ni ne partageons vos données personnelles avec des tiers, sauf obligation légale.</p>

<h2>7. Durée de conservation</h2>
<p>Vos données sont conservées tant que votre compte est actif. Les données comptables sont conservées conformément aux obligations légales marocaines (10 ans). Vous pouvez demander la suppression de votre compte à tout moment.</p>

<h2>8. Vos droits</h2>
<p>Conformément à la loi 09-08, vous disposez d'un droit d'accès, de rectification et de suppression de vos données. Pour exercer ces droits, contactez-nous à : <a href="mailto:contact@blackpinecap.com">contact@blackpinecap.com</a></p>

<h2>9. Cookies</h2>
<p>L'application mobile n'utilise pas de cookies. Les données de session sont stockées localement sur votre appareil.</p>

<h2>10. Modifications</h2>
<p>Nous nous réservons le droit de modifier cette politique. Toute modification sera notifiée via l'application.</p>

<h2>Contact</h2>
<p>Blackpine Capital Advisory — Oujda, Maroc<br>
<a href="mailto:contact@blackpinecap.com">contact@blackpinecap.com</a></p>
  `));
});

router.get("/terms", (_req: Request, res: Response) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(LEGAL_HTML_SHELL("Conditions d'Utilisation", `
<h1>Conditions Générales d'Utilisation</h1>
<p class="meta">Dernière mise à jour : avril 2026</p>

<h2>1. Objet</h2>
<p>Les présentes conditions régissent l'utilisation de l'application Blackpine Cabinet, éditée par Blackpine Capital Advisory SARL.</p>

<h2>2. Description du service</h2>
<p>Blackpine Cabinet est un outil de gestion financière et d'estimation fiscale destiné aux professionnels de santé exerçant au Maroc. L'application permet l'enregistrement de recettes et charges, le calcul d'estimations d'impôt sur le revenu, et la génération de rapports.</p>

<h2>3. Avertissement fiscal</h2>
<p><strong>Les calculs fournis par l'application sont des estimations et ne constituent pas un avis fiscal professionnel.</strong> Ils ne remplacent pas la consultation d'un expert-comptable agréé. Blackpine Capital Advisory décline toute responsabilité en cas d'erreur dans les calculs ou de décision prise sur la base exclusive des estimations de l'application.</p>

<h2>4. Compte utilisateur</h2>
<p>L'utilisation de l'application nécessite la création d'un compte. Vous êtes responsable de la confidentialité de vos identifiants. Toute activité sous votre compte est présumée effectuée par vous.</p>

<h2>5. Données utilisateur</h2>
<p>Vous conservez la propriété de toutes les données que vous saisissez dans l'application. Nous ne revendiquons aucun droit sur vos données financières. Voir notre <a href="/cabinet/privacy">Politique de Confidentialité</a> pour les détails de traitement.</p>

<h2>6. Disponibilité</h2>
<p>Nous nous efforçons de maintenir le service disponible en permanence mais ne garantissons pas un accès ininterrompu. L'application peut être temporairement indisponible pour maintenance.</p>

<h2>7. Tarification</h2>
<p>Les conditions tarifaires en vigueur sont communiquées dans l'application. Blackpine Capital Advisory se réserve le droit de modifier ses tarifs avec un préavis de 30 jours.</p>

<h2>8. Résiliation</h2>
<p>Vous pouvez supprimer votre compte à tout moment. Nous nous réservons le droit de suspendre ou résilier un compte en cas de violation des présentes conditions.</p>

<h2>9. Limitation de responsabilité</h2>
<p>L'application est fournie "en l'état". Blackpine Capital Advisory ne saurait être tenu responsable des dommages directs ou indirects résultant de l'utilisation de l'application, notamment en cas d'erreur dans les estimations fiscales.</p>

<h2>10. Droit applicable</h2>
<p>Les présentes conditions sont régies par le droit marocain. Tout litige sera soumis aux tribunaux compétents de Casablanca.</p>

<h2>Contact</h2>
<p>Blackpine Capital Advisory — Oujda, Maroc<br>
<a href="mailto:contact@blackpinecap.com">contact@blackpinecap.com</a></p>
  `));
});

// ── Doctor routes ────────────────────────────────────────────────────────────

// POST /cabinet/push — doctor pushes a full snapshot
router.post("/push", authRequired, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user.userId;
    const {
      appointments, patients, doctorProfile,
      // Optimistic-concurrency token: the updated_at the client last saw.
      baseUpdatedAt,
      // Extended fields stored in extra_data
      employees, prescriptionTemplates, prescriptions, certificates,
      stockItems, waTemplates, teleSessions, notes, suppliers,
      purchaseOrders, examResults, invoices, apptDocuments,
    } = req.body;

    const extraData = JSON.stringify({
      employees:             employees             ?? [],
      prescriptionTemplates: prescriptionTemplates ?? [],
      prescriptions:         prescriptions         ?? [],
      certificates:          certificates          ?? [],
      stockItems:            stockItems            ?? [],
      waTemplates:           waTemplates           ?? [],
      teleSessions:          teleSessions          ?? [],
      notes:                 notes                 ?? [],
      suppliers:             suppliers             ?? [],
      purchaseOrders:        purchaseOrders        ?? [],
      examResults:           examResults           ?? [],
      invoices:              invoices              ?? [],
      apptDocuments:         apptDocuments         ?? [],
    });

    const db = getDb();
    const now = new Date().toISOString();

    // ── Optimistic-concurrency check ────────────────────────────────────────
    // If the client sent the version it based its edit on, make sure the
    // server hasn't been written by another device since. This prevents a
    // stale device from silently clobbering newer data.
    if (baseUpdatedAt !== undefined && baseUpdatedAt !== null) {
      const current = await db.execute({
        sql: "SELECT appointments, patients, doctor_profile, extra_data, updated_at FROM cabinet_snapshots WHERE owner_user_id = ?",
        args: [userId],
      });
      if (current.rows.length > 0) {
        const serverUpdatedAt = current.rows[0].updated_at as string;
        if (serverUpdatedAt !== baseUpdatedAt) {
          // Conflict — return the current server snapshot so the client can adopt it.
          const row = current.rows[0];
          const extra = JSON.parse(decryptField((row.extra_data as string) || "{}"));
          console.log(`[CABINET] Doctor ${userId} push conflict (base=${baseUpdatedAt}, server=${serverUpdatedAt})`);
          return res.status(409).json({
            error: "conflict",
            snapshot: {
              appointments:  JSON.parse(decryptField(row.appointments as string)),
              patients:      JSON.parse(decryptField(row.patients as string)),
              doctorProfile: JSON.parse(decryptField(row.doctor_profile as string)),
              updatedAt:     serverUpdatedAt,
              ...extra,
            },
          });
        }
      }
    }

    await db.execute({
      sql: `INSERT INTO cabinet_snapshots
              (owner_user_id, appointments, patients, doctor_profile, extra_data, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(owner_user_id)
            DO UPDATE SET
              appointments   = excluded.appointments,
              patients       = excluded.patients,
              doctor_profile = excluded.doctor_profile,
              extra_data     = excluded.extra_data,
              updated_at     = excluded.updated_at`,
      args: [
        userId,
        encryptField(JSON.stringify(appointments ?? [])),
        encryptField(JSON.stringify(patients ?? [])),
        encryptField(JSON.stringify(doctorProfile ?? {})),
        encryptField(extraData),
        now,
      ],
    });

    await maybeCreateBackup(db, userId);

    console.log(`[CABINET] Doctor ${userId} pushed snapshot`);
    return res.json({ success: true, updatedAt: now });
  } catch (err: any) {
    console.error("[CABINET] Push error:", err.message);
    return res.status(500).json({ error: "Erreur lors de la sauvegarde" });
  }
});

// GET /cabinet/backups — list the doctor's automatic backups (newest first)
router.get("/backups", authRequired, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user.userId;
    const db = getDb();
    const result = await db.execute({
      sql: "SELECT id, created_at, reason FROM cabinet_backups WHERE owner_user_id = ? ORDER BY created_at DESC",
      args: [userId],
    });
    return res.json({
      backups: result.rows.map(r => ({
        id:        r.id as string,
        createdAt: r.created_at as string,
        reason:    r.reason as string,
      })),
    });
  } catch (err: any) {
    console.error("[CABINET] Backups list error:", err.message);
    return res.status(500).json({ error: "Erreur lors de la récupération des sauvegardes" });
  }
});

// POST /cabinet/restore — restore a backup into the live snapshot
router.post("/restore", authRequired, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user.userId;
    const { backupId } = req.body;
    if (!backupId) return res.status(400).json({ error: "backupId requis" });

    const db = getDb();

    const result = await db.execute({
      sql: "SELECT appointments, patients, doctor_profile, extra_data FROM cabinet_backups WHERE id = ? AND owner_user_id = ?",
      args: [backupId, userId],
    });
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Sauvegarde introuvable" });
    }
    const b = result.rows[0];

    // Snapshot the current state first so the restore itself is undoable.
    await maybeCreateBackup(db, userId, "pre-restore", true);

    const now = new Date().toISOString();
    await db.execute({
      sql: `INSERT INTO cabinet_snapshots
              (owner_user_id, appointments, patients, doctor_profile, extra_data, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(owner_user_id)
            DO UPDATE SET
              appointments   = excluded.appointments,
              patients       = excluded.patients,
              doctor_profile = excluded.doctor_profile,
              extra_data     = excluded.extra_data,
              updated_at     = excluded.updated_at`,
      args: [
        userId,
        b.appointments as string,
        b.patients as string,
        b.doctor_profile as string,
        (b.extra_data as string) ?? "{}",
        now,
      ],
    });

    const extra = JSON.parse(decryptField((b.extra_data as string) || "{}"));
    console.log(`[CABINET] Doctor ${userId} restored backup ${backupId}`);
    return res.json({
      success: true,
      snapshot: {
        appointments:  JSON.parse(decryptField(b.appointments as string)),
        patients:      JSON.parse(decryptField(b.patients as string)),
        doctorProfile: JSON.parse(decryptField(b.doctor_profile as string)),
        updatedAt:     now,
        ...extra,
      },
    });
  } catch (err: any) {
    console.error("[CABINET] Restore error:", err.message);
    return res.status(500).json({ error: "Erreur lors de la restauration" });
  }
});

// GET /cabinet/my — doctor pulls their own full snapshot (multi-device sync)
router.get("/my", authRequired, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user.userId;
    const db = getDb();

    const result = await db.execute({
      sql: "SELECT appointments, patients, doctor_profile, extra_data, updated_at FROM cabinet_snapshots WHERE owner_user_id = ?",
      args: [userId],
    });

    if (result.rows.length === 0) {
      return res.json(null); // no snapshot yet
    }

    const row = result.rows[0];
    const extra = JSON.parse(decryptField((row.extra_data as string) || "{}"));

    return res.json({
      appointments:          JSON.parse(decryptField(row.appointments as string)),
      patients:              JSON.parse(decryptField(row.patients as string)),
      doctorProfile:         JSON.parse(decryptField(row.doctor_profile as string)),
      updatedAt:             row.updated_at,
      ...extra,
    });
  } catch (err: any) {
    console.error("[CABINET] My pull error:", err.message);
    return res.status(500).json({ error: "Erreur lors de la récupération" });
  }
});

// ── Secretary write safety ────────────────────────────────────────────────────
// A secretary may only write a whitelist of scheduling / contact fields. Every
// other field (clinical notes, vitals, billing, …) is preserved from the server,
// and existing records are never hard-deleted. This makes it impossible for a
// secretary — even with a stale snapshot — to clobber the doctor's clinical data.

const SECRETARY_APPT_FIELDS = [
  "date", "startTime", "endTime", "status", "type",
  "patientId", "patientName", "patientPhone", "motif", "notes",
  "location", "recurringRuleId", "reminderSent",
  // Moroccan secretaries take the measurements and handle billing at the desk.
  "vitalSigns",
  "billedAt", "billedAmount", "invoiceNumber", "invoiceIssuedAt",
  // Itemized billing + payment tracking (the secretary encaisse; the items and
  // reduction she stamps come from the doctor's prepared bill).
  "billedItems", "billedReduction", "paidAmount", "payments",
  "preparedItems", "preparedReduction",
  // Bilan clinique types added at the desk (the measurement VALUES ride in
  // consultationNote.extraFields, merged separately key-by-key below).
  "extraBilans",
  "mutuellePapersFilled", "mutuellePapersDate",
];
const SECRETARY_PATIENT_FIELDS = [
  "firstName", "lastName", "phone", "email", "address", "city",
  "dob", "gender", "cin", "cnops", "mutuelle",
];

function mergeSecretaryWrite(
  serverList: any[],
  incoming: any[],
  allowedFields: string[],
): any[] {
  const serverById = new Map<string, any>(
    (serverList ?? []).filter(x => x && x.id).map(x => [x.id, x]),
  );
  const incomingById = new Map<string, any>(
    (incoming ?? []).filter(x => x && x.id).map(x => [x.id, x]),
  );

  const result: any[] = [];

  // 1. Reconcile every server record (never delete server records).
  for (const [id, srv] of serverById) {
    const inc = incomingById.get(id);
    if (!inc) { result.push(srv); continue; } // secretary didn't send it → keep as-is
    const merged = { ...srv };                 // start from server (preserves clinical fields)
    for (const f of allowedFields) {
      if (Object.prototype.hasOwnProperty.call(inc, f)) merged[f] = inc[f];
    }
    result.push(merged);
  }

  // 2. Append brand-new records the secretary created (id not on server).
  for (const [id, inc] of incomingById) {
    if (!serverById.has(id)) result.push(inc);
  }

  return result;
}

// ── Secretary routes ─────────────────────────────────────────────────────────

// GET /cabinet/pull — secretary pulls the latest cabinet snapshot
router.get("/pull", secretaryAuthRequired, async (req: Request, res: Response) => {
  try {
    const { ownerUserId } = (req as any).secretary;
    const db = getDb();

    const result = await db.execute({
      sql: "SELECT appointments, patients, doctor_profile, extra_data FROM cabinet_snapshots WHERE owner_user_id = ?",
      args: [ownerUserId],
    });

    if (result.rows.length === 0) {
      return res.json({ appointments: [], patients: [], doctorProfile: {}, apptDocuments: [] });
    }

    const row = result.rows[0];
    const extra = JSON.parse(decryptField((row.extra_data as string) || "{}"));
    return res.json({
      appointments: JSON.parse(decryptField(row.appointments as string)),
      patients: JSON.parse(decryptField(row.patients as string)),
      doctorProfile: JSON.parse(decryptField(row.doctor_profile as string)),
      // Appointment attachments: the desk attaches analyses / mutuelle forms /
      // scans, so the secretary sees and adds them (no other extra collection
      // is exposed to secretary sessions).
      apptDocuments: Array.isArray(extra.apptDocuments) ? extra.apptDocuments : [],
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
      const { appointments, deletedIds } = req.body;
      const db = getDb();
      const now = new Date().toISOString();

      // Ensure a snapshot row exists first (empty defaults)
      await db.execute({
        sql: `INSERT OR IGNORE INTO cabinet_snapshots
                (owner_user_id, appointments, patients, doctor_profile, updated_at)
              VALUES (?, '[]', '[]', '{}', ?)`,
        args: [ownerUserId, now],
      });

      // Merge against the current server array so clinical fields are preserved
      // and the doctor's concurrent records are never lost.
      const cur = await db.execute({
        sql: "SELECT appointments FROM cabinet_snapshots WHERE owner_user_id = ?",
        args: [ownerUserId],
      });
      const serverAppts = cur.rows.length ? JSON.parse(decryptField(cur.rows[0].appointments as string)) : [];
      let merged = mergeSecretaryWrite(serverAppts, appointments ?? [], SECRETARY_APPT_FIELDS);

      // Secretaries take measurements: accept consultationNote.extraFields
      // (bilan clinique spécialisé / specialty measurement fields) key-by-key,
      // while every other part of the clinical note (motif, examen, diagnostic,
      // traitement) stays exactly as the doctor wrote it on the server.
      const incApptById = new Map<string, any>(
        (appointments ?? []).filter((x: any) => x && x.id).map((x: any) => [x.id, x]),
      );
      merged = merged.map((a: any) => {
        const inc = incApptById.get(a.id);
        const incExtra = inc?.consultationNote?.extraFields;
        if (!incExtra || typeof incExtra !== "object") return a;
        const srvNote = a.consultationNote ?? {};
        return {
          ...a,
          consultationNote: {
            ...srvNote,
            extraFields: { ...(srvNote.extraFields ?? {}), ...incExtra },
          },
        };
      });

      // Secretaries manage the schedule, so explicit appointment deletions are
      // honoured — but only via this explicit id list (a stale/partial push can
      // still never silently drop records).
      if (Array.isArray(deletedIds) && deletedIds.length > 0) {
        const gone = new Set(deletedIds.filter((x: unknown) => typeof x === "string"));
        merged = merged.filter((a: any) => !gone.has(a.id));
      }

      await db.execute({
        sql: "UPDATE cabinet_snapshots SET appointments = ?, updated_at = ? WHERE owner_user_id = ?",
        args: [encryptField(JSON.stringify(merged)), now, ownerUserId],
      });

      await maybeCreateBackup(db, ownerUserId);

      return res.json({ success: true, updatedAt: now, appointments: merged });
    } catch (err: any) {
      console.error("[CABINET] Appointments update error:", err.message);
      return res.status(500).json({ error: "Erreur lors de la mise à jour" });
    }
  },
);

// POST /cabinet/appt-documents — secretary adds appointment attachments.
// Append-only by id (an existing server document is never modified by a
// secretary push); explicit deletions travel in deletedIds, like the other
// secretary slices. All other extra_data collections are untouched.
router.post(
  "/appt-documents",
  secretaryAuthRequired,
  async (req: Request, res: Response) => {
    try {
      const { ownerUserId } = (req as any).secretary;
      const { documents, deletedIds } = req.body;
      const db = getDb();
      const now = new Date().toISOString();

      await db.execute({
        sql: `INSERT OR IGNORE INTO cabinet_snapshots
                (owner_user_id, appointments, patients, doctor_profile, updated_at)
              VALUES (?, '[]', '[]', '{}', ?)`,
        args: [ownerUserId, now],
      });

      const cur = await db.execute({
        sql: "SELECT extra_data FROM cabinet_snapshots WHERE owner_user_id = ?",
        args: [ownerUserId],
      });
      const extra = cur.rows.length
        ? JSON.parse(decryptField((cur.rows[0].extra_data as string) || "{}"))
        : {};
      const serverDocs: any[] = Array.isArray(extra.apptDocuments) ? extra.apptDocuments : [];
      const serverIds = new Set(serverDocs.map((d: any) => d?.id).filter(Boolean));

      let merged = [...serverDocs];
      for (const doc of Array.isArray(documents) ? documents : []) {
        if (doc && doc.id && !serverIds.has(doc.id)) merged.push(doc);
      }
      if (Array.isArray(deletedIds) && deletedIds.length > 0) {
        const gone = new Set(deletedIds.filter((x: unknown) => typeof x === "string"));
        merged = merged.filter((d: any) => !gone.has(d.id));
      }

      extra.apptDocuments = merged;
      await db.execute({
        sql: "UPDATE cabinet_snapshots SET extra_data = ?, updated_at = ? WHERE owner_user_id = ?",
        args: [encryptField(JSON.stringify(extra)), now, ownerUserId],
      });

      return res.json({ success: true, updatedAt: now, apptDocuments: merged });
    } catch (err: any) {
      console.error("[CABINET] Appt-documents update error:", err.message);
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
      const { patients, deletedIds } = req.body;
      const db = getDb();
      const now = new Date().toISOString();

      // Ensure a snapshot row exists first
      await db.execute({
        sql: `INSERT OR IGNORE INTO cabinet_snapshots
                (owner_user_id, appointments, patients, doctor_profile, updated_at)
              VALUES (?, '[]', '[]', '{}', ?)`,
        args: [ownerUserId, now],
      });

      // Merge against the current server array so clinical fields (allergies,
      // antecedents, medications, …) are preserved and records aren't lost.
      const cur = await db.execute({
        sql: "SELECT patients FROM cabinet_snapshots WHERE owner_user_id = ?",
        args: [ownerUserId],
      });
      const serverPatients = cur.rows.length ? JSON.parse(decryptField(cur.rows[0].patients as string)) : [];
      let merged = mergeSecretaryWrite(serverPatients, patients ?? [], SECRETARY_PATIENT_FIELDS);

      // Secretaries manage the patient desk, so explicit record deletions are
      // honoured — only via this explicit id list (a stale/partial push can
      // still never silently drop records).
      if (Array.isArray(deletedIds) && deletedIds.length > 0) {
        const gone = new Set(deletedIds.filter((x: unknown) => typeof x === "string"));
        merged = merged.filter((p: any) => !gone.has(p.id));
      }

      await db.execute({
        sql: "UPDATE cabinet_snapshots SET patients = ?, updated_at = ? WHERE owner_user_id = ?",
        args: [encryptField(JSON.stringify(merged)), now, ownerUserId],
      });

      await maybeCreateBackup(db, ownerUserId);

      return res.json({ success: true, updatedAt: now, patients: merged });
    } catch (err: any) {
      console.error("[CABINET] Patients update error:", err.message);
      return res.status(500).json({ error: "Erreur lors de la mise à jour" });
    }
  },
);

export default router;
