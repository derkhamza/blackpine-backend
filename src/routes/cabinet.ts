import { Router, Request, Response, NextFunction } from "express";
import { getDb } from "../db/database";
import { authRequired, JWT_SECRET } from "../middleware/auth";
import { subscriptionRequired } from "../middleware/subscription";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import type { DbClient as Client } from "../db/database";
import { encryptField, decryptField } from "./../crypto/dataCipher";
import { webPushPublicKey, saveWebPushSub, sendWebPushToOtherRole } from "../push/webPush";

const router = Router();

// A snapshot's version is its updated_at; derive a stable ETag from it so pulls
// can be answered with 304 Not Modified when nothing has changed. Every write
// path bumps updated_at, so any change (doctor or secretary) busts the tag.
function snapshotEtag(updatedAt: string | null | undefined): string {
  return `"cab-${Buffer.from(String(updatedAt ?? "0")).toString("base64url")}"`;
}

// A content hash of the appointment attachments, used to skip re-sending the
// (heavy) base64 blobs on a pull when the client already holds the current set.
// Hashing a few MB is milliseconds and only runs on the non-304 path.
function apptDocsVersion(docs: unknown[]): string {
  return crypto.createHash("sha1").update(JSON.stringify(docs ?? [])).digest("base64url");
}

// Per-column content versions (JSON {a,p,r,e}) so a pull can send only the columns
// the client doesn't already hold, cutting Neon egress. Hash the PLAINTEXT JSON —
// encryption uses a random IV, so ciphertext isn't stable per content.
const colvHash = (json: string) => crypto.createHash("sha1").update(json).digest("base64url").slice(0, 12);
function buildColVersions(apptsJson: string, patientsJson: string, profileJson: string, extraJson: string): string {
  return JSON.stringify({ a: colvHash(apptsJson), p: colvHash(patientsJson), r: colvHash(profileJson), e: colvHash(extraJson) });
}
type ColVersions = { a: string; p: string; r: string; e: string };
function parseColVersions(raw: string | null | undefined): ColVersions | null {
  if (!raw) return null;
  try {
    const o = JSON.parse(raw);
    if (o && typeof o.a === "string" && typeof o.p === "string" && typeof o.r === "string" && typeof o.e === "string") {
      return { a: o.a, p: o.p, r: o.r, e: o.e };
    }
  } catch { /* malformed → treat as absent (full snapshot) */ }
  return null;
}
// Recompute ONE column's version after a secretary slice write, preserving the
// others (the secretary touched only this column). Returns null when the row has
// no baseline yet — the doctor's next full push establishes all four; until then
// the doctor pull safely falls back to full snapshots. Keeping the untouched
// columns' hashes intact is what lets the doctor pull skip them.
function bumpColVersion(prevRaw: string | null | undefined, key: keyof ColVersions, json: string): string | null {
  const prev = parseColVersions(prevRaw);
  if (!prev) return null;
  return JSON.stringify({ ...prev, [key]: colvHash(json) });
}

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
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] }) as any;
    if (decoded.type !== "secretary") {
      return res.status(401).json({ error: "Token invalide" });
    }

    // Verify the session hasn't been revoked, AND that the owner hasn't reset
    // their password / "logged out everywhere" since this token was minted — the
    // owner's tokens_valid_after is a cabinet-wide revocation point that must also
    // kill long-lived (365d) secretary tokens, not just the doctor's own.
    const db = getDb();
    const result = await db.execute({
      sql: `SELECT s.revoked AS revoked, u.tokens_valid_after AS cutoff
              FROM secretary_sessions s
              LEFT JOIN users u ON u.id = ?
             WHERE s.id = ?`,
      args: [decoded.ownerUserId, decoded.secretaryId],
    });

    if (result.rows.length === 0 || (result.rows[0].revoked as number) === 1) {
      return res.status(401).json({ error: "Accès révoqué" });
    }
    const cutoff = result.rows[0].cutoff as string | null | undefined;
    if (cutoff && decoded.iat && decoded.iat < Math.floor(new Date(cutoff).getTime() / 1000)) {
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
router.post("/push", authRequired, subscriptionRequired, async (req: Request, res: Response) => {
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
      examRequests, medicalReports,
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
      examRequests:          examRequests          ?? [],
      medicalReports:        medicalReports        ?? [],
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

    const apptsJson    = JSON.stringify(appointments ?? []);
    const patientsJson = JSON.stringify(patients ?? []);
    const profileJson  = JSON.stringify(doctorProfile ?? {});
    const cv = buildColVersions(apptsJson, patientsJson, profileJson, extraData);

    await db.execute({
      sql: `INSERT INTO cabinet_snapshots
              (owner_user_id, appointments, patients, doctor_profile, extra_data, updated_at, col_versions)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(owner_user_id)
            DO UPDATE SET
              appointments   = excluded.appointments,
              patients       = excluded.patients,
              doctor_profile = excluded.doctor_profile,
              extra_data     = excluded.extra_data,
              updated_at     = excluded.updated_at,
              col_versions   = excluded.col_versions`,
      args: [
        userId,
        encryptField(apptsJson),
        encryptField(patientsJson),
        encryptField(profileJson),
        encryptField(extraData),
        now,
        cv,
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
router.post("/restore", authRequired, subscriptionRequired, async (req: Request, res: Response) => {
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
    // Recompute col_versions from the restored plaintext so the next delta pull
    // sees the columns changed and re-sends them (otherwise a doctor on another
    // device would keep the pre-restore data until the periodic full pull).
    const apptsJson    = decryptField(b.appointments as string);
    const patientsJson = decryptField(b.patients as string);
    const profileJson  = decryptField(b.doctor_profile as string);
    const extraJson    = decryptField((b.extra_data as string) || "{}");
    const cv = buildColVersions(apptsJson, patientsJson, profileJson, extraJson);
    await db.execute({
      sql: `INSERT INTO cabinet_snapshots
              (owner_user_id, appointments, patients, doctor_profile, extra_data, updated_at, col_versions)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(owner_user_id)
            DO UPDATE SET
              appointments   = excluded.appointments,
              patients       = excluded.patients,
              doctor_profile = excluded.doctor_profile,
              extra_data     = excluded.extra_data,
              updated_at     = excluded.updated_at,
              col_versions   = excluded.col_versions`,
      args: [
        userId,
        b.appointments as string,
        b.patients as string,
        b.doctor_profile as string,
        (b.extra_data as string) ?? "{}",
        now,
        cv,
      ],
    });

    const extra = JSON.parse(extraJson);
    console.log(`[CABINET] Doctor ${userId} restored backup ${backupId}`);
    return res.json({
      success: true,
      snapshot: {
        appointments:  JSON.parse(apptsJson),
        patients:      JSON.parse(patientsJson),
        doctorProfile: JSON.parse(profileJson),
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

    // Light conditional-GET path: read ONLY updated_at first so an unchanged
    // poll (the overwhelming majority) never drags the multi-MB encrypted
    // snapshot out of Turso just to be discarded. Tag by updated_at and answer
    // with a bodyless 304 — cuts function duration + DB egress on the hot path.
    const verRow = await db.execute({
      sql: "SELECT updated_at, col_versions FROM cabinet_snapshots WHERE owner_user_id = ?",
      args: [userId],
    });
    if (verRow.rows.length === 0) {
      return res.json(null); // no snapshot yet
    }
    const etag = snapshotEtag(verRow.rows[0].updated_at as string);
    res.setHeader("ETag", etag);
    // Cache-Control is set globally to no-store (per-user data — see api/index.ts).
    if (req.headers["if-none-match"] === etag) {
      return res.status(304).end();
    }

    // Per-column delta: something changed (ETag differs), but usually only ONE
    // column did. Send only the columns whose content version differs from what
    // the client already holds — the client passes its last-seen versions in
    // ?cv=<json {a,p,r,e}>. This is the real Neon-egress win: an appointment edit
    // no longer drags the patients list + all clinical extras out of the DB.
    // Fall back to a FULL snapshot whenever either side lacks versions (a legacy
    // row not yet rewritten, or the client's first delta-aware pull) — safety
    // over savings. applySnapshot is partial-safe (absent column = keep current),
    // and the client's periodic full pull self-heals any missed delta.
    const serverCv = parseColVersions(verRow.rows[0].col_versions as string | null);
    const clientCv = parseColVersions(String(req.query.cv || "") || null);
    const full = !serverCv || !clientCv;
    const need = {
      a: full || serverCv!.a !== clientCv!.a,
      p: full || serverCv!.p !== clientCv!.p,
      r: full || serverCv!.r !== clientCv!.r,
      e: full || serverCv!.e !== clientCv!.e,
    };

    // Fetch (and thus pull out of Neon) only the columns we actually need to send.
    const cols = ["updated_at", "col_versions"];
    if (need.a) cols.push("appointments");
    if (need.p) cols.push("patients");
    if (need.r) cols.push("doctor_profile");
    if (need.e) cols.push("extra_data");
    const result = await db.execute({
      sql: `SELECT ${cols.join(", ")} FROM cabinet_snapshots WHERE owner_user_id = ?`,
      args: [userId],
    });
    if (result.rows.length === 0) {
      return res.json(null); // deleted between the two reads
    }
    const row = result.rows[0];
    // Re-tag from the fetched row so the client's stored ETag matches the body it
    // actually received (guards the rare change-between-reads race).
    res.setHeader("ETag", snapshotEtag(row.updated_at as string));

    // Always send updatedAt + colVersions so the client can store the new
    // per-column baseline; data columns ride along only when changed.
    const body: any = {
      updatedAt:   row.updated_at,
      colVersions: (row.col_versions as string) || null,
    };
    if (need.a) body.appointments  = JSON.parse(decryptField(row.appointments as string));
    if (need.p) body.patients      = JSON.parse(decryptField(row.patients as string));
    if (need.r) body.doctorProfile = JSON.parse(decryptField(row.doctor_profile as string));
    if (need.e) {
      const extra = JSON.parse(decryptField((row.extra_data as string) || "{}"));
      // Attachments (base64 scans/PDFs) are the heaviest part of extra_data but
      // rarely change, so version them separately and include the bytes only when
      // the client's version is stale (absent = "you already have the files").
      const { apptDocuments: docs, ...restExtra } = extra;
      const docsArr = Array.isArray(docs) ? docs : [];
      const docsVer = apptDocsVersion(docsArr);
      Object.assign(body, restExtra);
      body.apptDocumentsVersion = docsVer;
      if (String(req.query.docsVersion || "") !== docsVer) body.apptDocuments = docsArr;
    }
    return res.json(body);
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
  "date", "startTime", "endTime", "status", "type", "labelId",
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
  // consultationNote.extraFields, merged separately key-by-key below). The
  // secretary can also place a group in a section and add free-form measures.
  "extraBilans", "bilanSource", "customMeasures",
  // AMO / mutuelle paperwork + follow-up date — the secretary manages the
  // Suivi & AMO tab (paperwork, encaissement, next-visit scheduling).
  "mutuellePapersFilled", "mutuellePapersDate", "followUpDate",
];
// Field names MUST match the canonical Patient schema (web cabinetTypes.ts /
// the shared snapshot) exactly — a name the client never sends (e.g. "dob"
// instead of "dateOfBirth") silently drops the secretary's edit on merge, so
// the value reverts a couple seconds after they type it.
const SECRETARY_PATIENT_FIELDS = [
  "firstName", "lastName", "arabicName", "phone", "email", "address", "city",
  "dateOfBirth", "gender", "cin", "cnopsNumber", "mutuelle",
  // Patient-desk fields the secretary edits in the patient form.
  "bloodType", "allergies", "antecedents", "notes",
  // The secretary records the patient's current treatment at check-in.
  "currentMedications",
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

  // 2. Append brand-new records the secretary created (id not on server), but
  // FILTER them to the same allow-list — otherwise a tampered client could stamp
  // clinical fields (examen, diagnostic, traitement…) onto a new record, since
  // step 1's whitelist only guards records that already exist on the server.
  // The permitted clinical bits (consultationNote.motif / extraFields) are re-
  // added selectively by the caller after this merge.
  const STRUCTURAL = ["createdAt", "updatedAt"]; // harmless metadata, no clinical content
  for (const [id, inc] of incomingById) {
    if (serverById.has(id)) continue;
    const clean: any = { id };
    for (const f of allowedFields) {
      if (Object.prototype.hasOwnProperty.call(inc, f)) clean[f] = inc[f];
    }
    for (const f of STRUCTURAL) {
      if (Object.prototype.hasOwnProperty.call(inc, f)) clean[f] = inc[f];
    }
    result.push(clean);
  }

  return result;
}

// ── Secretary routes ─────────────────────────────────────────────────────────

// GET /cabinet/pull — secretary pulls the latest cabinet snapshot
router.get("/pull", secretaryAuthRequired, async (req: Request, res: Response) => {
  try {
    const { ownerUserId } = (req as any).secretary;
    const db = getDb();

    // Light conditional-GET path — see /cabinet/my. Read updated_at + col_versions
    // first so an unchanged desk poll never pulls the full encrypted snapshot.
    const verRow = await db.execute({
      sql: "SELECT updated_at, col_versions FROM cabinet_snapshots WHERE owner_user_id = ?",
      args: [ownerUserId],
    });
    if (verRow.rows.length === 0) {
      return res.json({ appointments: [], patients: [], doctorProfile: {}, apptDocuments: [] });
    }
    const etag = snapshotEtag(verRow.rows[0].updated_at as string);
    res.setHeader("ETag", etag);
    // Cache-Control is set globally to no-store (per-user data — see api/index.ts).
    if (req.headers["if-none-match"] === etag) {
      return res.status(304).end();
    }

    // Per-column delta (see /cabinet/my). The desk only ever sees appointments,
    // patients, doctorProfile and the apptDocuments attachments (inside
    // extra_data) — other extra collections are never exposed to a secretary.
    // Send only the columns whose version differs from the client's ?cv=; the
    // extra_data fetch is itself gated on the `e` version, so an appointment edit
    // no longer drags the patients list + attachments out of Neon.
    const serverCv = parseColVersions(verRow.rows[0].col_versions as string | null);
    const clientCv = parseColVersions(String(req.query.cv || "") || null);
    const full = !serverCv || !clientCv;
    const need = {
      a: full || serverCv!.a !== clientCv!.a,
      p: full || serverCv!.p !== clientCv!.p,
      r: full || serverCv!.r !== clientCv!.r,
      e: full || serverCv!.e !== clientCv!.e,
    };

    const cols = ["updated_at", "col_versions"];
    if (need.a) cols.push("appointments");
    if (need.p) cols.push("patients");
    if (need.r) cols.push("doctor_profile");
    if (need.e) cols.push("extra_data");
    const result = await db.execute({
      sql: `SELECT ${cols.join(", ")} FROM cabinet_snapshots WHERE owner_user_id = ?`,
      args: [ownerUserId],
    });
    if (result.rows.length === 0) {
      return res.json({ appointments: [], patients: [], doctorProfile: {}, apptDocuments: [] });
    }
    const row = result.rows[0];
    res.setHeader("ETag", snapshotEtag(row.updated_at as string));

    // Always echo the full col_versions baseline; data columns ride only when changed.
    const body: any = { colVersions: (row.col_versions as string) || null };
    if (need.a) body.appointments  = JSON.parse(decryptField(row.appointments as string));
    if (need.p) body.patients      = JSON.parse(decryptField(row.patients as string));
    if (need.r) body.doctorProfile = JSON.parse(decryptField(row.doctor_profile as string));
    if (need.e) {
      const extra = JSON.parse(decryptField((row.extra_data as string) || "{}"));
      const docsArr = Array.isArray(extra.apptDocuments) ? extra.apptDocuments : [];
      const docsVer = apptDocsVersion(docsArr);
      body.apptDocumentsVersion = docsVer;
      // Attachments are heavy + rarely change — send only when the client's
      // version is stale; omission means "keep the copy you already have".
      if (String(req.query.docsVersion || "") !== docsVer) body.apptDocuments = docsArr;
    }
    return res.json(body);
  } catch (err: any) {
    console.error("[CABINET] Pull error:", err.message);
    return res.status(500).json({ error: "Erreur lors de la récupération" });
  }
});

// POST /cabinet/appointments — secretary updates only the appointments slice
router.post(
  "/appointments",
  secretaryAuthRequired,
  subscriptionRequired,
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
        sql: "SELECT appointments, col_versions FROM cabinet_snapshots WHERE owner_user_id = ?",
        args: [ownerUserId],
      });
      const serverAppts = cur.rows.length ? JSON.parse(decryptField(cur.rows[0].appointments as string)) : [];
      let merged = mergeSecretaryWrite(serverAppts, appointments ?? [], SECRETARY_APPT_FIELDS);

      // Secretaries take measurements and record the reason for visit at the
      // desk: accept consultationNote.extraFields (bilan clinique spécialisé /
      // specialty measurement fields) key-by-key AND consultationNote.motif,
      // while the rest of the clinical note (examen, diagnostic, traitement)
      // stays exactly as the doctor wrote it on the server.
      const incApptById = new Map<string, any>(
        (appointments ?? []).filter((x: any) => x && x.id).map((x: any) => [x.id, x]),
      );
      merged = merged.map((a: any) => {
        const inc = incApptById.get(a.id);
        const incNote = inc?.consultationNote;
        if (!incNote || typeof incNote !== "object") return a;
        const incExtra = incNote.extraFields;
        const hasExtra = incExtra && typeof incExtra === "object";
        const hasMotif = typeof incNote.motif === "string"; // reason for visit, recorded at check-in
        if (!hasExtra && !hasMotif) return a;
        const srvNote = a.consultationNote ?? {};
        return {
          ...a,
          consultationNote: {
            ...srvNote,
            ...(hasMotif ? { motif: incNote.motif || undefined } : {}),
            ...(hasExtra ? { extraFields: { ...(srvNote.extraFields ?? {}), ...incExtra } } : {}),
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

      const mergedJson = JSON.stringify(merged);
      const cv = bumpColVersion(cur.rows[0]?.col_versions as string | null, "a", mergedJson);
      await db.execute({
        sql: "UPDATE cabinet_snapshots SET appointments = ?, updated_at = ?, col_versions = ? WHERE owner_user_id = ?",
        args: [encryptField(mergedJson), now, cv, ownerUserId],
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
  subscriptionRequired,
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
        sql: "SELECT extra_data, col_versions FROM cabinet_snapshots WHERE owner_user_id = ?",
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
      const extraJson = JSON.stringify(extra);
      const cv = bumpColVersion(cur.rows[0]?.col_versions as string | null, "e", extraJson);
      await db.execute({
        sql: "UPDATE cabinet_snapshots SET extra_data = ?, updated_at = ?, col_versions = ? WHERE owner_user_id = ?",
        args: [encryptField(extraJson), now, cv, ownerUserId],
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
  subscriptionRequired,
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
        sql: "SELECT patients, col_versions FROM cabinet_snapshots WHERE owner_user_id = ?",
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

      const mergedJson = JSON.stringify(merged);
      const cv = bumpColVersion(cur.rows[0]?.col_versions as string | null, "p", mergedJson);
      await db.execute({
        sql: "UPDATE cabinet_snapshots SET patients = ?, updated_at = ?, col_versions = ? WHERE owner_user_id = ?",
        args: [encryptField(mergedJson), now, cv, ownerUserId],
      });

      await maybeCreateBackup(db, ownerUserId);

      return res.json({ success: true, updatedAt: now, patients: merged });
    } catch (err: any) {
      console.error("[CABINET] Patients update error:", err.message);
      return res.status(500).json({ error: "Erreur lors de la mise à jour" });
    }
  },
);

// ── Live signal bus (doctor ↔ secretary) ─────────────────────────────────────
// A featherweight channel, separate from the heavy snapshot: the doctor calling
// a patient in ("Faire entrer") or ringing the secretary is reflected within the
// poll interval (~2.5 s) instead of the 25 s snapshot floor, with a toast. Accepts
// EITHER a doctor token or a secretary token and resolves the cabinet + role, so
// both sides share the same two endpoints. Rows are tiny and pruned aggressively.
async function cabinetIdentity(req: Request, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) return res.status(401).json({ error: "Token manquant" });
  try {
    const decoded = jwt.verify(header.slice(7), JWT_SECRET, { algorithms: ["HS256"] }) as any;
    if (decoded.type === "secretary") {
      const db = getDb();
      const r = await db.execute({
        sql: `SELECT s.revoked AS revoked, u.tokens_valid_after AS cutoff
                FROM secretary_sessions s
                LEFT JOIN users u ON u.id = ?
               WHERE s.id = ?`,
        args: [decoded.ownerUserId, decoded.secretaryId],
      });
      if (r.rows.length === 0 || (r.rows[0].revoked as number) === 1) {
        return res.status(401).json({ error: "Accès révoqué" });
      }
      const cutoff = r.rows[0].cutoff as string | null | undefined;
      if (cutoff && decoded.iat && decoded.iat < Math.floor(new Date(cutoff).getTime() / 1000)) {
        return res.status(401).json({ error: "Accès révoqué" });
      }
      (req as any).cab = { ownerUserId: decoded.ownerUserId, role: "secretary" };
    } else {
      (req as any).cab = { ownerUserId: decoded.userId, role: "doctor" };
    }
    next();
  } catch {
    return res.status(401).json({ error: "Token invalide ou expiré" });
  }
}

// POST /cabinet/signal — emit a live signal to the OTHER side of the cabinet.
router.post("/signal", cabinetIdentity, async (req: Request, res: Response) => {
  try {
    const { ownerUserId, role } = (req as any).cab;
    const { type, payload, fromName } = req.body ?? {};
    if (!type || typeof type !== "string") return res.status(400).json({ error: "type requis" });
    const db = getDb();
    const now = new Date().toISOString();
    await db.execute({
      sql: `INSERT INTO cabinet_signals (id, owner_user_id, from_role, from_name, type, payload, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
      args: [
        crypto.randomUUID(), ownerUserId, role,
        typeof fromName === "string" ? fromName.slice(0, 80) : null,
        type.slice(0, 40), JSON.stringify(payload ?? {}).slice(0, 2000), now,
      ],
    });
    // Keep the table tiny: drop this cabinet's signals older than 2h.
    await db.execute({
      sql: "DELETE FROM cabinet_signals WHERE owner_user_id = ? AND created_at < ?",
      args: [ownerUserId, new Date(Date.now() - 2 * 3600_000).toISOString()],
    });
    // Also fire a browser push to the other side so they're alerted even when the
    // tab is backgrounded/closed (the in-app poll only fires while it's visible).
    const p = (payload ?? {}) as any;
    const who = typeof fromName === "string" && fromName ? fromName : (role === "doctor" ? "Le médecin" : "La secrétaire");
    const pushBody = type === "patient_called"
      ? `Patient appelé en consultation${p.patientName ? " : " + p.patientName : ""}`
      : type === "intercom"
        ? `${who} vous appelle`
        : "Nouvelle notification";
    await sendWebPushToOtherRole(ownerUserId, role, { title: "Blackpine", body: pushBody, tag: "bp-" + type });
    return res.json({ ok: true, createdAt: now });
  } catch (err: any) {
    console.error("[CABINET] Signal emit error:", err.message);
    return res.status(500).json({ error: "Erreur" });
  }
});

// GET /cabinet/signals?since=<iso> — poll for signals from the OTHER role. Pass
// back the server `now` from the previous response as the next `since` (avoids
// client clock skew). Defaults to the last minute on first poll.
router.get("/signals", cabinetIdentity, async (req: Request, res: Response) => {
  try {
    const { ownerUserId, role } = (req as any).cab;
    const since = typeof req.query.since === "string" && req.query.since
      ? req.query.since
      : new Date(Date.now() - 60_000).toISOString();
    const db = getDb();
    const r = await db.execute({
      sql: `SELECT id, from_role, from_name, type, payload, created_at
            FROM cabinet_signals
            WHERE owner_user_id = ? AND from_role <> ? AND created_at > ?
            ORDER BY created_at ASC LIMIT 20`,
      args: [ownerUserId, role, since],
    });
    return res.json({
      now: new Date().toISOString(),
      signals: r.rows.map((s: any) => ({
        id: s.id, fromRole: s.from_role, fromName: s.from_name,
        type: s.type, payload: JSON.parse((s.payload as string) || "{}"), createdAt: s.created_at,
      })),
    });
  } catch (err: any) {
    console.error("[CABINET] Signals poll error:", err.message);
    return res.status(500).json({ error: "Erreur" });
  }
});

// ── Web push (browser notifications) ─────────────────────────────────────────
// The public VAPID key the browser needs to subscribe (not secret).
router.get("/vapid-key", (_req: Request, res: Response) => {
  const key = webPushPublicKey();
  if (!key) return res.status(503).json({ error: "push_not_configured" });
  return res.json({ key });
});

// Register this browser's push subscription for the caller's side of the cabinet.
router.post("/web-subscribe", cabinetIdentity, async (req: Request, res: Response) => {
  try {
    const { ownerUserId, role } = (req as any).cab;
    const { subscription } = req.body ?? {};
    await saveWebPushSub(ownerUserId, role, subscription);
    return res.json({ ok: true });
  } catch (err: any) {
    console.error("[CABINET] web-subscribe error:", err.message);
    return res.status(400).json({ error: "Abonnement invalide" });
  }
});

// ── Doctor ↔ secretary chat (persistent) ─────────────────────────────────────
// POST /cabinet/chat — send a message; also web-pushes the other side.
router.post("/chat", cabinetIdentity, async (req: Request, res: Response) => {
  try {
    const { ownerUserId, role } = (req as any).cab;
    const { body, fromName } = req.body ?? {};
    const text = String(body ?? "").trim();
    if (!text) return res.status(400).json({ error: "Message vide" });
    const db = getDb();
    const now = new Date().toISOString();
    const id = crypto.randomUUID();
    await db.execute({
      sql: `INSERT INTO cabinet_messages (id, owner_user_id, from_role, from_name, body, created_at)
            VALUES (?, ?, ?, ?, ?, ?)`,
      args: [id, ownerUserId, role, typeof fromName === "string" ? fromName.slice(0, 80) : null, text.slice(0, 2000), now],
    });
    // Cap history at the newest 300 messages per cabinet.
    await db.execute({
      sql: `DELETE FROM cabinet_messages WHERE owner_user_id = ? AND id NOT IN (
              SELECT id FROM cabinet_messages WHERE owner_user_id = ? ORDER BY created_at DESC LIMIT 300)`,
      args: [ownerUserId, ownerUserId],
    });
    const who = typeof fromName === "string" && fromName ? fromName : (role === "doctor" ? "Le médecin" : "La secrétaire");
    await sendWebPushToOtherRole(ownerUserId, role, { title: who, body: text.slice(0, 120), tag: "bp-chat", url: "/" });
    return res.json({ ok: true, id, createdAt: now });
  } catch (err: any) {
    console.error("[CABINET] chat send error:", err.message);
    return res.status(500).json({ error: "Erreur" });
  }
});

// GET /cabinet/chat[?since=<iso>] — messages both ways; without `since`, the last 50.
router.get("/chat", cabinetIdentity, async (req: Request, res: Response) => {
  try {
    const { ownerUserId } = (req as any).cab;
    const db = getDb();
    const since = typeof req.query.since === "string" && req.query.since ? req.query.since : null;
    const r = since
      ? await db.execute({
          sql: "SELECT id, from_role, from_name, body, created_at FROM cabinet_messages WHERE owner_user_id = ? AND created_at > ? ORDER BY created_at ASC LIMIT 100",
          args: [ownerUserId, since],
        })
      : await db.execute({
          sql: "SELECT id, from_role, from_name, body, created_at FROM (SELECT * FROM cabinet_messages WHERE owner_user_id = ? ORDER BY created_at DESC LIMIT 50) sub ORDER BY created_at ASC",
          args: [ownerUserId],
        });
    return res.json({
      now: new Date().toISOString(),
      messages: r.rows.map((m: any) => ({
        id: m.id, fromRole: m.from_role, fromName: m.from_name, body: m.body, createdAt: m.created_at,
      })),
    });
  } catch (err: any) {
    console.error("[CABINET] chat fetch error:", err.message);
    return res.status(500).json({ error: "Erreur" });
  }
});

// ── Attachment object storage (Vercel Blob) ────────────────────────────────────
// Moves the heavy patient files (scans, radiology, PDFs) OUT of the DB snapshot
// and into cheap object storage. The binary is ENCRYPTED server-side before
// upload (ciphertext at rest, even at a public blob URL) and only a tiny "blob:"
// marker travels in the synced snapshot. Downloads are proxied + decrypted here,
// scoped to the requesting cabinet's key prefix. Fully optional: without a Blob
// store (BLOB_READ_WRITE_TOKEN unset) these return 501 and the web app keeps its
// legacy inline-base64 behaviour.
const BLOB_ENABLED = () => !!process.env.BLOB_READ_WRITE_TOKEN;

// Whether the client should route new attachments to object storage.
router.get("/storage-mode", cabinetIdentity, (_req: Request, res: Response) => {
  res.json({ blob: BLOB_ENABLED() });
});

// Upload one attachment (base64 data URL) → returns the blob URL to store.
router.post("/attachments", cabinetIdentity, async (req: Request, res: Response) => {
  if (!BLOB_ENABLED()) return res.status(501).json({ error: "Stockage objet non configuré" });
  try {
    const { ownerUserId } = (req as any).cab;
    const id = String(req.body?.id ?? "").replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 60);
    const data = String(req.body?.data ?? "");
    if (!id || !data.startsWith("data:")) return res.status(400).json({ error: "Requête invalide" });
    const { put } = await import("@vercel/blob");
    const cipher = encryptField(data);                 // ciphertext at rest
    const key = `att/${ownerUserId}/${id}-${crypto.randomBytes(6).toString("hex")}`;
    const blob = await put(key, cipher, { access: "public", contentType: "text/plain", addRandomSuffix: false });
    return res.json({ ok: true, url: blob.url });
  } catch (err: any) {
    console.error("[CABINET] attachment upload error:", err.message);
    return res.status(500).json({ error: "Erreur" });
  }
});

// Validate that a caller-supplied blob URL is (a) a Vercel Blob host over HTTPS
// and (b) this cabinet's own attachment path. A loose substring check would allow
// SSRF (fetch internal hosts) and a cross-tenant decryption oracle (another
// cabinet's blob whose URL merely *contains* our /att/<id>/ in a query string).
function isOwnedBlobUrl(raw: string, ownerUserId: string): boolean {
  let u: URL;
  try { u = new URL(raw); } catch { return false; }
  return u.protocol === "https:"
    && u.hostname.endsWith(".public.blob.vercel-storage.com")
    && u.pathname.startsWith(`/att/${ownerUserId}/`);
}

// Fetch + decrypt one attachment by its blob URL (scoped to this cabinet).
router.post("/attachments/get", cabinetIdentity, async (req: Request, res: Response) => {
  if (!BLOB_ENABLED()) return res.status(501).json({ error: "Stockage objet non configuré" });
  try {
    const { ownerUserId } = (req as any).cab;
    const url = String(req.body?.url ?? "");
    if (!isOwnedBlobUrl(url, ownerUserId)) return res.status(403).json({ error: "Accès refusé" });
    const r = await fetch(url);
    if (!r.ok) return res.status(404).json({ error: "Fichier introuvable" });
    const cipher = await r.text();
    return res.json({ ok: true, data: decryptField(cipher) });
  } catch (err: any) {
    console.error("[CABINET] attachment get error:", err.message);
    return res.status(500).json({ error: "Erreur" });
  }
});

// Delete one attachment blob (scoped to this cabinet).
router.post("/attachments/del", cabinetIdentity, async (req: Request, res: Response) => {
  if (!BLOB_ENABLED()) return res.json({ ok: true });   // nothing to delete
  try {
    const { ownerUserId } = (req as any).cab;
    const url = String(req.body?.url ?? "");
    if (!isOwnedBlobUrl(url, ownerUserId)) return res.status(403).json({ error: "Accès refusé" });
    const { del } = await import("@vercel/blob");
    await del(url);
    return res.json({ ok: true });
  } catch (err: any) {
    console.error("[CABINET] attachment del error:", err.message);
    return res.status(500).json({ error: "Erreur" });
  }
});

export default router;
