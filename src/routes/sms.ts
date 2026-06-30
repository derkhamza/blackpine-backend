/**
 * Automated SMS appointment reminders.
 *
 *  GET  /sms/config           (auth)  → doctor's reminder settings + whether the
 *                                       server has any SMS provider configured.
 *  POST /sms/config           (auth)  → enable/disable + template + lead days.
 *  POST /sms/run-reminders    (cron)  → daily job: text patients whose appointment
 *                                       is `lead_days` away. Protected by CRON_SECRET.
 *
 * Everything is safe-by-default: with no provider env vars set, the job records
 * "not_configured" and sends nothing (no cost). A doctor must ALSO opt in.
 */
import { Router, Request, Response } from "express";
import { getDb } from "../db/database";
import { authRequired } from "../middleware/auth";
import { decryptField } from "../crypto/dataCipher";
import { sendSms, smsConfigured, activeProvider } from "../sms";

const router = Router();

const DEFAULT_TEMPLATE =
  "Bonjour {patient}, rappel de votre rendez-vous le {date} à {time}. {doctor}";
const MAX_SENDS_PER_RUN = 200;

function fmtDate(iso: string): string {
  try {
    return new Date(iso + "T12:00:00").toLocaleDateString("fr-FR", {
      weekday: "long", day: "numeric", month: "long",
    });
  } catch { return iso; }
}

// ── Doctor config ─────────────────────────────────────────────────────────────

router.get("/config", authRequired, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user.userId;
    const db = getDb();
    const r = await db.execute({ sql: "SELECT enabled, lead_days, template FROM sms_config WHERE owner_user_id = ?", args: [userId] });
    const row = r.rows[0] as any;
    return res.json({
      enabled: row ? !!row.enabled : false,
      leadDays: row?.lead_days ?? 1,
      template: row?.template ?? DEFAULT_TEMPLATE,
      defaultTemplate: DEFAULT_TEMPLATE,
      // True when the SERVER has provider credentials; the doctor still must enable.
      serverConfigured: smsConfigured(),
      provider: activeProvider(),
    });
  } catch (err: any) {
    console.error("[SMS] config get error:", err.message);
    return res.status(500).json({ error: "Erreur" });
  }
});

router.post("/config", authRequired, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user.userId;
    const db = getDb();
    const { enabled, leadDays, template } = req.body ?? {};
    const en = enabled ? 1 : 0;
    const lead = [0, 1, 2, 3].includes(leadDays) ? leadDays : 1;
    const tpl = (typeof template === "string" && template.trim()) ? template.trim().slice(0, 320) : DEFAULT_TEMPLATE;
    const now = new Date().toISOString();
    await db.execute({
      sql: `INSERT INTO sms_config (owner_user_id, enabled, lead_days, template, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(owner_user_id) DO UPDATE SET
              enabled = excluded.enabled, lead_days = excluded.lead_days,
              template = excluded.template, updated_at = excluded.updated_at`,
      args: [userId, en, lead, tpl, now],
    });
    return res.json({ enabled: !!en, leadDays: lead, template: tpl, serverConfigured: smsConfigured(), provider: activeProvider() });
  } catch (err: any) {
    console.error("[SMS] config save error:", err.message);
    return res.status(500).json({ error: "Erreur lors de l'enregistrement" });
  }
});

// ── Daily cron job ────────────────────────────────────────────────────────────

router.post("/run-reminders", async (req: Request, res: Response) => {
  // Cron protection: Vercel adds `Authorization: Bearer <CRON_SECRET>` when set.
  const secret = process.env.CRON_SECRET;
  if (!secret) return res.status(503).json({ error: "cron_secret_not_set" });
  if (req.headers.authorization !== `Bearer ${secret}`) return res.status(401).json({ error: "unauthorized" });

  const summary = { doctors: 0, candidates: 0, sent: 0, failed: 0, skipped: 0, notConfigured: false };
  if (!smsConfigured()) summary.notConfigured = true;

  try {
    const db = getDb();
    const cfgs = await db.execute("SELECT owner_user_id, lead_days, template FROM sms_config WHERE enabled = 1");

    for (const cfg of cfgs.rows as any[]) {
      summary.doctors++;
      const userId = cfg.owner_user_id as string;
      const leadDays = (cfg.lead_days as number) ?? 1;
      const template = (cfg.template as string) || DEFAULT_TEMPLATE;

      const target = new Date(); target.setDate(target.getDate() + leadDays);
      const targetIso = target.toISOString().slice(0, 10);

      const snap = await db.execute({ sql: "SELECT appointments, patients, doctor_profile FROM cabinet_snapshots WHERE owner_user_id = ?", args: [userId] });
      if (!snap.rows[0]) continue;
      const appts = JSON.parse(decryptField(snap.rows[0].appointments as string)) as any[];
      const patients = JSON.parse(decryptField(snap.rows[0].patients as string)) as any[];
      let doctorName = "";
      try { doctorName = (JSON.parse(decryptField(snap.rows[0].doctor_profile as string)) as any)?.fullName ?? ""; } catch { /* */ }
      const phoneOf = (a: any): string | undefined =>
        a.bookingPhone || (a.patientId ? patients.find(p => p.id === a.patientId)?.phone : undefined);

      const due = appts.filter(a => a.date === targetIso && (a.status === "scheduled" || a.status === "arrived") && phoneOf(a));
      for (const a of due) {
        if (summary.sent >= MAX_SENDS_PER_RUN) break;
        summary.candidates++;
        // Idempotency: already logged for this appt+date?
        const seen = await db.execute({ sql: "SELECT 1 FROM sms_log WHERE owner_user_id = ? AND appointment_id = ? AND appt_date = ?", args: [userId, a.id, targetIso] });
        if (seen.rows.length > 0) { summary.skipped++; continue; }

        const msg = template
          .replace(/\{patient\}/g, a.patientName ?? "")
          .replace(/\{date\}/g, fmtDate(targetIso))
          .replace(/\{time\}/g, a.startTime ?? "")
          .replace(/\{doctor\}/g, doctorName)
          .trim();

        const result = await sendSms(String(phoneOf(a)), msg);
        if (result.ok) summary.sent++; else summary.failed++;
        try {
          await db.execute({
            sql: "INSERT OR IGNORE INTO sms_log (owner_user_id, appointment_id, appt_date, sent_at, status) VALUES (?, ?, ?, ?, ?)",
            args: [userId, a.id, targetIso, new Date().toISOString(), result.ok ? "sent" : `error:${result.error ?? ""}`.slice(0, 80)],
          });
        } catch { /* best-effort log */ }
      }
    }

    console.log(`[SMS] run-reminders: ${JSON.stringify(summary)}`);
    return res.json({ ok: true, ...summary });
  } catch (err: any) {
    console.error("[SMS] run-reminders error:", err.message);
    return res.status(500).json({ error: "Erreur" });
  }
});

export default router;
