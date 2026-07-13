/**
 * Online self-booking.
 *
 * A doctor enables a public booking link (random slug) and sets working hours.
 * Patients (unauthenticated) fetch free slots and create a "pending" appointment
 * that is appended directly into the doctor's encrypted cabinet snapshot — so it
 * shows up in their agenda on the next sync. No patient data is ever read back
 * out to the public; only free slot *times* are exposed.
 *
 * Abuse controls: per-IP rate limit (mounted in api/index.ts) + a per-slug daily
 * cap on online bookings. The slug is random (not the enumerable user id), and
 * the public endpoints can only append — never read or modify existing data.
 */
import { Router, Request, Response } from "express";
import { getDb } from "../db/database";
import { authRequired } from "../middleware/auth";
import { encryptField, decryptField } from "../crypto/dataCipher";
import { sendExpoPush } from "../push";
import crypto from "crypto";

const router = Router();

const DEFAULT = { startMin: 540, endMin: 1020, slotMin: 30, days: "1,2,3,4,5,6" };
const MAX_DAYS_AHEAD = 60;
const DAILY_CAP = 20; // max online bookings accepted per doctor per day

// ── helpers ─────────────────────────────────────────────────────────────────
const pad = (n: number) => String(n).padStart(2, "0");
const minToHHMM = (m: number) => `${pad(Math.floor(m / 60))}:${pad(m % 60)}`;
const hhmmToMin = (s: string) => {
  const [h, m] = s.split(":").map(Number);
  return h * 60 + m;
};
function isValidDate(s: string): boolean {
  return /^\d{4}-\d{2}-\d{2}$/.test(s) && !isNaN(new Date(s + "T12:00:00").getTime());
}
function daysFromToday(dateStr: string): number {
  const a = new Date(dateStr + "T12:00:00").getTime();
  const today = new Date(); today.setHours(12, 0, 0, 0);
  return Math.round((a - today.getTime()) / 86400000);
}
function genSlots(startMin: number, endMin: number, slotMin: number): string[] {
  const out: string[] = [];
  for (let m = startMin; m + slotMin <= endMin; m += slotMin) out.push(minToHHMM(m));
  return out;
}

// Turn a doctor's name (or a custom phrase) into a clean URL slug:
//   "Dr. Amine Tazi" → "amine-tazi". Accents stripped, spaces → hyphens.
function slugify(s: string): string {
  return String(s ?? "")
    .normalize("NFD").replace(/[̀-ͯ]/g, "")  // strip accents
    .toLowerCase()
    .replace(/\bdr\b\.?/g, "")                          // drop a leading "Dr."
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40);
}

// Find a free slug starting from `base`, appending -2, -3… on collisions.
// A slug already owned by this same doctor counts as free (so re-saving is a no-op).
async function uniqueSlug(base: string, ownerUserId: string): Promise<string> {
  const db = getDb();
  const root = base || crypto.randomBytes(4).toString("hex");
  for (let i = 0; i < 50; i++) {
    const candidate = i === 0 ? root : `${root}-${i + 1}`;
    const r = await db.execute({ sql: "SELECT owner_user_id FROM booking_links WHERE slug = ?", args: [candidate] });
    const row = r.rows[0] as any | undefined;
    if (!row || row.owner_user_id === ownerUserId) return candidate;
  }
  return `${root}-${crypto.randomBytes(3).toString("hex")}`;
}

async function loadLink(slug: string) {
  const db = getDb();
  const r = await db.execute({ sql: "SELECT * FROM booking_links WHERE slug = ?", args: [slug] });
  return r.rows[0] as any | undefined;
}

// ── Doctor config (auth) ──────────────────────────────────────────────────────

router.get("/me", authRequired, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user.userId;
    const db = getDb();
    const r = await db.execute({ sql: "SELECT * FROM booking_links WHERE owner_user_id = ?", args: [userId] });
    const row = r.rows[0] as any;
    if (!row) return res.json({ slug: null });
    return res.json({
      slug: row.slug, enabled: !!row.enabled,
      doctorName: row.doctor_name ?? "", specialty: row.specialty ?? "",
      startMin: row.start_min, endMin: row.end_min, slotMin: row.slot_min, days: row.days,
    });
  } catch (err: any) {
    console.error("[BOOKING] me error:", err.message);
    return res.status(500).json({ error: "Erreur" });
  }
});

// Create/update the doctor's booking config (also enables it).
router.post("/me", authRequired, async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user.userId;
    const db = getDb();
    const { doctorName, specialty, startMin, endMin, slotMin, days, enabled } = req.body ?? {};

    const sMin = Number.isFinite(startMin) ? Math.max(0, Math.min(1439, startMin)) : DEFAULT.startMin;
    const eMin = Number.isFinite(endMin) ? Math.max(sMin + 15, Math.min(1440, endMin)) : DEFAULT.endMin;
    const slMin = [15, 20, 30, 45, 60].includes(slotMin) ? slotMin : DEFAULT.slotMin;
    const daysStr = typeof days === "string" && /^[0-6](,[0-6])*$/.test(days) ? days : DEFAULT.days;
    const en = enabled === false ? 0 : 1;

    const existing = await db.execute({ sql: "SELECT slug FROM booking_links WHERE owner_user_id = ?", args: [userId] });
    const currentSlug = (existing.rows[0] as any)?.slug as string | undefined;

    // Slug priority: an explicit custom slug from the doctor → keep the existing
    // one → otherwise derive a readable slug from the doctor's name (random only
    // as a last resort if the name has no usable letters). Always made unique.
    const requested = typeof req.body?.slug === "string" ? slugify(req.body.slug) : "";
    let slug: string;
    if (requested) {
      slug = await uniqueSlug(requested, userId);
    } else if (currentSlug) {
      slug = currentSlug;
    } else {
      slug = await uniqueSlug(slugify(doctorName) || crypto.randomBytes(5).toString("hex"), userId);
    }

    await db.execute({
      sql: `INSERT INTO booking_links (slug, owner_user_id, enabled, doctor_name, specialty, start_min, end_min, slot_min, days)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(owner_user_id) DO UPDATE SET
              slug = excluded.slug,
              enabled = excluded.enabled, doctor_name = excluded.doctor_name, specialty = excluded.specialty,
              start_min = excluded.start_min, end_min = excluded.end_min, slot_min = excluded.slot_min, days = excluded.days`,
      args: [slug, userId, en, String(doctorName ?? "").slice(0, 120), String(specialty ?? "").slice(0, 120), sMin, eMin, slMin, daysStr],
    });
    return res.json({ slug, enabled: !!en, doctorName: doctorName ?? "", specialty: specialty ?? "", startMin: sMin, endMin: eMin, slotMin: slMin, days: daysStr });
  } catch (err: any) {
    console.error("[BOOKING] save error:", err.message);
    return res.status(500).json({ error: "Erreur lors de l'enregistrement" });
  }
});

// ── Public: doctor info ───────────────────────────────────────────────────────

router.get("/:slug", async (req: Request, res: Response) => {
  try {
    const row = await loadLink(String(req.params.slug));
    if (!row || !row.enabled) return res.status(404).json({ error: "Lien indisponible" });
    return res.json({
      doctorName: row.doctor_name ?? "", specialty: row.specialty ?? "",
      slotMin: row.slot_min, days: row.days, maxDaysAhead: MAX_DAYS_AHEAD,
    });
  } catch (err: any) {
    console.error("[BOOKING] public info error:", err.message);
    return res.status(500).json({ error: "Erreur" });
  }
});

// ── Public: free slots for a date ─────────────────────────────────────────────

router.get("/:slug/slots", async (req: Request, res: Response) => {
  try {
    const row = await loadLink(String(req.params.slug));
    if (!row || !row.enabled) return res.status(404).json({ error: "Lien indisponible" });
    const date = String(req.query.date ?? "");
    if (!isValidDate(date)) return res.status(400).json({ error: "Date invalide" });
    const ahead = daysFromToday(date);
    if (ahead < 0 || ahead > MAX_DAYS_AHEAD) return res.json({ date, slots: [] });

    const dow = new Date(date + "T12:00:00").getDay();
    const allowed = String(row.days).split(",").map(Number);
    if (!allowed.includes(dow)) return res.json({ date, slots: [] });

    // taken times that date (from the doctor's encrypted snapshot)
    const db = getDb();
    const snap = await db.execute({ sql: "SELECT appointments FROM cabinet_snapshots WHERE owner_user_id = ?", args: [row.owner_user_id] });
    let taken = new Set<string>();
    if (snap.rows[0]) {
      const appts = JSON.parse(decryptField(snap.rows[0].appointments as string)) as any[];
      taken = new Set(appts.filter(a => a.date === date && a.status !== "cancelled").map(a => a.startTime));
    }

    // exclude past times when booking for today
    const nowMin = ahead === 0 ? new Date().getHours() * 60 + new Date().getMinutes() : -1;
    const slots = genSlots(row.start_min, row.end_min, row.slot_min)
      .filter(t => !taken.has(t) && hhmmToMin(t) > nowMin);

    return res.json({ date, slots });
  } catch (err: any) {
    console.error("[BOOKING] slots error:", err.message);
    return res.status(500).json({ error: "Erreur" });
  }
});

// ── Public: create a booking ──────────────────────────────────────────────────

router.post("/:slug/book", async (req: Request, res: Response) => {
  try {
    const row = await loadLink(String(req.params.slug));
    if (!row || !row.enabled) return res.status(404).json({ error: "Lien indisponible" });

    const { date, time } = req.body ?? {};
    const name = String((req.body?.name ?? "")).trim();
    const phone = String((req.body?.phone ?? "")).trim();
    const reason = String((req.body?.reason ?? "")).trim().slice(0, 200);

    if (name.length < 2 || name.length > 80) return res.status(400).json({ error: "Nom invalide" });
    if (!/^[\d +().-]{6,20}$/.test(phone)) return res.status(400).json({ error: "Téléphone invalide" });
    if (!isValidDate(String(date))) return res.status(400).json({ error: "Date invalide" });
    const ahead = daysFromToday(String(date));
    if (ahead < 0 || ahead > MAX_DAYS_AHEAD) return res.status(400).json({ error: "Date hors plage" });

    const dow = new Date(date + "T12:00:00").getDay();
    if (!String(row.days).split(",").map(Number).includes(dow)) return res.status(400).json({ error: "Jour non disponible" });
    const validSlots = genSlots(row.start_min, row.end_min, row.slot_min);
    if (!validSlots.includes(String(time))) return res.status(400).json({ error: "Créneau invalide" });

    const db = getDb();
    const snap = await db.execute({ sql: "SELECT appointments, patients, doctor_profile, extra_data, updated_at FROM cabinet_snapshots WHERE owner_user_id = ?", args: [row.owner_user_id] });
    if (!snap.rows[0]) return res.status(404).json({ error: "Cabinet introuvable" });

    const appts = JSON.parse(decryptField(snap.rows[0].appointments as string)) as any[];

    // slot still free?
    if (appts.some(a => a.date === date && a.startTime === time && a.status !== "cancelled")) {
      return res.status(409).json({ error: "Créneau déjà réservé" });
    }
    // per-day cap on online bookings
    if (appts.filter(a => a.date === date && a.bookingSource === "online").length >= DAILY_CAP) {
      return res.status(429).json({ error: "Trop de réservations pour cette journée" });
    }

    const endTime = minToHHMM(Math.min(1439, hhmmToMin(String(time)) + row.slot_min));
    const appt = {
      id: "bk_" + crypto.randomBytes(6).toString("hex"),
      patientName: name,
      date, startTime: time, endTime,
      type: "consultation",
      status: "scheduled",
      notes: reason || undefined,
      bookingSource: "online",
      bookingPhone: phone,
    };
    appts.push(appt);

    const now = new Date().toISOString();
    // Reset col_versions to NULL so the per-column delta pull re-sends the full
    // snapshot: the appointments column changed here, and without invalidating the
    // version the doctor's ?cv= delta would think appointments were unchanged and
    // SKIP the new booking until the periodic full pull. The next doctor push
    // re-establishes the versions.
    await db.execute({
      sql: "UPDATE cabinet_snapshots SET appointments = ?, updated_at = ?, col_versions = NULL WHERE owner_user_id = ?",
      args: [encryptField(JSON.stringify(appts)), now, row.owner_user_id],
    });

    console.log(`[BOOKING] online booking for ${row.owner_user_id} on ${date} ${time}`);

    // Best-effort: notify the doctor's device(s) that a patient just booked.
    try {
      const toks = await db.execute({ sql: "SELECT token FROM push_tokens WHERE owner_user_id = ?", args: [row.owner_user_id] });
      const tokens = (toks.rows as any[]).map(r => r.token as string);
      if (tokens.length > 0) {
        await sendExpoPush(tokens, "🌐 Nouvelle réservation en ligne", `${name} · ${date} à ${time}`, { type: "online_booking", date, time });
      }
    } catch { /* never let a notification failure break the booking */ }

    return res.json({ success: true, date, time, doctorName: row.doctor_name ?? "" });
  } catch (err: any) {
    console.error("[BOOKING] book error:", err.message);
    return res.status(500).json({ error: "Erreur lors de la réservation" });
  }
});

export default router;
