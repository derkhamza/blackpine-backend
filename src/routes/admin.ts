/**
 * Owner-only usage analytics.
 *
 *   GET /admin/stats   (auth + admin)  → aggregate platform metrics.
 *
 * Admin = the authenticated user's email is in ADMIN_EMAILS (comma-separated;
 * defaults to the owner's address). Returns COUNTS ONLY — never patient PII.
 * Data-volume counts decrypt snapshots transiently to read array lengths only.
 */
import { Router, Request, Response } from "express";
import bcrypt from "bcryptjs";
import { getDb, logSubEvent } from "../db/database";
import { authRequired } from "../middleware/auth";
import { decryptField } from "../crypto/dataCipher";

const router = Router();

function isAdmin(req: Request): boolean {
  const email = String((req as any).user?.email ?? "").toLowerCase();
  const admins = (process.env.ADMIN_EMAILS || "derkhamza@gmail.com")
    .toLowerCase().split(",").map(s => s.trim()).filter(Boolean);
  return !!email && admins.includes(email);
}

const num = (r: any, k = "c") => Number((r?.[k] as any) ?? 0);

router.get("/stats", authRequired, async (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ error: "Accès réservé" });
  try {
    const db = getDb();
    const nowIso = new Date().toISOString();
    const isoCut = (days: number) => new Date(Date.now() - days * 86400000).toISOString();

    // ── Doctors / signups (users.created_at = "YYYY-MM-DD HH:MM:SS") ──
    const total      = await db.execute("SELECT count(*) c FROM users");
    const newToday   = await db.execute("SELECT count(*) c FROM users WHERE created_at >= datetime('now','-1 day')");
    const new7       = await db.execute("SELECT count(*) c FROM users WHERE created_at >= datetime('now','-7 days')");
    const new30      = await db.execute("SELECT count(*) c FROM users WHERE created_at >= datetime('now','-30 days')");
    const byDay      = await db.execute("SELECT substr(created_at,1,10) d, count(*) c FROM users WHERE created_at >= datetime('now','-30 days') GROUP BY d ORDER BY d");

    // ── Active doctors (cabinet_snapshots.updated_at = ISO) ──
    const dau = await db.execute({ sql: "SELECT count(*) c FROM cabinet_snapshots WHERE updated_at >= ?", args: [isoCut(1)] });
    const wau = await db.execute({ sql: "SELECT count(*) c FROM cabinet_snapshots WHERE updated_at >= ?", args: [isoCut(7)] });
    const mau = await db.execute({ sql: "SELECT count(*) c FROM cabinet_snapshots WHERE updated_at >= ?", args: [isoCut(30)] });

    // ── Subscriptions ──
    const subs = await db.execute("SELECT COALESCE(subscription_plan,'free_trial') p, count(*) c FROM users GROUP BY p");
    const expiring = await db.execute("SELECT count(*) c FROM users WHERE subscription_expires_at IS NOT NULL AND subscription_expires_at >= datetime('now') AND subscription_expires_at <= datetime('now','+7 days')");

    // ── Feature adoption ──
    const bookingEnabled   = await db.execute("SELECT count(*) c FROM booking_links WHERE enabled = 1");
    const smsEnabled       = await db.execute("SELECT count(*) c FROM sms_config WHERE enabled = 1");
    const smsSent30        = await db.execute({ sql: "SELECT count(*) c FROM sms_log WHERE status = 'sent' AND sent_at >= ?", args: [isoCut(30)] });
    const pushDoctors      = await db.execute("SELECT count(DISTINCT owner_user_id) c FROM push_tokens");
    const pushDevices      = await db.execute("SELECT count(*) c FROM push_tokens");
    const secretaryDoctors = await db.execute("SELECT count(DISTINCT owner_user_id) c FROM secretary_accounts WHERE revoked = 0");
    const secretaryAccts   = await db.execute("SELECT count(*) c FROM secretary_accounts WHERE revoked = 0");

    // ── Data volumes (decrypt → array length only; no PII in the response) ──
    let snapshots = 0, totalAppointments = 0, totalPatients = 0, onlineBookings = 0;
    const snaps = await db.execute("SELECT appointments, patients FROM cabinet_snapshots");
    for (const r of snaps.rows as any[]) {
      snapshots++;
      try {
        const appts = JSON.parse(decryptField(r.appointments as string)) as any[];
        totalAppointments += appts.length;
        onlineBookings += appts.filter(a => a?.bookingSource === "online").length;
      } catch { /* skip unreadable */ }
      try { totalPatients += (JSON.parse(decryptField(r.patients as string)) as any[]).length; } catch { /* */ }
    }

    const subscriptions: Record<string, number> = {};
    for (const r of subs.rows as any[]) subscriptions[String(r.p)] = num(r);

    return res.json({
      generatedAt: nowIso,
      doctors: { total: num(total.rows[0]), newToday: num(newToday.rows[0]), new7: num(new7.rows[0]), new30: num(new30.rows[0]) },
      active: { dau: num(dau.rows[0]), wau: num(wau.rows[0]), mau: num(mau.rows[0]) },
      signupsByDay: (byDay.rows as any[]).map(r => ({ date: String(r.d), count: num(r) })),
      subscriptions,
      trialsExpiring7: num(expiring.rows[0]),
      features: {
        bookingEnabled:   num(bookingEnabled.rows[0]),
        smsEnabled:       num(smsEnabled.rows[0]),
        smsSent30:        num(smsSent30.rows[0]),
        pushDoctors:      num(pushDoctors.rows[0]),
        pushDevices:      num(pushDevices.rows[0]),
        secretaryDoctors: num(secretaryDoctors.rows[0]),
        secretaryAccounts: num(secretaryAccts.rows[0]),
      },
      volumes: { snapshots, totalAppointments, totalPatients, onlineBookings },
    });
  } catch (err: any) {
    console.error("[ADMIN] stats error:", err.message);
    return res.status(500).json({ error: "Erreur" });
  }
});

// ── Business / finance aggregation (CEO view) ────────────────────────────────
// Monetization is manual activation codes + plan fields (no payment table), so
// revenue is DERIVED: current active-paid state gives point-in-time MRR, and
// redeemed activation_codes give the real booked-revenue timeline. Aggregated in
// JS (single-operator scale) to avoid TEXT-date SQL pitfalls.
router.get("/finance", authRequired, async (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ error: "Accès réservé" });
  try {
    const db = getDb();
    const now = Date.now();
    const TRIAL_MS = 30 * 86400000;
    const curMonth = new Date().toISOString().slice(0, 7);
    const monthKey = (iso: string) => (iso || "").slice(0, 7);
    const last12 = () => {
      const out: string[] = [];
      const d = new Date();
      for (let i = 11; i >= 0; i--) {
        const m = new Date(d.getFullYear(), d.getMonth() - i, 1);
        out.push(`${m.getFullYear()}-${String(m.getMonth() + 1).padStart(2, "0")}`);
      }
      return out;
    };

    const users = await db.execute("SELECT created_at, trial_start, COALESCE(subscription_plan,'free_trial') plan, subscription_expires_at FROM users");
    let codes: any = { rows: [] };
    try { codes = await db.execute("SELECT plan, duration_days, used, used_at, created_at FROM activation_codes"); } catch { /* table may be empty/absent */ }

    const activeByPlan: Record<string, number> = {};
    let activePaid = 0, expiredPaid = 0, activeTrials = 0, expiredTrials = 0, activeLifetime = 0, expiredThisMonth = 0;
    const signupsByMonthMap: Record<string, number> = {};

    for (const u of users.rows as any[]) {
      const plan = String(u.plan || "free_trial");
      const exp = u.subscription_expires_at ? new Date(String(u.subscription_expires_at)).getTime() : null;
      const cm = monthKey(String(u.created_at || ""));
      if (cm) signupsByMonthMap[cm] = (signupsByMonthMap[cm] || 0) + 1;

      if (plan === "free_trial") {
        const ts = u.trial_start ? new Date(String(u.trial_start)).getTime() : null;
        if (ts && now - ts < TRIAL_MS) activeTrials++; else expiredTrials++;
      } else {
        const isLifetime = plan === "lifetime";
        const active = isLifetime || exp == null || exp > now;
        if (active) {
          activePaid++;
          activeByPlan[plan] = (activeByPlan[plan] || 0) + 1;
          if (isLifetime) activeLifetime++;
        } else {
          expiredPaid++;
          if (exp != null && new Date(exp).toISOString().slice(0, 7) === curMonth) expiredThisMonth++;
        }
      }
    }

    let issued = 0, redeemed = 0;
    const redeemedByMonthMap: Record<string, number> = {};
    const byPlan: Record<string, number> = {};
    const bucketMap: Record<string, { month: string; plan: string; durationDays: number; count: number }> = {};
    for (const c of codes.rows as any[]) {
      issued++;
      if (Number(c.used) === 1) {
        redeemed++;
        const m = monthKey(String(c.used_at || c.created_at || ""));
        if (m) redeemedByMonthMap[m] = (redeemedByMonthMap[m] || 0) + 1;
        const plan = String(c.plan || "pro");
        byPlan[plan] = (byPlan[plan] || 0) + 1;
        const dur = Number(c.duration_days || 0);
        const key = `${m}|${plan}|${dur}`;
        (bucketMap[key] ||= { month: m, plan, durationDays: dur, count: 0 }).count++;
      }
    }

    // ── Exact cohorts from the subscription_events log ──
    let cohorts: { month: string; signups: number; converted: number; rate: number }[] = [];
    let conversionsByMonth: { month: string; count: number }[] = [];
    let eventsLogged = 0;
    try {
      const evts = await db.execute("SELECT user_id, type, to_plan, created_at FROM subscription_events");
      eventsLogged = (evts.rows as any[]).length;
      const signupMonth: Record<string, string> = {};   // earliest signup month per user
      const converted: Record<string, boolean> = {};
      const convByMonth: Record<string, number> = {};
      for (const e of evts.rows as any[]) {
        const uid = String(e.user_id), t = String(e.type), mk = monthKey(String(e.created_at || ""));
        if (t === "signup") { if (!signupMonth[uid] || (mk && mk < signupMonth[uid])) signupMonth[uid] = mk; }
        const isConv = t === "convert" || t === "renew" || (t === "plan_change" && e.to_plan && String(e.to_plan) !== "free_trial");
        if (isConv) { converted[uid] = true; if (mk) convByMonth[mk] = (convByMonth[mk] || 0) + 1; }
      }
      const cMap: Record<string, { s: number; c: number }> = {};
      for (const uid of Object.keys(signupMonth)) {
        const mk = signupMonth[uid];
        (cMap[mk] ||= { s: 0, c: 0 }).s++;
        if (converted[uid]) cMap[mk].c++;
      }
      cohorts = last12().map(mo => {
        const e = cMap[mo] || { s: 0, c: 0 };
        return { month: mo, signups: e.s, converted: e.c, rate: e.s ? Math.round((e.c / e.s) * 100) : 0 };
      });
      conversionsByMonth = last12().map(mo => ({ month: mo, count: convByMonth[mo] || 0 }));
    } catch { /* events table optional */ }

    const months = last12();
    return res.json({
      generatedAt: new Date().toISOString(),
      subs: {
        total: (users.rows as any[]).length,
        activePaid, expiredPaid, activeByPlan, activeTrials, expiredTrials, activeLifetime,
      },
      signupsByMonth: months.map(m => ({ month: m, count: signupsByMonthMap[m] || 0 })),
      codes: {
        issued, redeemed, unused: issued - redeemed,
        redeemedByMonth: months.map(m => ({ month: m, count: redeemedByMonthMap[m] || 0 })),
        redeemedBuckets: Object.values(bucketMap),
        byPlan,
      },
      expiredThisMonth,
      cohorts,
      conversionsByMonth,
      eventsLogged,
    });
  } catch (err: any) {
    console.error("[ADMIN] finance error:", err.message);
    return res.status(500).json({ error: "Erreur" });
  }
});

// ── Behavioural analytics aggregation ────────────────────────────────────────

router.get("/events", authRequired, async (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ error: "Accès réservé" });
  try {
    const db = getDb();
    const days = Math.min(90, Math.max(1, Number(req.query.days ?? 30) || 30));
    const cut = new Date(Date.now() - days * 86400000).toISOString();

    const top = await db.execute({
      sql: "SELECT name, count(*) c FROM analytics_events WHERE created_at >= ? GROUP BY name ORDER BY c DESC LIMIT 40",
      args: [cut],
    });
    const byDay = await db.execute({
      sql: "SELECT substr(created_at,1,10) d, count(*) c FROM analytics_events WHERE created_at >= ? GROUP BY d ORDER BY d",
      args: [cut],
    });
    const totals = await db.execute({
      sql: "SELECT count(*) c, count(DISTINCT user_id) u FROM analytics_events WHERE created_at >= ?",
      args: [cut],
    });
    // Split usage by client: web / mobile (doctor) / mobile-secretary.
    const byPlat = await db.execute({
      sql: "SELECT COALESCE(platform,'web') p, count(*) c, count(DISTINCT user_id) u FROM analytics_events WHERE created_at >= ? GROUP BY p ORDER BY c DESC",
      args: [cut],
    });
    // Activity distribution across the hours of the day (created_at is UTC ISO
    // text; the client shifts to local time for display).
    const byHour = await db.execute({
      sql: "SELECT substr(created_at,12,2) h, count(*) c FROM analytics_events WHERE created_at >= ? GROUP BY h ORDER BY h",
      args: [cut],
    });

    const events = (top.rows as any[]).map(r => ({ name: String(r.name), count: num(r) }));
    const pages = events.filter(e => e.name.startsWith("page:"));
    const actions = events.filter(e => e.name.startsWith("action:"));

    return res.json({
      days,
      totalEvents: num(totals.rows[0]),
      activeUsers: num(totals.rows[0], "u"),
      topEvents: events,
      topPages: pages.slice(0, 20),
      topActions: actions.slice(0, 20),
      byDay: (byDay.rows as any[]).map(r => ({ date: String(r.d), count: num(r) })),
      byPlatform: (byPlat.rows as any[]).map(r => ({ platform: String(r.p), count: num(r), users: num(r, "u") })),
      byHour: (byHour.rows as any[]).map(r => ({ hour: Number(r.h), count: num(r) })),
    });
  } catch (err: any) {
    console.error("[ADMIN] events error:", err.message);
    return res.status(500).json({ error: "Erreur" });
  }
});

// ── Retention / returning-doctor view ────────────────────────────────────────
// Activity signal = cabinet_snapshots.updated_at (every cabinet sync bumps it).
// That column stores only the LATEST timestamp per doctor, so we can't rebuild a
// historical triangular cohort grid from it — instead we report point-in-time
// engagement segments, new-vs-returning, stickiness, and per-signup-week
// "still active now" cohort rates (all single-timestamp friendly + honest).
router.get("/retention", authRequired, async (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ error: "Accès réservé" });
  try {
    const db = getDb();
    const nowIso = new Date().toISOString();
    const isoCut = (days: number) => new Date(Date.now() - days * 86400000).toISOString();
    const cut1 = isoCut(1), cut7 = isoCut(7), cut30 = isoCut(30);

    // Engagement segments by last activity (LEFT JOIN → "never" = no snapshot row).
    const seg = await db.execute({
      sql: `SELECT
              count(*) total,
              sum(CASE WHEN s.updated_at >= ? THEN 1 ELSE 0 END) active7,
              sum(CASE WHEN s.updated_at >= ? AND s.updated_at < ? THEN 1 ELSE 0 END) sleeping,
              sum(CASE WHEN s.updated_at IS NOT NULL AND s.updated_at < ? THEN 1 ELSE 0 END) inactive,
              sum(CASE WHEN s.updated_at IS NULL THEN 1 ELSE 0 END) never
            FROM users u LEFT JOIN cabinet_snapshots s ON s.owner_user_id = u.id`,
      args: [cut7, cut30, cut7, cut30],
    });

    // New vs returning among 7-day-active doctors.
    const nvr = await db.execute({
      sql: `SELECT
              sum(CASE WHEN s.updated_at >= ? AND u.created_at <  datetime('now','-7 days') THEN 1 ELSE 0 END) ret,
              sum(CASE WHEN s.updated_at >= ? AND u.created_at >= datetime('now','-7 days') THEN 1 ELSE 0 END) neu
            FROM users u LEFT JOIN cabinet_snapshots s ON s.owner_user_id = u.id`,
      args: [cut7, cut7],
    });

    // Stickiness DAU/MAU.
    const stick = await db.execute({
      sql: `SELECT
              sum(CASE WHEN updated_at >= ? THEN 1 ELSE 0 END) dau,
              sum(CASE WHEN updated_at >= ? THEN 1 ELSE 0 END) mau
            FROM cabinet_snapshots`,
      args: [cut1, cut30],
    });

    // Signup cohorts (last 8 weeks): % of each week's signups still active (≤30j).
    const coh = await db.execute({
      sql: `SELECT strftime('%Y-%W', u.created_at) wk,
                   min(substr(u.created_at,1,10)) firstDay,
                   count(*) size,
                   sum(CASE WHEN s.updated_at >= ? THEN 1 ELSE 0 END) retained
            FROM users u LEFT JOIN cabinet_snapshots s ON s.owner_user_id = u.id
            WHERE u.created_at >= datetime('now','-56 days')
            GROUP BY wk ORDER BY wk`,
      args: [cut30],
    });

    const dau = num(stick.rows[0], "dau"), mau = num(stick.rows[0], "mau");
    return res.json({
      generatedAt: nowIso,
      segments: {
        total:    num(seg.rows[0], "total"),
        active7:  num(seg.rows[0], "active7"),
        sleeping: num(seg.rows[0], "sleeping"),
        inactive: num(seg.rows[0], "inactive"),
        never:    num(seg.rows[0], "never"),
      },
      newVsReturning: {
        returning: num(nvr.rows[0], "ret"),
        new:       num(nvr.rows[0], "neu"),
      },
      stickiness: { dau, mau, ratio: mau > 0 ? Math.round((dau / mau) * 100) : 0 },
      cohorts: (coh.rows as any[]).map(r => {
        const size = num(r, "size"), retained = num(r, "retained");
        return {
          label: String(r.firstDay),
          size,
          retained,
          rate: size > 0 ? retained / size : 0,
        };
      }),
    });
  } catch (err: any) {
    console.error("[ADMIN] retention error:", err.message);
    return res.status(500).json({ error: "Erreur" });
  }
});

// ── Per-doctor drill-down ─────────────────────────────────────────────────────
// Owner-only. COUNTS ONLY — never exposes patient PII. The doctor's own email +
// specialty/commune (their professional identity, from the encrypted profile) is
// shown so the operator can identify the account; appointments/patients are only
// ever counted (array length), never returned.

/** Decrypt a snapshot row → { appts, patients, online, specialty, commune } counts. */
function snapSummary(row: any): { appts: number; patients: number; online: number; specialty: string; commune: string } {
  let appts = 0, patients = 0, online = 0, specialty = "", commune = "";
  try {
    const a = JSON.parse(decryptField(row.appointments as string)) as any[];
    appts = a.length;
    online = a.filter((x) => x?.bookingSource === "online").length;
  } catch { /* unreadable */ }
  try { patients = (JSON.parse(decryptField(row.patients as string)) as any[]).length; } catch { /* */ }
  try {
    const p = JSON.parse(decryptField(row.doctor_profile as string)) as any;
    specialty = String(p?.specialty ?? "").slice(0, 60);
    commune = String(p?.commune ?? "").slice(0, 60);
  } catch { /* */ }
  return { appts, patients, online, specialty, commune };
}

router.get("/doctors", authRequired, async (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ error: "Accès réservé" });
  try {
    const db = getDb();
    const users = await db.execute("SELECT id, email, created_at, trial_start, subscription_plan, subscription_expires_at FROM users");
    const snaps = await db.execute("SELECT owner_user_id, appointments, patients, doctor_profile, updated_at FROM cabinet_snapshots");
    const evRows = await db.execute("SELECT user_id, count(*) c, max(created_at) last FROM analytics_events GROUP BY user_id");
    const secRows = await db.execute("SELECT owner_user_id, count(*) c FROM secretary_accounts WHERE revoked = 0 GROUP BY owner_user_id");
    const pushRows = await db.execute("SELECT owner_user_id, count(*) c FROM push_tokens GROUP BY owner_user_id");

    const snapById = new Map<string, any>();
    for (const r of snaps.rows as any[]) snapById.set(String(r.owner_user_id), r);
    const evById = new Map<string, { count: number; last: string }>();
    for (const r of evRows.rows as any[]) evById.set(String(r.user_id), { count: num(r), last: String(r.last ?? "") });
    const secById = new Map<string, number>();
    for (const r of secRows.rows as any[]) secById.set(String(r.owner_user_id), num(r));
    const pushById = new Map<string, number>();
    for (const r of pushRows.rows as any[]) pushById.set(String(r.owner_user_id), num(r));

    const doctors = (users.rows as any[]).map((u) => {
      const id = String(u.id);
      const snap = snapById.get(id);
      const s = snap ? snapSummary(snap) : { appts: 0, patients: 0, online: 0, specialty: "", commune: "" };
      const ev = evById.get(id);
      return {
        id,
        email: String(u.email),
        createdAt: String(u.created_at),
        plan: u.subscription_plan ? String(u.subscription_plan) : "free_trial",
        expiresAt: u.subscription_expires_at ? String(u.subscription_expires_at) : null,
        trialStart: u.trial_start ? String(u.trial_start) : null,
        lastActive: snap ? String(snap.updated_at) : null,
        specialty: s.specialty,
        commune: s.commune,
        apptCount: s.appts,
        patientCount: s.patients,
        onlineBookings: s.online,
        eventCount: ev?.count ?? 0,
        lastEvent: ev?.last || null,
        secretaryCount: secById.get(id) ?? 0,
        pushDevices: pushById.get(id) ?? 0,
      };
    });
    // Most recently active first (nulls last).
    doctors.sort((a, b) => (b.lastActive || "").localeCompare(a.lastActive || ""));
    return res.json({ generatedAt: new Date().toISOString(), count: doctors.length, doctors });
  } catch (err: any) {
    console.error("[ADMIN] doctors error:", err.message);
    return res.status(500).json({ error: "Erreur" });
  }
});

router.get("/doctors/:id", authRequired, async (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ error: "Accès réservé" });
  try {
    const db = getDb();
    const id = String(req.params.id);
    const u = await db.execute({ sql: "SELECT id, email, created_at, subscription_plan, subscription_expires_at FROM users WHERE id = ?", args: [id] });
    if (u.rows.length === 0) return res.status(404).json({ error: "Médecin introuvable" });
    const user = u.rows[0] as any;

    const snapR = await db.execute({ sql: "SELECT appointments, patients, doctor_profile, updated_at FROM cabinet_snapshots WHERE owner_user_id = ?", args: [id] });
    const snap = snapR.rows[0] as any;
    const s = snap ? snapSummary(snap) : { appts: 0, patients: 0, online: 0, specialty: "", commune: "" };

    const cut30 = new Date(Date.now() - 30 * 86400000).toISOString();
    const plat = await db.execute({ sql: "SELECT COALESCE(platform,'web') p, count(*) c FROM analytics_events WHERE user_id = ? GROUP BY p ORDER BY c DESC", args: [id] });
    const names = await db.execute({ sql: "SELECT name, count(*) c FROM analytics_events WHERE user_id = ? GROUP BY name ORDER BY c DESC LIMIT 40", args: [id] });
    const byDay = await db.execute({ sql: "SELECT substr(created_at,1,10) d, count(*) c FROM analytics_events WHERE user_id = ? AND created_at >= ? GROUP BY d ORDER BY d", args: [id, cut30] });
    const byHour = await db.execute({ sql: "SELECT substr(created_at,12,2) h, count(*) c FROM analytics_events WHERE user_id = ? GROUP BY h ORDER BY h", args: [id] });
    const evTot = await db.execute({ sql: "SELECT count(*) c, max(created_at) last FROM analytics_events WHERE user_id = ?", args: [id] });
    const booking = await db.execute({ sql: "SELECT enabled FROM booking_links WHERE owner_user_id = ?", args: [id] });
    const sms = await db.execute({ sql: "SELECT enabled FROM sms_config WHERE owner_user_id = ?", args: [id] });
    const sec = await db.execute({ sql: "SELECT count(*) c FROM secretary_accounts WHERE owner_user_id = ? AND revoked = 0", args: [id] });
    const push = await db.execute({ sql: "SELECT count(*) c FROM push_tokens WHERE owner_user_id = ?", args: [id] });

    const allNames = (names.rows as any[]).map((r) => ({ name: String(r.name), count: num(r) }));
    return res.json({
      doctor: {
        id, email: String(user.email), createdAt: String(user.created_at),
        plan: user.subscription_plan ? String(user.subscription_plan) : "free_trial",
        expiresAt: user.subscription_expires_at ? String(user.subscription_expires_at) : null,
        lastActive: snap ? String(snap.updated_at) : null,
        specialty: s.specialty, commune: s.commune,
        apptCount: s.appts, patientCount: s.patients, onlineBookings: s.online,
        eventCount: num(evTot.rows[0]), lastEvent: evTot.rows[0]?.last ? String(evTot.rows[0].last) : null,
        secretaryCount: num(sec.rows[0]), pushDevices: num(push.rows[0]),
      },
      features: {
        bookingEnabled: (booking.rows[0] as any)?.enabled === 1,
        smsEnabled: (sms.rows[0] as any)?.enabled === 1,
      },
      byPlatform: (plat.rows as any[]).map((r) => ({ platform: String(r.p), count: num(r) })),
      topPages: allNames.filter((e) => e.name.startsWith("page:")).slice(0, 12),
      topActions: allNames.filter((e) => e.name.startsWith("action:")).slice(0, 12),
      byDay: (byDay.rows as any[]).map((r) => ({ date: String(r.d), count: num(r) })),
      byHour: (byHour.rows as any[]).map((r) => ({ hour: Number(r.h), count: num(r) })),
    });
  } catch (err: any) {
    console.error("[ADMIN] doctor detail error:", err.message);
    return res.status(500).json({ error: "Erreur" });
  }
});

// ── Account administration (DESTRUCTIVE — owner-only) ─────────────────────────
// All gated by isAdmin(). Self-protection: the owner cannot delete their own
// account. Plan changes are validated against a whitelist. Deletion clears every
// user-keyed table (no FK cascades) inside one atomic batch.

const VALID_PLANS = ["free_trial", "pro", "premium", "lifetime"];

// Every table that references a user, with its key column (used for deletion).
export const USER_TABLES: { table: string; col: string }[] = [
  { table: "profiles",           col: "user_id" },
  { table: "transactions",       col: "user_id" },
  { table: "reset_codes",        col: "user_id" },
  { table: "analytics_events",   col: "user_id" },
  { table: "invite_codes",       col: "owner_user_id" },
  { table: "secretary_sessions", col: "owner_user_id" },
  { table: "secretary_accounts", col: "owner_user_id" },
  { table: "cabinet_snapshots",  col: "owner_user_id" },
  { table: "cabinet_backups",    col: "owner_user_id" },
  { table: "booking_links",      col: "owner_user_id" },
  { table: "sms_config",         col: "owner_user_id" },
  { table: "sms_log",            col: "owner_user_id" },
  { table: "push_tokens",        col: "owner_user_id" },
];

async function loadUser(id: string) {
  const db = getDb();
  const r = await db.execute({ sql: "SELECT id, email FROM users WHERE id = ?", args: [id] });
  return r.rows.length ? (r.rows[0] as any) : null;
}

// Change subscription plan (+ optional expiry).
router.post("/doctors/:id/plan", authRequired, async (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ error: "Accès réservé" });
  try {
    const id = String(req.params.id);
    const plan = String(req.body?.plan ?? "");
    if (!VALID_PLANS.includes(plan)) return res.status(400).json({ error: "Plan invalide" });
    const expiresAt = req.body?.expiresAt ? String(req.body.expiresAt) : null;
    if (expiresAt && Number.isNaN(Date.parse(expiresAt))) return res.status(400).json({ error: "Date invalide" });
    const user = await loadUser(id);
    if (!user) return res.status(404).json({ error: "Médecin introuvable" });

    // lifetime ignores expiry; free_trial clears it; paid plans set it.
    const exp = plan === "lifetime" || plan === "free_trial" ? null : expiresAt;
    await getDb().execute({
      sql: "UPDATE users SET subscription_plan = ?, subscription_expires_at = ? WHERE id = ?",
      args: [plan, exp, id],
    });
    void logSubEvent({ userId: id, type: "plan_change", fromPlan: (user as any).subscription_plan ?? null, toPlan: plan, source: "admin" });
    console.log(`[ADMIN] ${(req as any).user.email} set plan=${plan} exp=${exp} for ${user.email}`);
    return res.json({ ok: true, plan, expiresAt: exp });
  } catch (err: any) {
    console.error("[ADMIN] set plan error:", err.message);
    return res.status(500).json({ error: "Erreur" });
  }
});

// Reset / extend the free trial (fresh 30-day window from now).
router.post("/doctors/:id/trial", authRequired, async (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ error: "Accès réservé" });
  try {
    const id = String(req.params.id);
    const user = await loadUser(id);
    if (!user) return res.status(404).json({ error: "Médecin introuvable" });
    const now = new Date().toISOString();
    await getDb().execute({
      sql: "UPDATE users SET subscription_plan = 'free_trial', trial_start = ?, subscription_expires_at = NULL WHERE id = ?",
      args: [now, id],
    });
    void logSubEvent({ userId: id, type: "trial_reset", toPlan: "free_trial", source: "admin" });
    console.log(`[ADMIN] ${(req as any).user.email} reset trial for ${user.email}`);
    return res.json({ ok: true, trialStart: now });
  } catch (err: any) {
    console.error("[ADMIN] reset trial error:", err.message);
    return res.status(500).json({ error: "Erreur" });
  }
});

// Immediately expire (cut off) an account.
router.post("/doctors/:id/expire", authRequired, async (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ error: "Accès réservé" });
  try {
    const id = String(req.params.id);
    if (id === (req as any).user.userId) return res.status(400).json({ error: "Impossible sur votre propre compte" });
    const user = await loadUser(id);
    if (!user) return res.status(404).json({ error: "Médecin introuvable" });
    await getDb().execute({
      sql: "UPDATE users SET subscription_plan = 'free_trial', trial_start = '2000-01-01T00:00:00.000Z', subscription_expires_at = '2000-01-01T00:00:00.000Z' WHERE id = ?",
      args: [id],
    });
    void logSubEvent({ userId: id, type: "expire", fromPlan: (user as any).subscription_plan ?? null, toPlan: "free_trial", source: "admin" });
    console.log(`[ADMIN] ${(req as any).user.email} EXPIRED ${user.email}`);
    return res.json({ ok: true });
  } catch (err: any) {
    console.error("[ADMIN] expire error:", err.message);
    return res.status(500).json({ error: "Erreur" });
  }
});

// ── Deep powers ────────────────────────────────────────────────────────────────

// Force-logout everywhere: revoke every token issued before now (stateless JWTs
// are rejected once iat < tokens_valid_after). The doctor must sign in again.
router.post("/doctors/:id/logout", authRequired, async (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ error: "Accès réservé" });
  try {
    const id = String(req.params.id);
    const user = await loadUser(id);
    if (!user) return res.status(404).json({ error: "Médecin introuvable" });
    const now = new Date().toISOString();
    await getDb().execute({ sql: "UPDATE users SET tokens_valid_after = ? WHERE id = ?", args: [now, id] });
    console.warn(`[ADMIN] ${(req as any).user.email} force-logged-out ${user.email}`);
    return res.json({ ok: true, at: now });
  } catch (err: any) {
    console.error("[ADMIN] logout error:", err.message);
    return res.status(500).json({ error: "Erreur" });
  }
});

// Set a new password for a doctor (owner support action) + revoke existing
// sessions so the new password takes effect immediately.
router.post("/doctors/:id/password", authRequired, async (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ error: "Accès réservé" });
  try {
    const id = String(req.params.id);
    const password = String(req.body?.password ?? "");
    if (password.length < 8) return res.status(400).json({ error: "Mot de passe trop court (8 caractères min.)" });
    const user = await loadUser(id);
    if (!user) return res.status(404).json({ error: "Médecin introuvable" });
    const hash = await bcrypt.hash(password, 12);
    const now = new Date().toISOString();
    await getDb().execute({ sql: "UPDATE users SET password_hash = ?, tokens_valid_after = ? WHERE id = ?", args: [hash, now, id] });
    console.warn(`[ADMIN] ${(req as any).user.email} reset password for ${user.email}`);
    return res.json({ ok: true });
  } catch (err: any) {
    console.error("[ADMIN] set password error:", err.message);
    return res.status(500).json({ error: "Erreur" });
  }
});

// Extend (or shorten) the subscription by N days from the later of now / current
// expiry. Moves the account onto a paid plan if it was on the trial.
router.post("/doctors/:id/extend", authRequired, async (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ error: "Accès réservé" });
  try {
    const id = String(req.params.id);
    const days = Math.round(Number(req.body?.days));
    if (!Number.isFinite(days) || days === 0 || Math.abs(days) > 3650) return res.status(400).json({ error: "Nombre de jours invalide" });
    const r = await getDb().execute({ sql: "SELECT email, subscription_plan, subscription_expires_at FROM users WHERE id = ?", args: [id] });
    if (!r.rows.length) return res.status(404).json({ error: "Médecin introuvable" });
    const row = r.rows[0] as any;
    const now = Date.now();
    const cur = row.subscription_expires_at ? Date.parse(String(row.subscription_expires_at)) : NaN;
    const from = Number.isFinite(cur) && cur > now ? cur : now;
    const next = new Date(from + days * 86400000).toISOString();
    const plan = row.subscription_plan && row.subscription_plan !== "free_trial" ? row.subscription_plan : "pro";
    await getDb().execute({ sql: "UPDATE users SET subscription_plan = ?, subscription_expires_at = ? WHERE id = ?", args: [plan, next, id] });
    void logSubEvent({ userId: id, type: "renew", fromPlan: String(row.subscription_plan ?? ""), toPlan: plan, durationDays: days, source: "admin" });
    console.log(`[ADMIN] ${(req as any).user.email} extended ${row.email} by ${days}d → ${next}`);
    return res.json({ ok: true, plan, expiresAt: next });
  } catch (err: any) {
    console.error("[ADMIN] extend error:", err.message);
    return res.status(500).json({ error: "Erreur" });
  }
});

// Permanently delete an account and ALL its data. Requires confirmEmail to match.
router.delete("/doctors/:id", authRequired, async (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ error: "Accès réservé" });
  try {
    const id = String(req.params.id);
    if (id === (req as any).user.userId) return res.status(400).json({ error: "Impossible de supprimer votre propre compte" });
    const user = await loadUser(id);
    if (!user) return res.status(404).json({ error: "Médecin introuvable" });

    const confirm = String(req.body?.confirmEmail ?? "").trim().toLowerCase();
    if (confirm !== String(user.email).toLowerCase()) {
      return res.status(400).json({ error: "Confirmation incorrecte" });
    }

    const db = getDb();
    const stmts = USER_TABLES.map(({ table, col }) => ({
      sql: `DELETE FROM ${table} WHERE ${col} = ?`,
      args: [id],
    }));
    stmts.push({ sql: "DELETE FROM users WHERE id = ?", args: [id] });
    await db.batch(stmts, "write");   // atomic: all-or-nothing
    console.warn(`[ADMIN] ${(req as any).user.email} DELETED account ${user.email} (${id}) + all data`);
    return res.json({ ok: true, deleted: user.email });
  } catch (err: any) {
    console.error("[ADMIN] delete account error:", err.message);
    return res.status(500).json({ error: "Erreur" });
  }
});

// ── Resource consumption: storage per cabinet + per-user usage + connexion geo ──
// Storage = byte size of each cabinet's stored snapshot (encrypted blob length —
// exactly what sits in the DB). "Compute" isn't directly measurable on serverless;
// event volume + active hours are the engagement/activity proxies shown alongside.
router.get("/consumption", authRequired, async (req: Request, res: Response) => {
  if (!isAdmin(req)) return res.status(403).json({ error: "Accès réservé" });
  try {
    const db = getDb();
    const emailRows = await db.execute("SELECT id, email FROM users");
    const emailById = new Map<string, string>();
    for (const r of emailRows.rows as any[]) emailById.set(String(r.id), String(r.email));

    // Storage — snapshot byte size per cabinet.
    const stoRows = await db.execute(
      "SELECT owner_user_id, (octet_length(appointments)+octet_length(patients)+octet_length(doctor_profile)+octet_length(coalesce(extra_data,''))) bytes FROM cabinet_snapshots");
    let totalBytes = 0;
    const storeUsers = (stoRows.rows as any[]).map((r) => {
      const bytes = num(r, "bytes");
      totalBytes += bytes;
      return { email: emailById.get(String(r.owner_user_id)) ?? "—", bytes };
    });
    storeUsers.sort((a, b) => b.bytes - a.bytes);
    const storage = {
      totalBytes,
      cabinets: storeUsers.length,
      avgBytes: storeUsers.length ? Math.round(totalBytes / storeUsers.length) : 0,
      users: storeUsers.slice(0, 50).map((u) => ({ ...u, pct: totalBytes ? Math.round((u.bytes / totalBytes) * 1000) / 10 : 0 })),
    };

    // Usage — per user: events, active days, active hours (time-on-app proxy).
    const usageRows = await db.execute(
      "SELECT user_id, count(*) events, count(DISTINCT substr(created_at,1,10)) days, count(DISTINCT substr(created_at,1,13)) hours, max(created_at) last FROM analytics_events GROUP BY user_id");
    const usageUsers = (usageRows.rows as any[]).map((r) => ({
      email: emailById.get(String(r.user_id)) ?? "—",
      events: num(r, "events"), activeDays: num(r, "days"), activeHours: num(r, "hours"),
      lastEvent: String(r.last ?? ""),
    }));
    usageUsers.sort((a, b) => b.events - a.events);

    // Connexion countries (populated going forward from the Vercel geo header).
    const ctryRows = await db.execute(
      "SELECT ip_country ctry, count(*) events, count(DISTINCT user_id) users FROM analytics_events WHERE ip_country IS NOT NULL GROUP BY ip_country ORDER BY events DESC LIMIT 30");
    const countries = (ctryRows.rows as any[]).map((r) => ({ country: String(r.ctry), events: num(r, "events"), users: num(r, "users") }));

    return res.json({ generatedAt: new Date().toISOString(), storage, usage: { users: usageUsers.slice(0, 50) }, countries });
  } catch (err: any) {
    console.error("[ADMIN] consumption error:", err.message);
    return res.status(500).json({ error: "Erreur" });
  }
});

export default router;
