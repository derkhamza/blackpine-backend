import { neon, NeonQueryFunction } from "@neondatabase/serverless";
import { randomUUID } from "crypto";

// ── Neon (serverless Postgres) data layer ────────────────────────────────────
//
// Replaces Turso/libSQL. Neon's `neon()` driver runs every query as a stateless
// HTTPS request (fetch) — there is NO persistent TCP connection to hang or pool
// to exhaust, which is exactly the failure class that plagued the previous DB.
//
// To keep the 17 route files unchanged, a small translator adapts the app's
// SQLite-flavoured SQL to Postgres at runtime: `?`→`$n` placeholders,
// `datetime('now', …)`→ISO-text expressions, `strftime('%Y-%W', …)`→to_char,
// and `INSERT OR IGNORE`→`… ON CONFLICT DO NOTHING`. The result shape mirrors the
// old client: `{ rows, rowsAffected }`, so `.rows` access is untouched.

type Row = Record<string, any>;
export interface DbResult { rows: Row[]; rowsAffected: number; lastInsertRowid?: undefined; }
export type Stmt = string | { sql: string; args?: any[] };

export interface DbClient {
  execute(stmt: Stmt): Promise<DbResult>;
  execute(sql: string, args: any[]): Promise<DbResult>;
  // The optional mode arg (from the libsql API) is accepted and ignored — Neon
  // batches run atomically as a single transaction regardless.
  batch(stmts: Stmt[], mode?: string): Promise<DbResult[]>;
  executeMultiple(sql: string): Promise<void>;
}

let sqlFn: NeonQueryFunction<false, true> | null = null;
let client: DbClient | null = null;

const SCHEMA_VERSION = 9;

// Hard ceiling per query. Neon HTTP calls don't hang like a raw TCP connect, but
// this keeps a slow network from ever riding the function's 300s ceiling.
const QUERY_TIMEOUT_MS = 12_000;

function dbTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error("DB_TIMEOUT")), ms);
    p.then((v) => { clearTimeout(t); resolve(v); }, (e) => { clearTimeout(t); reject(e); });
  });
}

// ── SQLite → Postgres SQL translation ────────────────────────────────────────

// ISO-8601 UTC text (matches JS new Date().toISOString(), so string comparisons
// on the app's TEXT timestamp columns keep working).
const ISO = `'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'`;
const NOW_ISO = `to_char((now() at time zone 'utc'), ${ISO})`;

function translate(sql: string): string {
  let s = sql;

  // datetime('now', '+N unit') / ('-N unit') / ('now') → ISO text expression.
  s = s.replace(/datetime\(\s*'now'\s*(?:,\s*'([+-])\s*(\d+)\s+(day|days|hour|hours|minute|minutes|month|months|year|years)'\s*)?\)/gi,
    (_m, sign: string, num: string, unit: string) => {
      if (!sign) return NOW_ISO;
      const op = sign === "-" ? "-" : "+";
      return `to_char(((now() at time zone 'utc') ${op} interval '${num} ${unit}'), ${ISO})`;
    });

  // strftime('%Y-%W', X) → ISO year-week bucket.
  s = s.replace(/strftime\(\s*'%Y-%W'\s*,\s*([^)]+?)\)/gi, (_m, col: string) => `to_char((${col})::timestamptz, 'IYYY-IW')`);

  // INSERT OR IGNORE → INSERT … ON CONFLICT DO NOTHING.
  let ignore = false;
  s = s.replace(/INSERT\s+OR\s+IGNORE\s+INTO/gi, () => { ignore = true; return "INSERT INTO"; });
  if (ignore && !/ON\s+CONFLICT/i.test(s)) s = s.replace(/\s*;?\s*$/, "") + " ON CONFLICT DO NOTHING";

  // ON CONFLICT(col) → ON CONFLICT (col) (be lenient about the space).
  s = s.replace(/ON\s+CONFLICT\(/gi, "ON CONFLICT (");

  // Positional ?  →  $1, $2, … (skip anything inside single-quoted string literals).
  let i = 0;
  let out = "";
  let inStr = false;
  for (let k = 0; k < s.length; k++) {
    const c = s[k];
    if (c === "'") { inStr = !inStr; out += c; continue; }
    if (c === "?" && !inStr) { out += "$" + (++i); continue; }
    out += c;
  }
  return out;
}

async function runQuery(sql: string, args: any[]): Promise<DbResult> {
  if (!sqlFn) throw new Error("Database not initialized. Call initDatabase() first.");
  const text = translate(sql);
  const res: any = await dbTimeout(sqlFn.query(text, args), QUERY_TIMEOUT_MS);
  // fullResults:true → { rows, rowCount, fields, ... }
  return { rows: res.rows ?? [], rowsAffected: res.rowCount ?? 0 };
}

function stmtParts(s: Stmt): { sql: string; args: any[] } {
  return typeof s === "string" ? { sql: s, args: [] } : { sql: s.sql, args: s.args ?? [] };
}

function makeClient(): DbClient {
  const c: DbClient = {
    execute(stmt: Stmt | string, args?: any[]) {
      if (typeof stmt === "string") return runQuery(stmt, args ?? []);
      return runQuery(stmt.sql, stmt.args ?? []);
    },
    // Atomic: Neon's transaction() sends every statement in ONE request and
    // commits all-or-nothing (used for account/data deletion).
    async batch(stmts: Stmt[]) {
      if (!sqlFn) throw new Error("Database not initialized. Call initDatabase() first.");
      const queries = stmts.map((s) => { const { sql, args } = stmtParts(s); return sqlFn!.query(translate(sql), args); });
      const results: any[] = await dbTimeout(sqlFn.transaction(queries as any), QUERY_TIMEOUT_MS);
      return results.map((r) => ({ rows: r?.rows ?? [], rowsAffected: r?.rowCount ?? 0 }));
    },
    async executeMultiple(sql: string) {
      for (const part of sql.split(";").map((p) => p.trim()).filter(Boolean)) {
        await runQuery(part, []);
      }
    },
  };
  return c;
}

export function getDb(): DbClient {
  if (!client) throw new Error("Database not initialized. Call initDatabase() first.");
  return client;
}

// ── Postgres schema (one statement per array entry — Neon HTTP runs one at a
// time). Timestamp columns stay TEXT with an ISO default to match the app's
// string-based date handling. ─────────────────────────────────────────────────
const SCHEMA: string[] = [
  `CREATE TABLE IF NOT EXISTS users (
     id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
     created_at TEXT NOT NULL DEFAULT ${NOW_ISO}, updated_at TEXT NOT NULL DEFAULT ${NOW_ISO},
     trial_start TEXT, subscription_plan TEXT DEFAULT 'free_trial', subscription_expires_at TEXT,
     tokens_valid_after TEXT)`,
  // Any token issued before this instant is rejected (password reset / "log out
  // everywhere"). Lets us revoke otherwise-stateless doctor JWTs.
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS tokens_valid_after TEXT`,
  `CREATE TABLE IF NOT EXISTS profiles (
     user_id TEXT PRIMARY KEY, data TEXT NOT NULL, updated_at TEXT NOT NULL DEFAULT ${NOW_ISO})`,
  `CREATE TABLE IF NOT EXISTS transactions (
     id TEXT PRIMARY KEY, user_id TEXT NOT NULL, data TEXT NOT NULL,
     created_at TEXT NOT NULL DEFAULT ${NOW_ISO}, updated_at TEXT NOT NULL DEFAULT ${NOW_ISO})`,
  `CREATE INDEX IF NOT EXISTS idx_transactions_user ON transactions(user_id)`,
  `CREATE TABLE IF NOT EXISTS reset_codes (
     id TEXT PRIMARY KEY, user_id TEXT NOT NULL, code TEXT NOT NULL, expires_at TEXT NOT NULL,
     used INTEGER DEFAULT 0, attempts INTEGER DEFAULT 0, created_at TEXT NOT NULL DEFAULT ${NOW_ISO})`,
  `ALTER TABLE reset_codes ADD COLUMN IF NOT EXISTS attempts INTEGER DEFAULT 0`,
  `CREATE TABLE IF NOT EXISTS email_verifications (
     id TEXT PRIMARY KEY, email TEXT NOT NULL, code TEXT NOT NULL, expires_at TEXT NOT NULL,
     used INTEGER DEFAULT 0, attempts INTEGER DEFAULT 0, created_at TEXT NOT NULL DEFAULT ${NOW_ISO})`,
  `ALTER TABLE email_verifications ADD COLUMN IF NOT EXISTS attempts INTEGER DEFAULT 0`,
  `CREATE INDEX IF NOT EXISTS idx_email_verifications_email ON email_verifications(email)`,
  `CREATE TABLE IF NOT EXISTS activation_codes (
     code TEXT PRIMARY KEY, plan TEXT NOT NULL, duration_days INTEGER, customer_email TEXT,
     customer_name TEXT, created_at TEXT NOT NULL, used INTEGER DEFAULT 0, used_at TEXT)`,
  `CREATE TABLE IF NOT EXISTS invite_codes (
     code TEXT PRIMARY KEY, owner_user_id TEXT NOT NULL, expires_at TEXT NOT NULL,
     created_at TEXT NOT NULL DEFAULT ${NOW_ISO}, used INTEGER DEFAULT 0)`,
  `CREATE INDEX IF NOT EXISTS idx_invite_codes_owner ON invite_codes(owner_user_id)`,
  `CREATE TABLE IF NOT EXISTS secretary_sessions (
     id TEXT PRIMARY KEY, code TEXT NOT NULL, owner_user_id TEXT NOT NULL, token TEXT NOT NULL,
     created_at TEXT NOT NULL DEFAULT ${NOW_ISO}, revoked INTEGER DEFAULT 0, account_id TEXT)`,
  `CREATE INDEX IF NOT EXISTS idx_secretary_sessions_owner ON secretary_sessions(owner_user_id)`,
  `CREATE TABLE IF NOT EXISTS secretary_accounts (
     id TEXT PRIMARY KEY, owner_user_id TEXT NOT NULL, username TEXT NOT NULL, password_hash TEXT NOT NULL,
     name TEXT, created_at TEXT NOT NULL DEFAULT ${NOW_ISO}, revoked INTEGER DEFAULT 0)`,
  `CREATE UNIQUE INDEX IF NOT EXISTS idx_secretary_accounts_username ON secretary_accounts(username)`,
  `CREATE INDEX IF NOT EXISTS idx_secretary_accounts_owner ON secretary_accounts(owner_user_id)`,
  `CREATE TABLE IF NOT EXISTS cabinet_snapshots (
     owner_user_id TEXT PRIMARY KEY, appointments TEXT NOT NULL DEFAULT '[]', patients TEXT NOT NULL DEFAULT '[]',
     doctor_profile TEXT NOT NULL DEFAULT '{}', updated_at TEXT NOT NULL DEFAULT ${NOW_ISO},
     extra_data TEXT DEFAULT '{}')`,
  // Per-column content versions (JSON {a,p,r,e}) so a pull can skip columns the
  // client already has — cuts Neon egress. Null on legacy rows → pull sends full.
  `ALTER TABLE cabinet_snapshots ADD COLUMN IF NOT EXISTS col_versions TEXT`,
  `CREATE TABLE IF NOT EXISTS cabinet_backups (
     id TEXT PRIMARY KEY, owner_user_id TEXT NOT NULL, created_at TEXT NOT NULL, reason TEXT NOT NULL DEFAULT 'auto',
     appointments TEXT NOT NULL DEFAULT '[]', patients TEXT NOT NULL DEFAULT '[]',
     doctor_profile TEXT NOT NULL DEFAULT '{}', extra_data TEXT NOT NULL DEFAULT '{}')`,
  `CREATE INDEX IF NOT EXISTS idx_cabinet_backups_owner ON cabinet_backups(owner_user_id, created_at)`,
  // Live doctor↔secretary signal bus (call-in reflected instantly + intercom).
  // Tiny, transient rows — polled fast and pruned aggressively; NOT the snapshot.
  `CREATE TABLE IF NOT EXISTS cabinet_signals (
     id TEXT PRIMARY KEY, owner_user_id TEXT NOT NULL, from_role TEXT NOT NULL,
     from_name TEXT, type TEXT NOT NULL, payload TEXT DEFAULT '{}',
     created_at TEXT NOT NULL DEFAULT ${NOW_ISO})`,
  `CREATE INDEX IF NOT EXISTS idx_cabinet_signals_owner ON cabinet_signals(owner_user_id, created_at)`,
  // Web-push subscriptions (browser notifications when the tab is backgrounded).
  // Keyed by the (unique) push endpoint; role = which side of the cabinet subscribed.
  `CREATE TABLE IF NOT EXISTS web_push_subs (
     endpoint TEXT PRIMARY KEY, owner_user_id TEXT NOT NULL, role TEXT NOT NULL,
     p256dh TEXT NOT NULL, auth TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT ${NOW_ISO})`,
  `CREATE INDEX IF NOT EXISTS idx_web_push_subs_owner ON web_push_subs(owner_user_id)`,
  // Persistent doctor↔secretary chat (unlike the transient signal bus).
  `CREATE TABLE IF NOT EXISTS cabinet_messages (
     id TEXT PRIMARY KEY, owner_user_id TEXT NOT NULL, from_role TEXT NOT NULL,
     from_name TEXT, body TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT ${NOW_ISO})`,
  `CREATE INDEX IF NOT EXISTS idx_cabinet_messages_owner ON cabinet_messages(owner_user_id, created_at)`,
  `CREATE TABLE IF NOT EXISTS booking_links (
     slug TEXT PRIMARY KEY, owner_user_id TEXT NOT NULL UNIQUE, enabled INTEGER DEFAULT 1, doctor_name TEXT,
     specialty TEXT, start_min INTEGER DEFAULT 540, end_min INTEGER DEFAULT 1020, slot_min INTEGER DEFAULT 30,
     days TEXT DEFAULT '1,2,3,4,5,6', created_at TEXT NOT NULL DEFAULT ${NOW_ISO})`,
  `CREATE TABLE IF NOT EXISTS sms_config (
     owner_user_id TEXT PRIMARY KEY, enabled INTEGER DEFAULT 0, lead_days INTEGER DEFAULT 1,
     template TEXT, updated_at TEXT NOT NULL DEFAULT ${NOW_ISO})`,
  `CREATE TABLE IF NOT EXISTS sms_log (
     owner_user_id TEXT NOT NULL, appointment_id TEXT NOT NULL, appt_date TEXT NOT NULL,
     sent_at TEXT NOT NULL DEFAULT ${NOW_ISO}, status TEXT NOT NULL,
     PRIMARY KEY (owner_user_id, appointment_id, appt_date))`,
  `CREATE TABLE IF NOT EXISTS push_tokens (
     token TEXT PRIMARY KEY, owner_user_id TEXT NOT NULL, updated_at TEXT NOT NULL DEFAULT ${NOW_ISO})`,
  `CREATE INDEX IF NOT EXISTS idx_push_tokens_owner ON push_tokens(owner_user_id)`,
  `CREATE TABLE IF NOT EXISTS analytics_events (
     id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, platform TEXT,
     created_at TEXT NOT NULL DEFAULT ${NOW_ISO})`,
  `CREATE INDEX IF NOT EXISTS idx_analytics_created ON analytics_events(created_at)`,
  `CREATE INDEX IF NOT EXISTS idx_analytics_name ON analytics_events(name)`,
  // Connexion country (ISO-2), captured best-effort from the Vercel geo header on
  // event ingestion. Only populated for events sent after this column shipped.
  `ALTER TABLE analytics_events ADD COLUMN IF NOT EXISTS ip_country TEXT`,
  `CREATE INDEX IF NOT EXISTS idx_analytics_user ON analytics_events(user_id)`,
  `CREATE TABLE IF NOT EXISTS medications (
     code TEXT PRIMARY KEY, nom TEXT NOT NULL, dci TEXT, dosage TEXT, unite TEXT, forme TEXT, presentation TEXT,
     ppv REAL, ph REAL, prix_br REAL, type TEXT, taux_remboursement TEXT, search TEXT)`,
  `CREATE INDEX IF NOT EXISTS idx_medications_search ON medications(search)`,
  `CREATE INDEX IF NOT EXISTS idx_medications_nom ON medications(nom)`,
  // Durable, cross-instance rate-limit counters (serverless functions don't share
  // memory, so an in-process Map never aggregates). bucket = "<ip>:<route>".
  `CREATE TABLE IF NOT EXISTS rate_limits (
     bucket TEXT PRIMARY KEY, count INTEGER NOT NULL DEFAULT 0, reset_at TEXT NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS idx_rate_limits_reset ON rate_limits(reset_at)`,
  // Subscription lifecycle log — one row per plan transition (signup, convert,
  // renew, expire, plan_change, trial_reset). Enables EXACT cohort conversion /
  // churn / MRR-movement analytics over time (the users table only holds current
  // state). Append-only; backfilled once from users + activation_codes on first run.
  `CREATE TABLE IF NOT EXISTS subscription_events (
     id TEXT PRIMARY KEY, user_id TEXT NOT NULL, type TEXT NOT NULL,
     from_plan TEXT, to_plan TEXT, duration_days INTEGER, source TEXT,
     created_at TEXT NOT NULL DEFAULT ${NOW_ISO})`,
  `CREATE INDEX IF NOT EXISTS idx_sub_events_user ON subscription_events(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_sub_events_created ON subscription_events(created_at)`,
  `CREATE INDEX IF NOT EXISTS idx_sub_events_type ON subscription_events(type)`,
  `CREATE TABLE IF NOT EXISTS schema_meta (id INTEGER PRIMARY KEY, version INTEGER NOT NULL)`,
];

let initPromise: Promise<void> | null = null;

export function initDatabase(): Promise<void> {
  if (!initPromise) initPromise = doInit().catch((e) => { initPromise = null; throw e; });
  return initPromise;
}

async function doInit(): Promise<void> {
  const url = process.env.DATABASE_URL || process.env.NEON_DATABASE_URL;
  if (!url) throw new Error("DATABASE_URL environment variable is required");
  if (!sqlFn) { sqlFn = neon(url, { fullResults: true }); client = makeClient(); }

  // Fast path: schema already at the current version.
  try {
    const r = await runQuery("SELECT version FROM schema_meta WHERE id = 1", []);
    if (r.rows.length && Number(r.rows[0].version) >= SCHEMA_VERSION) return;
  } catch (e: any) {
    if (e?.message === "DB_TIMEOUT") throw new Error("DB_PROBE_TIMEOUT");
    // schema_meta absent (fresh DB) → fall through and create everything.
  }

  // NOTE: this runs only on a version bump (the fast-path above returns otherwise),
  // and the first post-deploy request that trips it blocks until every statement
  // finishes. `CREATE INDEX IF NOT EXISTS` on an already-large existing table takes
  // an ACCESS EXCLUSIVE lock for the build. Existing indexes are no-op re-checks, so
  // this is fine today — but a FUTURE index added to a big table (cabinet_snapshots,
  // analytics_events…) should be created out-of-band with CREATE INDEX CONCURRENTLY
  // (which cannot run here — it can't be inside a transaction/batch), not added to
  // this list, to avoid a migration stalling every request behind the lock.
  for (const stmt of SCHEMA) await runQuery(stmt, []);
  await runQuery(
    `INSERT INTO schema_meta (id, version) VALUES (1, ${SCHEMA_VERSION})
     ON CONFLICT (id) DO UPDATE SET version = ${SCHEMA_VERSION}`, []);

  // One-time backfill of subscription_events from existing data (runs only when
  // the table is empty). Gives immediate historical cohorts: a signup event per
  // user, and a convert event per redeemed activation code linked by email.
  try {
    const c = await runQuery("SELECT count(*) c FROM subscription_events", []);
    if (Number((c.rows[0] as any)?.c ?? 0) === 0) {
      await runQuery(
        `INSERT INTO subscription_events (id, user_id, type, to_plan, source, created_at)
         SELECT 'bf-signup-' || id, id, 'signup', 'free_trial', 'system', created_at FROM users`, []);
      await runQuery(
        `INSERT INTO subscription_events (id, user_id, type, to_plan, duration_days, source, created_at)
         SELECT 'bf-conv-' || ac.code, u.id, 'convert', ac.plan, ac.duration_days, 'code', ac.used_at
         FROM activation_codes ac JOIN users u ON lower(u.email) = lower(ac.customer_email)
         WHERE ac.used = 1 AND ac.used_at IS NOT NULL AND ac.customer_email IS NOT NULL`, []);
      console.log("[DB] subscription_events backfilled");
    }
  } catch (e: any) { console.error("[DB] sub-events backfill skipped:", e?.message); }

  console.log("[DB] Neon schema ensured (version " + SCHEMA_VERSION + ")");
}

/**
 * Append a subscription lifecycle event. Best-effort — never throws into the
 * caller's flow (analytics must not block signups/redemptions).
 */
export async function logSubEvent(ev: {
  userId: string; type: string;
  fromPlan?: string | null; toPlan?: string | null; durationDays?: number | null; source?: string;
}): Promise<void> {
  try {
    await getDb().execute({
      sql: `INSERT INTO subscription_events (id, user_id, type, from_plan, to_plan, duration_days, source, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [randomUUID(), ev.userId, ev.type, ev.fromPlan ?? null, ev.toPlan ?? null,
             ev.durationDays ?? null, ev.source ?? "system", new Date().toISOString()],
    });
  } catch (e: any) { console.error("[DB] logSubEvent failed:", e?.message); }
}
