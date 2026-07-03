import { createClient, Client } from "@libsql/client";

let db: Client;

export function getDb(): Client {
  if (!db) {
    throw new Error("Database not initialized. Call initDatabase() first.");
  }
  return db;
}

export async function initDatabase(): Promise<void> {
  const url = process.env.TURSO_DATABASE_URL;
  const authToken = process.env.TURSO_AUTH_TOKEN;

  if (!url) {
    throw new Error("TURSO_DATABASE_URL environment variable is required");
  }

  db = createClient({
    url,
    authToken,
  });

  // Create tables
  await db.executeMultiple(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS profiles (
      user_id TEXT PRIMARY KEY,
      data TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      data TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );


    CREATE TABLE IF NOT EXISTS reset_codes (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      code TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      used INTEGER DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Signup email-verification codes. Keyed by email (the user does not exist
    -- yet), durable so codes survive serverless cold starts between send + verify.
    CREATE TABLE IF NOT EXISTS email_verifications (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL,
      code TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      used INTEGER DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_email_verifications_email ON email_verifications(email);

    CREATE TABLE IF NOT EXISTS activation_codes (
  code TEXT PRIMARY KEY,
  plan TEXT NOT NULL,
  duration_days INTEGER,
  customer_email TEXT,
  customer_name TEXT,
  created_at TEXT NOT NULL,
  used INTEGER DEFAULT 0,
  used_at TEXT);
    CREATE INDEX IF NOT EXISTS idx_transactions_user ON transactions(user_id);

    CREATE TABLE IF NOT EXISTS invite_codes (
      code TEXT PRIMARY KEY,
      owner_user_id TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      used INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS secretary_sessions (
      id TEXT PRIMARY KEY,
      code TEXT NOT NULL,
      owner_user_id TEXT NOT NULL,
      token TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      revoked INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS cabinet_snapshots (
      owner_user_id TEXT PRIMARY KEY,
      appointments TEXT NOT NULL DEFAULT '[]',
      patients TEXT NOT NULL DEFAULT '[]',
      doctor_profile TEXT NOT NULL DEFAULT '{}',
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS cabinet_backups (
      id TEXT PRIMARY KEY,
      owner_user_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      reason TEXT NOT NULL DEFAULT 'auto',
      appointments TEXT NOT NULL DEFAULT '[]',
      patients TEXT NOT NULL DEFAULT '[]',
      doctor_profile TEXT NOT NULL DEFAULT '{}',
      extra_data TEXT NOT NULL DEFAULT '{}'
    );
    CREATE INDEX IF NOT EXISTS idx_cabinet_backups_owner ON cabinet_backups(owner_user_id, created_at);

    CREATE INDEX IF NOT EXISTS idx_invite_codes_owner ON invite_codes(owner_user_id);
    CREATE INDEX IF NOT EXISTS idx_secretary_sessions_owner ON secretary_sessions(owner_user_id);

    -- Persistent secretary login accounts (username + password), linked to a
    -- doctor, no expiry, revocable. Distinct from the one-off invite codes.
    CREATE TABLE IF NOT EXISTS secretary_accounts (
      id            TEXT PRIMARY KEY,
      owner_user_id TEXT NOT NULL,
      username      TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      name          TEXT,
      created_at    TEXT NOT NULL DEFAULT (datetime('now')),
      revoked       INTEGER DEFAULT 0
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_secretary_accounts_username ON secretary_accounts(username);
    CREATE INDEX IF NOT EXISTS idx_secretary_accounts_owner ON secretary_accounts(owner_user_id);

    -- Public online-booking links. One per doctor; slug is the public identifier.
    -- Working-hours config lives here (start/end minutes-from-midnight, slot length,
    -- allowed weekdays 0=Sun..6=Sat). No patient data → not encrypted.
    CREATE TABLE IF NOT EXISTS booking_links (
      slug          TEXT PRIMARY KEY,
      owner_user_id TEXT NOT NULL UNIQUE,
      enabled       INTEGER DEFAULT 1,
      doctor_name   TEXT,
      specialty     TEXT,
      start_min     INTEGER DEFAULT 540,
      end_min       INTEGER DEFAULT 1020,
      slot_min      INTEGER DEFAULT 30,
      days          TEXT DEFAULT '1,2,3,4,5,6',
      created_at    TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Automated SMS reminder config, one row per doctor. Disabled by default.
    CREATE TABLE IF NOT EXISTS sms_config (
      owner_user_id TEXT PRIMARY KEY,
      enabled       INTEGER DEFAULT 0,
      lead_days     INTEGER DEFAULT 1,
      template      TEXT,
      updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Idempotency / audit log so a reminder is sent at most once per appointment.
    CREATE TABLE IF NOT EXISTS sms_log (
      owner_user_id  TEXT NOT NULL,
      appointment_id TEXT NOT NULL,
      appt_date      TEXT NOT NULL,
      sent_at        TEXT NOT NULL DEFAULT (datetime('now')),
      status         TEXT NOT NULL,
      PRIMARY KEY (owner_user_id, appointment_id, appt_date)
    );

    -- Expo push tokens (one device = one row) for server-sent notifications.
    CREATE TABLE IF NOT EXISTS push_tokens (
      token         TEXT PRIMARY KEY,
      owner_user_id TEXT NOT NULL,
      updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_push_tokens_owner ON push_tokens(owner_user_id);

    -- Behavioural analytics: event NAMES only (e.g. "page:/agenda",
    -- "action:create_rdv"). No PII. Used by the owner usage dashboard.
    CREATE TABLE IF NOT EXISTS analytics_events (
      id         TEXT PRIMARY KEY,
      user_id    TEXT NOT NULL,
      name       TEXT NOT NULL,
      platform   TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_analytics_created ON analytics_events(created_at);
    CREATE INDEX IF NOT EXISTS idx_analytics_name ON analytics_events(name);

    -- Official Moroccan medication reference (DMP/CNOPS open data, ODbL).
    -- Public reference data — NOT patient data, so not encrypted; it is queried.
    CREATE TABLE IF NOT EXISTS medications (
      code               TEXT PRIMARY KEY,
      nom                TEXT NOT NULL,
      dci                TEXT,
      dosage             TEXT,
      unite              TEXT,
      forme              TEXT,
      presentation       TEXT,
      ppv                REAL,
      ph                 REAL,
      prix_br            REAL,
      type               TEXT,           -- P (princeps) / G (générique)
      taux_remboursement TEXT,
      search             TEXT            -- normalized "nom dci" for fast lookup
    );
    CREATE INDEX IF NOT EXISTS idx_medications_search ON medications(search);
    CREATE INDEX IF NOT EXISTS idx_medications_nom ON medications(nom);
  `);
    try { await db.execute("ALTER TABLE users ADD COLUMN trial_start TEXT"); } catch {}
    try { await db.execute("ALTER TABLE users ADD COLUMN subscription_plan TEXT DEFAULT 'free_trial'"); } catch {}
    try { await db.execute("ALTER TABLE users ADD COLUMN subscription_expires_at TEXT"); } catch {}
    try { await db.execute("ALTER TABLE cabinet_snapshots ADD COLUMN extra_data TEXT DEFAULT '{}'"); } catch {}
    // Link account-based secretary logins to their account so the doctor can revoke them.
    try { await db.execute("ALTER TABLE secretary_sessions ADD COLUMN account_id TEXT"); } catch {}
  console.log("[DB] Connected to Turso database");
}