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

    CREATE INDEX IF NOT EXISTS idx_invite_codes_owner ON invite_codes(owner_user_id);
    CREATE INDEX IF NOT EXISTS idx_secretary_sessions_owner ON secretary_sessions(owner_user_id);
  `);
    try { await db.execute("ALTER TABLE users ADD COLUMN trial_start TEXT"); } catch {}
    try { await db.execute("ALTER TABLE users ADD COLUMN subscription_plan TEXT DEFAULT 'free_trial'"); } catch {}
    try { await db.execute("ALTER TABLE users ADD COLUMN subscription_expires_at TEXT"); } catch {}
  console.log("[DB] Connected to Turso database");
}