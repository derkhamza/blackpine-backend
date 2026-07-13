import crypto from "crypto";

/**
 * Application-layer encryption at rest for the JSON data blobs stored in Turso.
 *
 * Threat model: a leaked database dump or stolen Turso credentials must reveal
 * only ciphertext. The key lives in the server environment (DATA_ENCRYPTION_KEY),
 * never in the database, so DB-only exposure is useless without the app server.
 *
 * Format:  enc:v1:<iv_b64>:<tag_b64>:<ciphertext_b64>   (AES-256-GCM)
 *
 * Backward compatibility: values that do NOT start with the prefix are treated
 * as legacy plaintext and returned as-is on decrypt. This lets existing rows
 * keep working with zero migration — they become ciphertext the next time they
 * are written. If no key is configured, encryption is a no-op (stores plaintext)
 * so the app keeps working until the env var is set.
 */

const PREFIX = "enc:v1:";
let cachedKey: Buffer | null | undefined; // undefined = not yet resolved

function getKey(): Buffer | null {
  if (cachedKey !== undefined) return cachedKey;
  const raw = process.env.DATA_ENCRYPTION_KEY;
  if (!raw) {
    console.warn("[CRYPTO] DATA_ENCRYPTION_KEY not set — data stored unencrypted at rest.");
    cachedKey = null;
    return null;
  }
  let buf: Buffer;
  if (/^[0-9a-fA-F]{64}$/.test(raw)) buf = Buffer.from(raw, "hex");
  else buf = Buffer.from(raw, "base64");
  if (buf.length !== 32) {
    throw new Error("DATA_ENCRYPTION_KEY must decode to 32 bytes (64 hex chars or base64).");
  }
  cachedKey = buf;
  return cachedKey;
}

/** True when a value is in our encrypted envelope. */
export function isEncrypted(value: string | null | undefined): boolean {
  return typeof value === "string" && value.startsWith(PREFIX);
}

/**
 * Whether a valid encryption key is configured on this instance. Safe to
 * expose (boolean only — never reveals the key). Used by /health so activation
 * can be verified without inspecting the database or logs.
 */
export function isCipherActive(): boolean {
  try {
    return getKey() !== null;
  } catch {
    return false; // key present but malformed
  }
}

/** Encrypt a UTF-8 string. Fails CLOSED in production (never silently writes PHI
 *  as plaintext); passthrough only in dev/test where no key is configured. */
export function encryptField(plaintext: string): string {
  const key = getKey();
  if (!key) {
    if (process.env.NODE_ENV === "production" || process.env.REQUIRE_ENCRYPTION === "1") {
      throw new Error("DATA_ENCRYPTION_KEY is not configured — refusing to store data unencrypted.");
    }
    return plaintext;
  }
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return PREFIX + iv.toString("base64") + ":" + tag.toString("base64") + ":" + ct.toString("base64");
}

/** Decrypt an encrypted envelope; returns legacy plaintext unchanged. */
export function decryptField(value: string): string {
  if (!isEncrypted(value)) return value; // legacy plaintext
  const key = getKey();
  if (!key) {
    throw new Error("Encrypted data found but DATA_ENCRYPTION_KEY is not configured.");
  }
  const parts = value.split(":"); // ["enc","v1",iv,tag,ct]
  const iv = Buffer.from(parts[2], "base64");
  const tag = Buffer.from(parts[3], "base64");
  const ct = Buffer.from(parts[4], "base64");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
}

/** Convenience: encrypt a JS value as an encrypted JSON string. */
export function encJson(value: unknown): string {
  return encryptField(JSON.stringify(value ?? null));
}

/** Convenience: decrypt + JSON.parse, tolerant of legacy plaintext. */
export function decJson<T = any>(stored: string | null | undefined, fallback: T): T {
  if (stored == null) return fallback;
  try {
    return JSON.parse(decryptField(stored)) as T;
  } catch {
    return fallback;
  }
}
