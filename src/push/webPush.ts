import webpush from "web-push";
import { getDb } from "../db/database";

// Browser web-push (VAPID). Separate from the Expo mobile push in ./index.ts.
// Lets the doctor/secretary get a notification for a signal even when the tab is
// backgrounded or closed. Keys live in the environment (never in the DB/client).
let configured = false;
function ensureConfigured(): boolean {
  if (configured) return true;
  const pub = process.env.VAPID_PUBLIC_KEY;
  const priv = process.env.VAPID_PRIVATE_KEY;
  if (!pub || !priv) return false;
  webpush.setVapidDetails(process.env.VAPID_SUBJECT || "mailto:contact@blackpinecap.com", pub, priv);
  configured = true;
  return true;
}

/** The public VAPID key the browser needs to subscribe (safe to expose). */
export function webPushPublicKey(): string | null {
  return process.env.VAPID_PUBLIC_KEY || null;
}

export interface WebSub { endpoint: string; keys: { p256dh: string; auth: string }; }

/** Store (or refresh) a browser subscription for one side of a cabinet. */
export async function saveWebPushSub(ownerUserId: string, role: string, sub: WebSub): Promise<void> {
  if (!sub?.endpoint || !sub?.keys?.p256dh || !sub?.keys?.auth) throw new Error("bad subscription");
  await getDb().execute({
    sql: `INSERT INTO web_push_subs (endpoint, owner_user_id, role, p256dh, auth, created_at)
          VALUES (?, ?, ?, ?, ?, ?)
          ON CONFLICT (endpoint) DO UPDATE SET
            owner_user_id = excluded.owner_user_id, role = excluded.role,
            p256dh = excluded.p256dh, auth = excluded.auth`,
    args: [sub.endpoint, ownerUserId, role, sub.keys.p256dh, sub.keys.auth, new Date().toISOString()],
  });
}

/** Push to the OTHER role in a cabinet (the recipients). Best-effort; prunes
 *  dead subscriptions (404/410). Never throws into the caller. */
export async function sendWebPushToOtherRole(
  ownerUserId: string,
  fromRole: string,
  payload: { title: string; body: string; url?: string; tag?: string },
): Promise<number> {
  try {
    if (!ensureConfigured()) return 0;
    const db = getDb();
    const r = await db.execute({
      sql: "SELECT endpoint, p256dh, auth FROM web_push_subs WHERE owner_user_id = ? AND role <> ?",
      args: [ownerUserId, fromRole],
    });
    const body = JSON.stringify(payload);
    let sent = 0;
    for (const row of r.rows as any[]) {
      const subscription = { endpoint: row.endpoint as string, keys: { p256dh: row.p256dh as string, auth: row.auth as string } };
      try {
        await webpush.sendNotification(subscription as any, body, { TTL: 120 });
        sent++;
      } catch (err: any) {
        if (err?.statusCode === 404 || err?.statusCode === 410) {
          await db.execute({ sql: "DELETE FROM web_push_subs WHERE endpoint = ?", args: [row.endpoint as string] }).catch(() => {});
        } else {
          console.error("[WEBPUSH] send failed:", err?.statusCode, err?.message);
        }
      }
    }
    return sent;
  } catch (err: any) {
    console.error("[WEBPUSH] error:", err?.message || err);
    return 0;
  }
}
