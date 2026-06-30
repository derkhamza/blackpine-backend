/**
 * Server-sent push via Expo's free push service.
 *
 * No account or credentials required — we POST messages to Expo's endpoint and
 * they fan out to APNs/FCM. Best-effort: failures never throw to the caller.
 */

export interface PushMessage {
  to: string;          // ExponentPushToken[...]
  title: string;
  body: string;
  data?: Record<string, unknown>;
}

const EXPO_PUSH_URL = "https://exp.host/--/api/v2/push/send";

function chunk<T>(arr: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

/** Send the same notification to many tokens. Returns count attempted. */
export async function sendExpoPush(
  tokens: string[],
  title: string,
  body: string,
  data?: Record<string, unknown>,
): Promise<number> {
  const valid = tokens.filter(t => typeof t === "string" && t.startsWith("ExponentPushToken"));
  if (valid.length === 0) return 0;

  let sent = 0;
  for (const batch of chunk(valid, 100)) {
    const messages: PushMessage[] = batch.map(to => ({ to, title, body, data }));
    try {
      const res = await fetch(EXPO_PUSH_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify(messages.map(m => ({ ...m, sound: "default" }))),
      });
      if (res.ok) sent += batch.length;
      else console.error("[PUSH] expo responded", res.status);
    } catch (e: any) {
      console.error("[PUSH] send error:", e?.message ?? "");
    }
  }
  return sent;
}
