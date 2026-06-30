/**
 * Provider-agnostic SMS sender.
 *
 * SAFE BY DEFAULT: with no provider credentials in the environment, sendSms()
 * is a no-op that reports "not_configured" — nothing is sent and nothing is
 * billed. Drop in one of the supported providers via env vars to activate:
 *
 *   Twilio:        TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM
 *   Generic HTTP:  SMS_HTTP_URL  (+ optional SMS_HTTP_AUTH header)
 *                  → POSTs JSON { to, message } to your gateway.
 *
 * To support a different Moroccan aggregator, either set SMS_HTTP_URL to a
 * matching endpoint or add an adapter branch below.
 */

export interface SmsResult { ok: boolean; error?: string; provider?: string; }

/** True when at least one provider is configured in the environment. */
export function smsConfigured(): boolean {
  const t = !!(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && process.env.TWILIO_FROM);
  return t || !!process.env.SMS_HTTP_URL;
}

export function activeProvider(): string | null {
  if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && process.env.TWILIO_FROM) return "twilio";
  if (process.env.SMS_HTTP_URL) return "http";
  return null;
}

/** Best-effort E.164 normalization for Moroccan numbers (+212). */
export function normalizePhone(raw: string): string {
  let p = (raw || "").replace(/[^\d+]/g, "");
  if (!p) return p;
  if (p.startsWith("+")) return p;
  if (p.startsWith("00")) return "+" + p.slice(2);
  if (p.startsWith("0") && p.length === 10) return "+212" + p.slice(1);
  if (p.startsWith("212")) return "+" + p;
  return p;
}

export async function sendSms(to: string, body: string): Promise<SmsResult> {
  const dest = normalizePhone(to);
  if (!dest) return { ok: false, error: "invalid_number" };

  if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && process.env.TWILIO_FROM) {
    return sendViaTwilio(dest, body);
  }
  if (process.env.SMS_HTTP_URL) {
    return sendViaHttp(dest, body);
  }
  return { ok: false, error: "not_configured" };
}

async function sendViaTwilio(to: string, body: string): Promise<SmsResult> {
  const sid = process.env.TWILIO_ACCOUNT_SID!;
  const token = process.env.TWILIO_AUTH_TOKEN!;
  const from = process.env.TWILIO_FROM!;
  const auth = Buffer.from(`${sid}:${token}`).toString("base64");
  const params = new URLSearchParams({ To: to, From: from, Body: body });
  try {
    const res = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`, {
      method: "POST",
      headers: { Authorization: `Basic ${auth}`, "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString(),
    });
    if (res.ok) return { ok: true, provider: "twilio" };
    const t = await res.text().catch(() => "");
    return { ok: false, error: `twilio_${res.status}:${t.slice(0, 140)}`, provider: "twilio" };
  } catch (e: any) {
    return { ok: false, error: `twilio_network:${e?.message ?? ""}`, provider: "twilio" };
  }
}

async function sendViaHttp(to: string, body: string): Promise<SmsResult> {
  const url = process.env.SMS_HTTP_URL!;
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(process.env.SMS_HTTP_AUTH ? { Authorization: process.env.SMS_HTTP_AUTH } : {}),
      },
      body: JSON.stringify({ to, message: body }),
    });
    if (res.ok) return { ok: true, provider: "http" };
    return { ok: false, error: `http_${res.status}`, provider: "http" };
  } catch (e: any) {
    return { ok: false, error: `http_network:${e?.message ?? ""}`, provider: "http" };
  }
}
