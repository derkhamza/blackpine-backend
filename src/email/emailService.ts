import { Resend } from "resend";

const resend = new Resend(process.env.RESEND_API_KEY);
const FROM_EMAIL = process.env.FROM_EMAIL || "onboarding@resend.dev";

// The Resend SDK does NOT throw on API errors (unverified domain, invalid key,
// "test mode can only send to your own address"…) — it resolves with
// { data, error }. Ignoring that return value means a rejected email looks like
// a success, so the user reaches the code-entry screen but never gets a mail.
// This wrapper surfaces the real reason: it throws so the route returns 500 and
// the actual Resend error lands in the logs.
async function send(opts: {
  to: string;
  subject: string;
  html: string;
  label: string;
}): Promise<void> {
  if (!process.env.RESEND_API_KEY) {
    throw new Error("RESEND_API_KEY is not configured on the server");
  }
  const { data, error } = await resend.emails.send({
    from: `Blackpine <${FROM_EMAIL}>`,
    to: opts.to,
    subject: opts.subject,
    html: opts.html,
  });
  if (error) {
    // e.g. "The <domain> domain is not verified", "You can only send testing
    // emails to your own email address", "API key is invalid".
    console.error(
      `[EMAIL] ${opts.label} FAILED to ${opts.to} (from ${FROM_EMAIL}):`,
      (error as any).name || "",
      (error as any).message || JSON.stringify(error),
    );
    throw new Error((error as any).message || "Email provider rejected the message");
  }
  console.log(`[EMAIL] ${opts.label} sent to ${opts.to} (id ${data?.id ?? "?"})`);
}

const codeBlockHtml = (intro: string, code: string, outro: string) => `
  <div style="font-family: sans-serif; max-width: 400px; margin: 0 auto; padding: 32px;">
    <h2 style="color: #1E3A2F; margin-bottom: 8px;">Blackpine</h2>
    <p style="color: #666; font-size: 14px;">${intro}</p>
    <div style="background: #F5F4EF; padding: 20px; border-radius: 8px; text-align: center; margin: 24px 0;">
      <span style="font-size: 32px; font-weight: 700; letter-spacing: 8px; color: #1E3A2F;">${code}</span>
    </div>
    <p style="color: #666; font-size: 13px;">Ce code expire dans 15 minutes.</p>
    <p style="color: #999; font-size: 12px; margin-top: 24px;">${outro}</p>
  </div>
`;

export async function sendResetCode(to: string, code: string): Promise<void> {
  await send({
    to,
    label: "Reset code",
    subject: "Votre code de réinitialisation — Blackpine",
    html: codeBlockHtml(
      "Votre code de réinitialisation :",
      code,
      "Si vous n'avez pas demandé cette réinitialisation, ignorez cet email.",
    ),
  });
}

export async function sendVerificationCode(to: string, code: string): Promise<void> {
  await send({
    to,
    label: "Verification code",
    subject: "Votre code de vérification — Blackpine",
    html: codeBlockHtml(
      "Confirmez votre adresse email avec ce code :",
      code,
      "Si vous n'êtes pas à l'origine de cette inscription, ignorez cet email.",
    ),
  });
}

export async function sendEmail(to: string, subject: string, html: string): Promise<void> {
  await send({ to, subject, html, label: "Email" });
}
