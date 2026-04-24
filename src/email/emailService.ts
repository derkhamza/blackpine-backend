import { Resend } from "resend";

const resend = new Resend(process.env.RESEND_API_KEY);
const FROM_EMAIL = process.env.FROM_EMAIL || "onboarding@resend.dev";

export async function sendResetCode(to: string, code: string): Promise<void> {
  await resend.emails.send({
    from: `Blackpine Cabinet <${FROM_EMAIL}>`,
    to,
    subject: "Votre code de réinitialisation — Blackpine Cabinet",
    html: `
      <div style="font-family: sans-serif; max-width: 400px; margin: 0 auto; padding: 32px;">
        <h2 style="color: #1E3A2F; margin-bottom: 8px;">Blackpine Cabinet</h2>
        <p style="color: #666; font-size: 14px;">Votre code de réinitialisation :</p>
        <div style="background: #F5F4EF; padding: 20px; border-radius: 8px; text-align: center; margin: 24px 0;">
          <span style="font-size: 32px; font-weight: 700; letter-spacing: 8px; color: #1E3A2F;">${code}</span>
        </div>
        <p style="color: #666; font-size: 13px;">Ce code expire dans 15 minutes.</p>
        <p style="color: #999; font-size: 12px; margin-top: 24px;">Si vous n'avez pas demandé cette réinitialisation, ignorez cet email.</p>
      </div>
    `,
  });
  console.log(`[EMAIL] Reset code sent to ${to}`);
}