import { Router } from "express";
import { getDb } from "../db";
import { sendEmail } from "../email/emailService";
import { Resend } from "resend";

async function sendVerificationEmail(to: string, code: string): Promise<void> {
  const resend = new Resend(process.env.RESEND_API_KEY);
  await resend.emails.send({
    from: "Blackpine Cabinet <onboarding@resend.dev>",
    to,
    subject: "Blackpine Cabinet — Code de vérification",
    html: `<div style="font-family: Arial, sans-serif; max-width: 400px; margin: 0 auto; padding: 20px;">
      <h2 style="color: #1A7F64; text-align: center;">BLACKPINE CABINET</h2>
      <p style="text-align: center; color: #666;">Votre code de vérification :</p>
      <div style="text-align: center; font-size: 32px; font-weight: 800; letter-spacing: 8px; color: #1A7F64; padding: 20px; background: #E3F5EF; border-radius: 10px; margin: 20px 0;">
        ${code}
      </div>
      <p style="text-align: center; color: #999; font-size: 12px;">Ce code expire dans 10 minutes.</p>
    </div>`,
  });
}

const router = Router();

// Store codes in memory (simple approach — resets on deploy)
const verificationCodes = new Map<string, { code: string; expiresAt: number }>();

function generateCode(): string {
  return String(Math.floor(100000 + Math.random() * 900000));
}

router.post("/send-code", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email requis" });

    const code = generateCode();
    verificationCodes.set(email.toLowerCase(), {
      code,
      expiresAt: Date.now() + 10 * 60 * 1000, // 10 minutes
    });

await sendVerificationEmail(email, code);

    res.json({ success: true });
  } catch (err: any) {
    console.error("[VERIFY] Send code error:", err);
    res.status(500).json({ error: err.message || "Erreur serveur" });
  }
});

router.post("/check-code", async (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) return res.status(400).json({ error: "Email et code requis" });

    const entry = verificationCodes.get(email.toLowerCase());
    if (!entry) return res.status(400).json({ error: "Aucun code envoyé pour cet email" });
    if (Date.now() > entry.expiresAt) {
      verificationCodes.delete(email.toLowerCase());
      return res.status(400).json({ error: "Code expiré. Demandez un nouveau code." });
    }
    if (entry.code !== code.trim()) {
      return res.status(400).json({ error: "Code incorrect" });
    }

    verificationCodes.delete(email.toLowerCase());
    res.json({ verified: true });
  } catch (err: any) {
    console.error("[VERIFY] Check code error:", err);
    res.status(500).json({ error: err.message || "Erreur serveur" });
  }
});

export default router;