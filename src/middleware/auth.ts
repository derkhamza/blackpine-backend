import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { getDb } from "../db/database";

// Fail closed: refuse to run with the old insecure default. A missing secret
// used to silently fall back to a public, source-visible string — which let
// anyone forge a valid token for any account. The single source of truth for
// the secret lives here and is imported everywhere it is needed.
const RAW_JWT_SECRET = process.env.JWT_SECRET;
if (!RAW_JWT_SECRET || RAW_JWT_SECRET.length < 16) {
  throw new Error(
    "[FATAL] JWT_SECRET is not set (or too short). Refusing to start with an " +
    "insecure default. Set a strong random JWT_SECRET (32+ bytes) in the environment.",
  );
}
export const JWT_SECRET: string = RAW_JWT_SECRET;
const TOKEN_EXPIRY = "365d";

export interface AuthPayload {
  userId: string;
  email: string;
}

export function generateToken(payload: AuthPayload): string {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: TOKEN_EXPIRY, algorithm: "HS256" });
}

export async function authRequired(req: Request, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Token manquant" });
  }

  const token = header.slice(7);
  let decoded: AuthPayload & { iat?: number };
  try {
    decoded = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] }) as AuthPayload & { iat?: number };
  } catch {
    return res.status(401).json({ error: "Token invalide ou expiré" });
  }

  // Revocation: reject tokens issued before the user's tokens_valid_after cutoff
  // (bumped on password reset / "log out everywhere"). Fail OPEN on a DB hiccup so
  // authentication stays resilient — this is a safeguard, not a hard gate.
  try {
    const r = await getDb().execute({
      sql: "SELECT tokens_valid_after FROM users WHERE id = ?",
      args: [decoded.userId],
    });
    const cutoff = r.rows[0]?.tokens_valid_after as string | null | undefined;
    // iat is whole-seconds, so compare against the cutoff floored to seconds — a
    // token minted in the SAME second as the cutoff stays valid (avoids nuking a
    // fresh post-reset login), only strictly-earlier tokens are rejected.
    if (cutoff && decoded.iat && decoded.iat < Math.floor(new Date(cutoff).getTime() / 1000)) {
      return res.status(401).json({ error: "Session expirée, reconnectez-vous" });
    }
  } catch { /* fail open */ }

  (req as any).user = decoded;
  next();
}