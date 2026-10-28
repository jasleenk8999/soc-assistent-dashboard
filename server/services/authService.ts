import crypto from "crypto";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { and, eq, isNull, lt } from "drizzle-orm";
import { db } from "../db/index";
import { users, refreshTokens } from "../db/schema";
import { UserRole, DEFAULT_USER_ROLE } from "../../shared/auth";

const JWT_SECRET = process.env.JWT_SECRET || "fallback_soc_jwt_secret_dev_2026";
const ACCESS_TOKEN_EXPIRY = "15m"; // Short-lived access token
const REFRESH_TOKEN_EXPIRY_DAYS = 7; // 7 days refresh token validity

export interface AuthUserPayload {
  id: number;
  email: string;
  role: UserRole;
  fullName: string;
}

/**
 * Normalizes email address to avoid duplicate accounts with case variations
 */
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

/**
 * Validates password complexity
 * Requires at least 8 characters, with at least one uppercase, one lowercase, one number, and one special character
 */
export function validatePasswordStrength(password: string): { valid: boolean; reason?: string } {
  if (!password || password.length < 8) {
    return { valid: false, reason: "Password must be at least 8 characters long." };
  }
  if (!/[A-Z]/.test(password)) {
    return { valid: false, reason: "Password must contain at least one uppercase letter." };
  }
  if (!/[a-z]/.test(password)) {
    return { valid: false, reason: "Password must contain at least one lowercase letter." };
  }
  if (!/[0-9]/.test(password)) {
    return { valid: false, reason: "Password must contain at least one numeric digit." };
  }
  if (!/[^A-Za-z0-9]/.test(password)) {
    return { valid: false, reason: "Password must contain at least one special character." };
  }
  return { valid: true };
}

/**
 * Hashes password using bcrypt with work factor 10
 */
export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 10);
}

/**
 * Compares plaintext password against bcrypt hash
 */
export async function comparePassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

/**
 * Issues short-lived JWT access token
 */
export function generateAccessToken(user: AuthUserPayload): string {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role,
      fullName: user.fullName,
    },
    JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_EXPIRY }
  );
}

/**
 * Verifies JWT access token
 */
export function verifyAccessToken(token: string): AuthUserPayload | null {
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as AuthUserPayload;
    return decoded;
  } catch {
    return null;
  }
}

/**
 * Computes SHA-256 hash of a refresh token for secure database storage
 */
export function hashToken(rawToken: string): string {
  return crypto.createHash("sha256").update(rawToken).digest("hex");
}

/**
 * Generates a cryptographically secure random refresh token string
 */
export function generateRawRefreshToken(): string {
  return crypto.randomBytes(40).toString("hex");
}

/**
 * Creates a new refresh token session in PostgreSQL
 */
export async function createSession(
  userId: number,
  ipAddress?: string,
  userAgent?: string
): Promise<{ rawRefreshToken: string; expiresAt: Date }> {
  const rawRefreshToken = generateRawRefreshToken();
  const tokenHash = hashToken(rawRefreshToken);
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + REFRESH_TOKEN_EXPIRY_DAYS);

  await db.insert(refreshTokens).values({
    userId,
    tokenHash,
    expiresAt,
    userAgent: userAgent ? userAgent.slice(0, 255) : null,
    ipAddress: ipAddress ? ipAddress.slice(0, 45) : null,
  });

  return { rawRefreshToken, expiresAt };
}

/**
 * Rotates a refresh token with theft detection
 * If a previously revoked token is presented, all sessions for that user are revoked.
 */
export async function rotateRefreshToken(
  rawRefreshToken: string,
  ipAddress?: string,
  userAgent?: string
): Promise<{ accessToken: string; newRawRefreshToken: string; expiresAt: Date; user: any } | null> {
  const incomingHash = hashToken(rawRefreshToken);

  const [existingRecord] = await db
    .select()
    .from(refreshTokens)
    .where(eq(refreshTokens.tokenHash, incomingHash));

  if (!existingRecord) {
    return null;
  }

  // Theft Detection: If this token was already revoked, someone is replaying an old token!
  // Invalidate all tokens for this user for security.
  if (existingRecord.revokedAt) {
    console.warn(`[Security Alert] Replayed revoked refresh token detected for user #${existingRecord.userId}. Revoking all sessions.`);
    await db
      .update(refreshTokens)
      .set({ revokedAt: new Date() })
      .where(and(eq(refreshTokens.userId, existingRecord.userId), isNull(refreshTokens.revokedAt)));
    return null;
  }

  // Check expiration
  if (new Date() > existingRecord.expiresAt) {
    await db
      .update(refreshTokens)
      .set({ revokedAt: new Date() })
      .where(eq(refreshTokens.id, existingRecord.id));
    return null;
  }

  // Fetch the user
  const [userRecord] = await db
    .select()
    .from(users)
    .where(eq(users.id, existingRecord.userId));

  if (!userRecord) {
    return null;
  }

  // Generate new refresh token
  const newRawRefreshToken = generateRawRefreshToken();
  const newHash = hashToken(newRawRefreshToken);
  const newExpiresAt = new Date();
  newExpiresAt.setDate(newExpiresAt.getDate() + REFRESH_TOKEN_EXPIRY_DAYS);

  // Revoke the old token and link to the new token
  await db
    .update(refreshTokens)
    .set({
      revokedAt: new Date(),
      replacedByTokenHash: newHash,
    })
    .where(eq(refreshTokens.id, existingRecord.id));

  // Store the new token
  await db.insert(refreshTokens).values({
    userId: userRecord.id,
    tokenHash: newHash,
    expiresAt: newExpiresAt,
    userAgent: userAgent ? userAgent.slice(0, 255) : null,
    ipAddress: ipAddress ? ipAddress.slice(0, 45) : null,
  });

  const accessToken = generateAccessToken({
    id: userRecord.id,
    email: userRecord.email,
    role: userRecord.role as UserRole,
    fullName: userRecord.fullName,
  });

  return {
    accessToken,
    newRawRefreshToken,
    expiresAt: newExpiresAt,
    user: {
      id: userRecord.id,
      email: userRecord.email,
      fullName: userRecord.fullName,
      role: userRecord.role,
      initials: userRecord.initials,
      status: userRecord.status,
      color: userRecord.color,
    },
  };
}

/**
 * Revokes a session on logout
 */
export async function revokeSession(rawRefreshToken: string): Promise<boolean> {
  const tokenHash = hashToken(rawRefreshToken);
  const result = await db
    .update(refreshTokens)
    .set({ revokedAt: new Date() })
    .where(and(eq(refreshTokens.tokenHash, tokenHash), isNull(refreshTokens.revokedAt)))
    .returning();

  return result.length > 0;
}
