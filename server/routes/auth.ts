import { Router, type Request, type Response } from "express";
import rateLimit from "express-rate-limit";
import { eq } from "drizzle-orm";
import { db } from "../db/index";
import { users } from "../db/schema";
import {
  normalizeEmail,
  validatePasswordStrength,
  hashPassword,
  comparePassword,
  generateAccessToken,
  createSession,
  rotateRefreshToken,
  revokeSession,
} from "../services/authService";
import { requireAuth } from "../middleware/authMiddleware";
import { DEFAULT_USER_ROLE, REFRESH_COOKIE_NAME, type UserRole } from "../../shared/auth";

export const authRouter = Router();

// Rate limiter for authentication endpoints (prevent brute force & enumeration)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.NODE_ENV === "production" ? 15 : 150, // 15 in production, 150 in dev/test
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Too many authentication attempts from this IP. Please try again after 15 minutes.",
    code: "RATE_LIMITED",
  },
});

function getCookieOptions() {
  const isProd = process.env.NODE_ENV === "production";
  return {
    httpOnly: true,
    secure: isProd,
    sameSite: "lax" as const,
    path: "/",
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in ms
  };
}

// ---------------------------------------------------------------------------
// 1. POST /api/auth/register
// ---------------------------------------------------------------------------
authRouter.post("/register", authLimiter, async (req: Request, res: Response) => {
  try {
    const { email, password, fullName } = req.body;

    if (!email || typeof email !== "string" || !fullName || typeof fullName !== "string") {
      return res.status(400).json({
        error: "Full name and email are required fields.",
        code: "VALIDATION_ERROR",
      });
    }

    const cleanEmail = normalizeEmail(email);
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(cleanEmail)) {
      return res.status(400).json({
        error: "Invalid email address format.",
        code: "INVALID_EMAIL",
      });
    }

    const passwordCheck = validatePasswordStrength(password);
    if (!passwordCheck.valid) {
      return res.status(400).json({
        error: passwordCheck.reason,
        code: "WEAK_PASSWORD",
      });
    }

    // Check if user already exists
    const [existing] = await db.select().from(users).where(eq(users.email, cleanEmail));
    if (existing) {
      // Generic error or clear duplicate warning
      return res.status(409).json({
        error: "An account with this email address already exists.",
        code: "USER_EXISTS",
      });
    }

    // Mandatory Security Requirement:
    // "Public registration must assign a safe default role. Do not let clients submit arbitrary role values to obtain privileges."
    const assignedRole: UserRole = DEFAULT_USER_ROLE;

    // Calculate initials
    const nameParts = fullName.trim().split(/\s+/);
    const initials =
      nameParts.length > 1
        ? `${nameParts[0][0]}${nameParts[nameParts.length - 1][0]}`.toUpperCase()
        : fullName.slice(0, 2).toUpperCase();

    const passwordHash = await hashPassword(password);

    const [newUser] = await db
      .insert(users)
      .values({
        email: cleanEmail,
        fullName: fullName.trim(),
        passwordHash,
        role: assignedRole,
        initials,
        status: "On shift",
        color: "#b7f960",
      })
      .returning();

    // Create session & refresh token
    const ip = req.ip || req.socket.remoteAddress;
    const userAgent = req.headers["user-agent"];
    const { rawRefreshToken } = await createSession(newUser.id, ip, userAgent);

    // Set secure HTTP-only refresh token cookie
    res.cookie(REFRESH_COOKIE_NAME, rawRefreshToken, getCookieOptions());

    const accessToken = generateAccessToken({
      id: newUser.id,
      email: newUser.email,
      role: newUser.role as UserRole,
      fullName: newUser.fullName,
    });

    return res.status(201).json({
      success: true,
      user: {
        id: newUser.id,
        email: newUser.email,
        fullName: newUser.fullName,
        role: newUser.role,
        initials: newUser.initials,
        status: newUser.status,
        color: newUser.color,
      },
      accessToken,
    });
  } catch (error: any) {
    console.error("[Auth Register Error]", error);
    return res.status(500).json({ error: "Failed to register user." });
  }
});

// ---------------------------------------------------------------------------
// 2. POST /api/auth/login
// ---------------------------------------------------------------------------
authRouter.post("/login", authLimiter, async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    // Generic error constant to prevent account enumeration
    const GENERIC_LOGIN_ERROR = "Invalid email or password.";

    if (!email || !password || typeof email !== "string" || typeof password !== "string") {
      return res.status(400).json({ error: GENERIC_LOGIN_ERROR, code: "INVALID_CREDENTIALS" });
    }

    const cleanEmail = normalizeEmail(email);

    const [user] = await db.select().from(users).where(eq(users.email, cleanEmail));
    if (!user) {
      // Run dummy compare to mitigate timing attacks
      await hashPassword("dummy_delay_password_timing");
      return res.status(401).json({ error: GENERIC_LOGIN_ERROR, code: "INVALID_CREDENTIALS" });
    }

    const passwordMatch = await comparePassword(password, user.passwordHash);
    if (!passwordMatch) {
      return res.status(401).json({ error: GENERIC_LOGIN_ERROR, code: "INVALID_CREDENTIALS" });
    }

    // Create session & refresh token
    const ip = req.ip || req.socket.remoteAddress;
    const userAgent = req.headers["user-agent"];
    const { rawRefreshToken } = await createSession(user.id, ip, userAgent);

    // Set HTTP-only cookie
    res.cookie(REFRESH_COOKIE_NAME, rawRefreshToken, getCookieOptions());

    const accessToken = generateAccessToken({
      id: user.id,
      email: user.email,
      role: user.role as UserRole,
      fullName: user.fullName,
    });

    return res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        fullName: user.fullName,
        role: user.role,
        initials: user.initials,
        status: user.status,
        color: user.color,
      },
      accessToken,
    });
  } catch (error: any) {
    console.error("[Auth Login Error]", error);
    return res.status(500).json({ error: "Authentication service error." });
  }
});

// ---------------------------------------------------------------------------
// 3. POST /api/auth/logout
// ---------------------------------------------------------------------------
authRouter.post("/logout", async (req: Request, res: Response) => {
  try {
    const rawRefreshToken = req.cookies?.[REFRESH_COOKIE_NAME];
    if (rawRefreshToken) {
      await revokeSession(rawRefreshToken);
    }

    res.clearCookie(REFRESH_COOKIE_NAME, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
    });

    return res.json({ success: true, message: "Logged out successfully." });
  } catch (error: any) {
    console.error("[Auth Logout Error]", error);
    return res.status(500).json({ error: "Failed to logout session." });
  }
});

// ---------------------------------------------------------------------------
// 4. POST /api/auth/refresh
// ---------------------------------------------------------------------------
authRouter.post("/refresh", async (req: Request, res: Response) => {
  try {
    const rawRefreshToken = req.cookies?.[REFRESH_COOKIE_NAME];
    if (!rawRefreshToken) {
      return res.status(401).json({
        error: "No refresh token provided.",
        code: "NO_REFRESH_TOKEN",
      });
    }

    const ip = req.ip || req.socket.remoteAddress;
    const userAgent = req.headers["user-agent"];

    const rotationResult = await rotateRefreshToken(rawRefreshToken, ip, userAgent);
    if (!rotationResult) {
      res.clearCookie(REFRESH_COOKIE_NAME, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/",
      });
      return res.status(401).json({
        error: "Session expired or invalid. Please login again.",
        code: "SESSION_EXPIRED",
      });
    }

    // Issue updated rotated cookie
    res.cookie(REFRESH_COOKIE_NAME, rotationResult.newRawRefreshToken, getCookieOptions());

    return res.json({
      success: true,
      accessToken: rotationResult.accessToken,
      user: rotationResult.user,
    });
  } catch (error: any) {
    console.error("[Auth Refresh Error]", error);
    return res.status(500).json({ error: "Failed to refresh authentication session." });
  }
});

// ---------------------------------------------------------------------------
// 5. GET /api/auth/me
// ---------------------------------------------------------------------------
authRouter.get("/me", requireAuth, async (req: Request, res: Response) => {
  try {
    const [user] = await db
      .select({
        id: users.id,
        email: users.email,
        fullName: users.fullName,
        role: users.role,
        initials: users.initials,
        status: users.status,
        color: users.color,
        activeCasesCount: users.activeCasesCount,
        createdAt: users.createdAt,
      })
      .from(users)
      .where(eq(users.id, req.user!.id));

    if (!user) {
      return res.status(404).json({ error: "User account not found.", code: "USER_NOT_FOUND" });
    }

    return res.json({ user });
  } catch (error: any) {
    console.error("[Auth Me Error]", error);
    return res.status(500).json({ error: "Failed to fetch user profile." });
  }
});
