import { type Request, type Response, type NextFunction } from "express";
import { verifyAccessToken, type AuthUserPayload } from "../services/authService";
import { hasPermission, type Permission, type UserRole } from "../../shared/auth";

// Augment Express Request type with authenticated user
declare global {
  namespace Express {
    interface Request {
      user?: AuthUserPayload;
    }
  }
}

/**
 * Middleware ensuring the request contains a valid, non-expired Bearer access token
 */
export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Authentication required. Please provide a valid Bearer token in the Authorization header.",
      code: "UNAUTHORIZED",
    });
  }

  const token = authHeader.split(" ")[1];
  const payload = verifyAccessToken(token);

  if (!payload) {
    return res.status(401).json({
      error: "Access token is invalid or has expired. Please refresh your session.",
      code: "TOKEN_EXPIRED",
    });
  }

  req.user = payload;
  next();
}

/**
 * Middleware verifying that the authenticated user possesses the required permission
 */
export function requirePermission(permission: Permission) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({
        error: "Authentication required.",
        code: "UNAUTHORIZED",
      });
    }

    if (!hasPermission(req.user.role, permission)) {
      return res.status(403).json({
        error: `Access denied. Role '${req.user.role}' lacks the required permission: '${permission}'.`,
        code: "FORBIDDEN",
        requiredPermission: permission,
        userRole: req.user.role,
      });
    }

    next();
  };
}

/**
 * Middleware verifying that the user belongs to one of the authorized roles
 */
export function requireRole(allowedRoles: UserRole[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({
        error: "Authentication required.",
        code: "UNAUTHORIZED",
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: `Access denied. Role '${req.user.role}' is not authorized to perform this operation. Required: [${allowedRoles.join(", ")}]`,
        code: "FORBIDDEN",
      });
    }

    next();
  };
}

/**
 * Optional authentication middleware for endpoints that can benefit from knowing user identity
 */
export function optionalAuth(req: Request, _res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    const token = authHeader.split(" ")[1];
    const payload = verifyAccessToken(token);
    if (payload) {
      req.user = payload;
    }
  }
  next();
}
