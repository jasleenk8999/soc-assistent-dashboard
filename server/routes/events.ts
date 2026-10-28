import { Router, type Request, type Response } from "express";
import { requireAuth } from "../middleware/authMiddleware";
import { RealtimeService } from "../services/realtimeService";

export const eventsRouter = Router();

/**
 * GET /api/events/stream
 * Authenticated Server-Sent Events (SSE) streaming endpoint.
 * Requires a valid Bearer JWT access token in the Authorization header.
 */
eventsRouter.get("/stream", requireAuth, (req: Request, res: Response) => {
  const user = req.user;
  if (!user) {
    return res.status(401).json({
      error: "Authentication required to establish security event stream.",
      code: "UNAUTHORIZED",
    });
  }

  // Register client stream
  RealtimeService.registerClient(req, res, user.id, user.role);
});

/**
 * GET /api/events/status
 * Telemetry endpoint providing status of active real-time subscriber streams.
 */
eventsRouter.get("/status", requireAuth, (_req: Request, res: Response) => {
  return res.json({
    status: "operational",
    activeConnections: RealtimeService.getActiveConnectionsCount(),
    maxConnections: RealtimeService.getMaxConnections(),
    transport: "Server-Sent Events (SSE)",
    timestamp: new Date().toISOString(),
  });
});
