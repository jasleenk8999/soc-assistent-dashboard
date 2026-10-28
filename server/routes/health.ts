import { Router, type Request, type Response } from "express";
import { checkDatabaseConnection } from "../db/index";

export const healthRouter = Router();

healthRouter.get("/", async (_req: Request, res: Response) => {
  const dbHealth = await checkDatabaseConnection();
  const statusCode = dbHealth.ok ? 200 : 503;

  return res.status(statusCode).json({
    status: dbHealth.ok ? "healthy" : "degraded",
    uptimeSeconds: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
    services: {
      database: {
        status: dbHealth.ok ? "connected" : "unreachable",
        type: "PostgreSQL",
        latencyMs: dbHealth.latencyMs,
        ...(dbHealth.error ? { error: dbHealth.error } : {}),
      },
      api: {
        status: "operational",
        version: "1.0.0",
      },
    },
  });
});
