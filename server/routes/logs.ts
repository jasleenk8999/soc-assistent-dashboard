import { Router, type Request, type Response } from "express";
import { and, desc, eq } from "drizzle-orm";
import { db } from "../db/index";
import { logs } from "../db/schema";
import { requireAuth, requirePermission, optionalAuth } from "../middleware/authMiddleware";
import { PERMISSIONS } from "../../shared/auth";

export const logsRouter = Router();

// GET /api/logs (with optional authentication)
logsRouter.get("/", optionalAuth, async (req: Request, res: Response) => {
  try {
    const sourceType = req.query.sourceType as string | undefined;
    const isThreat = req.query.isThreat as string | undefined;
    const limit = Math.min(Math.max(parseInt(req.query.limit as string) || 50, 1), 200);
    const offset = Math.max(parseInt(req.query.offset as string) || 0, 0);

    const conditions = [];

    if (sourceType) {
      conditions.push(eq(logs.sourceType, sourceType));
    }

    if (isThreat !== undefined) {
      conditions.push(eq(logs.isThreat, isThreat === "true"));
    }

    const whereClause = conditions.length > 0 ? and(...conditions) : undefined;

    const items = await db
      .select()
      .from(logs)
      .where(whereClause)
      .orderBy(desc(logs.timestamp))
      .limit(limit)
      .offset(offset);

    return res.json({
      items,
      pagination: {
        limit,
        offset,
        total: items.length,
      },
    });
  } catch (error: any) {
    console.error("Fetch logs error:", error);
    return res.status(500).json({ error: "Failed to fetch log entries" });
  }
});

// POST /api/logs (Requires Detection Engineer or Incident Commander)
logsRouter.post("/", requireAuth, requirePermission(PERMISSIONS.INGEST_LOGS), async (req: Request, res: Response) => {
  try {
    const { sourceType, sourceHost, sourceIp, destinationIp, eventId, logLevel, rawLog, parsedFields, isThreat, threatReason } = req.body;

    if (!sourceType || !rawLog) {
      return res.status(400).json({ error: "sourceType and rawLog are required fields." });
    }

    const [inserted] = await db
      .insert(logs)
      .values({
        sourceType,
        sourceHost,
        sourceIp,
        destinationIp,
        eventId,
        logLevel: logLevel || "INFO",
        rawLog,
        parsedFields: parsedFields || {},
        isThreat: Boolean(isThreat),
        threatReason,
      })
      .returning();

    return res.status(201).json({ success: true, log: inserted });
  } catch (error: any) {
    console.error("Ingest log error:", error);
    return res.status(500).json({ error: "Failed to ingest log entry" });
  }
});
