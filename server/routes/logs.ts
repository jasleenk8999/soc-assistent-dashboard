/**
 * Log Ingestion and Telemetry Query Router
 *
 * Provides:
 * - POST /api/logs (Single log ingestion)
 * - POST /api/logs/bulk (Batch log ingestion)
 * - POST /api/logs/upload (Log file upload)
 * - GET /api/logs (Filtered & paginated log search)
 * - GET /api/logs/:id (Individual log inspection)
 */

import { Router, type Request, type Response } from "express";
import multer from "multer";
import { and, desc, eq, gte, ilike, inArray, lte, or, sql } from "drizzle-orm";
import { db } from "../db/index";
import { alerts, logs } from "../db/schema";
import { requireAuth, requirePermission, optionalAuth } from "../middleware/authMiddleware";
import { PERMISSIONS } from "../../shared/auth";
import { LogNormalizer, type NormalizedLog } from "../services/logNormalizer";
import { DetectionEngine } from "../services/detectionEngine";
import { RealtimeService } from "../services/realtimeService";
import { PythonDetectorService } from "../services/pythonDetectorService";

export const logsRouter = Router();

// Configure Multer for in-memory file uploads with a 10MB limit
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB maximum file upload
  },
  fileFilter: (_req, file, cb) => {
    const allowedExtensions = [".log", ".txt", ".json", ".csv"];
    const ext = file.originalname.toLowerCase().slice(file.originalname.lastIndexOf("."));
    if (allowedExtensions.includes(ext) || file.mimetype.includes("text") || file.mimetype.includes("json")) {
      cb(null, true);
    } else {
      cb(new Error("Unsupported file type. Please upload a .log, .txt, .json, or .csv file."));
    }
  },
});

// ---------------------------------------------------------------------------
// 1. GET /api/logs - Search, Filter, and Paginate Logs
// ---------------------------------------------------------------------------
logsRouter.get("/", optionalAuth, async (req: Request, res: Response) => {
  try {
    const search = req.query.search as string | undefined;
    const sourceType = req.query.sourceType as string | undefined;
    const logLevel = req.query.logLevel as string | undefined;
    const isThreat = req.query.isThreat as string | undefined;
    const startDate = req.query.startDate as string | undefined;
    const endDate = req.query.endDate as string | undefined;

    const limit = Math.min(Math.max(parseInt(req.query.limit as string) || 50, 1), 200);
    const offset = Math.max(parseInt(req.query.offset as string) || 0, 0);

    const conditions = [];

    if (sourceType && sourceType !== "All") {
      conditions.push(eq(logs.sourceType, sourceType));
    }

    if (logLevel && logLevel !== "All") {
      conditions.push(eq(logs.logLevel, logLevel.toUpperCase()));
    }

    if (isThreat !== undefined && isThreat !== "All") {
      conditions.push(eq(logs.isThreat, isThreat === "true"));
    }

    if (startDate) {
      const parsedStart = new Date(startDate);
      if (!isNaN(parsedStart.getTime())) {
        conditions.push(gte(logs.timestamp, parsedStart));
      }
    }

    if (endDate) {
      const parsedEnd = new Date(endDate);
      if (!isNaN(parsedEnd.getTime())) {
        conditions.push(lte(logs.timestamp, parsedEnd));
      }
    }

    if (search && search.trim()) {
      const term = `%${search.trim()}%`;
      conditions.push(
        or(
          ilike(logs.rawLog, term),
          ilike(logs.sourceIp, term),
          ilike(logs.destinationIp, term),
          ilike(logs.sourceHost, term),
          ilike(logs.username, term),
          ilike(logs.threatReason, term)
        )
      );
    }

    const whereClause = conditions.length > 0 ? and(...conditions) : undefined;

    // Fetch paginated log records
    const items = await db
      .select()
      .from(logs)
      .where(whereClause)
      .orderBy(desc(logs.timestamp), desc(logs.id))
      .limit(limit)
      .offset(offset);

    // Total count for current query
    const [countResult] = await db
      .select({ count: sql<number>`count(*)::int` })
      .from(logs)
      .where(whereClause);
    const total = countResult?.count || 0;

    // Source breakdown counts for UI filter badges
    const sourceBreakdown = await db
      .select({
        sourceType: logs.sourceType,
        count: sql<number>`count(*)::int`,
      })
      .from(logs)
      .groupBy(logs.sourceType);

    const sourceCounts: Record<string, number> = {};
    for (const row of sourceBreakdown) {
      sourceCounts[row.sourceType] = row.count;
    }

    return res.json({
      items,
      total,
      sourceCounts,
      pagination: {
        total,
        limit,
        offset,
        page: Math.floor(offset / limit) + 1,
        pages: Math.ceil(total / limit) || 1,
      },
      breakdown: {
        total,
        sources: sourceCounts,
      },
    });
  } catch (error: any) {
    console.error("Fetch logs error:", error);
    return res.status(500).json({ error: "Failed to fetch log entries" });
  }
});

// ---------------------------------------------------------------------------
// 2. GET /api/logs/:id - Single Log Detail & Associated Alerts
// ---------------------------------------------------------------------------
logsRouter.get("/:id", optionalAuth, async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) {
      return res.status(400).json({ error: "Invalid log ID format." });
    }

    const [log] = await db.select().from(logs).where(eq(logs.id, id));
    if (!log) {
      return res.status(404).json({ error: `Log entry #${id} not found.` });
    }

    // Check if this log triggered any alerts
    const relatedAlerts = await db
      .select()
      .from(alerts)
      .where(sql`${alerts.relatedLogIds}::jsonb @> ${JSON.stringify([id])}::jsonb`)
      .limit(10);

    return res.json({ log, relatedAlerts });
  } catch (error: any) {
    console.error("Get log error:", error);
    return res.status(500).json({ error: "Failed to fetch log details" });
  }
});

// ---------------------------------------------------------------------------
// 3. POST /api/logs - Ingest Single Log Record
// ---------------------------------------------------------------------------
logsRouter.post("/", requireAuth, requirePermission(PERMISSIONS.INGEST_LOGS), async (req: Request, res: Response) => {
  try {
    const body = req.body;
    if (!body || (typeof body === "object" && Object.keys(body).length === 0)) {
      return res.status(400).json({ error: "Log payload cannot be empty." });
    }

    // Normalize incoming record (handles raw string or JSON object)
    const normalized = LogNormalizer.normalize(body, body.sourceType || "Generic Ingestion");

    if (!normalized.rawLog && !normalized.sourceType) {
      return res.status(400).json({ error: "rawLog or message field is required." });
    }

    // Persist normalized log
    const [inserted] = await db
      .insert(logs)
      .values({
        timestamp: normalized.timestamp,
        sourceType: normalized.sourceType,
        sourceHost: normalized.sourceHost,
        sourceIp: normalized.sourceIp,
        destinationIp: normalized.destinationIp,
        sourcePort: normalized.sourcePort,
        destinationPort: normalized.destinationPort,
        protocol: normalized.protocol,
        username: normalized.username,
        eventId: normalized.eventId,
        eventCategory: normalized.eventCategory,
        logLevel: normalized.logLevel,
        rawLog: normalized.rawLog,
        parsedFields: normalized.parsedFields,
        isThreat: normalized.isThreat || false,
        threatReason: normalized.threatReason,
      })
      .returning();

    // Evaluate detection engine rules
    const { alerts: generatedAlerts, matches } = await DetectionEngine.evaluateAndAlert(inserted.id, normalized);

    // Publish log.ingested real-time event
    RealtimeService.publish({
      id: `evt_log_${inserted.id}_${Date.now()}`,
      type: "log.ingested",
      timestamp: new Date().toISOString(),
      data: {
        id: inserted.id,
        timestamp: inserted.timestamp.toISOString(),
        sourceType: inserted.sourceType,
        sourceHost: inserted.sourceHost || undefined,
        sourceIp: inserted.sourceIp || undefined,
        destinationIp: inserted.destinationIp || undefined,
        username: inserted.username || undefined,
        isThreat: inserted.isThreat,
        threatReason: inserted.threatReason || undefined,
        logLevel: inserted.logLevel,
      },
    });
    RealtimeService.notifyStatsUpdated();

    return res.status(201).json({
      success: true,
      log: inserted,
      alerts: generatedAlerts,
      alertGenerated: generatedAlerts.length > 0,
      alert: generatedAlerts.length > 0 ? generatedAlerts[0] : null,
      alertsGenerated: generatedAlerts,
      matchesCount: matches.length,
      detectionMatchesCount: matches.length,
    });
  } catch (error: any) {
    console.error("Ingest single log error:", error);
    return res.status(500).json({ error: "Failed to ingest log entry." });
  }
});

// ---------------------------------------------------------------------------
// 4. POST /api/logs/bulk - Bounded Batch Log Ingestion
// ---------------------------------------------------------------------------
logsRouter.post("/bulk", requireAuth, requirePermission(PERMISSIONS.INGEST_LOGS), async (req: Request, res: Response) => {
  try {
    const items = Array.isArray(req.body)
      ? req.body
      : req.body?.items || req.body?.logs || [];
    const defaultSourceType = req.body?.defaultSourceType;

    if (!Array.isArray(items)) {
      return res.status(400).json({ error: "Invalid payload: 'items' or 'logs' must be an array of logs." });
    }

    if (items.length === 0) {
      return res.status(400).json({ error: "Batch array cannot be empty." });
    }

    // Enforce reasonable upper limit per bulk request
    const MAX_BATCH_SIZE = 500;
    if (items.length > MAX_BATCH_SIZE) {
      return res.status(400).json({
        error: `Batch size exceeds maximum limit of ${MAX_BATCH_SIZE} records per request.`,
      });
    }

    const normalizedBatch = items.map((item) =>
      LogNormalizer.normalize(item, defaultSourceType || "Batch Ingestion")
    );

    const insertedLogs = await db
      .insert(logs)
      .values(
        normalizedBatch.map((n) => ({
          timestamp: n.timestamp,
          sourceType: n.sourceType,
          sourceHost: n.sourceHost,
          sourceIp: n.sourceIp,
          destinationIp: n.destinationIp,
          sourcePort: n.sourcePort,
          destinationPort: n.destinationPort,
          protocol: n.protocol,
          username: n.username,
          eventId: n.eventId,
          eventCategory: n.eventCategory,
          logLevel: n.logLevel,
          rawLog: n.rawLog,
          parsedFields: n.parsedFields,
          isThreat: n.isThreat || false,
          threatReason: n.threatReason,
        }))
      )
      .returning();

    // Run detection engine on each inserted record
    const allGeneratedAlerts: typeof alerts.$inferSelect[] = [];
    for (let i = 0; i < insertedLogs.length; i++) {
      const inserted = insertedLogs[i];
      const norm = normalizedBatch[i];
      const { alerts: genAlerts } = await DetectionEngine.evaluateAndAlert(inserted.id, norm);
      allGeneratedAlerts.push(...genAlerts);
    }

    // Deduplicate alerts in response
    const uniqueAlerts = Array.from(new Map(allGeneratedAlerts.map((a) => [a.id, a])).values());

    // Publish logs.bulk_ingested real-time event
    RealtimeService.publish({
      id: `evt_bulk_${Date.now()}`,
      type: "logs.bulk_ingested",
      timestamp: new Date().toISOString(),
      data: {
        source: defaultSourceType || "Batch Ingestion",
        ingestedCount: insertedLogs.length,
        alertsGeneratedCount: uniqueAlerts.length,
        timestamp: new Date().toISOString(),
      },
    });
    RealtimeService.notifyStatsUpdated();

    return res.status(201).json({
      success: true,
      ingestedCount: insertedLogs.length,
      alertsGeneratedCount: uniqueAlerts.length,
      alerts: uniqueAlerts,
    });
  } catch (error: any) {
    console.error("Bulk log ingestion error:", error);
    return res.status(500).json({ error: "Failed to process bulk log batch." });
  }
});

// ---------------------------------------------------------------------------
// 5. POST /api/logs/upload - Upload Supported Log File
// ---------------------------------------------------------------------------
logsRouter.post(
  "/upload",
  requireAuth,
  requirePermission(PERMISSIONS.INGEST_LOGS),
  upload.single("file"),
  async (req: Request, res: Response) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: "No file uploaded. Please select a valid log file." });
      }

      const fileBuffer = req.file.buffer;
      const fileContent = fileBuffer.toString("utf-8");
      const defaultSourceType = (req.body.sourceType as string) || "File Upload";

      // Parse file content using log normalizer
      const normalizedLogs = LogNormalizer.parseFileContent(fileContent, defaultSourceType);

      if (normalizedLogs.length === 0) {
        return res.status(400).json({ error: "The uploaded file did not contain any parseable log lines." });
      }

      // Cap at 1000 logs per upload to protect database memory
      const MAX_UPLOAD_RECORDS = 1000;
      const batchToIngest = normalizedLogs.slice(0, MAX_UPLOAD_RECORDS);

      const insertedLogs = await db
        .insert(logs)
        .values(
          batchToIngest.map((n) => ({
            timestamp: n.timestamp,
            sourceType: n.sourceType,
            sourceHost: n.sourceHost,
            sourceIp: n.sourceIp,
            destinationIp: n.destinationIp,
            sourcePort: n.sourcePort,
            destinationPort: n.destinationPort,
            protocol: n.protocol,
            username: n.username,
            eventId: n.eventId,
            eventCategory: n.eventCategory,
            logLevel: n.logLevel,
            rawLog: n.rawLog,
            parsedFields: n.parsedFields,
            isThreat: n.isThreat || false,
            threatReason: n.threatReason,
          }))
        )
        .returning();

      // Run detection engine
      const allAlerts: typeof alerts.$inferSelect[] = [];
      for (let i = 0; i < insertedLogs.length; i++) {
        const inserted = insertedLogs[i];
        const norm = batchToIngest[i];
        const { alerts: gen } = await DetectionEngine.evaluateAndAlert(inserted.id, norm);
        allAlerts.push(...gen);
      }

      const uniqueAlerts = Array.from(new Map(allAlerts.map((a) => [a.id, a])).values());

      // Publish logs.bulk_ingested real-time event for file upload
      RealtimeService.publish({
        id: `evt_upload_${Date.now()}`,
        type: "logs.bulk_ingested",
        timestamp: new Date().toISOString(),
        data: {
          source: `File Upload (${req.file.originalname})`,
          ingestedCount: insertedLogs.length,
          alertsGeneratedCount: uniqueAlerts.length,
          fileName: req.file.originalname,
          timestamp: new Date().toISOString(),
        },
      });
      RealtimeService.notifyStatsUpdated();

      // Optional Python threat enrichment (non-blocking, never fails normal ingestion)
      const pythonAnalysis = await PythonDetectorService.analyzeLogs(fileBuffer, req.file.originalname);

      return res.status(201).json({
        success: true,
        fileName: req.file.originalname,
        fileSize: req.file.size,
        totalParsed: normalizedLogs.length,
        totalParsedInFile: normalizedLogs.length,
        insertedLogsCount: insertedLogs.length,
        logsIngested: insertedLogs.length,
        alertsGeneratedCount: uniqueAlerts.length,
        alerts: uniqueAlerts,
        truncated: normalizedLogs.length > MAX_UPLOAD_RECORDS,
        pythonAnalysis,
      });
    } catch (error: any) {
      console.error("Log file upload error:", error);
      return res.status(500).json({ error: error.message || "Failed to process uploaded log file." });
    }
  }
);
