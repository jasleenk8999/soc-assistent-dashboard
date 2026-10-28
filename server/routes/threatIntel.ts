import { Router, type Request, type Response } from "express";
import { desc, ilike, sql } from "drizzle-orm";
import { db } from "../db/index";
import { threatIntelCache } from "../db/schema";
import { requireAuth, requirePermission } from "../middleware/authMiddleware";
import { PERMISSIONS } from "@shared/auth";
import {
  getProviderStatus,
  lookupThreatIntel,
  getAlertThreatIntel,
  validateAndNormalizeIndicator,
} from "../services/threatIntelService";

export const threatIntelRouter = Router();

// ---------------------------------------------------------------------------
// 1. GET /api/threat-intel/providers — View provider health & status (No secrets)
// ---------------------------------------------------------------------------
threatIntelRouter.get(
  "/providers",
  requireAuth,
  requirePermission(PERMISSIONS.READ_THREAT_INTEL),
  async (_req: Request, res: Response) => {
    try {
      const providers = getProviderStatus();
      return res.json({
        success: true,
        providers,
        anyConfigured: providers.some((p) => p.configured),
      });
    } catch (error: any) {
      console.error("[ThreatIntel Providers Error]", error);
      return res.status(500).json({ error: "Failed to retrieve provider configuration status" });
    }
  }
);

// ---------------------------------------------------------------------------
// 2. POST /api/threat-intel/lookup — Unified indicator lookup (IP, domain, hash, URL)
// ---------------------------------------------------------------------------
threatIntelRouter.post(
  "/lookup",
  requireAuth,
  requirePermission(PERMISSIONS.READ_THREAT_INTEL),
  async (req: Request, res: Response) => {
    try {
      const rawIndicator = req.body?.indicator;
      if (!rawIndicator || typeof rawIndicator !== "string") {
        return res.status(400).json({ error: "Indicator is required and must be a non-empty string." });
      }

      if (rawIndicator.length > 2000) {
        return res.status(400).json({ error: "Indicator length exceeds maximum limit (2000 characters)." });
      }

      const explicitType = typeof req.body?.indicatorType === "string" ? req.body.indicatorType : undefined;
      const forceRefresh = Boolean(req.body?.forceRefresh);

      // Validate indicator structure before passing to provider
      const validation = validateAndNormalizeIndicator(rawIndicator, explicitType);
      if (!validation.valid) {
        return res.status(400).json({ error: validation.error || "Invalid indicator format" });
      }

      const result = await lookupThreatIntel(validation.normalized, {
        forceRefresh,
        explicitType: validation.type,
      });

      return res.json({
        success: true,
        found: result.verdict !== "Unknown" || result.isCached,
        source: result.source,
        indicator: result,
      });
    } catch (error: any) {
      console.error("[ThreatIntel Lookup Error]", error);
      return res.status(500).json({ error: error.message || "Failed to perform threat intelligence lookup" });
    }
  }
);

// ---------------------------------------------------------------------------
// 3. GET /api/threat-intel/lookup?indicator=... — Backward-compatible query lookup
// ---------------------------------------------------------------------------
threatIntelRouter.get(
  "/lookup",
  requireAuth,
  requirePermission(PERMISSIONS.READ_THREAT_INTEL),
  async (req: Request, res: Response) => {
    try {
      const rawIndicator = (req.query.indicator as string)?.trim();
      if (!rawIndicator) {
        return res.status(400).json({ error: "Indicator query parameter is required." });
      }

      if (rawIndicator.length > 2000) {
        return res.status(400).json({ error: "Indicator length exceeds maximum limit." });
      }

      const explicitType = (req.query.type as string) || undefined;
      const forceRefresh = req.query.refresh === "true";

      const validation = validateAndNormalizeIndicator(rawIndicator, explicitType);
      if (!validation.valid) {
        return res.status(400).json({ error: validation.error || "Invalid indicator format" });
      }

      const result = await lookupThreatIntel(validation.normalized, {
        forceRefresh,
        explicitType: validation.type,
      });

      return res.json({
        success: true,
        found: result.verdict !== "Unknown" || result.isCached,
        source: result.source,
        indicator: result,
      });
    } catch (error: any) {
      console.error("[ThreatIntel GET Lookup Error]", error);
      return res.status(500).json({ error: error.message || "Threat intelligence lookup failed" });
    }
  }
);

// ---------------------------------------------------------------------------
// 4. GET /api/threat-intel/alerts/:alertId — Extract and enrich all indicators for an alert
// ---------------------------------------------------------------------------
threatIntelRouter.get(
  "/alerts/:alertId",
  requireAuth,
  requirePermission(PERMISSIONS.READ_THREAT_INTEL),
  async (req: Request, res: Response) => {
    try {
      const alertId = parseInt(req.params.alertId, 10);
      if (isNaN(alertId)) {
        return res.status(400).json({ error: "Invalid alert ID format. Must be an integer." });
      }

      const result = await getAlertThreatIntel(alertId);

      return res.json({
        success: true,
        ...result,
      });
    } catch (error: any) {
      if (error?.message?.includes("not found")) {
        return res.status(404).json({ error: error.message });
      }
      console.error("[ThreatIntel Alert Enrichment Error]", error);
      return res.status(500).json({ error: error.message || "Failed to retrieve threat intelligence for alert" });
    }
  }
);

// ---------------------------------------------------------------------------
// 5. GET /api/threat-intel/history — Paginated history of cached intelligence
// ---------------------------------------------------------------------------
threatIntelRouter.get(
  "/history",
  requireAuth,
  requirePermission(PERMISSIONS.READ_THREAT_INTEL),
  async (req: Request, res: Response) => {
    try {
      const limit = Math.min(parseInt(req.query.limit as string) || 50, 100);
      const offset = Math.max(parseInt(req.query.offset as string) || 0, 0);
      const search = (req.query.search as string)?.trim();

      let query = db.select().from(threatIntelCache);

      if (search) {
        query = query.where(ilike(threatIntelCache.indicator, `%${search}%`)) as any;
      }

      const items = await query
        .orderBy(desc(threatIntelCache.lastSeen))
        .limit(limit)
        .offset(offset);

      const [countResult] = await db
        .select({ count: sql<number>`count(*)` })
        .from(threatIntelCache);

      return res.json({
        success: true,
        items,
        total: Number(countResult?.count || items.length),
        limit,
        offset,
      });
    } catch (error: any) {
      console.error("[ThreatIntel History Error]", error);
      return res.status(500).json({ error: "Failed to fetch threat intelligence history" });
    }
  }
);
