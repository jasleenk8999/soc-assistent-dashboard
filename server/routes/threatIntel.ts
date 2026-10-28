import { Router, type Request, type Response } from "express";
import { desc, eq } from "drizzle-orm";
import { db } from "../db/index";
import { threatIntelCache } from "../db/schema";

export const threatIntelRouter = Router();

// GET /api/threat-intel/history
threatIntelRouter.get("/history", async (_req: Request, res: Response) => {
  try {
    const items = await db
      .select()
      .from(threatIntelCache)
      .orderBy(desc(threatIntelCache.lastSeen));

    return res.json({
      items,
      total: items.length,
    });
  } catch (error: any) {
    console.error("Fetch threat intel history error:", error);
    return res.status(500).json({ error: "Failed to fetch threat intelligence history" });
  }
});

// GET /api/threat-intel/lookup?indicator=...
threatIntelRouter.get("/lookup", async (req: Request, res: Response) => {
  try {
    const indicator = (req.query.indicator as string)?.trim();
    if (!indicator) {
      return res.status(400).json({ error: "Indicator query parameter is required." });
    }

    // Check database cache first
    const [cached] = await db
      .select()
      .from(threatIntelCache)
      .where(eq(threatIntelCache.indicator, indicator));

    if (cached) {
      return res.json({
        found: true,
        source: "database_cache",
        indicator: cached,
      });
    }

    // If not in cache and external API keys are not yet configured in Phase 1:
    const hasVtKey = Boolean(process.env.VIRUSTOTAL_API_KEY);
    const hasAbuseKey = Boolean(process.env.ABUSEIPDB_API_KEY);

    return res.json({
      found: false,
      indicator: {
        indicator,
        indicatorType: indicator.includes(".") ? (indicator.match(/^\d+\.\d+\.\d+\.\d+$/) ? "IP address" : "Domain") : "Unknown",
        verdict: "Unknown",
        reputationScore: 0,
        detectionsCount: 0,
        totalEngines: 0,
        confidence: "Unassessed",
        associatedContext: ["Uncached indicator."],
        feedVerdicts: [
          {
            source: "VirusTotal",
            detail: hasVtKey ? "Pending live lookup" : "API key not configured in environment",
            status: hasVtKey ? "Pending" : "Config Required",
          },
          {
            source: "AbuseIPDB",
            detail: hasAbuseKey ? "Pending live lookup" : "API key not configured in environment",
            status: hasAbuseKey ? "Pending" : "Config Required",
          },
        ],
      },
    });
  } catch (error: any) {
    console.error("Threat intel lookup error:", error);
    return res.status(500).json({ error: "Threat intelligence lookup failed" });
  }
});
