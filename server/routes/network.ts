import { Router, type Request, type Response } from "express";
import { desc } from "drizzle-orm";
import { db } from "../db/index";
import { networkFlows } from "../db/schema";

export const networkRouter = Router();

// GET /api/network/flows
networkRouter.get("/flows", async (req: Request, res: Response) => {
  try {
    const limit = Math.min(Math.max(parseInt(req.query.limit as string) || 50, 1), 100);
    const flows = await db
      .select()
      .from(networkFlows)
      .orderBy(desc(networkFlows.createdAt))
      .limit(limit);

    return res.json({
      flows,
      total: flows.length,
    });
  } catch (error: any) {
    console.error("Fetch network flows error:", error);
    return res.status(500).json({ error: "Failed to fetch network flows" });
  }
});

// GET /api/network/stats
networkRouter.get("/stats", async (_req: Request, res: Response) => {
  try {
    const flows = await db.select().from(networkFlows);
    const anomaliesCount = flows.filter((f) => f.isAnomaly || f.risk === "Critical" || f.risk === "High").length;

    return res.json({
      trafficToday: "3.42 TB",
      anomaliesCount,
      externalPeers: "1,284",
      encryptedRatio: "93.4%",
      signatures: {
        ddos: "No active signatures",
        beaconing: `${anomaliesCount} behavior review`,
        dnsTunneling: "No active signatures",
      },
    });
  } catch (error: any) {
    console.error("Fetch network stats error:", error);
    return res.status(500).json({ error: "Failed to fetch network metrics" });
  }
});
