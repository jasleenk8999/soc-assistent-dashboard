import { Router, type Request, type Response } from "express";
import { and, desc, eq, ilike, or } from "drizzle-orm";
import { db } from "../db/index";
import { alerts } from "../db/schema";
import { requireAuth, requirePermission, optionalAuth } from "../middleware/authMiddleware";
import { PERMISSIONS } from "../../shared/auth";

export const alertsRouter = Router();

// GET /api/alerts (with optional authentication)
alertsRouter.get("/", optionalAuth, async (req: Request, res: Response) => {
  try {
    const severity = req.query.severity as string | undefined;
    const status = req.query.status as string | undefined;
    const search = req.query.search as string | undefined;
    const limit = Math.min(Math.max(parseInt(req.query.limit as string) || 50, 1), 100);
    const offset = Math.max(parseInt(req.query.offset as string) || 0, 0);

    const conditions = [];

    if (severity && severity !== "All") {
      conditions.push(eq(alerts.severity, severity));
    }

    if (status) {
      conditions.push(eq(alerts.status, status));
    }

    if (search && search.trim()) {
      const term = `%${search.trim()}%`;
      conditions.push(
        or(
          ilike(alerts.title, term),
          ilike(alerts.source, term),
          ilike(alerts.tactic, term)
        )
      );
    }

    const whereClause = conditions.length > 0 ? and(...conditions) : undefined;

    const items = await db
      .select()
      .from(alerts)
      .where(whereClause)
      .orderBy(desc(alerts.createdAt))
      .limit(limit)
      .offset(offset);

    // Summary counts for filter badges
    const allAlerts = await db.select({ severity: alerts.severity, status: alerts.status }).from(alerts);
    const counts = {
      all: allAlerts.length,
      critical: allAlerts.filter((a) => a.severity === "Critical").length,
      high: allAlerts.filter((a) => a.severity === "High").length,
      medium: allAlerts.filter((a) => a.severity === "Medium").length,
      low: allAlerts.filter((a) => a.severity === "Low").length,
      open: allAlerts.filter((a) => a.status === "Open").length,
    };

    return res.json({
      items,
      counts,
      pagination: {
        limit,
        offset,
        total: items.length,
      },
    });
  } catch (error: any) {
    console.error("Fetch alerts error:", error);
    return res.status(500).json({ error: "Failed to fetch alerts from database" });
  }
});

// GET /api/alerts/:id
alertsRouter.get("/:id", async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) {
      return res.status(400).json({ error: "Invalid alert ID format" });
    }

    const [alert] = await db.select().from(alerts).where(eq(alerts.id, id));

    if (!alert) {
      return res.status(404).json({ error: `Alert #${id} not found` });
    }

    return res.json(alert);
  } catch (error: any) {
    console.error("Get alert error:", error);
    return res.status(500).json({ error: "Failed to fetch alert details" });
  }
});

// PATCH /api/alerts/:id/status (Triage action - Requires Senior Analyst or Incident Commander)
alertsRouter.patch("/:id/status", requireAuth, requirePermission(PERMISSIONS.UPDATE_ALERT_STATUS), async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const { status } = req.body;

    const validStatuses = ["Open", "In review", "Escalated", "Resolved", "Contained"];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        error: `Invalid status. Must be one of: ${validStatuses.join(", ")}`,
      });
    }

    const [updated] = await db
      .update(alerts)
      .set({ status, updatedAt: new Date() })
      .where(eq(alerts.id, id))
      .returning();

    if (!updated) {
      return res.status(404).json({ error: `Alert #${id} not found` });
    }

    return res.json({ success: true, alert: updated });
  } catch (error: any) {
    console.error("Update alert status error:", error);
    return res.status(500).json({ error: "Failed to update alert status" });
  }
});
