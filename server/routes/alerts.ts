import { Router, type Request, type Response } from "express";
import { and, desc, eq, ilike, or, inArray } from "drizzle-orm";
import { db } from "../db/index";
import { alerts, logs } from "../db/schema";
import { requireAuth, requirePermission, optionalAuth } from "../middleware/authMiddleware";
import { PERMISSIONS } from "../../shared/auth";
import { RealtimeService } from "../services/realtimeService";

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
          ilike(alerts.tactic, term),
          ilike(alerts.technique, term),
          ilike(alerts.ruleId, term),
          ilike(alerts.ruleName, term)
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

// GET /api/alerts/:id/logs - Retrieve all originating logs linked to this alert
alertsRouter.get("/:id/logs", optionalAuth, async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) {
      return res.status(400).json({ error: "Invalid alert ID format" });
    }

    const [alert] = await db.select().from(alerts).where(eq(alerts.id, id));
    if (!alert) {
      return res.status(404).json({ error: `Alert #${id} not found` });
    }

    const logIds: number[] = Array.isArray(alert.relatedLogIds) ? (alert.relatedLogIds as number[]) : [];
    let originatingLogs: any[] = [];

    if (logIds.length > 0) {
      originatingLogs = await db
        .select()
        .from(logs)
        .where(inArray(logs.id, logIds))
        .orderBy(desc(logs.timestamp));
    }

    return res.json({
      alertId: alert.id,
      ruleId: alert.ruleId,
      ruleName: alert.ruleName,
      logsCount: originatingLogs.length,
      logs: originatingLogs,
    });
  } catch (error: any) {
    console.error("Get alert logs error:", error);
    return res.status(500).json({ error: "Failed to fetch originating logs for alert" });
  }
});

// Handler for alert status updates
const updateAlertStatusHandler = async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const { status } = req.body;

    const validStatuses = ["Open", "In review", "Escalated", "Resolved", "Contained"];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        error: `Invalid status. Must be one of: ${validStatuses.join(", ")}`,
      });
    }

    const [existing] = await db.select({ status: alerts.status }).from(alerts).where(eq(alerts.id, id));
    if (!existing) {
      return res.status(404).json({ error: `Alert #${id} not found` });
    }

    const previousStatus = existing.status;

    const [updated] = await db
      .update(alerts)
      .set({ status, updatedAt: new Date() })
      .where(eq(alerts.id, id))
      .returning();

    if (!updated) {
      return res.status(404).json({ error: `Alert #${id} not found` });
    }

    // Publish alert.status_changed event to real-time subscribers
    RealtimeService.publish({
      id: `evt_status_${updated.id}_${Date.now()}`,
      type: "alert.status_changed",
      timestamp: new Date().toISOString(),
      data: {
        alertId: updated.id,
        previousStatus,
        newStatus: updated.status,
        updatedAt: updated.updatedAt.toISOString(),
        actor: {
          id: req.user?.id || 0,
          fullName: req.user?.fullName || "Security Analyst",
          role: req.user?.role || "Senior Analyst",
        },
      },
    });

    RealtimeService.notifyStatsUpdated();

    return res.json({ success: true, alert: updated });
  } catch (error: any) {
    console.error("Update alert status error:", error);
    return res.status(500).json({ error: "Failed to update alert status" });
  }
};

// PATCH /api/alerts/:id and PATCH /api/alerts/:id/status (Requires UPDATE_ALERT_STATUS permission)
alertsRouter.patch("/:id/status", requireAuth, requirePermission(PERMISSIONS.UPDATE_ALERT_STATUS), updateAlertStatusHandler);
alertsRouter.patch("/:id", requireAuth, requirePermission(PERMISSIONS.UPDATE_ALERT_STATUS), updateAlertStatusHandler);
