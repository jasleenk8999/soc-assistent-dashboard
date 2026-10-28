import { Router, type Request, type Response } from "express";
import { and, desc, eq, ilike, or, inArray } from "drizzle-orm";
import { db } from "../db/index";
import { alerts, logs, incidentExplanations } from "../db/schema";
import { requireAuth, requirePermission, optionalAuth } from "../middleware/authMiddleware";
import { PERMISSIONS } from "../../shared/auth";
import { RealtimeService } from "../services/realtimeService";
import { generateExplanation, type AlertContext, type LogContext } from "../services/incidentExplanationService";
import { getAlertThreatIntel } from "../services/threatIntelService";

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

// Helper: Check if an existing explanation has become stale compared to current alert evidence
function checkExplanationStaleness(
  explanation: typeof incidentExplanations.$inferSelect,
  alert: typeof alerts.$inferSelect
): { isStale: boolean; stalenessReason?: string } {
  if (explanation.isStale) {
    return { isStale: true, stalenessReason: "Explanation is marked stale." };
  }

  // 1. Check if linked log IDs changed
  const currentLogIds: number[] = Array.isArray(alert.relatedLogIds) ? (alert.relatedLogIds as number[]) : [];
  const snapshotLogIds: number[] = Array.isArray(explanation.evidenceSnapshotLogIds)
    ? (explanation.evidenceSnapshotLogIds as number[])
    : [];

  if (currentLogIds.length !== snapshotLogIds.length) {
    return { isStale: true, stalenessReason: "Linked log records count changed." };
  }
  const currentSet = new Set(currentLogIds);
  for (const logId of snapshotLogIds) {
    if (!currentSet.has(logId)) {
      return { isStale: true, stalenessReason: "Linked log evidence has changed." };
    }
  }

  // 2. Check if key alert fields changed
  const snapshotFields = (explanation.evidenceSnapshotAlertFields as Record<string, any>) || {};
  if (snapshotFields.severity && snapshotFields.severity !== alert.severity) {
    return { isStale: true, stalenessReason: `Alert severity changed from ${snapshotFields.severity} to ${alert.severity}` };
  }
  if (snapshotFields.status && snapshotFields.status !== alert.status) {
    return { isStale: true, stalenessReason: `Alert status changed from ${snapshotFields.status} to ${alert.status}` };
  }
  if (snapshotFields.source && snapshotFields.source !== alert.source) {
    return { isStale: true, stalenessReason: `Alert source changed from ${snapshotFields.source} to ${alert.source}` };
  }

  return { isStale: false };
}

// GET /api/alerts/:id/explanation - Retrieve saved incident explanation (Phase 5)
alertsRouter.get(
  "/:id/explanation",
  requireAuth,
  requirePermission(PERMISSIONS.READ_EXPLANATION),
  async (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id, 10);
      if (isNaN(id)) {
        return res.status(400).json({ error: "Invalid alert ID format" });
      }

      const [alert] = await db.select().from(alerts).where(eq(alerts.id, id));
      if (!alert) {
        return res.status(404).json({ error: `Alert #${id} not found` });
      }

      const [explanation] = await db
        .select()
        .from(incidentExplanations)
        .where(eq(incidentExplanations.alertId, id))
        .orderBy(desc(incidentExplanations.createdAt))
        .limit(1);

      if (!explanation) {
        return res.json({ success: true, explanation: null, isStale: false });
      }

      const staleness = checkExplanationStaleness(explanation, alert);
      if (staleness.isStale !== explanation.isStale) {
        await db
          .update(incidentExplanations)
          .set({ isStale: staleness.isStale, updatedAt: new Date() })
          .where(eq(incidentExplanations.id, explanation.id));
        explanation.isStale = staleness.isStale;
      }

      return res.json({
        success: true,
        explanation,
        isStale: staleness.isStale,
        stalenessReason: staleness.stalenessReason,
      });
    } catch (error: any) {
      console.error("[Get Alert Explanation Error]", error);
      return res.status(500).json({ error: "Failed to fetch alert explanation" });
    }
  }
);

// POST /api/alerts/:id/explain - Generate or refresh structured AI explanation (Phase 5)
alertsRouter.post(
  "/:id/explain",
  requireAuth,
  requirePermission(PERMISSIONS.GENERATE_EXPLANATION),
  async (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id, 10);
      if (isNaN(id)) {
        return res.status(400).json({ error: "Invalid alert ID format" });
      }

      const forceRegenerate = Boolean(req.body?.forceRegenerate);

      const [alert] = await db.select().from(alerts).where(eq(alerts.id, id));
      if (!alert) {
        return res.status(404).json({ error: `Alert #${id} not found` });
      }

      // Check for existing saved explanation
      const [existing] = await db
        .select()
        .from(incidentExplanations)
        .where(eq(incidentExplanations.alertId, id))
        .orderBy(desc(incidentExplanations.createdAt))
        .limit(1);

      const staleness = existing ? checkExplanationStaleness(existing, alert) : { isStale: false };

      // Reuse existing explanation if not forced, not stale, and already completed
      if (existing && !forceRegenerate && !staleness.isStale && existing.status === "completed") {
        return res.json({
          success: true,
          explanation: existing,
          generated: false,
          reused: true,
          isStale: false,
        });
      }

      // Fetch originating logs for grounded evidence
      const logIds: number[] = Array.isArray(alert.relatedLogIds) ? (alert.relatedLogIds as number[]) : [];
      let originatingLogs: any[] = [];
      if (logIds.length > 0) {
        originatingLogs = await db
          .select()
          .from(logs)
          .where(inArray(logs.id, logIds))
          .orderBy(desc(logs.timestamp));
      }

      // Correlate with threat intelligence (Phase 6)
      let alertThreatIntel: any[] = [];
      try {
        const intelResult = await getAlertThreatIntel(alert.id);
        alertThreatIntel = intelResult.indicators || [];
      } catch (err) {
        // Continue gracefully if threat intel lookup has issues
      }

      const alertContext: AlertContext = {
        id: alert.id,
        ruleId: alert.ruleId,
        ruleName: alert.ruleName,
        severity: alert.severity,
        title: alert.title,
        source: alert.source,
        destination: alert.destination,
        tactic: alert.tactic,
        technique: alert.technique,
        confidence: alert.confidence,
        description: alert.description,
        evidence: alert.evidence,
        suggestedNextSteps: alert.suggestedNextSteps,
        dedupKey: alert.dedupKey,
        threatIntel: alertThreatIntel,
        createdAt: new Date(alert.createdAt),
      };

      const logContexts: LogContext[] = originatingLogs.map((l) => ({
        id: l.id,
        timestamp: new Date(l.timestamp),
        sourceType: l.sourceType,
        sourceIp: l.sourceIp,
        destinationIp: l.destinationIp,
        sourcePort: l.sourcePort,
        destinationPort: l.destinationPort,
        username: l.username,
        eventId: l.eventId,
        eventCategory: l.eventCategory,
        logLevel: l.logLevel,
        rawLog: l.rawLog,
        parsedFields: l.parsedFields,
        isThreat: l.isThreat,
        threatReason: l.threatReason,
      }));

      // Generate structured explanation (deterministic fallback if no provider API key)
      const result = await generateExplanation(alertContext, logContexts);

      const evidenceSnapshotLogIds = logIds;
      const evidenceSnapshotAlertFields = {
        severity: alert.severity,
        status: alert.status,
        source: alert.source,
        destination: alert.destination,
        tactic: alert.tactic,
        technique: alert.technique,
        evidence: alert.evidence,
      };

      let savedRecord: typeof incidentExplanations.$inferSelect;

      if (existing) {
        const [updated] = await db
          .update(incidentExplanations)
          .set({
            provider: result.provider,
            model: result.model,
            status: result.status,
            errorMessage: result.errorMessage ?? null,
            evidenceSnapshotLogIds,
            evidenceSnapshotAlertFields,
            isStale: false,
            executiveSummary: result.sections.executiveSummary,
            whyItTriggered: result.sections.whyItTriggered,
            evidenceNarrative: result.sections.evidenceNarrative,
            mitreContext: result.sections.mitreContext,
            potentialImpact: result.sections.potentialImpact,
            confidenceAndUncertainty: result.sections.confidenceAndUncertainty,
            investigationSteps: result.sections.investigationSteps,
            containmentConsiderations: result.sections.containmentConsiderations,
            missingEvidence: result.sections.missingEvidence,
            generatedByUserId: req.user?.id ?? null,
            generatedByUserName: req.user?.fullName ?? null,
            updatedAt: new Date(),
          })
          .where(eq(incidentExplanations.id, existing.id))
          .returning();
        savedRecord = updated;
      } else {
        const [inserted] = await db
          .insert(incidentExplanations)
          .values({
            alertId: alert.id,
            provider: result.provider,
            model: result.model,
            status: result.status,
            errorMessage: result.errorMessage ?? null,
            evidenceSnapshotLogIds,
            evidenceSnapshotAlertFields,
            isStale: false,
            executiveSummary: result.sections.executiveSummary,
            whyItTriggered: result.sections.whyItTriggered,
            evidenceNarrative: result.sections.evidenceNarrative,
            mitreContext: result.sections.mitreContext,
            potentialImpact: result.sections.potentialImpact,
            confidenceAndUncertainty: result.sections.confidenceAndUncertainty,
            investigationSteps: result.sections.investigationSteps,
            containmentConsiderations: result.sections.containmentConsiderations,
            missingEvidence: result.sections.missingEvidence,
            generatedByUserId: req.user?.id ?? null,
            generatedByUserName: req.user?.fullName ?? null,
          })
          .returning();
        savedRecord = inserted;
      }

      // Broadcast real-time SSE event
      RealtimeService.publish({
        id: `evt_explain_${savedRecord.id}_${Date.now()}`,
        type: "alert.explanation_updated",
        timestamp: new Date().toISOString(),
        data: {
          alertId: alert.id,
          explanationId: savedRecord.id,
          provider: savedRecord.provider,
          model: savedRecord.model,
          status: savedRecord.status as "completed" | "failed",
          generatedAt: savedRecord.updatedAt.toISOString(),
          generatedByUserName: savedRecord.generatedByUserName,
        },
      });

      return res.status(existing ? 200 : 201).json({
        success: true,
        explanation: savedRecord,
        generated: true,
        reused: false,
        isStale: false,
      });
    } catch (error: any) {
      console.error("[Generate Alert Explanation Error]", error);
      return res.status(500).json({ error: "Failed to generate alert explanation" });
    }
  }
);

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
