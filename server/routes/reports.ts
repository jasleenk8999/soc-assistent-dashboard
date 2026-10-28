import { Router, type Request, type Response } from "express";
import { and, desc, eq, ilike, or } from "drizzle-orm";
import { db } from "../db/index";
import { cases, reports } from "../db/schema";
import { ReportService, type GenerateReportOptions } from "../services/reportService";
import { optionalAuth, requireAuth } from "../middleware/authMiddleware";

export const reportsRouter = Router();

// ---------------------------------------------------------------------------
// 1. GET /api/reports - Filtered & paginated reports list
// ---------------------------------------------------------------------------
reportsRouter.get("/", optionalAuth, async (req: Request, res: Response) => {
  try {
    const search = req.query.search as string | undefined;
    const reportType = req.query.reportType as string | undefined;
    const status = req.query.status as string | undefined;

    const conditions = [];

    if (reportType && reportType !== "All") {
      conditions.push(eq(reports.reportType, reportType));
    }

    if (status && status !== "All") {
      conditions.push(eq(reports.status, status));
    }

    if (search && search.trim()) {
      const term = `%${search.trim()}%`;
      conditions.push(
        or(
          ilike(reports.reportCode, term),
          ilike(reports.title, term),
          ilike(reports.incidentName, term)
        )
      );
    }

    const whereClause = conditions.length > 0 ? and(...conditions) : undefined;

    const items = await db
      .select()
      .from(reports)
      .where(whereClause)
      .orderBy(desc(reports.createdAt));

    return res.json({
      items,
      total: items.length,
    });
  } catch (error: any) {
    console.error("Fetch reports error:", error);
    return res.status(500).json({ error: "Failed to fetch reports" });
  }
});

// ---------------------------------------------------------------------------
// 2. GET /api/reports/:id - Single report with linked case
// ---------------------------------------------------------------------------
reportsRouter.get("/:id", optionalAuth, async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) {
      return res.status(400).json({ error: "Invalid report ID format" });
    }

    const [item] = await db.select().from(reports).where(eq(reports.id, id));
    if (!item) {
      return res.status(404).json({ error: `Report #${id} not found` });
    }

    let linkedCase = null;
    if (item.caseId) {
      const [c] = await db.select().from(cases).where(eq(cases.id, item.caseId));
      linkedCase = c || null;
    }

    return res.json({
      ...item,
      linkedCase,
    });
  } catch (error: any) {
    console.error("Get report error:", error);
    return res.status(500).json({ error: "Failed to fetch report details" });
  }
});

// ---------------------------------------------------------------------------
// 3. POST /api/reports - Generate new incident / operational report
// ---------------------------------------------------------------------------
reportsRouter.post("/", optionalAuth, async (req: Request, res: Response) => {
  try {
    const { reportType, title, incidentName, caseId } = req.body;

    const validTypes = [
      "Executive incident report",
      "Technical investigation report",
      "Operational summary",
    ];

    if (!reportType || !validTypes.includes(reportType)) {
      return res.status(400).json({
        error: `Invalid reportType. Must be one of: ${validTypes.join(", ")}`,
      });
    }

    const userId = (req as any).user?.id || null;

    const result = await ReportService.generateReport({
      reportType,
      title,
      incidentName,
      caseId: caseId ? parseInt(caseId, 10) : undefined,
      userId,
    });

    return res.status(201).json({
      success: true,
      report: result.report,
      linkedCase: result.linkedCase || null,
      message: `Report ${result.report.reportCode} generated successfully from live incident telemetry.`,
    });
  } catch (error: any) {
    console.error("Generate report error:", error);
    return res.status(500).json({ error: "Failed to generate security report" });
  }
});

// ---------------------------------------------------------------------------
// 4. PATCH /api/reports/:id/status - Update report status
// ---------------------------------------------------------------------------
reportsRouter.patch("/:id/status", optionalAuth, async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id, 10);
    const { status } = req.body;

    const validStatuses = ["Draft", "Review", "Published"];
    if (!status || !validStatuses.includes(status)) {
      return res.status(400).json({
        error: `Invalid status. Must be one of: ${validStatuses.join(", ")}`,
      });
    }

    const [updated] = await db
      .update(reports)
      .set({ status, updatedAt: new Date() })
      .where(eq(reports.id, id))
      .returning();

    if (!updated) {
      return res.status(404).json({ error: `Report #${id} not found` });
    }

    return res.json({ success: true, report: updated });
  } catch (error: any) {
    console.error("Update report status error:", error);
    return res.status(500).json({ error: "Failed to update report status" });
  }
});

// ---------------------------------------------------------------------------
// 5. GET /api/reports/:id/export - Export report in JSON, Markdown, or HTML
// ---------------------------------------------------------------------------
reportsRouter.get("/:id/export", optionalAuth, async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id, 10);
    const format = ((req.query.format as string) || "json").toLowerCase();

    const [item] = await db.select().from(reports).where(eq(reports.id, id));
    if (!item) {
      return res.status(404).json({ error: `Report #${id} not found` });
    }

    if (format === "markdown" || format === "md") {
      const markdown = ReportService.formatMarkdown(item);
      res.setHeader("Content-Type", "text/markdown; charset=utf-8");
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="report-${item.reportCode}.md"`
      );
      return res.send(markdown);
    }

    if (format === "html" || format === "pdf") {
      const html = ReportService.formatHtml(item);
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      return res.send(html);
    }

    // Default to JSON format
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="report-${item.reportCode}.json"`
    );
    return res.json(item);
  } catch (error: any) {
    console.error("Export report error:", error);
    return res.status(500).json({ error: "Failed to export report" });
  }
});

// ---------------------------------------------------------------------------
// 6. DELETE /api/reports/:id - Delete a report
// ---------------------------------------------------------------------------
reportsRouter.delete("/:id", optionalAuth, async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id, 10);
    const [deleted] = await db.delete(reports).where(eq(reports.id, id)).returning();
    if (!deleted) {
      return res.status(404).json({ error: `Report #${id} not found` });
    }
    return res.json({ success: true, message: `Report #${id} deleted.` });
  } catch (error: any) {
    console.error("Delete report error:", error);
    return res.status(500).json({ error: "Failed to delete report" });
  }
});
