import { Router, type Request, type Response } from "express";
import { desc, eq } from "drizzle-orm";
import { db } from "../db/index";
import { cases } from "../db/schema";
import { requireAuth, requirePermission, optionalAuth } from "../middleware/authMiddleware";
import { PERMISSIONS } from "../../shared/auth";

export const casesRouter = Router();

// GET /api/cases (with optional authentication)
casesRouter.get("/", optionalAuth, async (_req: Request, res: Response) => {
  try {
    const items = await db.select().from(cases).orderBy(desc(cases.createdAt));
    return res.json({
      items,
      total: items.length,
      activeCount: items.filter((c) => c.status === "Active" || c.status === "In review").length,
    });
  } catch (error: any) {
    console.error("Fetch cases error:", error);
    return res.status(500).json({ error: "Failed to fetch investigation cases" });
  }
});

// GET /api/cases/:id
casesRouter.get("/:id", optionalAuth, async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) {
      return res.status(400).json({ error: "Invalid case ID format" });
    }

    const [item] = await db.select().from(cases).where(eq(cases.id, id));
    if (!item) {
      return res.status(404).json({ error: `Case #${id} not found` });
    }

    return res.json(item);
  } catch (error: any) {
    console.error("Get case error:", error);
    return res.status(500).json({ error: "Failed to fetch case details" });
  }
});

// PATCH /api/cases/:id/status (Requires Senior Analyst or Incident Commander)
casesRouter.patch("/:id/status", requireAuth, requirePermission(PERMISSIONS.UPDATE_CASE_STATUS), async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    const { status } = req.body;

    const validStatuses = ["Active", "In review", "Contained", "Closed"];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        error: `Invalid status. Must be one of: ${validStatuses.join(", ")}`,
      });
    }

    const [updated] = await db
      .update(cases)
      .set({ status, updatedAt: new Date() })
      .where(eq(cases.id, id))
      .returning();

    if (!updated) {
      return res.status(404).json({ error: `Case #${id} not found` });
    }

    return res.json({ success: true, case: updated });
  } catch (error: any) {
    console.error("Update case status error:", error);
    return res.status(500).json({ error: "Failed to update case status" });
  }
});
