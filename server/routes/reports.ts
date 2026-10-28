import { Router, type Request, type Response } from "express";
import { desc, eq } from "drizzle-orm";
import { db } from "../db/index";
import { reports } from "../db/schema";

export const reportsRouter = Router();

// GET /api/reports
reportsRouter.get("/", async (_req: Request, res: Response) => {
  try {
    const items = await db.select().from(reports).orderBy(desc(reports.createdAt));
    return res.json({
      items,
      total: items.length,
    });
  } catch (error: any) {
    console.error("Fetch reports error:", error);
    return res.status(500).json({ error: "Failed to fetch reports" });
  }
});

// GET /api/reports/:id
reportsRouter.get("/:id", async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) {
      return res.status(400).json({ error: "Invalid report ID format" });
    }

    const [item] = await db.select().from(reports).where(eq(reports.id, id));
    if (!item) {
      return res.status(404).json({ error: `Report #${id} not found` });
    }

    return res.json(item);
  } catch (error: any) {
    console.error("Get report error:", error);
    return res.status(500).json({ error: "Failed to fetch report details" });
  }
});
