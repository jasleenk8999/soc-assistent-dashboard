import express, { type Request, type Response, type NextFunction } from "express";
import { createServer } from "http";
import path from "path";
import { fileURLToPath } from "url";
import cors from "cors";
import morgan from "morgan";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import * as dotenv from "dotenv";

import { checkDatabaseConnection } from "./db/index";
import { authRouter } from "./routes/auth";
import { healthRouter } from "./routes/health";
import { dashboardRouter } from "./routes/dashboard";
import { alertsRouter } from "./routes/alerts";
import { casesRouter } from "./routes/cases";
import { logsRouter } from "./routes/logs";
import { networkRouter } from "./routes/network";
import { threatIntelRouter } from "./routes/threatIntel";
import { reportsRouter } from "./routes/reports";
import { malwareRouter } from "./routes/malware";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export async function createApp() {
  const app = express();

  // Security & Utility Middleware
  app.use(morgan("dev"));
  app.use(cookieParser());
  app.use(express.json({ limit: "10mb" }));
  app.use(express.urlencoded({ extended: true, limit: "10mb" }));

  // CORS configuration
  const allowedOrigins = [
    process.env.CLIENT_URL || "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5001",
  ];
  app.use(
    cors({
      origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
          callback(null, true);
        } else {
          callback(null, true); // Allow during local development
        }
      },
      credentials: true,
    })
  );

  // Rate Limiter
  const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 1000,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Too many requests from this IP, please try again later." },
  });
  app.use("/api", apiLimiter);

  // API Routes
  app.use("/api/auth", authRouter);
  app.use("/api/health", healthRouter);
  app.use("/api/dashboard", dashboardRouter);
  app.use("/api/alerts", alertsRouter);
  app.use("/api/cases", casesRouter);
  app.use("/api/logs", logsRouter);
  app.use("/api/network", networkRouter);
  app.use("/api/threat-intel", threatIntelRouter);
  app.use("/api/reports", reportsRouter);
  app.use("/api/malware", malwareRouter);

  // Production Static File Serving
  const staticPath =
    process.env.NODE_ENV === "production"
      ? path.resolve(__dirname, "public")
      : path.resolve(__dirname, "..", "dist", "public");

  app.use(express.static(staticPath));

  // Client-side fallback routing for non-API routes
  app.get("*", (req: Request, res: Response, next: NextFunction) => {
    if (req.path.startsWith("/api")) {
      return res.status(404).json({ error: `API route ${req.method} ${req.path} not found` });
    }
    res.sendFile(path.join(staticPath, "index.html"), (err) => {
      if (err) {
        next();
      }
    });
  });

  // Centralized Error Handler
  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    console.error("[Unhandled Server Error]", err);
    const status = err.status || err.statusCode || 500;
    res.status(status).json({
      error: err.message || "Internal Server Error",
      status,
      timestamp: new Date().toISOString(),
    });
  });

  return app;
}

async function startServer() {
  const app = await createApp();
  const server = createServer(app);
  const port = parseInt(process.env.PORT || "5001", 10);

  // Check database connectivity upon start
  console.log("Checking PostgreSQL database connection...");
  const dbHealth = await checkDatabaseConnection();
  if (dbHealth.ok) {
    console.log(`✅ Connected to PostgreSQL database (latency: ${dbHealth.latencyMs}ms)`);
  } else {
    console.error(`❌ CRITICAL: ${dbHealth.error}`);
    console.warn("⚠️ Server will start, but database-dependent endpoints will return 500/503.");
  }

  server.listen(port, "0.0.0.0", () => {
    console.log(`🚀 SOC Assistant Backend API listening on http://localhost:${port}/`);
    console.log(`📋 Health check: http://localhost:${port}/api/health`);
  });
}

// Start if invoked directly
if (import.meta.url === `file://${process.argv[1]}`) {
  startServer().catch((err) => {
    console.error("Fatal startup error:", err);
    process.exit(1);
  });
}
