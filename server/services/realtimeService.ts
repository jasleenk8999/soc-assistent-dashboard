/**
 * Real-Time Event Streaming Service (Server-Sent Events)
 * Manages authenticated SSE subscriber connections, heartbeat broadcasting,
 * connection lifecycle, backpressure handling, and typed event distribution.
 */

import { type Request, type Response } from "express";
import crypto from "crypto";
import { count, eq } from "drizzle-orm";
import { db } from "../db/index";
import { alerts, cases, logs } from "../db/schema";
import type {
  SecurityEvent,
  SecurityEventType,
  ConnectionEstablishedPayload,
  HeartbeatPayload,
  DashboardStatsUpdatedPayload,
} from "../../shared/events";

interface ConnectedClient {
  id: string;
  userId: number;
  role: string;
  res: Response;
  connectedAt: Date;
  lastActive: Date;
}

export class RealtimeService {
  private static clients: Map<string, ConnectedClient> = new Map();
  private static heartbeatTimer: NodeJS.Timeout | null = null;
  private static statsUpdateDebounceTimer: NodeJS.Timeout | null = null;

  private static readonly HEARTBEAT_INTERVAL_MS = parseInt(
    process.env.REALTIME_HEARTBEAT_INTERVAL_MS || "20000",
    10
  );

  private static readonly MAX_CONNECTIONS = parseInt(
    process.env.REALTIME_MAX_CONNECTIONS || "500",
    10
  );

  /**
   * Initializes the heartbeat timer if not already running.
   */
  public static init() {
    if (!this.heartbeatTimer) {
      this.heartbeatTimer = setInterval(() => {
        this.broadcastHeartbeat();
      }, this.HEARTBEAT_INTERVAL_MS);

      // Ensure timer does not prevent process exit
      if (this.heartbeatTimer.unref) {
        this.heartbeatTimer.unref();
      }
    }
  }

  /**
   * Registers a newly authenticated SSE client connection.
   */
  public static registerClient(
    req: Request,
    res: Response,
    userId: number,
    role: string
  ): string | null {
    this.init();

    if (this.clients.size >= this.MAX_CONNECTIONS) {
      console.warn(`[RealtimeService] Max connection capacity (${this.MAX_CONNECTIONS}) reached.`);
      res.status(503).json({
        error: "Real-time streaming capacity limit reached. Please retry shortly.",
        code: "CAPACITY_EXCEEDED",
      });
      return null;
    }

    const clientId = `client_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`;

    // Configure essential SSE headers
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no", // Prevents Nginx/proxy buffer latency
    });

    // Flush headers immediately
    res.flushHeaders?.();

    const client: ConnectedClient = {
      id: clientId,
      userId,
      role,
      res,
      connectedAt: new Date(),
      lastActive: new Date(),
    };

    this.clients.set(clientId, client);

    // Send connection confirmation event
    const welcomeEvent: SecurityEvent = {
      id: `evt_${Date.now()}_init`,
      type: "connection.established",
      timestamp: new Date().toISOString(),
      data: {
        clientId,
        userId,
        role,
        serverTime: new Date().toISOString(),
        heartbeatIntervalMs: this.HEARTBEAT_INTERVAL_MS,
      },
    };

    this.sendEventToClient(client, welcomeEvent);

    // Cleanup listeners when connection closes
    const cleanup = () => {
      this.unregisterClient(clientId);
    };

    req.on("close", cleanup);
    res.on("close", cleanup);
    res.on("error", cleanup);

    return clientId;
  }

  /**
   * Unregisters a client and releases associated resources.
   */
  public static unregisterClient(clientId: string) {
    const client = this.clients.get(clientId);
    if (client) {
      try {
        if (!client.res.writableEnded) {
          client.res.end();
        }
      } catch {
        // Socket may already be destroyed
      }
      this.clients.delete(clientId);
    }
  }

  /**
   * Returns count of currently active subscriber streams.
   */
  public static getActiveConnectionsCount(): number {
    return this.clients.size;
  }

  /**
   * Returns the maximum allowed concurrent connections.
   */
  public static getMaxConnections(): number {
    return this.MAX_CONNECTIONS;
  }

  /**
   * Broadcasts a typed security event to all authenticated clients.
   */
  public static publish(event: SecurityEvent) {
    if (this.clients.size === 0) return;

    const deadClientIds: string[] = [];

    this.clients.forEach((client, clientId) => {
      const success = this.sendEventToClient(client, event);
      if (!success) {
        deadClientIds.push(clientId);
      }
    });

    // Clean up stale sockets
    for (let i = 0; i < deadClientIds.length; i++) {
      this.unregisterClient(deadClientIds[i]);
    }
  }

  /**
   * Sends a single SSE formatted frame to a specific client.
   */
  private static sendEventToClient(client: ConnectedClient, event: SecurityEvent): boolean {
    try {
      if (client.res.writableEnded || !client.res.writable) {
        return false;
      }

      const payload = `id: ${event.id}\nevent: ${event.type}\ndata: ${JSON.stringify(event.data)}\n\n`;
      client.res.write(payload);
      client.lastActive = new Date();
      return true;
    } catch (err) {
      console.warn(`[RealtimeService] Error writing to client ${client.id}:`, err);
      return false;
    }
  }

  /**
   * Broadcasts periodic keep-alive heartbeat.
   */
  private static broadcastHeartbeat() {
    if (this.clients.size === 0) return;

    const event: SecurityEvent = {
      id: `hb_${Date.now()}`,
      type: "heartbeat",
      timestamp: new Date().toISOString(),
      data: {
        serverTime: new Date().toISOString(),
        activeConnections: this.clients.size,
      },
    };

    this.publish(event);
  }

  /**
   * Coalesced helper to re-calculate stats and broadcast dashboard.stats_updated.
   * Debounced by 300ms so high-frequency ingestion does not flood database queries.
   */
  public static notifyStatsUpdated() {
    if (this.statsUpdateDebounceTimer) {
      clearTimeout(this.statsUpdateDebounceTimer);
    }

    this.statsUpdateDebounceTimer = setTimeout(async () => {
      try {
        const [alertsCount] = await db
          .select({ count: count() })
          .from(alerts)
          .where(eq(alerts.status, "Open"));

        const [criticalAlerts] = await db
          .select({ count: count() })
          .from(alerts)
          .where(eq(alerts.severity, "Critical"));

        const [activeCasesCount] = await db
          .select({ count: count() })
          .from(cases)
          .where(eq(cases.status, "Active"));

        const [totalLogsCount] = await db.select({ count: count() }).from(logs);

        const statsEvent: SecurityEvent = {
          id: `stats_${Date.now()}`,
          type: "dashboard.stats_updated",
          timestamp: new Date().toISOString(),
          data: {
            openAlertsCount: Number(alertsCount?.count || 0),
            criticalAlertsCount: Number(criticalAlerts?.count || 0),
            activeCasesCount: Number(activeCasesCount?.count || 0),
            totalLogsCount: Number(totalLogsCount?.count || 0),
            lastUpdated: new Date().toISOString(),
          },
        };

        this.publish(statsEvent);
      } catch (err) {
        console.warn("[RealtimeService] Failed to publish coalesced stats update:", err);
      }
    }, 300);
  }

  /**
   * Graceful shutdown of all active streams.
   */
  public static shutdown() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }

    if (this.statsUpdateDebounceTimer) {
      clearTimeout(this.statsUpdateDebounceTimer);
      this.statsUpdateDebounceTimer = null;
    }

    console.log(`[RealtimeService] Gracefully terminating ${this.clients.size} active SSE stream(s)...`);

    this.clients.forEach((client) => {
      try {
        client.res.write(
          `event: system.status_changed\ndata: ${JSON.stringify({
            status: "maintenance",
            service: "SSE",
            message: "Server shutting down",
            timestamp: new Date().toISOString(),
          })}\n\n`
        );
        client.res.end();
      } catch {}
    });

    this.clients.clear();
  }
}
