/**
 * Real-Time Security Event Stream Client (Fetch-based SSE reader)
 * Uses native fetch with ReadableStream to support custom Bearer Authorization headers
 * without exposing JWT access tokens in query parameters or URL logs.
 */

import { getAccessToken } from "./api";
import type { SecurityEvent, SecurityEventType } from "@shared/events";

export type ConnectionStatus = "connected" | "reconnecting" | "disconnected" | "auth_required";

export type EventHandler = (event: SecurityEvent) => void;
export type StatusChangeHandler = (status: ConnectionStatus) => void;

export class RealtimeClient {
  private abortController: AbortController | null = null;
  private status: ConnectionStatus = "disconnected";
  private subscribers: Map<string, Set<EventHandler>> = new Map();
  private statusHandlers: Set<StatusChangeHandler> = new Set();

  private reconnectAttempts = 0;
  private reconnectTimer: any = null;
  private isExplicitlyClosed = false;

  private readonly initialRetryDelay = 1000;
  private readonly maxRetryDelay = 15000;
  private readonly retryMultiplier = 1.5;

  private lastHeartbeatAt: Date | null = null;

  constructor() {
    // Singleton or instantiated per session
  }

  public getStatus(): ConnectionStatus {
    return this.status;
  }

  public getLastHeartbeat(): Date | null {
    return this.lastHeartbeatAt;
  }

  public onStatusChange(handler: StatusChangeHandler): () => void {
    this.statusHandlers.add(handler);
    handler(this.status);
    return () => {
      this.statusHandlers.delete(handler);
    };
  }

  public subscribe(eventType: SecurityEventType | "*", handler: EventHandler): () => void {
    if (!this.subscribers.has(eventType)) {
      this.subscribers.set(eventType, new Set());
    }
    this.subscribers.get(eventType)!.add(handler);

    return () => {
      const set = this.subscribers.get(eventType);
      if (set) {
        set.delete(handler);
        if (set.size === 0) {
          this.subscribers.delete(eventType);
        }
      }
    };
  }

  private setStatus(newStatus: ConnectionStatus) {
    if (this.status !== newStatus) {
      this.status = newStatus;
      this.statusHandlers.forEach((handler) => handler(newStatus));
    }
  }

  /**
   * Connects to the SSE stream.
   */
  public connect() {
    this.isExplicitlyClosed = false;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    const token = getAccessToken();
    if (!token) {
      this.setStatus("auth_required");
      return;
    }

    this.abortController?.abort();
    this.abortController = new AbortController();

    this.setStatus(this.reconnectAttempts === 0 ? "reconnecting" : "reconnecting");

    this.startStreaming(token, this.abortController.signal);
  }

  private async startStreaming(token: string, signal: AbortSignal) {
    try {
      const response = await fetch("/api/events/stream", {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "text/event-stream",
        },
        signal,
      });

      if (response.status === 401 || response.status === 403) {
        this.setStatus("auth_required");
        return;
      }

      if (!response.ok) {
        throw new Error(`Server returned status ${response.status}`);
      }

      if (!response.body) {
        throw new Error("Response body is not readable");
      }

      // Connection established successfully
      this.reconnectAttempts = 0;
      this.setStatus("connected");

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });

        // Split messages by double newline (standard SSE frame separator)
        const parts = buffer.split("\n\n");
        // Keep the last partial chunk in buffer
        buffer = parts.pop() || "";

        for (const messageChunk of parts) {
          this.processSseMessage(messageChunk);
        }
      }

      // Stream closed by server
      if (!this.isExplicitlyClosed) {
        this.scheduleReconnect();
      }
    } catch (err: any) {
      if (err.name === "AbortError" || this.isExplicitlyClosed) {
        // Expected cancellation
        return;
      }

      console.warn("[RealtimeClient] SSE Connection error:", err.message);
      this.scheduleReconnect();
    }
  }

  private processSseMessage(chunk: string) {
    const lines = chunk.split("\n");
    let eventId = "";
    let eventType: SecurityEventType = "heartbeat";
    let dataString = "";

    for (const line of lines) {
      if (line.startsWith("id:")) {
        eventId = line.slice(3).trim();
      } else if (line.startsWith("event:")) {
        eventType = line.slice(6).trim() as SecurityEventType;
      } else if (line.startsWith("data:")) {
        dataString = line.slice(5).trim();
      }
    }

    if (!dataString) return;

    try {
      const parsedData = JSON.parse(dataString);
      const securityEvent: SecurityEvent = {
        id: eventId || `evt_${Date.now()}`,
        type: eventType,
        timestamp: new Date().toISOString(),
        data: parsedData,
      } as SecurityEvent;

      if (eventType === "heartbeat") {
        this.lastHeartbeatAt = new Date();
      }

      this.dispatch(securityEvent);
    } catch (err) {
      console.warn("[RealtimeClient] Malformed SSE event data skipped:", err);
    }
  }

  private dispatch(event: SecurityEvent) {
    // Specific handlers
    const handlers = this.subscribers.get(event.type);
    if (handlers) {
      handlers.forEach((h) => {
        try {
          h(event);
        } catch (err) {
          console.error(`[RealtimeClient] Error in ${event.type} subscriber:`, err);
        }
      });
    }

    // Catch-all handlers
    const wildcard = this.subscribers.get("*");
    if (wildcard) {
      wildcard.forEach((h) => {
        try {
          h(event);
        } catch (err) {
          console.error("[RealtimeClient] Error in wildcard subscriber:", err);
        }
      });
    }
  }

  private scheduleReconnect() {
    if (this.isExplicitlyClosed) return;

    this.setStatus("reconnecting");
    this.reconnectAttempts++;

    // Bounded exponential backoff + jitter
    const delay = Math.min(
      this.initialRetryDelay * Math.pow(this.retryMultiplier, this.reconnectAttempts),
      this.maxRetryDelay
    );
    const jitter = Math.floor(Math.random() * 500);
    const totalDelay = Math.round(delay + jitter);

    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);

    this.reconnectTimer = setTimeout(() => {
      this.connect();
    }, totalDelay);
  }

  /**
   * Explicitly closes the real-time stream.
   */
  public disconnect() {
    this.isExplicitlyClosed = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.abortController?.abort();
    this.abortController = null;
    this.reconnectAttempts = 0;
    this.setStatus("disconnected");
  }
}

// Global shared client instance
export const realtimeClient = new RealtimeClient();
