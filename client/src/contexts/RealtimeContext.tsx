import React, { createContext, useContext, useEffect, useState, ReactNode, useCallback } from "react";
import { useAuth } from "./AuthContext";
import { realtimeClient, type ConnectionStatus } from "@/lib/realtime";
import { api } from "@/lib/api";
import type { SecurityEvent, SecurityEventType } from "@shared/events";

interface RealtimeContextType {
  status: ConnectionStatus;
  lastEvent: SecurityEvent | null;
  lastHeartbeat: Date | null;
  activityEvents: SecurityEvent[];
  reconnect: () => void;
  subscribe: (type: SecurityEventType | "*", handler: (event: SecurityEvent) => void) => () => void;
}

const RealtimeContext = createContext<RealtimeContextType | undefined>(undefined);

export function RealtimeProvider({ children }: { children: ReactNode }) {
  const { isAuthenticated, user } = useAuth();
  const [status, setStatus] = useState<ConnectionStatus>(realtimeClient.getStatus());
  const [lastEvent, setLastEvent] = useState<SecurityEvent | null>(null);
  const [lastHeartbeat, setLastHeartbeat] = useState<Date | null>(realtimeClient.getLastHeartbeat());
  const [activityEvents, setActivityEvents] = useState<SecurityEvent[]>([]);

  // 1. Initial baseline: load recent activity from PostgreSQL REST API so feed is pre-populated
  useEffect(() => {
    let isMounted = true;
    if (isAuthenticated) {
      api.getAlerts().then((res) => {
        if (!isMounted) return;
        const initialActivity: SecurityEvent[] = res.items.slice(0, 15).map((alert) => ({
          id: `seed_alert_${alert.id}`,
          type: "alert.created",
          timestamp: alert.createdAt,
          data: {
            id: alert.id,
            ruleId: alert.ruleId,
            ruleName: alert.ruleName,
            severity: alert.severity,
            title: alert.title,
            source: alert.source,
            destination: alert.destination,
            status: alert.status,
            tactic: alert.tactic,
            technique: alert.technique,
            confidence: alert.confidence,
            createdAt: alert.createdAt,
          },
        }));
        setActivityEvents(initialActivity);
      }).catch(() => {});
    }
    return () => {
      isMounted = false;
    };
  }, [isAuthenticated]);

  // 2. Connect / Disconnect with Auth state
  useEffect(() => {
    if (isAuthenticated && user) {
      realtimeClient.connect();
    } else {
      realtimeClient.disconnect();
      setActivityEvents([]);
    }

    const unsubStatus = realtimeClient.onStatusChange((newStatus) => {
      setStatus(newStatus);
      if (newStatus === "connected") {
        setLastHeartbeat(new Date());
      }
    });

    // Listen to all real-time events to record in activity feed and state
    const unsubEvents = realtimeClient.subscribe("*", (event) => {
      setLastEvent(event);

      if (event.type === "heartbeat") {
        setLastHeartbeat(new Date());
      } else if (
        event.type === "alert.created" ||
        event.type === "alert.status_changed" ||
        event.type === "log.ingested" ||
        event.type === "logs.bulk_ingested"
      ) {
        setActivityEvents((prev) => [event, ...prev.slice(0, 49)]);
      }
    });

    return () => {
      unsubStatus();
      unsubEvents();
    };
  }, [isAuthenticated, user]);

  const reconnect = useCallback(() => {
    realtimeClient.connect();
  }, []);

  const subscribe = useCallback(
    (type: SecurityEventType | "*", handler: (event: SecurityEvent) => void) => {
      return realtimeClient.subscribe(type, handler);
    },
    []
  );

  return (
    <RealtimeContext.Provider
      value={{
        status,
        lastEvent,
        lastHeartbeat,
        activityEvents,
        reconnect,
        subscribe,
      }}
    >
      {children}
    </RealtimeContext.Provider>
  );
}

export function useRealtime() {
  const context = useContext(RealtimeContext);
  if (!context) {
    throw new Error("useRealtime must be used within a RealtimeProvider");
  }
  return context;
}
