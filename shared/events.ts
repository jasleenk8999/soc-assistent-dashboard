/**
 * Shared Security Event Definitions and Envelope Schemas for Real-Time Streaming
 */

export const SECURITY_EVENT_TYPES = [
  "connection.established",
  "heartbeat",
  "alert.created",
  "alert.updated",
  "alert.status_changed",
  "log.ingested",
  "logs.bulk_ingested",
  "dashboard.stats_updated",
  "system.status_changed",
] as const;

export type SecurityEventType = (typeof SECURITY_EVENT_TYPES)[number];

export interface BaseSecurityEvent<T = any> {
  id: string;
  type: SecurityEventType;
  timestamp: string; // ISO 8601
  data: T;
}

// 1. connection.established
export interface ConnectionEstablishedPayload {
  clientId: string;
  userId: number;
  role: string;
  serverTime: string;
  heartbeatIntervalMs: number;
}

// 2. heartbeat
export interface HeartbeatPayload {
  serverTime: string;
  activeConnections: number;
}

// 3. alert.created
export interface AlertCreatedPayload {
  id: number;
  ruleId?: string;
  ruleName?: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  title: string;
  source: string;
  destination?: string;
  tactic: string;
  technique?: string;
  status: string;
  confidence: string;
  description?: string;
  evidence?: any;
  suggestedNextSteps?: string;
  relatedLogIds?: number[];
  createdAt: string;
}

// 4. alert.updated (e.g. deduplicated / additional logs linked)
export interface AlertUpdatedPayload {
  id: number;
  ruleId?: string;
  ruleName?: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  title: string;
  source: string;
  destination?: string;
  status: string;
  relatedLogsCount: number;
  suppressedDuplicateCount: number;
  updatedAt: string;
}

// 5. alert.status_changed (triage action)
export interface AlertStatusChangedPayload {
  alertId: number;
  previousStatus: string;
  newStatus: string;
  updatedAt: string;
  actor: {
    id: number;
    fullName: string;
    role: string;
  };
}

// 6. log.ingested
export interface LogIngestedPayload {
  id: number;
  timestamp: string;
  sourceType: string;
  sourceHost?: string;
  sourceIp?: string;
  destinationIp?: string;
  username?: string;
  isThreat: boolean;
  threatReason?: string;
  logLevel: string;
}

// 7. logs.bulk_ingested
export interface LogsBulkIngestedPayload {
  source: string;
  ingestedCount: number;
  alertsGeneratedCount: number;
  fileName?: string;
  timestamp: string;
}

// 8. dashboard.stats_updated
export interface DashboardStatsUpdatedPayload {
  openAlertsCount: number;
  criticalAlertsCount: number;
  activeCasesCount: number;
  totalLogsCount: number;
  lastUpdated: string;
}

// 9. system.status_changed
export interface SystemStatusChangedPayload {
  status: "operational" | "degraded" | "maintenance";
  service: string;
  timestamp: string;
  message?: string;
}

// Discriminated Union of Typed Security Events
export type SecurityEvent =
  | (BaseSecurityEvent<ConnectionEstablishedPayload> & { type: "connection.established" })
  | (BaseSecurityEvent<HeartbeatPayload> & { type: "heartbeat" })
  | (BaseSecurityEvent<AlertCreatedPayload> & { type: "alert.created" })
  | (BaseSecurityEvent<AlertUpdatedPayload> & { type: "alert.updated" })
  | (BaseSecurityEvent<AlertStatusChangedPayload> & { type: "alert.status_changed" })
  | (BaseSecurityEvent<LogIngestedPayload> & { type: "log.ingested" })
  | (BaseSecurityEvent<LogsBulkIngestedPayload> & { type: "logs.bulk_ingested" })
  | (BaseSecurityEvent<DashboardStatsUpdatedPayload> & { type: "dashboard.stats_updated" })
  | (BaseSecurityEvent<SystemStatusChangedPayload> & { type: "system.status_changed" });
