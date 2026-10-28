/**
 * SOC Assistant API Client
 * Provides typed HTTP communication with the Express/PostgreSQL backend,
 * automatic JWT Authorization header attachment, and token refreshing.
 */

import { UserRole } from "@shared/auth";

export interface AuthUser {
  id: number;
  email: string;
  fullName: string;
  role: UserRole;
  initials: string;
  status: string;
  color: string;
  activeCasesCount?: number;
}

export interface AuthResponse {
  success: boolean;
  user: AuthUser;
  accessToken: string;
}

export interface DashboardStats {
  period: string;
  metrics: {
    eventsIngested: string;
    eventsIngestedExact: number;
    openAlerts: number;
    activeAttacks: number;
    detectionHealth: string;
    coverageScore: number;
  };
  trend: Array<{ time: string; high: number; medium: number; low: number }>;
  attackMix: Array<{ name: string; value: number; color: string }>;
  severityCounts: Array<{ severity: string; count: number }>;
  lastUpdated: string;
}

export interface AlertItem {
  id: number;
  ruleId?: string;
  ruleName?: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  title: string;
  source: string;
  destination?: string;
  tactic: string;
  technique?: string;
  status: "Open" | "In review" | "Escalated" | "Resolved" | "Contained";
  detectionMethod: string;
  confidence: string;
  description?: string;
  evidence?: any;
  suggestedNextSteps?: string;
  relatedLogIds?: number[];
  dedupKey?: string;
  createdAt: string;
  updatedAt: string;
}

export interface LogItem {
  id: number;
  timestamp: string;
  sourceType: string;
  sourceHost?: string;
  sourceIp?: string;
  destinationIp?: string;
  sourcePort?: number;
  destinationPort?: number;
  protocol?: string;
  username?: string;
  eventId?: string;
  eventCategory?: string;
  logLevel: string;
  rawLog: string;
  parsedFields: Record<string, any>;
  isThreat: boolean;
  threatReason?: string;
  createdAt: string;
}

export interface LogsResponse {
  items: LogItem[];
  total: number;
  sourceCounts: Record<string, number>;
  pagination: {
    limit: number;
    offset: number;
    page: number;
    pages: number;
  };
}

export interface IngestLogResponse {
  success: boolean;
  log: LogItem;
  alertsGenerated: AlertItem[];
  detectionMatchesCount: number;
}

export interface BulkIngestResponse {
  success: boolean;
  ingestedCount: number;
  alertsGeneratedCount: number;
  alerts: AlertItem[];
}

export interface LogUploadResponse {
  success: boolean;
  fileName: string;
  fileSize: number;
  totalParsedInFile: number;
  logsIngested: number;
  alertsGeneratedCount: number;
  alerts: AlertItem[];
  truncated?: boolean;
}

export interface AlertsResponse {
  items: AlertItem[];
  counts: {
    all: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    open: number;
  };
  pagination: {
    limit: number;
    offset: number;
    total: number;
  };
}

export interface CaseItem {
  id: number;
  caseNumber: string;
  alertId?: number;
  title: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  status: "Active" | "In review" | "Contained" | "Closed";
  assignedUserName?: string;
  affectedAsset: string;
  primaryEntity: string;
  mitreTechnique: string;
  aiConfidence: string;
  summary?: string;
  timeline: Array<{ time: string; title: string; status: string }>;
  aiExplanation?: string;
  remediationSteps?: string[];
  createdAt: string;
}

export interface NetworkFlowItem {
  id: number;
  sourceHost: string;
  sourceIp: string;
  destinationHost?: string;
  destinationIp: string;
  protocol: string;
  volumeBytes: number;
  volumeFormatted: string;
  packetCount: number;
  risk: "Critical" | "High" | "Medium" | "Low";
  anomalyScore: string;
  isAnomaly: boolean;
  tags?: string[];
  createdAt: string;
}

export interface ThreatIntelItem {
  id: number;
  indicator: string;
  indicatorType: string;
  verdict: "Malicious" | "Suspicious" | "Clean" | "Unknown";
  reputationScore: number;
  detectionsCount: number;
  totalEngines: number;
  confidence: string;
  associatedContext: string[];
  feedVerdicts: Array<{ source: string; detail: string; status: string }>;
  lastSeen: string;
}

export interface ReportItem {
  id: number;
  reportCode: string;
  title: string;
  incidentName: string;
  reportType: string;
  status: "Draft" | "Review" | "Published";
  caseId?: number;
  contentJson?: any;
  createdAt: string;
}

export interface MalwareSampleItem {
  id: number;
  filename: string;
  sha256: string;
  fileSize: number;
  fileType: string;
  verdict: string;
  confidence: string;
  modelUsed: string;
  riskScore: string;
  indicators: string[];
  status: string;
  createdAt: string;
}

// In-memory short-lived access token
let inMemoryAccessToken: string | null = null;

export function setAccessToken(token: string | null) {
  inMemoryAccessToken = token;
}

export function getAccessToken(): string | null {
  return inMemoryAccessToken;
}

let isRefreshing = false;
let refreshSubscribers: Array<(token: string | null) => void> = [];

function onRefreshed(token: string | null) {
  refreshSubscribers.forEach((cb) => cb(token));
  refreshSubscribers = [];
}

async function request<T>(endpoint: string, options?: RequestInit, isRetry = false): Promise<T> {
  const url = endpoint.startsWith("/api") ? endpoint : `/api${endpoint}`;

  const headers: Record<string, string> = {
    ...(options?.headers as Record<string, string>),
  };

  if (!(options?.body instanceof FormData)) {
    headers["Content-Type"] = headers["Content-Type"] || "application/json";
  }

  if (inMemoryAccessToken) {
    headers["Authorization"] = `Bearer ${inMemoryAccessToken}`;
  }

  const response = await fetch(url, {
    credentials: "include", // Ensures HttpOnly cookies are attached
    headers,
    ...options,
  });

  // Handle Token Expiration and Automatic Refresh
  if (response.status === 401 && !isRetry && !endpoint.includes("/auth/login") && !endpoint.includes("/auth/refresh")) {
    if (!isRefreshing) {
      isRefreshing = true;
      try {
        const refreshRes = await fetch("/api/auth/refresh", {
          method: "POST",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
        });

        if (refreshRes.ok) {
          const data: AuthResponse = await refreshRes.json();
          setAccessToken(data.accessToken);
          isRefreshing = false;
          onRefreshed(data.accessToken);
          return request<T>(endpoint, options, true);
        } else {
          setAccessToken(null);
          isRefreshing = false;
          onRefreshed(null);
        }
      } catch (err) {
        setAccessToken(null);
        isRefreshing = false;
        onRefreshed(null);
      }
    } else {
      // Queue requests while token refresh is in flight
      return new Promise<T>((resolve, reject) => {
        refreshSubscribers.push((newToken) => {
          if (newToken) {
            resolve(request<T>(endpoint, options, true));
          } else {
            reject(new Error("Session expired. Please log in again."));
          }
        });
      });
    }
  }

  if (!response.ok) {
    let errorMessage = `HTTP error ${response.status}: ${response.statusText}`;
    try {
      const errorJson = await response.json();
      if (errorJson.error) errorMessage = errorJson.error;
    } catch {
      // ignore
    }
    throw new Error(errorMessage);
  }

  return response.json();
}

export const api = {
  // Authentication
  login: (credentials: { email: string; password: string }) =>
    request<AuthResponse>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify(credentials),
    }),

  register: (payload: { email: string; password: string; fullName: string }) =>
    request<AuthResponse>("/api/auth/register", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  logout: () =>
    request<{ success: boolean; message: string }>("/api/auth/logout", {
      method: "POST",
    }),

  refresh: () =>
    request<AuthResponse>("/api/auth/refresh", {
      method: "POST",
    }),

  getMe: () =>
    request<{ user: AuthUser }>("/api/auth/me"),

  // Health
  checkHealth: () => request<{ status: string; uptimeSeconds: number; services: any }>("/api/health"),

  // Dashboard
  getDashboardStats: (period = "24h") =>
    request<DashboardStats>(`/api/dashboard/stats?period=${encodeURIComponent(period)}`),

  // Alerts
  getAlerts: (params?: { severity?: string; status?: string; search?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.severity && params.severity !== "All") searchParams.set("severity", params.severity);
    if (params?.status) searchParams.set("status", params.status);
    if (params?.search) searchParams.set("search", params.search);
    const qs = searchParams.toString();
    return request<AlertsResponse>(`/api/alerts${qs ? `?${qs}` : ""}`);
  },

  getAlertById: (id: number) => request<AlertItem>(`/api/alerts/${id}`),

  getAlertLogs: (id: number) =>
    request<{ alertId: number; ruleId: string; ruleName: string; logsCount: number; logs: LogItem[] }>(
      `/api/alerts/${id}/logs`
    ),

  updateAlertStatus: (id: number, status: string) =>
    request<{ success: boolean; alert: AlertItem }>(`/api/alerts/${id}/status`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    }),

  // Logs & Ingestion (Phase 3)
  getLogs: (params?: {
    search?: string;
    sourceType?: string;
    logLevel?: string;
    isThreat?: string;
    startDate?: string;
    endDate?: string;
    limit?: number;
    offset?: number;
  }) => {
    const sp = new URLSearchParams();
    if (params?.search) sp.set("search", params.search);
    if (params?.sourceType && params.sourceType !== "All") sp.set("sourceType", params.sourceType);
    if (params?.logLevel && params.logLevel !== "All") sp.set("logLevel", params.logLevel);
    if (params?.isThreat && params.isThreat !== "All") sp.set("isThreat", params.isThreat);
    if (params?.startDate) sp.set("startDate", params.startDate);
    if (params?.endDate) sp.set("endDate", params.endDate);
    if (params?.limit) sp.set("limit", String(params.limit));
    if (params?.offset) sp.set("offset", String(params.offset));
    const qs = sp.toString();
    return request<LogsResponse>(`/api/logs${qs ? `?${qs}` : ""}`);
  },

  getLogById: (id: number) => request<{ log: LogItem; relatedAlerts: AlertItem[] }>(`/api/logs/${id}`),

  ingestLog: (payload: any) =>
    request<IngestLogResponse>("/api/logs", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  ingestLogsBulk: (items: any[], defaultSourceType?: string) =>
    request<BulkIngestResponse>("/api/logs/bulk", {
      method: "POST",
      body: JSON.stringify({ items, defaultSourceType }),
    }),

  uploadLogFile: (file: File, sourceType?: string) => {
    const formData = new FormData();
    formData.append("file", file);
    if (sourceType) {
      formData.append("sourceType", sourceType);
    }
    return request<LogUploadResponse>("/api/logs/upload", {
      method: "POST",
      body: formData,
    });
  },

  // Cases / Investigations
  getCases: () => request<{ items: CaseItem[]; total: number; activeCount: number }>("/api/cases"),

  updateCaseStatus: (id: number, status: string) =>
    request<{ success: boolean; case: CaseItem }>(`/api/cases/${id}/status`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    }),

  // Network
  getNetworkFlows: () => request<{ flows: NetworkFlowItem[]; total: number }>("/api/network/flows"),

  getNetworkStats: () =>
    request<{
      trafficToday: string;
      anomaliesCount: number;
      externalPeers: string;
      encryptedRatio: string;
      signatures: { ddos: string; beaconing: string; dnsTunneling: string };
    }>("/api/network/stats"),

  // Threat Intelligence
  getThreatIntelHistory: () =>
    request<{ items: ThreatIntelItem[]; total: number }>("/api/threat-intel/history"),

  lookupThreatIntel: (indicator: string) =>
    request<{ found: boolean; source?: string; indicator: ThreatIntelItem }>(
      `/api/threat-intel/lookup?indicator=${encodeURIComponent(indicator)}`
    ),

  // Reports
  getReports: () => request<{ items: ReportItem[]; total: number }>("/api/reports"),

  // Malware
  getMalwareSamples: () =>
    request<{ samples: MalwareSampleItem[]; total: number }>("/api/malware/samples"),
};
