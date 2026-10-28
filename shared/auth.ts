/**
 * Shared Authentication and RBAC Role Definitions
 */

export const ROLES = [
  "Senior Analyst",
  "Threat Hunter",
  "Incident Commander",
  "Detection Engineer",
] as const;

export type UserRole = (typeof ROLES)[number];

export const DEFAULT_USER_ROLE: UserRole = "Senior Analyst";

export const PERMISSIONS = {
  // Read permissions across dashboard modules
  READ_DASHBOARD: "read:dashboard",
  READ_ALERTS: "read:alerts",
  READ_INVESTIGATIONS: "read:investigations",
  READ_NETWORK: "read:network",
  READ_THREAT_INTEL: "read:threat_intel",
  READ_REPORTS: "read:reports",
  READ_LOGS: "read:logs",
  READ_MALWARE: "read:malware",

  // Triage & Case Containment
  UPDATE_ALERT_STATUS: "update:alert_status",
  UPDATE_CASE_STATUS: "update:case_status",
  ASSIGN_CASES: "assign:cases",

  // Threat Intel & Hunting
  MANAGE_THREAT_INTEL: "manage:threat_intel",
  ANALYZE_PCAP: "analyze:pcap",
  UPLOAD_MALWARE: "upload:malware",

  // Detection Rules & Logging
  INGEST_LOGS: "ingest:logs",
  MANAGE_DETECTION_RULES: "manage:detection_rules",

  // Administrative / Escalation
  ADMIN_USERS: "admin:users",
  EXPORT_REPORTS: "export:reports",
  APPROVE_INCIDENT: "approve:incident",
} as const;

export type Permission = (typeof PERMISSIONS)[keyof typeof PERMISSIONS];

/**
 * Role Permission Matrix
 * Explicitly defines what actions each role is authorized to perform.
 */
export const ROLE_PERMISSIONS: Record<UserRole, readonly Permission[]> = {
  "Senior Analyst": [
    PERMISSIONS.READ_DASHBOARD,
    PERMISSIONS.READ_ALERTS,
    PERMISSIONS.READ_INVESTIGATIONS,
    PERMISSIONS.READ_NETWORK,
    PERMISSIONS.READ_THREAT_INTEL,
    PERMISSIONS.READ_REPORTS,
    PERMISSIONS.READ_LOGS,
    PERMISSIONS.READ_MALWARE,
    PERMISSIONS.UPDATE_ALERT_STATUS,
    PERMISSIONS.UPDATE_CASE_STATUS,
    PERMISSIONS.UPLOAD_MALWARE,
    PERMISSIONS.EXPORT_REPORTS,
  ],
  "Threat Hunter": [
    PERMISSIONS.READ_DASHBOARD,
    PERMISSIONS.READ_ALERTS,
    PERMISSIONS.READ_INVESTIGATIONS,
    PERMISSIONS.READ_NETWORK,
    PERMISSIONS.READ_THREAT_INTEL,
    PERMISSIONS.READ_REPORTS,
    PERMISSIONS.READ_LOGS,
    PERMISSIONS.READ_MALWARE,
    PERMISSIONS.MANAGE_THREAT_INTEL,
    PERMISSIONS.ANALYZE_PCAP,
    PERMISSIONS.UPLOAD_MALWARE,
  ],
  "Incident Commander": [
    // Full authority across all security actions
    PERMISSIONS.READ_DASHBOARD,
    PERMISSIONS.READ_ALERTS,
    PERMISSIONS.READ_INVESTIGATIONS,
    PERMISSIONS.READ_NETWORK,
    PERMISSIONS.READ_THREAT_INTEL,
    PERMISSIONS.READ_REPORTS,
    PERMISSIONS.READ_LOGS,
    PERMISSIONS.READ_MALWARE,
    PERMISSIONS.UPDATE_ALERT_STATUS,
    PERMISSIONS.UPDATE_CASE_STATUS,
    PERMISSIONS.ASSIGN_CASES,
    PERMISSIONS.APPROVE_INCIDENT,
    PERMISSIONS.EXPORT_REPORTS,
    PERMISSIONS.ADMIN_USERS,
    PERMISSIONS.MANAGE_THREAT_INTEL,
    PERMISSIONS.ANALYZE_PCAP,
    PERMISSIONS.UPLOAD_MALWARE,
  ],
  "Detection Engineer": [
    PERMISSIONS.READ_DASHBOARD,
    PERMISSIONS.READ_ALERTS,
    PERMISSIONS.READ_INVESTIGATIONS,
    PERMISSIONS.READ_NETWORK,
    PERMISSIONS.READ_THREAT_INTEL,
    PERMISSIONS.READ_REPORTS,
    PERMISSIONS.READ_LOGS,
    PERMISSIONS.READ_MALWARE,
    PERMISSIONS.INGEST_LOGS,
    PERMISSIONS.MANAGE_DETECTION_RULES,
    PERMISSIONS.ANALYZE_PCAP,
  ],
};

export function normalizeRole(role: string): UserRole {
  if (role === "Senior Security Analyst" || role === "Senior Analyst") return "Senior Analyst";
  if (role === "Threat Hunter") return "Threat Hunter";
  if (role === "Incident Commander") return "Incident Commander";
  if (role === "Detection Engineer") return "Detection Engineer";
  return DEFAULT_USER_ROLE;
}

export function hasPermission(role: string, permission: Permission): boolean {
  const normalized = normalizeRole(role);
  const perms = ROLE_PERMISSIONS[normalized];
  if (!perms) return false;
  return perms.includes(permission);
}

export const REFRESH_COOKIE_NAME = "soc_refresh_token";
export const CSRF_HEADER_NAME = "x-csrf-token";
