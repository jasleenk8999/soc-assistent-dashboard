import {
  boolean,
  bigint,
  integer,
  jsonb,
  numeric,
  pgTable,
  serial,
  text,
  timestamp,
  varchar,
  index,
} from "drizzle-orm/pg-core";

// ---------------------------------------------------------------------------
// 1. Users & Analysts
// ---------------------------------------------------------------------------
export const users = pgTable(
  "users",
  {
    id: serial("id").primaryKey(),
    email: varchar("email", { length: 255 }).notNull().unique(),
    passwordHash: text("password_hash").notNull(),
    fullName: varchar("full_name", { length: 100 }).notNull(),
    role: varchar("role", { length: 50 }).notNull().default("Senior Analyst"),
    initials: varchar("initials", { length: 10 }).notNull(),
    status: varchar("status", { length: 50 }).notNull().default("On shift"),
    color: varchar("color", { length: 20 }).notNull().default("#b7f960"),
    activeCasesCount: integer("active_cases_count").notNull().default(0),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    index("users_email_idx").on(table.email),
    index("users_role_idx").on(table.role),
  ]
);

// ---------------------------------------------------------------------------
// 1b. Refresh Tokens & Sessions
// ---------------------------------------------------------------------------
export const refreshTokens = pgTable(
  "refresh_tokens",
  {
    id: serial("id").primaryKey(),
    userId: integer("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    tokenHash: varchar("token_hash", { length: 64 }).notNull().unique(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    replacedByTokenHash: varchar("replaced_by_token_hash", { length: 64 }),
    userAgent: varchar("user_agent", { length: 255 }),
    ipAddress: varchar("ip_address", { length: 45 }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    index("refresh_tokens_user_idx").on(table.userId),
    index("refresh_tokens_hash_idx").on(table.tokenHash),
    index("refresh_tokens_expires_idx").on(table.expiresAt),
  ]
);

// ---------------------------------------------------------------------------
// 2. Logs
// ---------------------------------------------------------------------------
export const logs = pgTable(
  "logs",
  {
    id: serial("id").primaryKey(),
    timestamp: timestamp("timestamp", { withTimezone: true }).defaultNow().notNull(),
    sourceType: varchar("source_type", { length: 50 }).notNull(), // Windows Event, Linux Syslog, Firewall, Web Server, IDS/IPS
    sourceHost: varchar("source_host", { length: 100 }),
    sourceIp: varchar("source_ip", { length: 45 }),
    destinationIp: varchar("destination_ip", { length: 45 }),
    eventId: varchar("event_id", { length: 50 }),
    logLevel: varchar("log_level", { length: 20 }).notNull().default("INFO"),
    rawLog: text("raw_log").notNull(),
    parsedFields: jsonb("parsed_fields").default({}),
    isThreat: boolean("is_threat").notNull().default(false),
    threatReason: text("threat_reason"),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    index("logs_timestamp_idx").on(table.timestamp),
    index("logs_source_ip_idx").on(table.sourceIp),
    index("logs_is_threat_idx").on(table.isThreat),
  ]
);

// ---------------------------------------------------------------------------
// 3. Alerts
// ---------------------------------------------------------------------------
export const alerts = pgTable(
  "alerts",
  {
    id: serial("id").primaryKey(),
    severity: varchar("severity", { length: 20 }).notNull(), // Critical, High, Medium, Low
    title: varchar("title", { length: 255 }).notNull(),
    source: varchar("source", { length: 255 }).notNull(),
    tactic: varchar("tactic", { length: 50 }).notNull(), // MITRE Tactic ID (e.g. TA0006)
    technique: varchar("technique", { length: 50 }), // MITRE Technique ID (e.g. T1110)
    status: varchar("status", { length: 50 }).notNull().default("Open"), // Open, In review, Escalated, Resolved
    detectionMethod: varchar("detection_method", { length: 100 }).notNull().default("Rule-based"),
    confidence: numeric("confidence", { precision: 5, scale: 2 }).notNull().default("90.00"),
    description: text("description"),
    evidence: jsonb("evidence").default({}),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    index("alerts_severity_idx").on(table.severity),
    index("alerts_status_idx").on(table.status),
    index("alerts_created_at_idx").on(table.createdAt),
  ]
);

// ---------------------------------------------------------------------------
// 4. Cases (Investigations)
// ---------------------------------------------------------------------------
export const cases = pgTable(
  "cases",
  {
    id: serial("id").primaryKey(),
    caseNumber: varchar("case_number", { length: 50 }).notNull().unique(), // INC-2026-0418
    alertId: integer("alert_id").references(() => alerts.id, { onDelete: "set null" }),
    title: varchar("title", { length: 255 }).notNull(),
    severity: varchar("severity", { length: 20 }).notNull().default("High"),
    status: varchar("status", { length: 50 }).notNull().default("Active"), // Active, In review, Contained, Closed
    assignedUserId: integer("assigned_user_id").references(() => users.id, { onDelete: "set null" }),
    assignedUserName: varchar("assigned_user_name", { length: 100 }).default("Avery Reed"),
    affectedAsset: varchar("affected_asset", { length: 100 }).notNull().default("VPN Gateway"),
    primaryEntity: varchar("primary_entity", { length: 100 }).notNull().default("185.220.101.45"),
    mitreTechnique: varchar("mitre_technique", { length: 50 }).notNull().default("T1110"),
    aiConfidence: numeric("ai_confidence", { precision: 5, scale: 2 }).notNull().default("94.80"),
    summary: text("summary"),
    timeline: jsonb("timeline").default([]), // array of { time: string, title: string, status: string }
    aiExplanation: text("ai_explanation"),
    remediationSteps: jsonb("remediation_steps").default([]),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    index("cases_case_number_idx").on(table.caseNumber),
    index("cases_status_idx").on(table.status),
  ]
);

// ---------------------------------------------------------------------------
// 5. Malware Samples
// ---------------------------------------------------------------------------
export const malwareSamples = pgTable(
  "malware_samples",
  {
    id: serial("id").primaryKey(),
    filename: varchar("filename", { length: 255 }).notNull(),
    sha256: varchar("sha256", { length: 64 }).notNull(),
    fileSize: integer("file_size").notNull(),
    fileType: varchar("file_type", { length: 50 }).notNull().default("PE executable"),
    verdict: varchar("verdict", { length: 50 }).notNull().default("Pending"), // Likely trojan, Benign file, Ransomware, etc.
    confidence: numeric("confidence", { precision: 5, scale: 2 }).default("0.00"),
    modelUsed: varchar("model_used", { length: 50 }).default("Static Analysis"),
    riskScore: numeric("risk_score", { precision: 3, scale: 1 }).default("0.0"),
    indicators: jsonb("indicators").default([]),
    peFeatures: jsonb("pe_features").default({}),
    status: varchar("status", { length: 50 }).notNull().default("Completed"), // Queue, Completed, Quarantined
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    index("malware_sha256_idx").on(table.sha256),
    index("malware_status_idx").on(table.status),
  ]
);

// ---------------------------------------------------------------------------
// 6. Network Flows
// ---------------------------------------------------------------------------
export const networkFlows = pgTable(
  "network_flows",
  {
    id: serial("id").primaryKey(),
    sourceHost: varchar("source_host", { length: 100 }).notNull(),
    sourceIp: varchar("source_ip", { length: 45 }).notNull(),
    destinationHost: varchar("destination_host", { length: 100 }),
    destinationIp: varchar("destination_ip", { length: 45 }).notNull(),
    protocol: varchar("protocol", { length: 20 }).notNull(), // HTTPS, VPN, SMTP, DNS, etc.
    volumeBytes: bigint("volume_bytes", { mode: "number" }).notNull().default(0),
    volumeFormatted: varchar("volume_formatted", { length: 50 }).notNull().default("0 KB"),
    packetCount: integer("packet_count").default(0),
    risk: varchar("risk", { length: 20 }).notNull().default("Low"), // Critical, High, Medium, Low
    anomalyScore: numeric("anomaly_score", { precision: 5, scale: 2 }).default("0.00"),
    isAnomaly: boolean("is_anomaly").notNull().default(false),
    tags: jsonb("tags").default([]),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    index("network_source_ip_idx").on(table.sourceIp),
    index("network_risk_idx").on(table.risk),
  ]
);

// ---------------------------------------------------------------------------
// 7. Threat Intelligence Cache
// ---------------------------------------------------------------------------
export const threatIntelCache = pgTable(
  "threat_intel_cache",
  {
    id: serial("id").primaryKey(),
    indicator: varchar("indicator", { length: 255 }).notNull().unique(),
    indicatorType: varchar("indicator_type", { length: 50 }).notNull(), // IP address, Domain, URL, File hash
    verdict: varchar("verdict", { length: 50 }).notNull(), // Malicious, Suspicious, Clean, Unknown
    reputationScore: integer("reputation_score").notNull().default(0), // 0-100
    detectionsCount: integer("detections_count").notNull().default(0),
    totalEngines: integer("total_engines").notNull().default(0),
    confidence: varchar("confidence", { length: 20 }).default("High"),
    associatedContext: jsonb("associated_context").default([]),
    feedVerdicts: jsonb("feed_verdicts").default([]),
    firstSeen: timestamp("first_seen", { withTimezone: true }).defaultNow(),
    lastSeen: timestamp("last_seen", { withTimezone: true }).defaultNow(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    index("threat_intel_indicator_idx").on(table.indicator),
  ]
);

// ---------------------------------------------------------------------------
// 8. Incident Reports
// ---------------------------------------------------------------------------
export const reports = pgTable(
  "reports",
  {
    id: serial("id").primaryKey(),
    reportCode: varchar("report_code", { length: 50 }).notNull().unique(), // INC-2026-0418, WEEK-2026-16
    title: varchar("title", { length: 255 }).notNull(),
    incidentName: varchar("incident_name", { length: 255 }).notNull(),
    reportType: varchar("report_type", { length: 100 }).notNull(), // Executive incident report, Technical investigation report, Operational summary
    status: varchar("status", { length: 50 }).notNull().default("Draft"), // Draft, Review, Published
    caseId: integer("case_id").references(() => cases.id, { onDelete: "set null" }),
    generatedById: integer("generated_by_id").references(() => users.id, { onDelete: "set null" }),
    contentJson: jsonb("content_json").default({}),
    filePath: text("file_path"),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    index("reports_code_idx").on(table.reportCode),
    index("reports_status_idx").on(table.status),
  ]
);
