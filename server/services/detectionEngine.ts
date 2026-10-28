/**
 * Security Detection Engine
 * Deterministic, rule-based correlation and detection engine.
 *
 * Implements:
 * A. Brute-force attack detection (configurable threshold: > 10 failures in 3m)
 * B. SQL injection indicators (URI, query params, web access logs)
 * C. Cross-site scripting (XSS) indicators (script tags, event handlers, javascript:)
 * D. Port scanning activity (single source contacting > 15 distinct ports in 2m)
 * E. Suspicious privilege escalation (sudo failures, user not in sudoers, admin group changes)
 * F. Authentication success after multiple failures (credential guessing breakthrough)
 *
 * Provides alert deduplication, auditability, MITRE ATT&CK mapping, and persistence.
 */

import { and, desc, eq, gte, ilike, inArray, or, sql } from "drizzle-orm";
import { db } from "../db/index";
import { alerts, logs } from "../db/schema";
import type { NormalizedLog } from "./logNormalizer";

export interface DetectionMatch {
  ruleId: string;
  ruleName: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  title: string;
  source: string;
  destination?: string;
  tactic: string;
  technique: string;
  confidence: string; // e.g. "95.00"
  description: string;
  evidence: Record<string, any>;
  suggestedNextSteps: string;
  relatedLogIds: number[];
  dedupKey: string;
}

export class DetectionEngine {
  // Configurable thresholds with fallback defaults
  private static readonly BRUTE_FORCE_THRESHOLD = parseInt(
    process.env.DETECTION_BRUTE_FORCE_THRESHOLD || "10",
    10
  );
  private static readonly BRUTE_FORCE_WINDOW_SECONDS = parseInt(
    process.env.DETECTION_BRUTE_FORCE_WINDOW_SECONDS || "180",
    10
  );
  private static readonly PORTSCAN_THRESHOLD = parseInt(
    process.env.DETECTION_PORTSCAN_THRESHOLD || "15",
    10
  );
  private static readonly PORTSCAN_WINDOW_SECONDS = parseInt(
    process.env.DETECTION_PORTSCAN_WINDOW_SECONDS || "120",
    10
  );
  private static readonly DEDUP_WINDOW_SECONDS = parseInt(
    process.env.DETECTION_DEDUP_WINDOW_SECONDS || "600",
    10
  );

  /**
   * Main evaluation pipeline for a newly ingested log.
   * Runs single-event and correlated rules, persists matches, and links them to the log.
   */
  public static async evaluateAndAlert(
    logId: number,
    log: NormalizedLog
  ): Promise<{ alerts: typeof alerts.$inferSelect[]; matches: DetectionMatch[] }> {
    const matches: DetectionMatch[] = [];

    // 1. Single-Event Evaluations
    const sqliMatch = this.evaluateSqlInjection(logId, log);
    if (sqliMatch) matches.push(sqliMatch);

    const xssMatch = this.evaluateXss(logId, log);
    if (xssMatch) matches.push(xssMatch);

    const privEscMatch = this.evaluatePrivilegeEscalation(logId, log);
    if (privEscMatch) matches.push(privEscMatch);

    // 2. Correlated Time-Window Evaluations
    const bruteForceMatch = await this.evaluateBruteForce(logId, log);
    if (bruteForceMatch) matches.push(bruteForceMatch);

    const portScanMatch = await this.evaluatePortScan(logId, log);
    if (portScanMatch) matches.push(portScanMatch);

    const authBreakthroughMatch = await this.evaluateAuthBreakthrough(logId, log);
    if (authBreakthroughMatch) matches.push(authBreakthroughMatch);

    // 3. Persist and Deduplicate Alerts in PostgreSQL
    const persistedAlerts: typeof alerts.$inferSelect[] = [];
    for (const match of matches) {
      const persisted = await this.persistOrDeduplicateAlert(match);
      if (persisted) {
        persistedAlerts.push(persisted);
      }
    }

    // 4. Update the log record if a threat was identified
    if (matches.length > 0) {
      try {
        await db
          .update(logs)
          .set({
            isThreat: true,
            threatReason: matches.map((m) => `${m.ruleId}: ${m.ruleName}`).join("; "),
          })
          .where(eq(logs.id, logId));
      } catch (err) {
        console.error("Failed to update log threat flag:", err);
      }
    }

    return { alerts: persistedAlerts, matches };
  }

  // ---------------------------------------------------------------------------
  // Rule A: Brute-Force Attacks (RULE-AUTH-001)
  // ---------------------------------------------------------------------------
  private static async evaluateBruteForce(
    logId: number,
    log: NormalizedLog
  ): Promise<DetectionMatch | null> {
    const isAuthFailure =
      log.eventCategory === "Authentication Failure" ||
      log.eventId === "4625" ||
      log.rawLog.includes("Failed password") ||
      log.rawLog.includes("authentication failure") ||
      (log.sourceType === "Web Server" && log.parsedFields?.httpStatus === 401);

    if (!isAuthFailure) return null;

    const sourceIp = log.sourceIp;
    const username = log.username;
    if (!sourceIp && !username) return null;

    const windowStart = new Date(Date.now() - this.BRUTE_FORCE_WINDOW_SECONDS * 1000);

    try {
      // Find recent authentication failures matching either sourceIp or username
      const conditions = [
        gte(logs.timestamp, windowStart),
        or(
          eq(logs.eventCategory, "Authentication Failure"),
          eq(logs.eventId, "4625"),
          ilike(logs.rawLog, "%Failed password%"),
          ilike(logs.rawLog, "%authentication failure%")
        ),
      ];

      if (sourceIp) {
        conditions.push(eq(logs.sourceIp, sourceIp));
      } else if (username) {
        conditions.push(eq(logs.username, username));
      }

      const recentFailures = await db
        .select({
          id: logs.id,
          sourceIp: logs.sourceIp,
          username: logs.username,
          timestamp: logs.timestamp,
        })
        .from(logs)
        .where(and(...conditions))
        .orderBy(desc(logs.timestamp))
        .limit(100);

      const count = recentFailures.length;
      if (count >= this.BRUTE_FORCE_THRESHOLD) {
        const relatedIds = Array.from(new Set([logId, ...recentFailures.map((f) => f.id)]));
        const targetedUsers = Array.from(
          new Set(recentFailures.map((f) => f.username).filter(Boolean))
        );

        const severity = count > 25 ? "Critical" : "High";
        const targetDesc = targetedUsers.length > 0 ? `targeting accounts [${targetedUsers.join(", ")}]` : "";

        return {
          ruleId: "RULE-AUTH-001",
          ruleName: "Repeated Authentication Failures (Brute Force)",
          severity,
          title: `Brute-force attack detected from ${sourceIp || "unknown"} ${targetDesc}`.trim(),
          source: sourceIp || log.sourceHost || "Remote Attacker",
          destination: log.destinationIp || log.sourceHost,
          tactic: "TA0006", // Credential Access
          technique: "T1110 - Brute Force",
          confidence: "95.00",
          description: `Detected ${count} authentication failures within ${this.BRUTE_FORCE_WINDOW_SECONDS} seconds (threshold: ${this.BRUTE_FORCE_THRESHOLD}). Indicates active automated credential brute-force or dictionary attack.`,
          evidence: {
            failureCount: count,
            threshold: this.BRUTE_FORCE_THRESHOLD,
            timeWindowSeconds: this.BRUTE_FORCE_WINDOW_SECONDS,
            sourceIp,
            targetedAccounts: targetedUsers,
            sampleLogIds: relatedIds.slice(0, 10),
          },
          suggestedNextSteps: `1. Temporarily ban source IP ${sourceIp} at the perimeter firewall.\n2. Audit targeted accounts (${targetedUsers.join(", ") || "all"}) for account lockouts.\n3. Check for successful logins from this IP (RULE-AUTH-002).`,
          relatedLogIds: relatedIds,
          dedupKey: `RULE-AUTH-001:${sourceIp || "no-ip"}:${username || "any-user"}`,
        };
      }
    } catch (err) {
      console.error("Error evaluating brute force rule:", err);
    }

    return null;
  }

  // ---------------------------------------------------------------------------
  // Rule B: SQL Injection Indicators (RULE-WEB-001)
  // ---------------------------------------------------------------------------
  private static evaluateSqlInjection(logId: number, log: NormalizedLog): DetectionMatch | null {
    const raw = log.rawLog;
    const uri = log.parsedFields?.uri || "";
    let decoded = `${uri} ${raw}`;
    try {
      decoded = decodeURIComponent(decoded.replace(/\+/g, " "));
    } catch {
      // Ignore malformed URI sequences
    }
    const payload = `${uri} ${raw} ${decoded}`;

    const sqliPatterns = [
      { pattern: /'\s*(?:or|and)\s*['"]?\d+['"]?\s*=\s*['"]?\d+/i, name: "Boolean-based SQL Injection (' OR 1=1)" },
      { pattern: /'\s*(?:or|and)\s*['"][a-zA-Z0-9]+['"]\s*=\s*['"][a-zA-Z0-9]+/i, name: "String-based SQL Injection (' OR 'a'='a')" },
      { pattern: /union\s+(?:all\s+)?select\s+/i, name: "UNION-based SQL Injection" },
      { pattern: /select\s+.*?\s+from\s+/i, name: "Direct SELECT Query Injection" },
      { pattern: /(?:drop|alter|truncate)\s+table\s+/i, name: "DDL Database Destructive Injection" },
      { pattern: /insert\s+into\s+.*?\s+values/i, name: "INSERT Data Manipulation Injection" },
      { pattern: /(?:sleep|benchmark)\s*\(\s*\d+\s*\)/i, name: "Time-based Blind SQL Injection" },
      { pattern: /waitfor\s+delay\s+/i, name: "MSSQL Time-delay Blind Injection" },
      { pattern: /(?:--|#|\/\*).*?(?:select|union|or|and)/i, name: "SQL Comment Inline Query Evasion" },
      { pattern: /'\s*;\s*exec\s*\(/i, name: "Stacked Query Execution Injection" },
    ];

    for (const { pattern, name } of sqliPatterns) {
      const match = payload.match(pattern);
      if (match) {
        const matchedSnippet = match[0];
        const status = log.parsedFields?.httpStatus;
        const severity = status === 200 || status === 500 ? "Critical" : "High";

        return {
          ruleId: "RULE-WEB-001",
          ruleName: "SQL Injection Attack Indicator",
          severity,
          title: `SQL Injection attempt in web request (${name})`,
          source: log.sourceIp || log.sourceHost || "Web Client",
          destination: log.destinationIp || "Web Application Server",
          tactic: "TA0001", // Initial Access
          technique: "T1190 - Exploit Public-Facing Application",
          confidence: "92.00",
          description: `Identified SQL syntax injection (${name}) in HTTP request telemetry. Attacker attempted to manipulate database query structure.`,
          evidence: {
            matchedPattern: pattern.source,
            patternDescription: name,
            matchedSnippet,
            httpMethod: log.parsedFields?.httpMethod,
            uri: log.parsedFields?.uri,
            httpStatus: status,
            clientIp: log.sourceIp,
          },
          suggestedNextSteps: "1. Inspect web application endpoint code to ensure parameterized/prepared statements are enforced.\n2. Review WAF rules to block signature pattern.\n3. Check database query logs for execution of unauthorized payloads.",
          relatedLogIds: [logId],
          dedupKey: `RULE-WEB-001:${log.sourceIp || "no-ip"}:${log.sourceHost || "app"}`,
        };
      }
    }

    return null;
  }

  // ---------------------------------------------------------------------------
  // Rule C: Cross-Site Scripting (XSS) Indicators (RULE-WEB-002)
  // ---------------------------------------------------------------------------
  private static evaluateXss(logId: number, log: NormalizedLog): DetectionMatch | null {
    const raw = log.rawLog;
    const uri = log.parsedFields?.uri || "";
    let decoded = `${uri} ${raw}`;
    try {
      decoded = decodeURIComponent(decoded.replace(/\+/g, " "));
    } catch {
      // Ignore malformed URI sequences
    }
    const payload = `${uri} ${raw} ${decoded}`;

    const xssPatterns = [
      { pattern: /<script[\s\S]*?>[\s\S]*?<\/script>/i, name: "HTML Script Tag Injection" },
      { pattern: /<script\b/i, name: "Unclosed Script Tag Injection" },
      { pattern: /javascript:[^\s"'>]+/i, name: "JavaScript URI Scheme Injection" },
      { pattern: /\b(?:onerror|onload|onclick|onmouseover|onfocus|onblur)\s*=\s*["']?[^"'>]+/i, name: "Inline HTML Event Handler Injection" },
      { pattern: /<svg[\s\S]*?onload\s*=/i, name: "SVG Vector Event Injection" },
      { pattern: /<iframe[\s\S]*?src\s*=/i, name: "IFrame Redirection Injection" },
      { pattern: /\b(?:alert|eval|prompt|confirm)\s*\([^\)]*\)/i, name: "Dangerous JavaScript Function Call" },
      { pattern: /document\.(?:cookie|location|write)/i, name: "DOM Property Cookie/Location Access" },
    ];

    for (const { pattern, name } of xssPatterns) {
      const match = payload.match(pattern);
      if (match) {
        const matchedSnippet = match[0];
        return {
          ruleId: "RULE-WEB-002",
          ruleName: "Cross-Site Scripting (XSS) Indicator",
          severity: "Medium",
          title: `XSS injection vector detected (${name})`,
          source: log.sourceIp || log.sourceHost || "Web Client",
          destination: log.destinationIp || "Web Application Server",
          tactic: "TA0001", // Initial Access
          technique: "T1059.007 - Command and Scripting Interpreter: JavaScript",
          confidence: "88.00",
          description: `Identified Cross-Site Scripting (${name}) in incoming HTTP telemetry. Attacker attempted to inject executable JavaScript into the client browsing context.`,
          evidence: {
            matchedPattern: pattern.source,
            patternDescription: name,
            matchedSnippet,
            httpMethod: log.parsedFields?.httpMethod,
            uri: log.parsedFields?.uri,
            clientIp: log.sourceIp,
          },
          suggestedNextSteps: "1. Enforce contextual output encoding (HTML, JavaScript, Attribute context) on all rendered user inputs.\n2. Validate Content Security Policy (CSP) headers (script-src 'self').\n3. Verify session cookies are configured with HttpOnly and SameSite attributes.",
          relatedLogIds: [logId],
          dedupKey: `RULE-WEB-002:${log.sourceIp || "no-ip"}:${log.sourceHost || "app"}`,
        };
      }
    }

    return null;
  }

  // ---------------------------------------------------------------------------
  // Rule D: Port Scanning Reconnaissance (RULE-NET-001)
  // ---------------------------------------------------------------------------
  private static async evaluatePortScan(
    logId: number,
    log: NormalizedLog
  ): Promise<DetectionMatch | null> {
    const isNetworkLog =
      log.sourceType === "Firewall" ||
      log.sourceType === "IDS/IPS" ||
      Boolean(log.destinationPort);

    if (!isNetworkLog || !log.sourceIp || !log.destinationPort) {
      return null;
    }

    const refTime =
      log.timestamp instanceof Date && !isNaN(log.timestamp.getTime())
        ? log.timestamp.getTime()
        : Date.now();
    const windowStart = new Date(Math.min(refTime, Date.now()) - this.PORTSCAN_WINDOW_SECONDS * 1000);

    try {
      const recentConnections = await db
        .select({
          id: logs.id,
          destinationPort: logs.destinationPort,
          destinationIp: logs.destinationIp,
          protocol: logs.protocol,
        })
        .from(logs)
        .where(
          and(
            eq(logs.sourceIp, log.sourceIp),
            gte(logs.timestamp, windowStart)
          )
        )
        .limit(200);

      const distinctPorts = Array.from(
        new Set(recentConnections.map((c) => c.destinationPort).filter((p): p is number => Boolean(p)))
      );

      if (distinctPorts.length >= this.PORTSCAN_THRESHOLD) {
        const privilegedPorts = distinctPorts.filter((p) => p < 1024);
        const severity = privilegedPorts.length >= 5 ? "High" : "Medium";
        const relatedIds = Array.from(new Set([logId, ...recentConnections.map((c) => c.id)]));

        return {
          ruleId: "RULE-NET-001",
          ruleName: "Network Service Discovery (Port Scan)",
          severity,
          title: `Port scan reconnaissance detected from ${log.sourceIp} (${distinctPorts.length} ports)`,
          source: log.sourceIp,
          destination: log.destinationIp || "Multiple internal hosts",
          tactic: "TA0007", // Discovery
          technique: "T1046 - Network Service Discovery",
          confidence: "90.00",
          description: `Single source IP ${log.sourceIp} attempted connection to ${distinctPorts.length} distinct destination ports in ${this.PORTSCAN_WINDOW_SECONDS} seconds (threshold: ${this.PORTSCAN_THRESHOLD}). Indicates automated network reconnaissance (e.g. nmap, masscan).`,
          evidence: {
            distinctPortCount: distinctPorts.length,
            scannedPortsCount: distinctPorts.length,
            threshold: this.PORTSCAN_THRESHOLD,
            timeWindowSeconds: this.PORTSCAN_WINDOW_SECONDS,
            scannedPortsSample: distinctPorts.slice(0, 20),
            privilegedPortsSample: privilegedPorts,
            sourceIp: log.sourceIp,
          },
          suggestedNextSteps: `1. Implement edge perimeter IP drop for ${log.sourceIp}.\n2. Confirm no closed ports returned open status.\n3. Inspect destination IPs for follow-on exploitation probes.`,
          relatedLogIds: relatedIds,
          dedupKey: `RULE-NET-001:${log.sourceIp}`,
        };
      }
    } catch (err) {
      console.error("Error evaluating port scan rule:", err);
    }

    return null;
  }

  // ---------------------------------------------------------------------------
  // Rule E: Suspicious Privilege Escalation (RULE-PRIV-001)
  // ---------------------------------------------------------------------------
  private static evaluatePrivilegeEscalation(
    logId: number,
    log: NormalizedLog
  ): DetectionMatch | null {
    const raw = log.rawLog;

    // Pattern 1: Linux user NOT in sudoers
    if (raw.includes("user NOT in sudoers") || (raw.includes("sudo:") && raw.includes("NOT in sudoers"))) {
      const userMatch = raw.match(/([a-zA-Z0-9_\-\.]+)\s*:\s*user NOT in sudoers/i);
      const user = userMatch ? userMatch[1] : log.username || "unknown";

      return {
        ruleId: "RULE-PRIV-001",
        ruleName: "Unauthorized Sudo Privilege Escalation Attempt",
        severity: "High",
        title: `Unauthorized sudo escalation attempt by user '${user}'`,
        source: log.sourceHost || log.sourceIp || "Local Host",
        tactic: "TA0004", // Privilege Escalation
        technique: "T1548.003 - Sudo and Sudo Caching",
        confidence: "94.00",
        description: `User '${user}' attempted to execute commands with elevated root/sudo privileges but is not a member of the sudoers policy.`,
        evidence: {
          attemptedUser: user,
          rawLog: raw,
          host: log.sourceHost,
        },
        suggestedNextSteps: `1. Verify identity of user '${user}' and confirm whether account is compromised.\n2. Review auth.log for initial logon vectors.\n3. Verify integrity of /etc/sudoers and /etc/sudoers.d.`,
        relatedLogIds: [logId],
        dedupKey: `RULE-PRIV-001:sudoers:${user}:${log.sourceHost || "local"}`,
      };
    }

    // Pattern 2: Windows EventID 4728 (Member added to Security Group - e.g. Administrators)
    if (log.eventId === "4728" || (raw.includes("4728") && raw.toLowerCase().includes("member"))) {
      return {
        ruleId: "RULE-PRIV-001",
        ruleName: "Security-Enabled Global Group Member Added",
        severity: "High",
        title: "Privilege Escalation: Account added to privileged security group",
        source: log.sourceHost || "Domain Controller",
        tactic: "TA0004", // Privilege Escalation
        technique: "T1098 - Account Manipulation",
        confidence: "91.00",
        description: "Windows Security Event 4728 triggered: A member was added to a security-enabled group (potential lateral movement / persistence).",
        evidence: {
          eventId: "4728",
          parsedFields: log.parsedFields,
          rawLog: raw,
        },
        suggestedNextSteps: "1. Identify the administrative user who granted group membership.\n2. Confirm change-management approval ticket.\n3. Audit user's newly granted domain privileges.",
        relatedLogIds: [logId],
        dedupKey: `RULE-PRIV-001:4728:${log.username || "unknown"}`,
      };
    }

    // Pattern 3: Unauthorized Interactive Shell Sudo Command
    if (
      raw.includes("sudo:") &&
      (raw.includes("COMMAND=/bin/bash") ||
        raw.includes("COMMAND=/bin/sh") ||
        raw.includes("COMMAND=/usr/bin/python") ||
        raw.includes("COMMAND=/usr/bin/perl"))
    ) {
      return {
        ruleId: "RULE-PRIV-001",
        ruleName: "Suspicious Root Shell Spawn via Sudo",
        severity: "High",
        title: "Suspicious interactive root shell execution via sudo",
        source: log.sourceHost || "Local Host",
        tactic: "TA0004", // Privilege Escalation
        technique: "T1548.003 - Sudo and Sudo Caching",
        confidence: "89.00",
        description: "Detected execution of an interactive root shell (e.g. /bin/bash, /bin/sh) via sudo. This frequently accompanies interactive post-exploitation access.",
        evidence: {
          rawLog: raw,
          user: log.username,
        },
        suggestedNextSteps: "1. Terminate the active shell process session.\n2. Collect process tree and command history for the parent process.\n3. Inspect audit logs for file creations during root shell lifetime.",
        relatedLogIds: [logId],
        dedupKey: `RULE-PRIV-001:rootshell:${log.username || "unknown"}:${log.sourceHost || "local"}`,
      };
    }

    return null;
  }

  // ---------------------------------------------------------------------------
  // Rule F: Authentication Success After Multiple Failures (RULE-AUTH-002)
  // ---------------------------------------------------------------------------
  private static async evaluateAuthBreakthrough(
    logId: number,
    log: NormalizedLog
  ): Promise<DetectionMatch | null> {
    const isAuthSuccess =
      log.eventCategory === "Authentication Success" ||
      log.eventId === "4624" ||
      log.rawLog.includes("Accepted password") ||
      log.rawLog.includes("Accepted publickey") ||
      (log.sourceType === "Web Server" &&
        log.parsedFields?.httpStatus === 200 &&
        (log.parsedFields?.path?.includes("login") || log.parsedFields?.uri?.includes("login")));

    if (!isAuthSuccess) return null;

    const sourceIp = log.sourceIp;
    const username = log.username;
    if (!sourceIp && !username) return null;

    // Check if there were >= 3 failures in previous 5 minutes
    const refTime =
      log.timestamp instanceof Date && !isNaN(log.timestamp.getTime())
        ? log.timestamp.getTime()
        : Date.now();
    const windowStart = new Date(Math.min(refTime, Date.now()) - 300 * 1000);

    try {
      const failureConditions = [
        gte(logs.timestamp, windowStart),
        or(
          eq(logs.eventCategory, "Authentication Failure"),
          eq(logs.eventId, "4625"),
          ilike(logs.rawLog, "%Failed password%"),
          ilike(logs.rawLog, "%authentication failure%")
        ),
      ];

      if (sourceIp) {
        failureConditions.push(eq(logs.sourceIp, sourceIp));
      } else if (username) {
        failureConditions.push(eq(logs.username, username));
      }

      const priorFailures = await db
        .select({ id: logs.id, timestamp: logs.timestamp })
        .from(logs)
        .where(and(...failureConditions))
        .limit(20);

      if (priorFailures.length >= 3) {
        const relatedIds = Array.from(new Set([logId, ...priorFailures.map((f) => f.id)]));

        return {
          ruleId: "RULE-AUTH-002",
          ruleName: "Credential Guessing Breakthrough",
          severity: "Critical",
          title: `Successful login following repeated failures for account '${username || "target"}'`,
          source: sourceIp || log.sourceHost || "Remote Attacker",
          destination: log.destinationIp || log.sourceHost,
          tactic: "TA0006", // Credential Access
          technique: "T1110.001 - Password Guessing",
          confidence: "96.00",
          description: `Detected successful authentication immediately following ${priorFailures.length} failed attempts from IP ${sourceIp || "same origin"} within 5 minutes. High probability of successful credential compromise.`,
          evidence: {
            priorFailureCount: priorFailures.length,
            authenticatedUser: username,
            sourceIp,
            breakthroughLogId: logId,
            priorFailureLogIds: priorFailures.map((f) => f.id),
          },
          suggestedNextSteps: "1. IMMEDIATELY revoke active session and credentials for the authenticated account.\n2. Quarantine source IP at perimeter firewall.\n3. Initiate incident response containment procedure.",
          relatedLogIds: relatedIds,
          dedupKey: `RULE-AUTH-002:${sourceIp || "no-ip"}:${username || "any-user"}`,
        };
      }
    } catch (err) {
      console.error("Error evaluating auth breakthrough rule:", err);
    }

    return null;
  }

  // ---------------------------------------------------------------------------
  // Alert Persistence & Deduplication
  // ---------------------------------------------------------------------------
  private static async persistOrDeduplicateAlert(
    match: DetectionMatch
  ): Promise<typeof alerts.$inferSelect | null> {
    const dedupWindowStart = new Date(Date.now() - this.DEDUP_WINDOW_SECONDS * 1000);

    try {
      // 1. Look for an active alert with the same dedupKey in the recent window
      const [existingAlert] = await db
        .select()
        .from(alerts)
        .where(
          and(
            eq(alerts.dedupKey, match.dedupKey),
            inArray(alerts.status, ["Open", "In review"]),
            gte(alerts.createdAt, dedupWindowStart)
          )
        )
        .orderBy(desc(alerts.createdAt))
        .limit(1);

      if (existingAlert) {
        // Merge relatedLogIds without duplicates
        const currentIds: number[] = Array.isArray(existingAlert.relatedLogIds)
          ? (existingAlert.relatedLogIds as number[])
          : [];
        const mergedIds = Array.from(new Set([...currentIds, ...match.relatedLogIds]));

        const existingEvidence =
          typeof existingAlert.evidence === "object" && existingAlert.evidence !== null
            ? existingAlert.evidence
            : {};

        const updatedEvidence = {
          ...existingEvidence,
          lastSeenTimestamp: new Date().toISOString(),
          suppressedDuplicateCount: ((existingEvidence as any).suppressedDuplicateCount || 1) + 1,
        };

        const [updated] = await db
          .update(alerts)
          .set({
            relatedLogIds: mergedIds,
            evidence: updatedEvidence,
            updatedAt: new Date(),
          })
          .where(eq(alerts.id, existingAlert.id))
          .returning();

        return updated;
      }

      // 2. Insert brand new alert
      const [newAlert] = await db
        .insert(alerts)
        .values({
          ruleId: match.ruleId,
          ruleName: match.ruleName,
          severity: match.severity,
          title: match.title,
          source: match.source,
          destination: match.destination,
          tactic: match.tactic,
          technique: match.technique,
          status: "Open",
          detectionMethod: "Rule-based Engine",
          confidence: match.confidence,
          description: match.description,
          evidence: {
            ...match.evidence,
            firstSeenTimestamp: new Date().toISOString(),
            suppressedDuplicateCount: 1,
          },
          suggestedNextSteps: match.suggestedNextSteps,
          relatedLogIds: match.relatedLogIds,
          dedupKey: match.dedupKey,
        })
        .returning();

      return newAlert;
    } catch (err) {
      console.error("Failed to persist alert in database:", err);
      return null;
    }
  }
}
