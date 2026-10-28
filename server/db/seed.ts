import bcrypt from "bcryptjs";
import path from "path";
import { fileURLToPath } from "url";
import { db, pool, checkDatabaseConnection } from "./index";
import {
  users,
  alerts,
  cases,
  malwareSamples,
  networkFlows,
  threatIntelCache,
  reports,
  logs,
} from "./schema";

export async function seedDatabase() {
  console.log("🌱 Verifying database connectivity...");
  const conn = await checkDatabaseConnection();
  if (!conn.ok) {
    throw new Error(`Cannot seed database: ${conn.error}`);
  }

  console.log("🌱 Seeding demonstration SOC records into PostgreSQL...");

  // Generate real bcrypt hash for demonstration password: "SocAnalyst2026!"
  const demoPasswordHash = await bcrypt.hash("SocAnalyst2026!", 10);

  // 1. Seed Users / Analysts
  const analystList = [
    {
      email: "avery.reed@soc.local",
      passwordHash: demoPasswordHash,
      fullName: "Avery Reed",
      role: "Senior Analyst",
      initials: "AR",
      status: "On shift",
      color: "#b7f960",
      activeCasesCount: 4,
    },
    {
      email: "mina.kapoor@soc.local",
      passwordHash: demoPasswordHash,
      fullName: "Mina Kapoor",
      role: "Threat Hunter",
      initials: "MK",
      status: "On shift",
      color: "#6fb6cc",
      activeCasesCount: 2,
    },
    {
      email: "darren.liu@soc.local",
      passwordHash: demoPasswordHash,
      fullName: "Darren Liu",
      role: "Incident Commander",
      initials: "DL",
      status: "On call",
      color: "#d9aa58",
      activeCasesCount: 1,
    },
    {
      email: "jordan.smith@soc.local",
      passwordHash: demoPasswordHash,
      fullName: "Jordan Smith",
      role: "Detection Engineer",
      initials: "JS",
      status: "Offline",
      color: "#74818a",
      activeCasesCount: 0,
    },
  ];

  for (const analyst of analystList) {
    await db
      .insert(users)
      .values(analyst)
      .onConflictDoUpdate({
        target: users.email,
        set: { passwordHash: demoPasswordHash },
      });
  }

  // 2. Seed Alerts
  const existingAlerts = await db.select().from(alerts).limit(1);
  let seededAlertId = 1;
  if (existingAlerts.length === 0) {
    const insertedAlerts = await db
      .insert(alerts)
      .values([
        {
          severity: "Critical",
          title: "Brute force activity detected",
          source: "185.220.101.45 · VPN Gateway",
          tactic: "TA0006",
          technique: "T1110",
          status: "Open",
          detectionMethod: "Rule-based threshold (100 failed logins in 2m)",
          confidence: "94.80",
          description:
            "[Demonstration Data] 100 consecutive authentication failures recorded against VPN gateway service from rotating exit node.",
          evidence: {
            source_ip: "185.220.101.45",
            target_service: "OpenVPN / LDAP Auth",
            failed_attempts: 100,
            interval_seconds: 120,
          },
        },
        {
          severity: "High",
          title: "Unusual outbound transfer",
          source: "WS-FIN-042 · 2.8 GB to unknown host",
          tactic: "TA0010",
          technique: "T1048",
          status: "In review",
          detectionMethod: "Network volume anomaly (Isolation Forest)",
          confidence: "91.20",
          description:
            "[Demonstration Data] Host WS-FIN-042 transferred 2.8 GB via HTTPS to unclassified external IP 103.192.12.44.",
          evidence: {
            source_host: "WS-FIN-042",
            dest_ip: "103.192.12.44",
            bytes_transferred: 3006477107,
          },
        },
        {
          severity: "Medium",
          title: "Suspicious PowerShell chain",
          source: "ENG-LT-018 · Endpoint telemetry",
          tactic: "TA0002",
          technique: "T1059.001",
          status: "Open",
          detectionMethod: "Endpoint behavioral detection",
          confidence: "87.50",
          description:
            "[Demonstration Data] Hidden window execution of powershell.exe invoking encoded download cradle.",
          evidence: {
            parent_process: "cmd.exe",
            child_process: "powershell.exe",
            command_line: "powershell -enc SQBFAFgA...",
          },
        },
        {
          severity: "Medium",
          title: "New domain matches phishing pattern",
          source: "mail-relay-03 · Threat intelligence",
          tactic: "TA0043",
          technique: "T1566",
          status: "Open",
          detectionMethod: "Threat Feed Match (OpenPhish)",
          confidence: "82.40",
          description:
            "[Demonstration Data] Inbound email containing domain account-verify-auth.net flagged as deceptive lookalike.",
          evidence: {
            domain: "account-verify-auth.net",
            sender: "no-reply@account-verify-auth.net",
          },
        },
        {
          severity: "Low",
          title: "Unusual authentication country",
          source: "guest-portal · Identity analytics",
          tactic: "TA0001",
          technique: "T1078",
          status: "Escalated",
          detectionMethod: "Geo-velocity rule",
          confidence: "74.00",
          description:
            "[Demonstration Data] Authentication session initiated from unexpected autonomous system within 30 minutes of domestic login.",
          evidence: {
            user: "jdoe@company.com",
            country: "RO",
            prior_country: "US",
          },
        },
      ])
      .returning();
    seededAlertId = insertedAlerts[0]?.id || 1;
  } else {
    seededAlertId = existingAlerts[0].id;
  }

  // 3. Seed Cases
  const existingCases = await db.select().from(cases).limit(1);
  if (existingCases.length === 0) {
    await db.insert(cases).values([
      {
        caseNumber: "INC-2026-0418",
        alertId: seededAlertId,
        title: "Brute force activity detected",
        severity: "Critical",
        status: "Active",
        assignedUserName: "Avery Reed",
        affectedAsset: "VPN Gateway",
        primaryEntity: "185.220.101.45",
        mitreTechnique: "T1110",
        aiConfidence: "94.80",
        summary:
          "[Demonstration Data] Detection correlated across identity, VPN, and conditional-access telemetry. Attacker conducted high-frequency password guessing.",
        timeline: [
          {
            time: "09:42:14 UTC",
            title: "100 authentication failures recorded from 185.220.101.45",
            status: "alert",
          },
          {
            time: "09:44:02 UTC",
            title: "Conditional access denied further authentication attempts",
            status: "contained",
          },
          {
            time: "09:45:18 UTC",
            title: "AI mapped pattern to Password Guessing (T1110)",
            status: "analysis",
          },
          {
            time: "09:48:30 UTC",
            title: "No user session or endpoint activity followed the attempt",
            status: "verified",
          },
        ],
        aiExplanation:
          "Multiple failed login attempts were detected from IP 185.220.101.45 within 2 minutes against the VPN Gateway. This behavior matches MITRE ATT&CK technique T1110 (Brute Force / Password Guessing). The automated rule contained the source via IP block. No credentials were confirmed compromised.",
        remediationSteps: [
          "Block source IP 185.220.101.45 at external perimeter firewall.",
          "Enforce MFA across all VPN user groups.",
          "Audit accounts targeted during the attack window.",
        ],
      },
      {
        caseNumber: "INC-2026-0414",
        title: "Unusual outbound transfer",
        severity: "High",
        status: "In review",
        assignedUserName: "Mina Kapoor",
        affectedAsset: "WS-FIN-042",
        primaryEntity: "103.192.12.44",
        mitreTechnique: "T1048",
        aiConfidence: "91.20",
        summary:
          "[Demonstration Data] 2.8 GB exfiltration spike observed from workstation in finance subnet to unclassified foreign hosting provider.",
        timeline: [
          { time: "08:15:00 UTC", title: "Outbound transfer commenced over TCP 443", status: "observed" },
          { time: "08:35:12 UTC", title: "Traffic anomaly flagged by volume baseline model", status: "alert" },
          { time: "08:40:00 UTC", title: "Host quarantined pending user interview", status: "contained" },
        ],
      },
      {
        caseNumber: "INC-2026-0410",
        title: "Suspicious PowerShell chain",
        severity: "Medium",
        status: "Active",
        assignedUserName: "Darren Liu",
        affectedAsset: "ENG-LT-018",
        primaryEntity: "powershell.exe",
        mitreTechnique: "T1059.001",
        aiConfidence: "87.50",
        summary:
          "[Demonstration Data] PowerShell script executed with encoded command flags originating from developer machine.",
        timeline: [
          { time: "14:10:02 UTC", title: "cmd.exe spawned powershell with base64 payload", status: "alert" },
          { time: "14:12:00 UTC", title: "Endpoint sensor blocked execution", status: "contained" },
        ],
      },
    ]);
  }

  // 4. Seed Malware Samples
  const existingMalware = await db.select().from(malwareSamples).limit(1);
  if (existingMalware.length === 0) {
    await db.insert(malwareSamples).values([
      {
        filename: "invoice_review.exe",
        sha256: "6ce73af38992e541a7d65b7194fef2287a2a0a20f92a188be2844883907a5eac",
        fileSize: 498176,
        fileType: "PE32 Executable",
        verdict: "Likely trojan",
        confidence: "98.20",
        modelUsed: "XGBoost Static Classifier",
        riskScore: "9.4",
        indicators: [
          "High entropy section (.rsrc 7.82)",
          "Process injection APIs imported",
          "C2 beacon URL pattern in strings",
          "Obfuscated import table",
        ],
        peFeatures: {
          sections: 5,
          subsystem: "WINDOWS_GUI",
          entry_point: "0x00401000",
          imports_count: 48,
        },
        status: "Completed",
      },
      {
        filename: "browser_update.dll",
        sha256: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        fileSize: 1245184,
        fileType: "PE32+ DLL",
        verdict: "Benign file",
        confidence: "92.70",
        modelUsed: "Random Forest Classifier",
        riskScore: "1.2",
        indicators: ["Valid digital signature", "Standard Microsoft runtime imports"],
        status: "Completed",
      },
      {
        filename: "delivery_docs.exe",
        sha256: "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00",
        fileSize: 782336,
        fileType: "PE32 Executable",
        verdict: "Ransomware",
        confidence: "96.10",
        modelUsed: "CNN Binary Model",
        riskScore: "9.8",
        indicators: [
          "Cryptographic API calls (CryptEncrypt)",
          "Shadow copy deletion commands",
          "Known ransomware ransom note artifact",
        ],
        status: "Quarantined",
      },
    ]);
  }

  // 5. Seed Network Flows
  const existingFlows = await db.select().from(networkFlows).limit(1);
  if (existingFlows.length === 0) {
    await db.insert(networkFlows).values([
      {
        sourceHost: "WS-FIN-042",
        sourceIp: "10.0.4.42",
        destinationHost: "ext-host-44.cloud",
        destinationIp: "103.192.12.44",
        protocol: "HTTPS",
        volumeBytes: 3006477107,
        volumeFormatted: "2.8 GB",
        packetCount: 194820,
        risk: "High",
        anomalyScore: "92.40",
        isAnomaly: true,
        tags: ["Data Exfiltration Risk", "Unclassified External Host"],
      },
      {
        sourceHost: "ENG-LT-018",
        sourceIp: "10.0.2.18",
        destinationHost: "vpn-gw-01.internal",
        destinationIp: "185.220.101.45",
        protocol: "VPN",
        volumeBytes: 1048576,
        volumeFormatted: "100 req",
        packetCount: 340,
        risk: "Critical",
        anomalyScore: "98.50",
        isAnomaly: true,
        tags: ["Brute Force Attacker", "Tor Exit Node"],
      },
      {
        sourceHost: "mail-relay-03",
        sourceIp: "10.0.1.3",
        destinationHost: "mx-pool.upstream.net",
        destinationIp: "89.45.67.129",
        protocol: "SMTP",
        volumeBytes: 48234496,
        volumeFormatted: "46 MB",
        packetCount: 1420,
        risk: "Medium",
        anomalyScore: "68.20",
        isAnomaly: false,
        tags: ["Inbound Bulk Mail"],
      },
      {
        sourceHost: "srv-app-01",
        sourceIp: "10.0.5.10",
        destinationHost: "dns-resolver.internal",
        destinationIp: "172.17.0.18",
        protocol: "DNS",
        volumeBytes: 4194304,
        volumeFormatted: "4.1k req",
        packetCount: 4120,
        risk: "Low",
        anomalyScore: "14.10",
        isAnomaly: false,
        tags: ["Baseline DNS Resolution"],
      },
    ]);
  }

  // 6. Seed Threat Intel Cache
  const existingIntel = await db.select().from(threatIntelCache).limit(1);
  if (existingIntel.length === 0) {
    await db.insert(threatIntelCache).values([
      {
        indicator: "185.220.101.45",
        indicatorType: "IP address",
        verdict: "Malicious",
        reputationScore: 92,
        detectionsCount: 18,
        totalEngines: 22,
        confidence: "High",
        associatedContext: [
          "Credential access infrastructure",
          "Observed in VPN attack chain",
          "Tor exit node / rotating proxy",
          "Linked to 3 internal security events",
        ],
        feedVerdicts: [
          { source: "VirusTotal", detail: "18 malicious detections", status: "Malicious" },
          { source: "AbuseIPDB", detail: "Confidence of abuse: 89%", status: "High risk" },
          { source: "AlienVault OTX", detail: "2 correlated pulses", status: "Observed" },
          { source: "Internal sightings", detail: "3 detections in 24 hours", status: "Active" },
        ],
      },
      {
        indicator: "account-verify-auth.net",
        indicatorType: "Domain",
        verdict: "Malicious",
        reputationScore: 88,
        detectionsCount: 14,
        totalEngines: 20,
        confidence: "High",
        associatedContext: ["Credential phishing landing page", "Lookalike domain targeting SSO portal"],
        feedVerdicts: [
          { source: "VirusTotal", detail: "14 security vendors flagged as phishing", status: "Malicious" },
          { source: "OpenPhish", detail: "Active phishing URL listed", status: "Active" },
        ],
      },
    ]);
  }

  // 7. Seed Reports
  const existingReports = await db.select().from(reports).limit(1);
  if (existingReports.length === 0) {
    await db.insert(reports).values([
      {
        reportCode: "INC-2026-0418",
        title: "Credential attack / VPN gateway",
        incidentName: "VPN Brute Force Incident Investigation",
        reportType: "Executive incident report",
        status: "Draft",
        contentJson: {
          executiveSummary:
            "[Demonstration Data] Automated credential attack against perimeter VPN gateway was contained before lateral movement.",
          affectedAsset: "VPN Gateway (vpn-gw-01)",
          mitreMapping: "T1110 - Brute Force",
        },
      },
      {
        reportCode: "INC-2026-0414",
        title: "Unusual outbound transfer",
        incidentName: "WS-FIN-042 Exfiltration Review",
        reportType: "Technical investigation report",
        status: "Review",
        contentJson: {
          executiveSummary:
            "[Demonstration Data] 2.8 GB flow trace from finance subnet to unclassified destination.",
        },
      },
      {
        reportCode: "WEEK-2026-16",
        title: "Weekly security posture",
        incidentName: "Week 16 SOC Operational Metrics & Posture",
        reportType: "Operational summary",
        status: "Published",
        contentJson: {
          coverageScore: 96,
          totalEvents: 1240000,
          totalAlerts: 12,
        },
      },
    ]);
  }

  // 8. Seed Sample Logs
  const existingLogs = await db.select().from(logs).limit(1);
  if (existingLogs.length === 0) {
    await db.insert(logs).values([
      {
        sourceType: "Windows Event Logs",
        sourceHost: "AD-DC-01",
        sourceIp: "185.220.101.45",
        eventId: "4625",
        logLevel: "WARN",
        rawLog:
          "Event 4625, Microsoft-Windows-Security-Auditing: An account failed to log on. Subject: User SID: S-1-0-0, Account Name: admin, Logon Type: 3, Failure Reason: Unknown user name or bad password.",
        parsedFields: {
          event_id: 4625,
          account_name: "admin",
          logon_type: 3,
          status_code: "0xC000006D",
        },
        isThreat: true,
        threatReason: "Repeated failed logon attempt (Event 4625)",
      },
      {
        sourceType: "Linux Syslogs",
        sourceHost: "web-app-02",
        sourceIp: "45.33.32.156",
        eventId: "sshd",
        logLevel: "INFO",
        rawLog: "sshd[28491]: Failed password for invalid user root from 45.33.32.156 port 54822 ssh2",
        parsedFields: {
          service: "sshd",
          user: "root",
          port: 54822,
        },
        isThreat: true,
        threatReason: "SSH authentication failure for root user",
      },
      {
        sourceType: "Firewall Logs",
        sourceHost: "FW-EDGE-01",
        sourceIp: "10.0.4.42",
        destinationIp: "103.192.12.44",
        eventId: "TRAFFIC_DROP",
        logLevel: "INFO",
        rawLog: "FW-EDGE-01: DENY TCP src=10.0.4.42:58392 dst=103.192.12.44:443 rule=OUTBOUND_EXFIL_MONITOR",
        parsedFields: {
          action: "DENY",
          rule: "OUTBOUND_EXFIL_MONITOR",
        },
        isThreat: false,
      },
    ]);
  }

  console.log("✅ Demonstration database seeding complete!");
}

// Allow direct execution: npx tsx server/db/seed.ts
const isMainModule = () => {
  if (!process.argv[1]) return false;
  try {
    return fileURLToPath(import.meta.url).toLowerCase() === path.resolve(process.argv[1]).toLowerCase();
  } catch {
    return false;
  }
};

if (isMainModule()) {
  seedDatabase()
    .then(() => {
      console.log("Seeding finished successfully.");
      process.exit(0);
    })
    .catch((err) => {
      console.error("Seeding error:", err);
      process.exit(1);
    });
}
