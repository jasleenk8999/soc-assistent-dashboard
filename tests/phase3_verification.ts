/**
 * Phase 3 Verification Test Suite
 * Fully tests Log Ingestion Pipeline, Normalization, Modular Detection Engine,
 * Alert Deduplication, Originating Log Linking, RBAC Enforcement, and Auditability.
 */

const BASE_URL = process.env.TEST_API_URL || "http://localhost:5001";

interface TestResult {
  name: string;
  passed: boolean;
  error?: string;
  details?: any;
}

const results: TestResult[] = [];

function assert(condition: boolean, message: string) {
  if (!condition) {
    throw new Error(message);
  }
}

async function runTest(name: string, fn: () => Promise<void>) {
  try {
    await fn();
    results.push({ name, passed: true });
    console.log(`  ✅ PASS: ${name}`);
  } catch (err: any) {
    results.push({ name, passed: false, error: err.message });
    console.error(`  ❌ FAIL: ${name}`);
    console.error(`     Error: ${err.message}`);
  }
}

async function loginUser(email: string, password = "SocAnalyst2026!") {
  const res = await fetch(`${BASE_URL}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(`Login failed for ${email}: ${res.status} ${JSON.stringify(data)}`);
  }
  return res.json();
}

async function main() {
  console.log("\n=======================================================");
  console.log("   AI CYBER SECURITY SOC ASSISTANT - PHASE 3 TEST SUITE");
  console.log("=======================================================\n");

  let detectionEngineerToken = "";
  let seniorAnalystToken = "";
  let generatedBruteForceAlertId = 0;
  let generatedSqliAlertId = 0;

  // 1. Health & Phase 1/2 Check
  await runTest("1. Health Endpoint & Database Connection", async () => {
    const res = await fetch(`${BASE_URL}/api/health`);
    assert(res.status === 200, `Expected 200, got ${res.status}`);
    const data = await res.json();
    assert(data.status === "healthy", "Expected status 'healthy'");
    assert(data.services?.database?.status === "connected", "Database is not connected");
  });

  // 2. Authentication & User Personas
  await runTest("2. Authentication & Persona Tokens", async () => {
    const engineer = await loginUser("jordan.smith@soc.local");
    const engToken = engineer.accessToken || engineer.tokens?.accessToken;
    assert(Boolean(engToken), "Missing accessToken for Detection Engineer");
    assert(engineer.user.role === "Detection Engineer", "Incorrect role");
    detectionEngineerToken = engToken;

    const analyst = await loginUser("avery.reed@soc.local");
    const anaToken = analyst.accessToken || analyst.tokens?.accessToken;
    assert(Boolean(anaToken), "Missing accessToken for Senior Analyst");
    seniorAnalystToken = anaToken;
  });

  // 3. RBAC Enforcement on Log Ingestion
  await runTest("3. RBAC: Deny Log Ingestion without ingest:logs permission", async () => {
    // Senior Analyst does not have ingest:logs
    const res = await fetch(`${BASE_URL}/api/logs`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${seniorAnalystToken}`,
      },
      body: JSON.stringify({
        sourceType: "syslog",
        rawLog: "Oct 28 10:00:00 soc-host test: unauthorized ingestion probe",
      }),
    });
    assert(res.status === 403, `Expected 403 Forbidden, got ${res.status}`);
    const data = await res.json();
    assert(data.error.includes("ingest:logs"), `Expected permission error message, got: ${data.error}`);
  });

  await runTest("4. RBAC: Reject unauthenticated ingestion requests", async () => {
    const res = await fetch(`${BASE_URL}/api/logs`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sourceType: "syslog",
        rawLog: "Oct 28 10:00:00 test unauthorized",
      }),
    });
    assert(res.status === 401, `Expected 401 Unauthorized, got ${res.status}`);
  });

  await runTest("5. RBAC: Allow Log Ingestion with Detection Engineer persona", async () => {
    const res = await fetch(`${BASE_URL}/api/logs`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${detectionEngineerToken}`,
      },
      body: JSON.stringify({
        sourceType: "syslog",
        rawLog: "Oct 28 10:00:00 soc-gateway sshd[1234]: Accepted publickey for admin from 10.0.0.5 port 54321 ssh2",
      }),
    });
    assert(res.status === 201, `Expected 201 Created, got ${res.status}`);
    const data = await res.json();
    assert(Boolean(data.log?.id), "Expected inserted log object with ID");
    assert(data.log.username === "admin", `Expected username 'admin', got '${data.log.username}'`);
    assert(data.log.sourceIp === "10.0.0.5", `Expected sourceIp '10.0.0.5', got '${data.log.sourceIp}'`);
  });

  // 4. Input Validation & Error Handling
  await runTest("6. Validation: Reject empty or malformed log payload", async () => {
    const res = await fetch(`${BASE_URL}/api/logs`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${detectionEngineerToken}`,
      },
      body: JSON.stringify({}),
    });
    assert(res.status === 400, `Expected 400 Bad Request, got ${res.status}`);
    const data = await res.json();
    assert(Boolean(data.error), "Expected validation error message");
  });

  // 5. Multi-Source Normalization Testing
  await runTest("7. Normalization: Windows Event Log (4625 Failed Logon)", async () => {
    const winEvent = {
      EventID: 4625,
      TimeCreated: new Date().toISOString(),
      Computer: "DC-PRIMARY.corp.local",
      TargetUserName: "svc_backup",
      IpAddress: "192.168.10.45",
      IpPort: 60234,
      LogonType: 3,
      FailureReason: "%%2313 - Unknown user name or bad password",
    };

    const res = await fetch(`${BASE_URL}/api/logs`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${detectionEngineerToken}`,
      },
      body: JSON.stringify({
        sourceType: "windows",
        rawLog: JSON.stringify(winEvent),
      }),
    });

    assert(res.status === 201, `Expected 201, got ${res.status}`);
    const data = await res.json();
    assert(data.log.sourceType.toLowerCase().includes("window"), "Source type mismatch");
    assert(data.log.username === "svc_backup", `Expected svc_backup, got ${data.log.username}`);
    assert(data.log.sourceIp === "192.168.10.45", `Expected 192.168.10.45, got ${data.log.sourceIp}`);
    assert(data.log.sourcePort === 60234, `Expected port 60234, got ${data.log.sourcePort}`);
    assert(data.log.eventCategory.toLowerCase().includes("auth"), `Expected auth category, got ${data.log.eventCategory}`);
  });

  await runTest("8. Normalization: Firewall Key-Value Log (iptables)", async () => {
    const rawFw = "Oct 28 10:14:02 gw-fw kernel: [IPTABLES-DROP] IN=eth0 OUT= SRC=203.0.113.88 DST=192.168.1.100 LEN=60 PROTO=TCP SPT=49210 DPT=445";
    const res = await fetch(`${BASE_URL}/api/logs`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${detectionEngineerToken}`,
      },
      body: JSON.stringify({
        sourceType: "firewall",
        rawLog: rawFw,
      }),
    });
    assert(res.status === 201, `Expected 201, got ${res.status}`);
    const data = await res.json();
    assert(data.log.sourceIp === "203.0.113.88", `Expected 203.0.113.88, got ${data.log.sourceIp}`);
    assert(data.log.destinationIp === "192.168.1.100", `Expected 192.168.1.100, got ${data.log.destinationIp}`);
    assert(data.log.sourcePort === 49210, `Expected 49210, got ${data.log.sourcePort}`);
    assert(data.log.destinationPort === 445, `Expected 445, got ${data.log.destinationPort}`);
    assert(data.log.protocol === "TCP", `Expected TCP, got ${data.log.protocol}`);
  });

  await runTest("9. Normalization: Suricata EVE JSON Log", async () => {
    const eveLog = {
      timestamp: new Date().toISOString(),
      event_type: "alert",
      src_ip: "198.51.100.12",
      src_port: 52144,
      dest_ip: "10.0.0.20",
      dest_port: 80,
      proto: "TCP",
      alert: {
        action: "allowed",
        signature_id: 2010935,
        signature: "ET WEB_SERVER Possible SQL Injection in URI",
        category: "Web Application Attack",
        severity: 1,
      },
    };
    const res = await fetch(`${BASE_URL}/api/logs`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${detectionEngineerToken}`,
      },
      body: JSON.stringify({
        sourceType: "ids",
        rawLog: JSON.stringify(eveLog),
      }),
    });
    assert(res.status === 201, `Expected 201, got ${res.status}`);
    const data = await res.json();
    assert(data.log.sourceIp === "198.51.100.12", "Source IP mismatch");
    assert(data.log.destinationIp === "10.0.0.20", "Dest IP mismatch");
    assert(data.log.destinationPort === 80, "Dest port mismatch");
    assert(data.log.protocol === "TCP", "Protocol mismatch");
  });

  // 6. SQL Injection Detection Engine
  await runTest("10. Detection Engine: SQL Injection (RULE-WEB-001)", async () => {
    const rawAccess = '203.0.113.77 - - [28/Oct/2026:10:20:00 +0000] "GET /api/v1/products?id=1%20UNION%20SELECT%20username,password_hash%20FROM%20users-- HTTP/1.1" 200 4521 "-" "sqlmap/1.7"';
    const res = await fetch(`${BASE_URL}/api/logs`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${detectionEngineerToken}`,
      },
      body: JSON.stringify({
        sourceType: "web",
        rawLog: rawAccess,
      }),
    });
    assert(res.status === 201, `Expected 201, got ${res.status}`);
    const data = await res.json();
    assert(data.alerts && data.alerts.length > 0, "No alerts generated for SQL injection");

    const sqliAlert = data.alerts.find((a: any) => a.ruleId === "RULE-WEB-001");
    assert(Boolean(sqliAlert), "RULE-WEB-001 not fired");
    assert(sqliAlert.severity === "High" || sqliAlert.severity === "Critical", `Expected High/Critical severity, got ${sqliAlert.severity}`);
    assert(sqliAlert.evidence && Boolean(sqliAlert.evidence.matchedPattern), "Evidence missing matchedPattern");
    assert(sqliAlert.suggestedNextSteps.length > 0, "Missing suggestedNextSteps");
    generatedSqliAlertId = sqliAlert.id;
  });

  // 7. Cross-Site Scripting (XSS) Detection Engine
  await runTest("11. Detection Engine: Cross-Site Scripting (RULE-WEB-002)", async () => {
    const rawAccess = '198.51.100.91 - - [28/Oct/2026:10:25:00 +0000] "POST /comment?msg=%3Cscript%3Ealert(document.cookie)%3C/script%3E HTTP/1.1" 200 1204 "-" "Mozilla/5.0"';
    const res = await fetch(`${BASE_URL}/api/logs`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${detectionEngineerToken}`,
      },
      body: JSON.stringify({
        sourceType: "web",
        rawLog: rawAccess,
      }),
    });
    assert(res.status === 201, `Expected 201, got ${res.status}`);
    const data = await res.json();
    const xssAlert = data.alerts.find((a: any) => a.ruleId === "RULE-WEB-002");
    assert(Boolean(xssAlert), "RULE-WEB-002 not fired");
    assert(xssAlert.severity === "Medium", `Expected Medium, got ${xssAlert.severity}`);
    assert(Boolean(xssAlert.evidence.matchedSnippet || xssAlert.evidence.matchedPattern), "Evidence missing matched snippet/pattern");
  });

  // 8. Brute-Force Correlation Detection (> 10 failures in 180s)
  await runTest("12. Detection Engine: Brute-Force Correlation (RULE-AUTH-001)", async () => {
    const attackerIp = "192.0.2.144";
    const batchLogs = [];
    const now = Date.now();

    for (let i = 0; i < 12; i++) {
      const ts = new Date(now - (12 - i) * 2000).toISOString();
      batchLogs.push({
        sourceType: "syslog",
        sourceIp: attackerIp,
        username: "victim_admin",
        eventCategory: "authentication",
        severity: "Medium",
        timestamp: ts,
        rawLog: `Oct 28 10:30:${String(i).padStart(2, "0")} srv-auth sshd[${5000 + i}]: Failed password for invalid user victim_admin from ${attackerIp} port ${40000 + i} ssh2`,
      });
    }

    const res = await fetch(`${BASE_URL}/api/logs/bulk`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${detectionEngineerToken}`,
      },
      body: JSON.stringify({ logs: batchLogs }),
    });

    assert(res.status === 201, `Expected 201, got ${res.status}`);
    const data = await res.json();
    assert(data.alerts && data.alerts.length > 0, "No alerts generated for brute force batch");

    const bfAlert = data.alerts.find((a: any) => a.ruleId === "RULE-AUTH-001");
    assert(Boolean(bfAlert), "RULE-AUTH-001 not fired");
    assert(bfAlert.severity === "High", `Expected High severity, got ${bfAlert.severity}`);
    assert(bfAlert.evidence.failureCount >= 11, `Expected >= 11 failures, got ${bfAlert.evidence.failureCount}`);
    assert(bfAlert.relatedLogIds.length >= 11, "Related log IDs missing in brute force alert");
    generatedBruteForceAlertId = bfAlert.id;
  });

  // 9. Port Scanning Correlation (> 15 ports in 120s)
  await runTest("13. Detection Engine: Port Scan Correlation (RULE-NET-001)", async () => {
    const scannerIp = "198.51.100.222";
    const batchLogs = [];
    const ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 8080];

    for (let i = 0; i < ports.length; i++) {
      const port = ports[i];
      const ts = new Date(Date.now() - (ports.length - i) * 1000).toISOString();
      batchLogs.push({
        sourceType: "firewall",
        sourceIp: scannerIp,
        destinationIp: "10.0.0.1",
        destinationPort: port,
        protocol: "TCP",
        timestamp: ts,
        rawLog: `firewall kernel: DROP IN=eth0 SRC=${scannerIp} DST=10.0.0.1 PROTO=TCP DPT=${port}`,
      });
    }

    const res = await fetch(`${BASE_URL}/api/logs/bulk`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${detectionEngineerToken}`,
      },
      body: JSON.stringify({ logs: batchLogs }),
    });

    assert(res.status === 201, `Expected 201, got ${res.status}`);
    const data = await res.json();
    const scanAlert = data.alerts.find((a: any) => a.ruleId === "RULE-NET-001");
    assert(Boolean(scanAlert), "RULE-NET-001 port scan not fired");
    const portCount = scanAlert.evidence.scannedPortsCount || scanAlert.evidence.distinctPortCount;
    assert(portCount >= 15, `Expected >= 15 distinct ports, got ${portCount}`);
  });

  // 10. Privilege Escalation Detection
  await runTest("14. Detection Engine: Suspicious Privilege Escalation (RULE-PRIV-001)", async () => {
    const rawPriv = "Oct 28 10:40:00 linux-sec sudo: webapp : user NOT in sudoers ; TTY=pts/1 ; PWD=/var/www ; USER=root ; COMMAND=/bin/sh";
    const res = await fetch(`${BASE_URL}/api/logs`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${detectionEngineerToken}`,
      },
      body: JSON.stringify({
        sourceType: "syslog",
        rawLog: rawPriv,
      }),
    });
    assert(res.status === 201, `Expected 201, got ${res.status}`);
    const data = await res.json();
    const privAlert = data.alerts.find((a: any) => a.ruleId === "RULE-PRIV-001");
    assert(Boolean(privAlert), "RULE-PRIV-001 not fired");
    assert(privAlert.severity === "High", `Expected High, got ${privAlert.severity}`);
  });

  // 11. Auth Success After Failures
  await runTest("15. Detection Engine: Auth Success After Repeated Failures (RULE-AUTH-002)", async () => {
    const testIp = "203.0.113.199";
    const userTarget = "finance_vp";

    // Ingest 4 failures
    for (let i = 0; i < 4; i++) {
      const ts = new Date(Date.now() - (6 - i) * 2000).toISOString();
      await fetch(`${BASE_URL}/api/logs`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${detectionEngineerToken}`,
        },
        body: JSON.stringify({
          sourceType: "syslog",
          sourceIp: testIp,
          username: userTarget,
          timestamp: ts,
          eventCategory: "Authentication Failure",
          rawLog: `srv sshd[${8000 + i}]: Failed password for ${userTarget} from ${testIp} port 4400${i} ssh2`,
        }),
      });
    }

    // Now ingest 1 success
    const res = await fetch(`${BASE_URL}/api/logs`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${detectionEngineerToken}`,
      },
      body: JSON.stringify({
        sourceType: "syslog",
        sourceIp: testIp,
        username: userTarget,
        timestamp: new Date().toISOString(),
        eventCategory: "Authentication Success",
        rawLog: `srv sshd[8010]: Accepted password for ${userTarget} from ${testIp} port 44010 ssh2`,
      }),
    });

    assert(res.status === 201, `Expected 201, got ${res.status}`);
    const data = await res.json();
    const breakthroughAlert = data.alerts.find((a: any) => a.ruleId === "RULE-AUTH-002");
    assert(Boolean(breakthroughAlert), "RULE-AUTH-002 auth success after failures not fired");
    assert(breakthroughAlert.severity === "High" || breakthroughAlert.severity === "Critical", `Expected High/Critical severity, got ${breakthroughAlert.severity}`);
  });

  // 12. Alert Deduplication
  await runTest("16. Deduplication: Suppress alert flooding within dedup window", async () => {
    // Re-trigger SQLi from the same source
    const rawAccess = '203.0.113.77 - - [28/Oct/2026:10:45:00 +0000] "GET /api/v1/search?q=1%20UNION%20SELECT%20null,null-- HTTP/1.1" 200 120 "-" "sqlmap"';
    const res = await fetch(`${BASE_URL}/api/logs`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${detectionEngineerToken}`,
      },
      body: JSON.stringify({
        sourceType: "web",
        rawLog: rawAccess,
      }),
    });

    assert(res.status === 201, `Expected 201, got ${res.status}`);
    const data = await res.json();
    const sqliAlert = data.alerts.find((a: any) => a.ruleId === "RULE-WEB-001");
    assert(Boolean(sqliAlert), "Expected sqli alert returned");
    // Verify alert ID matches previously generated alert ID (updated, not duplicated)
    assert(sqliAlert.id === generatedSqliAlertId, `Expected updated alert #${generatedSqliAlertId}, got new alert #${sqliAlert.id}`);
  });

  // 13. Originating Logs Auditability API
  await runTest("17. Auditability: Retrieve originating logs for alert (/api/alerts/:id/logs)", async () => {
    assert(generatedBruteForceAlertId > 0, "No brute force alert ID saved");
    const res = await fetch(`${BASE_URL}/api/alerts/${generatedBruteForceAlertId}/logs`, {
      headers: { Authorization: `Bearer ${detectionEngineerToken}` },
    });
    assert(res.status === 200, `Expected 200, got ${res.status}`);
    const data = await res.json();
    assert(data.alertId === generatedBruteForceAlertId, "Alert ID mismatch");
    assert(data.logsCount >= 11, `Expected >= 11 originating logs, got ${data.logsCount}`);
    assert(Array.isArray(data.logs) && data.logs.length >= 11, "Logs array missing or insufficient");
    assert(data.logs[0].rawLog.includes("Failed password"), "Log does not contain expected raw content");
  });

  // 14. File Upload Ingestion (multipart/form-data)
  await runTest("18. File Upload: Ingest multi-line log file (/api/logs/upload)", async () => {
    const fileContent = [
      'Oct 28 10:50:01 web01 nginx: 192.168.1.50 - - [28/Oct/2026:10:50:01 +0000] "GET /index.html HTTP/1.1" 200 1024',
      'Oct 28 10:50:02 web01 nginx: 192.168.1.51 - - [28/Oct/2026:10:50:02 +0000] "GET /about.html HTTP/1.1" 200 2048',
      'Oct 28 10:50:03 web01 nginx: 192.168.1.52 - - [28/Oct/2026:10:50:03 +0000] "GET /login HTTP/1.1" 200 512',
    ].join("\n");

    const formData = new FormData();
    const blob = new Blob([fileContent], { type: "text/plain" });
    formData.append("file", blob, "web_access.log");
    formData.append("sourceType", "web");

    const res = await fetch(`${BASE_URL}/api/logs/upload`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${detectionEngineerToken}`,
      },
      body: formData,
    });

    assert(res.status === 201, `Expected 201, got ${res.status}`);
    const data = await res.json();
    assert(data.totalParsed === 3, `Expected 3 parsed logs, got ${data.totalParsed}`);
    assert(data.insertedLogsCount === 3, `Expected 3 inserted logs, got ${data.insertedLogsCount}`);
  });

  // 15. Log Search, Filter & Pagination
  await runTest("19. Log Query API: Filtering, Search, and Aggregations (/api/logs)", async () => {
    const res = await fetch(`${BASE_URL}/api/logs?limit=10&sourceType=web&search=UNION`, {
      headers: { Authorization: `Bearer ${detectionEngineerToken}` },
    });
    assert(res.status === 200, `Expected 200, got ${res.status}`);
    const data = await res.json();
    assert(Array.isArray(data.items), "Items is not an array");
    assert(data.pagination && typeof data.pagination.total === "number", "Missing pagination metadata");
    assert(data.breakdown && typeof data.breakdown.total === "number", "Missing breakdown metadata");
    assert(data.items.length > 0, "Expected search results for UNION");
  });

  // 16. Alert Lifecycle Status Updates
  await runTest("20. Alert Lifecycle: Transition status through investigation workflow", async () => {
    const statuses = ["In review", "Escalated", "Resolved"];
    for (const st of statuses) {
      const res = await fetch(`${BASE_URL}/api/alerts/${generatedSqliAlertId}`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${seniorAnalystToken}`,
        },
        body: JSON.stringify({ status: st }),
      });
      assert(res.status === 200, `Expected 200, got ${res.status}`);
      const data = await res.json();
      assert(data.alert.status === st, `Expected status '${st}', got '${data.alert.status}'`);
    }
  });

  // Summary
  console.log("\n=======================================================");
  console.log("                  TEST RUN SUMMARY");
  console.log("=======================================================");
  const passed = results.filter((r) => r.passed).length;
  const failed = results.filter((r) => !r.passed).length;
  console.log(`Total tests: ${results.length}`);
  console.log(`Passed:      ${passed}`);
  console.log(`Failed:      ${failed}`);

  if (failed > 0) {
    console.log("\nFailed tests:");
    results
      .filter((r) => !r.passed)
      .forEach((r) => console.log(`  - ${r.name}: ${r.error}`));
    process.exit(1);
  } else {
    console.log("\n🎉 ALL PHASE 3 VERIFICATION TESTS PASSED SUCCESSFULLY!");
  }
}

main().catch((err) => {
  console.error("Unhandled error running tests:", err);
  process.exit(1);
});
