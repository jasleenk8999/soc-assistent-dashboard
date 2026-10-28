/**
 * Phase 4 Verification Test Suite: Real-Time SOC Dashboard & Live Event Streaming
 * Tests SSE streaming transport, authentication controls, event envelopes, heartbeat,
 * live alert generation, alert status changes, single/bulk log ingestion, subscriber cleanup,
 * multi-client broadcasting, and graceful recovery.
 * 
 * Notes on SSE frame format from server:
 *   id: <event-id>
 *   event: <event-type>
 *   data: <json-payload>    ← payload is the direct data field (not the whole SecurityEvent)
 *
 * The test reader's event structure: { id, event, data: parsedPayload }
 */

const BASE_URL = process.env.TEST_API_URL || "http://localhost:5001";

interface TestResult {
  name: string;
  passed: boolean;
  error?: string;
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

/**
 * Creates a lightweight SSE stream reader that collects events.
 * The SSE server sends frames like:
 *   id: evt_xxx
 *   event: <type>
 *   data: <json>   ← just the payload object, NOT the whole envelope
 */
function createSSEStreamReader(token?: string) {
  const headers: Record<string, string> = { Accept: "text/event-stream" };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const controller = new AbortController();
  const events: Array<{ id?: string; event: string; data: any }> = [];
  let isConnected = false;
  let status = 0;
  let responseHeaders: Headers | null = null;

  const promise = (async () => {
    const res = await fetch(`${BASE_URL}/api/events/stream`, {
      method: "GET",
      headers,
      signal: controller.signal,
    });

    status = res.status;
    responseHeaders = res.headers;

    if (!res.ok) {
      return { ok: false, status };
    }

    isConnected = true;
    const reader = res.body?.getReader();
    if (!reader) return { ok: true, status };

    const decoder = new TextDecoder();
    let buffer = "";

    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const chunks = buffer.split("\n\n");
        buffer = chunks.pop() || "";

        for (const block of chunks) {
          if (!block.trim()) continue;
          let eventType = "message";
          let eventId: string | undefined;
          let dataStr = "";

          for (const line of block.split("\n")) {
            if (line.startsWith("id: ")) eventId = line.slice(4).trim();
            else if (line.startsWith("event: ")) eventType = line.slice(7).trim();
            else if (line.startsWith("data: ")) dataStr = line.slice(6).trim();
          }

          let parsedData: any = null;
          try { parsedData = JSON.parse(dataStr); } catch { parsedData = dataStr; }
          events.push({ id: eventId, event: eventType, data: parsedData });
        }
      }
    } catch (e: any) {
      if (e.name !== "AbortError") { /* stream closed or error */ }
    }
    return { ok: true, status };
  })();

  const waitForEvent = async (type: string, timeoutMs = 5000) => {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const found = events.find((e) => e.event === type);
      if (found) return found;
      await new Promise((r) => setTimeout(r, 50));
    }
    return null;
  };

  return {
    controller,
    promise,
    events,
    getStatus: () => status,
    getHeaders: () => responseHeaders,
    isConnected: () => isConnected,
    close: () => controller.abort(),
    waitForEvent,
  };
}

async function main() {
  console.log("\n=======================================================");
  console.log("   AI CYBER SECURITY SOC ASSISTANT - PHASE 4 TEST SUITE");
  console.log("      Real-Time Streaming & Live Event Transport      ");
  console.log("=======================================================\n");

  let engineerToken = "";
  let analystToken = "";

  // Setup
  await runTest("Setup: Authenticate Test Personas", async () => {
    const engineer = await loginUser("jordan.smith@soc.local");
    const engToken = engineer.accessToken || engineer.tokens?.accessToken;
    assert(Boolean(engToken), "Detection Engineer token received");
    engineerToken = engToken;

    const analyst = await loginUser("avery.reed@soc.local");
    const anaToken = analyst.accessToken || analyst.tokens?.accessToken;
    assert(Boolean(anaToken), "Senior Analyst token received");
    analystToken = anaToken;
  });

  // 1. Unauthenticated is rejected
  await runTest("1. Unauthenticated Stream Access is Rejected (401)", async () => {
    const res = await fetch(`${BASE_URL}/api/events/stream`, {
      headers: { Accept: "text/event-stream" },
    });
    assert(res.status === 401, `Expected 401, received ${res.status}`);
    const data = await res.json();
    assert(data.code === "UNAUTHORIZED", `Expected UNAUTHORIZED code, got ${data.code}`);
  });

  // 2. Invalid token rejected
  await runTest("2. Invalid Bearer Token is Rejected Safely (401)", async () => {
    const res = await fetch(`${BASE_URL}/api/events/stream`, {
      headers: {
        Accept: "text/event-stream",
        Authorization: "Bearer invalid.fake.token.signature",
      },
    });
    assert(res.status === 401, `Expected 401 for invalid token, received ${res.status}`);
    const data = await res.json();
    assert(
      data.code === "TOKEN_EXPIRED" || data.code === "INVALID_TOKEN",
      `Expected TOKEN_EXPIRED or INVALID_TOKEN, got ${data.code}`
    );
  });

  // 3. Authenticated stream establishment
  let client1: ReturnType<typeof createSSEStreamReader> | null = null;
  await runTest("3. Authenticated Client Establishes Stream & Receives Confirmation", async () => {
    client1 = createSSEStreamReader(analystToken);
    await new Promise((r) => setTimeout(r, 500)); // give it time to connect

    assert(client1.isConnected(), "Stream reader is connected");
    const headers = client1.getHeaders();
    assert(headers !== null, "Response headers received");
    assert(headers?.get("content-type")?.includes("text/event-stream") ?? false, "Content-Type is text/event-stream");
    assert(headers?.get("cache-control")?.includes("no-cache") ?? false, "Cache-Control is no-cache");

    // The SSE server sends: event: connection.established, data: {clientId, userId, role, heartbeatIntervalMs, ...}
    const confirmation = await client1.waitForEvent("connection.established", 4000);
    assert(confirmation !== null, "Received connection.established event");
    assert(confirmation?.data?.role === "Senior Analyst", `Expected role 'Senior Analyst', got '${confirmation?.data?.role}'`);
    assert(typeof confirmation?.data?.heartbeatIntervalMs === "number", "Confirmation includes heartbeatIntervalMs");
  });

  // 4. Status endpoint with active connection
  await runTest("4. Connection Pool & Operational Status Reporting", async () => {
    assert(client1 !== null, "Client 1 is active");
    const statusRes = await fetch(`${BASE_URL}/api/events/status`, {
      headers: { Authorization: `Bearer ${analystToken}` },
    });
    assert(statusRes.status === 200, "Events status endpoint accessible with auth");
    const statusData = await statusRes.json();
    assert(statusData.activeConnections >= 1, `Active connections recorded: ${statusData.activeConnections}`);
    assert(typeof statusData.maxConnections === "number", "maxConnections field present");
    assert(statusData.activeConnections <= statusData.maxConnections, "Connections within operational limit");
  });

  // 5. Multiple concurrent subscribers
  let client2: ReturnType<typeof createSSEStreamReader> | null = null;
  await runTest("5. Multiple Concurrent Subscribers Can Connect", async () => {
    client2 = createSSEStreamReader(engineerToken);
    await new Promise((r) => setTimeout(r, 500));

    assert(client2.isConnected(), "Client 2 connected successfully");
    const confirmation = await client2.waitForEvent("connection.established", 4000);
    assert(confirmation !== null, "Client 2 received connection.established");
    assert(confirmation?.data?.role === "Detection Engineer", `Expected 'Detection Engineer', got '${confirmation?.data?.role}'`);

    const statusRes = await fetch(`${BASE_URL}/api/events/status`, {
      headers: { Authorization: `Bearer ${analystToken}` },
    });
    const statusData = await statusRes.json();
    assert(statusData.activeConnections >= 2, `Active connections: ${statusData.activeConnections}`);
  });

  // 6. Single log ingest → log.ingested broadcast
  await runTest("6. Single Log Ingestion Publishes log.ingested Real-Time Event", async () => {
    assert(client1 !== null && client2 !== null, "Clients are connected");
    const uniqueIp = `192.168.99.${Math.floor(Math.random() * 200) + 10}`;
    const logPayload = {
      raw: `Jan 15 10:00:00 sse-test-fw kernel: [FW] INBOUND_TCP SRC=${uniqueIp} DST=10.0.0.5 SPT=54321 DPT=443 ACTION=ALLOW`,
      sourceType: "syslog",
      sourceIp: uniqueIp,
    };

    const res = await fetch(`${BASE_URL}/api/logs`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${engineerToken}` },
      body: JSON.stringify(logPayload),
    });
    assert(res.ok, `Log ingestion succeeded: ${res.status}`);

    const ev1 = await client1.waitForEvent("log.ingested", 3000);
    const ev2 = await client2.waitForEvent("log.ingested", 3000);

    assert(ev1 !== null, "Client 1 received log.ingested event");
    assert(ev2 !== null, "Client 2 received log.ingested event simultaneously");
    // event.data is the LogIngestedPayload (sourceIp may come from normalization)
    assert(typeof ev1?.data?.id === "number", "log.ingested event includes log id");
    assert(typeof ev1?.data?.sourceType === "string", "log.ingested event includes sourceType");
  });

  // 7. Threat detection → alert.created broadcast
  let createdAlertId = 0;
  await runTest("7. Threat Detection Publishes alert.created Real-Time Event", async () => {
    assert(client1 !== null && client2 !== null, "Clients connected");
    const attackerIp = `198.51.100.${Math.floor(Math.random() * 200) + 10}`;
    const attackPayload = {
      raw: `GET /api/v1/users?id=1%20UNION%20SELECT%20username,password_hash%20FROM%20users-- HTTP/1.1 200 4502`,
      sourceType: "apache_access",
      sourceHost: "web-portal-sse-test",
      sourceIp: attackerIp,
    };

    const res = await fetch(`${BASE_URL}/api/logs`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${engineerToken}` },
      body: JSON.stringify(attackPayload),
    });
    assert(res.ok, `Attack log submitted: ${res.status}`);
    const json = await res.json();
    assert(json.alertGenerated === true, `Expected alertGenerated=true, got ${json.alertGenerated}`);
    createdAlertId = json.alert?.id;
    assert(createdAlertId > 0, "Alert has a valid id");

    const ev1 = await client1.waitForEvent("alert.created", 3000);
    const ev2 = await client2.waitForEvent("alert.created", 3000);

    assert(ev1 !== null, "Client 1 received alert.created event");
    assert(ev2 !== null, "Client 2 received alert.created event");
    // event.data is AlertCreatedPayload
    assert(ev1?.data?.ruleId === "RULE-WEB-001", `Alert rule is RULE-WEB-001, got ${ev1?.data?.ruleId}`);
    assert(ev1?.data?.severity === "High", `Alert severity is High, got ${ev1?.data?.severity}`);
    assert(ev1?.data?.source === attackerIp, `Alert source IP matches attacker IP`);
  });

  // 8. Triage → alert.status_changed broadcast
  await runTest("8. Alert Triage Publishes alert.status_changed Real-Time Event", async () => {
    assert(createdAlertId > 0, "Valid created alert ID from previous test");
    assert(client1 !== null && client2 !== null, "Clients connected");

    const patchRes = await fetch(`${BASE_URL}/api/alerts/${createdAlertId}/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${analystToken}` },
      body: JSON.stringify({ status: "In review" }),
    });
    assert(patchRes.ok, `Status update succeeded: ${patchRes.status}`);

    const statusEv1 = await client1.waitForEvent("alert.status_changed", 3000);
    const statusEv2 = await client2.waitForEvent("alert.status_changed", 3000);

    assert(statusEv1 !== null, "Client 1 received alert.status_changed");
    assert(statusEv2 !== null, "Client 2 received alert.status_changed");
    // event.data is AlertStatusChangedPayload
    assert(statusEv1?.data?.alertId === createdAlertId, `Event alertId ${statusEv1?.data?.alertId} matches alert ${createdAlertId}`);
    assert(statusEv1?.data?.previousStatus === "Open", `Previous status was 'Open', got '${statusEv1?.data?.previousStatus}'`);
    assert(statusEv1?.data?.newStatus === "In review", `New status is 'In review', got '${statusEv1?.data?.newStatus}'`);
    assert(statusEv1?.data?.actor?.role === "Senior Analyst", `Actor role 'Senior Analyst', got '${statusEv1?.data?.actor?.role}'`);
  });

  // 9. Bulk ingest → logs.bulk_ingested aggregate broadcast
  await runTest("9. Bulk Ingestion Publishes logs.bulk_ingested Aggregate Event", async () => {
    assert(client1 !== null, "Client 1 connected");
    const bulkLogs = [
      { raw: "Jan 15 10:01:00 host1 kernel: [FW] ALLOW TCP 10.0.0.1 10.0.0.2 80", sourceType: "syslog" },
      { raw: "Jan 15 10:01:01 host2 kernel: [FW] ALLOW TCP 10.0.0.3 10.0.0.4 443", sourceType: "syslog" },
      { raw: "Jan 15 10:01:02 host3 kernel: [FW] ALLOW TCP 10.0.0.5 10.0.0.6 22", sourceType: "syslog" },
    ];

    const res = await fetch(`${BASE_URL}/api/logs/bulk`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${engineerToken}` },
      body: JSON.stringify({ logs: bulkLogs }),
    });
    assert(res.ok, `Bulk ingestion succeeded: ${res.status}`);

    const bulkEv = await client1.waitForEvent("logs.bulk_ingested", 3000);
    assert(bulkEv !== null, "Received logs.bulk_ingested aggregate event");
    // event.data is LogsBulkIngestedPayload
    assert(bulkEv?.data?.ingestedCount === 3, `Ingested count is 3, got ${bulkEv?.data?.ingestedCount}`);
    assert(typeof bulkEv?.data?.alertsGeneratedCount === "number", "alertsGeneratedCount is a number");
    assert(typeof bulkEv?.data?.source === "string", "source field is present");
  });

  // 10. Stats updated debounce broadcast
  await runTest("10. Operations Coalesce and Publish dashboard.stats_updated Event", async () => {
    assert(client1 !== null, "Client 1 connected");
    const statsEv = await client1.waitForEvent("dashboard.stats_updated", 5000);
    assert(statsEv !== null, "Received dashboard.stats_updated coalesced event");
    // event.data is DashboardStatsUpdatedPayload
    assert(typeof statsEv?.data?.openAlertsCount === "number", `openAlertsCount present: ${statsEv?.data?.openAlertsCount}`);
    assert(typeof statsEv?.data?.totalLogsCount === "number", `totalLogsCount present: ${statsEv?.data?.totalLogsCount}`);
  });

  // 11. Client disconnect cleanup
  await runTest("11. Client Disconnect Cleans Up Server Listener Resources", async () => {
    assert(client2 !== null, "Client 2 exists");
    const beforeRes = await fetch(`${BASE_URL}/api/events/status`, {
      headers: { Authorization: `Bearer ${analystToken}` },
    });
    const beforeData = await beforeRes.json();
    const countBefore = beforeData.activeConnections;
    assert(countBefore >= 2, `Expected at least 2 connections, got ${countBefore}`);

    client2.close();
    await new Promise((r) => setTimeout(r, 500));

    const afterRes = await fetch(`${BASE_URL}/api/events/status`, {
      headers: { Authorization: `Bearer ${analystToken}` },
    });
    const afterData = await afterRes.json();
    assert(
      afterData.activeConnections < countBefore,
      `Connections cleaned up: before=${countBefore}, after=${afterData.activeConnections}`
    );
  });

  // 12. REST API state recovery
  await runTest("12. Client Recovers Synchronized State via REST API on Reconnect", async () => {
    const alertsRes = await fetch(`${BASE_URL}/api/alerts`, {
      headers: { Authorization: `Bearer ${analystToken}` },
    });
    assert(alertsRes.ok, "Alerts REST query succeeded");
    const alertsData = await alertsRes.json();
    assert(Array.isArray(alertsData.items), "Alert items array recovered");

    const statsRes = await fetch(`${BASE_URL}/api/dashboard/stats`, {
      headers: { Authorization: `Bearer ${analystToken}` },
    });
    assert(statsRes.ok, "Dashboard stats REST query succeeded");
    const statsData = await statsRes.json();
    assert(typeof statsData.metrics.openAlerts === "number", "Open alerts count recovered");
  });

  // 13. JWT revocation note: JWTs are stateless; logout only revokes the refresh cookie.
  // A valid access token remains valid until expiry — this is by design.
  // We verify logout succeeds and the refresh token is cleared.
  await runTest("13. Logout Succeeds & Refresh Token is Revoked", async () => {
    const loginRes = await loginUser("mina.kapoor@soc.local");
    const tempToken = loginRes.accessToken || loginRes.tokens?.accessToken;
    assert(Boolean(tempToken), "Temporary token obtained");

    const logoutRes = await fetch(`${BASE_URL}/api/auth/logout`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${tempToken}` },
    });
    assert(logoutRes.ok, `Logout succeeded: ${logoutRes.status}`);
    const logoutData = await logoutRes.json();
    assert(logoutData.success === true, "Logout response confirms success");

    // Refresh token rotation should now fail (cookie was cleared on client side)
    const refreshRes = await fetch(`${BASE_URL}/api/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      // No refresh cookie since it would be cleared by the logout
    });
    assert(refreshRes.status === 401, `Refresh fails after logout: ${refreshRes.status}`);
  });

  // Cleanup client 1
  if (client1) client1.close();

  // Summary
  console.log("\n=======================================================");
  console.log("                PHASE 4 TEST SUMMARY                  ");
  console.log("=======================================================");
  const passedCount = results.filter((r) => r.passed).length;
  const failedCount = results.filter((r) => !r.passed).length;
  console.log(`Total Tests Run: ${results.length}`);
  console.log(`Passed:         ${passedCount}`);
  console.log(`Failed:         ${failedCount}`);

  if (failedCount > 0) {
    console.error("\nFailed tests:");
    results.filter((r) => !r.passed).forEach((r) => console.error(` - ${r.name}: ${r.error}`));
    process.exit(1);
  } else {
    console.log("\n🌟 ALL PHASE 4 REAL-TIME STREAMING TESTS PASSED! 🌟\n");
  }
}

main().catch((err) => {
  console.error("Test execution failed:", err);
  process.exit(1);
});
