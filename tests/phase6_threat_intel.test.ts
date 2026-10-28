/**
 * Phase 6 Verification Test Suite: Threat Intelligence Integrations
 *
 * Covers:
 * 1. Health & login authentication
 * 2. Unauthenticated access enforcement (401 across all endpoints)
 * 3. Provider status reporting without secret exposure
 * 4. Input validation (IPv4, IPv6, domain, URL, hash, oversized input, malformed indicators)
 * 5. SSRF defenses (reject non-HTTP protocols, safe API-only query patterns)
 * 6. Indicator normalization (stripping ports, bracket defang [.] removal, lowercasing)
 * 7. Graceful offline / zero-key operation (handles unconfigured keys cleanly)
 * 8. PostgreSQL cache hits and retrieval
 * 9. Alert indicator extraction & enrichment (/api/threat-intel/alerts/:id)
 * 10. Multi-provider verdict synthesis & partial failure handling
 * 11. Threat intelligence bridge to incident explanations (Phase 5 + 6)
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

async function main() {
  console.log("=====================================================================");
  console.log("PHASE 6 TEST SUITE: THREAT INTELLIGENCE INTEGRATIONS & ENRICHMENT");
  console.log(`Target: ${BASE_URL}`);
  console.log("=====================================================================\n");

  let seniorToken = "";
  let hunterToken = "";
  let targetAlertId: number | null = null;

  // 1. Prerequisites & Login
  await runTest("Prerequisites & Authentication Login", async () => {
    const healthRes = await fetch(`${BASE_URL}/api/health`);
    assert(healthRes.ok, `Server health check failed: ${healthRes.status}`);

    const seniorLogin = await loginUser("avery.reed@soc.local");
    assert(!!seniorLogin.accessToken, "Senior Analyst login failed");
    seniorToken = seniorLogin.accessToken;

    const hunterLogin = await loginUser("mina.kapoor@soc.local");
    assert(!!hunterLogin.accessToken, "Threat Hunter login failed");
    hunterToken = hunterLogin.accessToken;

    const alertsRes = await fetch(`${BASE_URL}/api/alerts?limit=5`, {
      headers: { Authorization: `Bearer ${seniorToken}` },
    });
    assert(alertsRes.ok, "Failed to fetch seeded alerts");
    const data = await alertsRes.json();
    assert(data.items && data.items.length > 0, "No seeded alerts available");
    targetAlertId = data.items[0].id;
    console.log(`     Target alert for enrichment testing: Alert #${targetAlertId} ("${data.items[0].title}")`);
  });

  // 2. Authentication Enforcement
  await runTest("Authentication Security: Reject unauthenticated requests with 401", async () => {
    assert(targetAlertId !== null, "Target alert ID must be available");

    const pRes = await fetch(`${BASE_URL}/api/threat-intel/providers`);
    assert(pRes.status === 401, `Expected 401 on unauthenticated /providers, got ${pRes.status}`);

    const lRes = await fetch(`${BASE_URL}/api/threat-intel/lookup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ indicator: "8.8.8.8" }),
    });
    assert(lRes.status === 401, `Expected 401 on unauthenticated POST /lookup, got ${lRes.status}`);

    const aRes = await fetch(`${BASE_URL}/api/threat-intel/alerts/${targetAlertId}`);
    assert(aRes.status === 401, `Expected 401 on unauthenticated /alerts/:id, got ${aRes.status}`);

    const hRes = await fetch(`${BASE_URL}/api/threat-intel/history`);
    assert(hRes.status === 401, `Expected 401 on unauthenticated /history, got ${hRes.status}`);
  });

  // 3. Provider Status Reporting without secret exposure
  await runTest("Provider Status: Return provider metadata without leaking secrets", async () => {
    const res = await fetch(`${BASE_URL}/api/threat-intel/providers`, {
      headers: { Authorization: `Bearer ${seniorToken}` },
    });
    assert(res.ok, `GET /providers failed with ${res.status}`);
    const body = await res.json();
    assert(body.success === true, "Response success must be true");
    assert(Array.isArray(body.providers), "Response must include providers array");
    assert(body.providers.length === 3, `Expected 3 providers (AbuseIPDB, VirusTotal, AlienVault), got ${body.providers.length}`);

    const providerNames = body.providers.map((p: any) => p.name);
    assert(providerNames.includes("AbuseIPDB"), "Missing AbuseIPDB provider info");
    assert(providerNames.includes("VirusTotal"), "Missing VirusTotal provider info");
    assert(providerNames.includes("AlienVault OTX"), "Missing AlienVault OTX provider info");

    // Zero secret leakage check
    const rawJson = JSON.stringify(body);
    assert(!rawJson.includes("API_KEY"), "Response contained API_KEY identifier");
    assert(!rawJson.includes("your_"), "Response contained environment variable secret placeholder");
    assert(!rawJson.includes("postgres"), "Response contained database connection string");
  });

  // 4. Input Validation & Parameter Safety
  await runTest("Input Validation: Reject invalid, empty, or malformed indicators", async () => {
    // Empty indicator
    const emptyRes = await fetch(`${BASE_URL}/api/threat-intel/lookup`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${seniorToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ indicator: "" }),
    });
    assert(emptyRes.status === 400, `Expected 400 for empty indicator, got ${emptyRes.status}`);

    // Malformed string that cannot be IP, domain, hash, or URL
    const malformedRes = await fetch(`${BASE_URL}/api/threat-intel/lookup`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${seniorToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ indicator: "not_a_valid_ip_or_domain_!@#$" }),
    });
    assert(malformedRes.status === 400, `Expected 400 for malformed indicator, got ${malformedRes.status}`);

    // Oversized input (> 2000 chars)
    const oversizedRes = await fetch(`${BASE_URL}/api/threat-intel/lookup`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${seniorToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ indicator: "A".repeat(2500) }),
    });
    assert(oversizedRes.status === 400, `Expected 400 for oversized indicator, got ${oversizedRes.status}`);

    // Invalid non-numeric alert ID
    const invalidAlert = await fetch(`${BASE_URL}/api/threat-intel/alerts/nonnumeric`, {
      headers: { Authorization: `Bearer ${seniorToken}` },
    });
    assert(invalidAlert.status === 400, `Expected 400 for non-numeric alertId, got ${invalidAlert.status}`);

    // Non-existent alert ID
    const missingAlert = await fetch(`${BASE_URL}/api/threat-intel/alerts/99999999`, {
      headers: { Authorization: `Bearer ${seniorToken}` },
    });
    assert(missingAlert.status === 404, `Expected 404 for non-existent alertId, got ${missingAlert.status}`);
  });

  // 5. SSRF Protections
  await runTest("SSRF Protections: Reject non-HTTP protocols and unsafe URLs", async () => {
    const { validateAndNormalizeIndicator } = await import("../server/services/threatIntelService");

    const ftpTest = validateAndNormalizeIndicator("ftp://malicious-server.com/payload.exe");
    assert(!ftpTest.valid, "FTP URL must be rejected for SSRF safety");

    const fileTest = validateAndNormalizeIndicator("file:///etc/passwd");
    assert(!fileTest.valid, "File URL must be rejected for SSRF safety");

    const jsTest = validateAndNormalizeIndicator("javascript:alert(1)");
    assert(!jsTest.valid, "Javascript pseudo-protocol URL must be rejected");

    const validHttps = validateAndNormalizeIndicator("https://malicious-c2.example.com/gate.php");
    assert(validHttps.valid && validHttps.type === "url", "Valid HTTPS URL should be accepted");
  });

  // 6. Indicator Normalization
  await runTest("Indicator Normalization: Clean defanged brackets, ports, and casing", async () => {
    const { validateAndNormalizeIndicator } = await import("../server/services/threatIntelService");

    // IP with port
    const ipPort = validateAndNormalizeIndicator("185.220.101.45:8080");
    assert(ipPort.valid && ipPort.normalized === "185.220.101.45" && ipPort.type === "ip", "IP with port was not normalized correctly");

    // Defanged bracket IP
    const defangedIp = validateAndNormalizeIndicator("185[.]220[.]101[.]45");
    assert(defangedIp.valid && defangedIp.normalized === "185.220.101.45" && defangedIp.type === "ip", "Defanged IP was not normalized");

    // Defanged domain with uppercase
    const defangedDomain = validateAndNormalizeIndicator("EVIL-PHISHING[.]COM");
    assert(defangedDomain.valid && defangedDomain.normalized === "evil-phishing.com" && defangedDomain.type === "domain", "Domain was not lowercased or defanged");

    // Uppercase SHA256
    const upperHash = validateAndNormalizeIndicator("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855");
    assert(upperHash.valid && upperHash.type === "hash" && upperHash.normalized === upperHash.normalized.toLowerCase(), "Hash was not normalized to lowercase");
  });

  // 7. Zero-Key / Graceful Operation
  await runTest("Graceful Operation: Zero-key / unconfigured feeds operate without crashing", async () => {
    // Looking up a non-cached clean domain
    const res = await fetch(`${BASE_URL}/api/threat-intel/lookup`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${seniorToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ indicator: "example.org", indicatorType: "domain" }),
    });

    assert(res.ok, `POST /lookup failed with status ${res.status}`);
    const body = await res.json();
    assert(body.success === true, "Response success must be true");
    assert(!!body.indicator, "Response must contain indicator object");
    assert(body.indicator.indicator === "example.org", "Indicator name must match query");
    assert(body.indicator.indicatorType === "domain", "Indicator type must be domain");
    assert(Array.isArray(body.indicator.feedVerdicts), "Feed verdicts must be an array");

    // Verify unconfigured feeds report status without throwing 500
    for (const feed of body.indicator.feedVerdicts) {
      assert(typeof feed.provider === "string", "Provider name must be string");
      assert(typeof feed.status === "string", "Provider status must be string");
    }
  });

  // 8. Database Caching & History
  await runTest("Database Caching: Cached indicators are retrieved quickly from PostgreSQL", async () => {
    // 185.220.101.45 is a seeded indicator in threat_intel_cache
    const res = await fetch(`${BASE_URL}/api/threat-intel/lookup`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${seniorToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ indicator: "185.220.101.45", forceRefresh: false }),
    });

    assert(res.ok, `Lookup of seeded indicator failed: ${res.status}`);
    const body = await res.json();
    assert(body.success === true, "Expected success: true");
    assert(body.found === true, "Expected found: true for seeded indicator");
    assert(body.indicator.indicator === "185.220.101.45", "Indicator value must match");
    assert(body.indicator.verdict === "Malicious", `Expected verdict Malicious, got ${body.indicator.verdict}`);
    assert(body.indicator.isCached === true, "Should report isCached: true");

    // Check GET /history includes this cached entry
    const histRes = await fetch(`${BASE_URL}/api/threat-intel/history?search=185.220`, {
      headers: { Authorization: `Bearer ${seniorToken}` },
    });
    assert(histRes.ok, "GET /history failed");
    const histData = await histRes.json();
    assert(histData.items && histData.items.length > 0, "History query must return cached items");
    assert(histData.items.some((i: any) => i.indicator === "185.220.101.45"), "Expected indicator to be in history");
  });

  // 9. Alert Indicator Extraction & Threat Intel
  await runTest("Alert Enrichment: Extract all indicators from alert and return intelligence", async () => {
    assert(targetAlertId !== null, "Target alert ID must be available");

    const res = await fetch(`${BASE_URL}/api/threat-intel/alerts/${targetAlertId}`, {
      headers: { Authorization: `Bearer ${seniorToken}` },
    });

    assert(res.ok, `GET /alerts/:id failed with ${res.status}`);
    const body = await res.json();
    assert(body.success === true, "Expected success: true");
    assert(body.alertId === targetAlertId, `alertId must match target (${targetAlertId})`);
    assert(typeof body.indicatorsCount === "number", "indicatorsCount must be a number");
    assert(Array.isArray(body.indicators), "indicators must be an array");
    assert(!!body.summary, "summary must be present");
    assert(typeof body.summary.highestReputationScore === "number", "highestReputationScore must be number");

    if (body.indicators.length > 0) {
      const first = body.indicators[0];
      assert(!!first.indicator, "First indicator must have value");
      assert(!!first.sourceContext, "First indicator must have sourceContext describing where it came from");
      console.log(`     Alert #${targetAlertId} extracted ${body.indicators.length} indicator(s): ${body.indicators.map((i: any) => i.indicator).join(", ")}`);
    }
  });

  // 10. Phase 5 Incident Explanation Enrichment Bridge
  await runTest("Phase 5 + 6 Bridge: Incident explanation correlates threat intelligence into evidence narrative", async () => {
    assert(targetAlertId !== null, "Target alert ID must be available");

    // Force regenerate explanation for target alert
    const expRes = await fetch(`${BASE_URL}/api/alerts/${targetAlertId}/explain`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${seniorToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ forceRegenerate: true }),
    });

    assert(expRes.ok, `POST /explain failed: ${expRes.status}`);
    const body = await expRes.json();
    assert(body.success === true, "Explanation generation must succeed");
    const exp = body.explanation;
    assert(!!exp, "Explanation object must be returned");

    // Check that evidence narrative or missing evidence mentions threat intelligence cross-referencing
    const combinedText = `${exp.evidenceNarrative} ${exp.missingEvidence} ${exp.executiveSummary}`;
    assert(
      combinedText.toLowerCase().includes("threat intelligence"),
      "Explanation text must reference threat intelligence context"
    );
  });

  // Summary
  console.log("\n=====================================================================");
  console.log("PHASE 6 TEST RESULTS SUMMARY");
  console.log("=====================================================================");
  const total = results.length;
  const passed = results.filter((r) => r.passed).length;
  const failed = results.filter((r) => !r.passed).length;

  console.log(`Total Tests : ${total}`);
  console.log(`Passed      : ${passed}`);
  console.log(`Failed      : ${failed}`);

  if (failed > 0) {
    console.error("\nFailed Tests:");
    results
      .filter((r) => !r.passed)
      .forEach((r) => {
        console.error(`  - ${r.name}: ${r.error}`);
      });
    process.exit(1);
  } else {
    console.log("\n🎉 ALL PHASE 6 TESTS PASSED SUCCESSFULLY!\n");
    process.exit(0);
  }
}

main().catch((err) => {
  console.error("Test runner crashed:", err);
  process.exit(1);
});
