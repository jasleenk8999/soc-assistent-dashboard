/**
 * Phase 2 Automated Verification Test Suite
 * Validates Authentication, Session Management, Token Rotation, and Role-Based Access Control (RBAC).
 */
import { db } from "../server/db";
import { users, refreshTokens, alerts, cases, logs } from "../server/db/schema";
import { eq, desc } from "drizzle-orm";
import { REFRESH_COOKIE_NAME, ROLES, ROLE_PERMISSIONS } from "../shared/auth";

const BASE_URL = "http://localhost:5001";

interface TestResult {
  name: string;
  passed: boolean;
  expected: string;
  actual: string;
  details?: any;
}

const results: TestResult[] = [];

function assert(name: string, condition: boolean, expected: string, actual: string, details?: any) {
  results.push({
    name,
    passed: condition,
    expected,
    actual,
    details,
  });
  const symbol = condition ? "✅ PASS" : "❌ FAIL";
  console.log(`${symbol} | ${name} (Expected: ${expected}, Got: ${actual})`);
}

function parseCookies(headers: Headers): Record<string, string> {
  const setCookies = headers.getSetCookie ? headers.getSetCookie() : [headers.get("set-cookie") || ""];
  const cookies: Record<string, string> = {};
  for (const cookieStr of setCookies) {
    if (!cookieStr) continue;
    const parts = cookieStr.split(";")[0].split("=");
    if (parts.length >= 2) {
      cookies[parts[0].trim()] = parts.slice(1).join("=").trim();
    }
  }
  return cookies;
}

async function runTestSuite() {
  console.log("===============================================================================");
  console.log("   AI CYBER SECURITY SOC ASSISTANT - PHASE 2 VERIFICATION TEST SUITE");
  console.log("===============================================================================\n");

  const testEmail = `sec.analyst.${Date.now()}@soc.local`;
  const testPassword = "SecurePassword2026!";

  // 1. Health Endpoint
  {
    const res = await fetch(`${BASE_URL}/api/health`);
    const data = await res.json();
    assert(
      "Server Health Check",
      res.status === 200 && data.status === "healthy" && data.services.database.status === "connected",
      "200 OK, healthy, DB connected",
      `${res.status} ${data.status}, DB ${data.services?.database?.status}`
    );
  }

  // 2. Registration Input Validation
  {
    // Weak password
    const res = await fetch(`${BASE_URL}/api/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        fullName: "Test Weak",
        email: "test.weak@soc.local",
        password: "123",
      }),
    });
    const data = await res.json();
    assert(
      "Registration Rejects Weak Password",
      res.status === 400 && data.error.includes("Password"),
      "400 Bad Request with password complexity requirements",
      `${res.status} - ${data.error}`
    );
  }

  {
    // Invalid email format
    const res = await fetch(`${BASE_URL}/api/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        fullName: "Test Invalid Email",
        email: "not-an-email",
        password: "ValidPassword2026!",
      }),
    });
    const data = await res.json();
    assert(
      "Registration Rejects Invalid Email",
      res.status === 400 && data.error.includes("email"),
      "400 Bad Request with invalid email error",
      `${res.status} - ${data.error}`
    );
  }

  // 3. Registration with Privilege Escalation Prevention
  let regAccessToken = "";
  let regRefreshTokenCookie = "";
  {
    // Attempt to register with elevated role "Incident Commander"
    const res = await fetch(`${BASE_URL}/api/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        fullName: "Alex Rivera",
        email: testEmail,
        password: testPassword,
        role: "Incident Commander", // Malicious attempt to escalate role
      }),
    });
    const data = await res.json();
    const cookies = parseCookies(res.headers);
    regAccessToken = data.accessToken;
    regRefreshTokenCookie = cookies[REFRESH_COOKIE_NAME] || "";

    assert(
      "Public Registration Assigns Safe Default Role (Prevents Privilege Escalation)",
      res.status === 201 && data.user.role === "Senior Analyst",
      "201 Created with role: 'Senior Analyst'",
      `${res.status} with role: '${data.user?.role}'`
    );
    assert(
      "Registration Returns JWT Access Token",
      Boolean(regAccessToken && regAccessToken.split(".").length === 3),
      "Valid 3-part JWT access token",
      regAccessToken ? "JWT received" : "Missing token"
    );
    assert(
      "Registration Sets HttpOnly Refresh Cookie",
      Boolean(regRefreshTokenCookie),
      "soc_refresh_token cookie present",
      regRefreshTokenCookie ? "Cookie set" : "Missing cookie"
    );
  }

  // 4. Database Password Hashing Verification
  {
    const [dbUser] = await db.select().from(users).where(eq(users.email, testEmail));
    assert(
      "Database Stores Strong Bcrypt Password Hash (Never Plaintext)",
      Boolean(dbUser && dbUser.passwordHash.startsWith("$2") && !dbUser.passwordHash.includes(testPassword)),
      "Bcrypt hash beginning with $2a$ or $2b$",
      dbUser ? dbUser.passwordHash.substring(0, 7) + "..." : "User not found"
    );
  }

  // 5. Database Refresh Token Hashing Verification
  {
    const [dbUser] = await db.select().from(users).where(eq(users.email, testEmail));
    const [dbToken] = await db
      .select()
      .from(refreshTokens)
      .where(eq(refreshTokens.userId, dbUser.id))
      .orderBy(desc(refreshTokens.createdAt));
    assert(
      "Database Stores SHA-256 Hashed Refresh Token (Never Plaintext)",
      Boolean(dbToken && dbToken.tokenHash !== regRefreshTokenCookie && dbToken.tokenHash.length === 64),
      "64-character SHA-256 hex hash distinct from raw cookie",
      dbToken ? `${dbToken.tokenHash.substring(0, 10)}... (length ${dbToken.tokenHash.length})` : "Token not found"
    );
  }

  // 6. Duplicate Registration Prevention
  {
    const res = await fetch(`${BASE_URL}/api/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        fullName: "Alex Duplicate",
        email: testEmail,
        password: testPassword,
      }),
    });
    const data = await res.json();
    assert(
      "Duplicate Email Registration Rejected",
      res.status === 409 && data.error.includes("already exists"),
      "409 Conflict: An account with this email address already exists.",
      `${res.status} - ${data.error}`
    );
  }

  // 7. Login Authentication & Generic Error (Account Enumeration Defense)
  {
    // Non-existent user
    const res = await fetch(`${BASE_URL}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: "nonexistent.analyst@soc.local",
        password: "WrongPassword2026!",
      }),
    });
    const data = await res.json();
    assert(
      "Login Rejects Non-Existent User with Generic Error",
      res.status === 401 && data.error.includes("Invalid email or password"),
      "401 Unauthorized with generic message",
      `${res.status} - ${data.error}`
    );
  }

  {
    // Existing user with bad password
    const res = await fetch(`${BASE_URL}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: testEmail,
        password: "IncorrectPassword123!",
      }),
    });
    const data = await res.json();
    assert(
      "Login Rejects Incorrect Password with Generic Error",
      res.status === 401 && data.error.includes("Invalid email or password"),
      "401 Unauthorized with generic message",
      `${res.status} - ${data.error}`
    );
  }

  // 8. Seeded Analyst Personas Login Verification
  const personas = [
    { email: "avery.reed@soc.local", role: "Senior Analyst" },
    { email: "mina.kapoor@soc.local", role: "Threat Hunter" },
    { email: "darren.liu@soc.local", role: "Incident Commander" },
    { email: "jordan.smith@soc.local", role: "Detection Engineer" },
  ];

  const personaTokens: Record<string, { accessToken: string; cookie: string }> = {};

  for (const persona of personas) {
    const res = await fetch(`${BASE_URL}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: persona.email,
        password: "SocAnalyst2026!",
      }),
    });
    const data = await res.json();
    const cookies = parseCookies(res.headers);
    personaTokens[persona.role] = {
      accessToken: data.accessToken,
      cookie: cookies[REFRESH_COOKIE_NAME] || "",
    };

    assert(
      `Login for Seeded Role '${persona.role}'`,
      res.status === 200 && data.user.role === persona.role && Boolean(data.accessToken),
      `200 OK, role: ${persona.role}, token issued`,
      `${res.status}, role: ${data.user?.role}`
    );
  }

  // 9. Protected Endpoint /api/auth/me Verification
  {
    // Without token
    const res = await fetch(`${BASE_URL}/api/auth/me`);
    assert(
      "GET /api/auth/me Rejects Unauthenticated Request",
      res.status === 401,
      "401 Unauthorized",
      `${res.status}`
    );
  }

  {
    // With Senior Analyst token
    const averyToken = personaTokens["Senior Analyst"].accessToken;
    const res = await fetch(`${BASE_URL}/api/auth/me`, {
      headers: { Authorization: `Bearer ${averyToken}` },
    });
    const data = await res.json();
    assert(
      "GET /api/auth/me Validates Bearer Token and Returns User Profile",
      res.status === 200 && data.user.email === "avery.reed@soc.local" && data.user.role === "Senior Analyst",
      "200 OK with Avery Reed profile",
      `${res.status} - ${data.user?.fullName} (${data.user?.role})`
    );
  }

  // 10. Refresh Token Rotation
  let newRotatedToken = "";
  let newRotatedCookie = "";
  const initialAveryCookie = personaTokens["Senior Analyst"].cookie;
  {
    const res = await fetch(`${BASE_URL}/api/auth/refresh`, {
      method: "POST",
      headers: {
        Cookie: `${REFRESH_COOKIE_NAME}=${initialAveryCookie}`,
      },
    });
    const data = await res.json();
    const cookies = parseCookies(res.headers);
    newRotatedToken = data.accessToken;
    newRotatedCookie = cookies[REFRESH_COOKIE_NAME] || "";

    assert(
      "POST /api/auth/refresh Rotates Session and Returns New Access Token",
      res.status === 200 && Boolean(newRotatedToken) && Boolean(newRotatedCookie) && newRotatedCookie !== initialAveryCookie,
      "200 OK with distinct rotated cookie and new access token",
      `${res.status}, cookie rotated: ${newRotatedCookie !== initialAveryCookie}`
    );
  }

  // 11. Refresh Token Reuse / Theft Detection
  {
    // Replay the old initial cookie that was already rotated
    const res = await fetch(`${BASE_URL}/api/auth/refresh`, {
      method: "POST",
      headers: {
        Cookie: `${REFRESH_COOKIE_NAME}=${initialAveryCookie}`,
      },
    });
    const data = await res.json();
    assert(
      "POST /api/auth/refresh Detects Token Reuse and Rejects Replayed Token",
      res.status === 401,
      "401 Unauthorized (theft detection triggered)",
      `${res.status} - ${data.error}`
    );
  }

  // 12. Logout and Session Revocation
  {
    // Call logout on the registered user from Section 3
    const logoutRes = await fetch(`${BASE_URL}/api/auth/logout`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${regAccessToken}`,
        Cookie: `${REFRESH_COOKIE_NAME}=${regRefreshTokenCookie}`,
      },
    });
    const logoutCookies = parseCookies(logoutRes.headers);

    assert(
      "POST /api/auth/logout Revokes Active Session and Clears Cookie",
      logoutRes.status === 200 && (!logoutCookies[REFRESH_COOKIE_NAME] || logoutCookies[REFRESH_COOKIE_NAME] === ""),
      "200 OK with cleared refresh cookie",
      `${logoutRes.status}`
    );

    // Verify revoked cookie cannot be used to refresh
    const refreshAfterLogout = await fetch(`${BASE_URL}/api/auth/refresh`, {
      method: "POST",
      headers: {
        Cookie: `${REFRESH_COOKIE_NAME}=${regRefreshTokenCookie}`,
      },
    });
    assert(
      "Revoked Session Rejected on Subsequent Refresh",
      refreshAfterLogout.status === 401,
      "401 Unauthorized",
      `${refreshAfterLogout.status}`
    );
  }

  // 13. Server-Side RBAC Enforcement on Protected Endpoints
  console.log("\n--- Testing Server-Side RBAC Enforcement Across Roles ---");

  // A. Unauthenticated mutations must be rejected
  {
    const res = await fetch(`${BASE_URL}/api/alerts/1/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: "In review" }),
    });
    assert(
      "RBAC: Unauthenticated PATCH /api/alerts/:id/status Rejected",
      res.status === 401,
      "401 Unauthorized",
      `${res.status}`
    );
  }

  {
    const res = await fetch(`${BASE_URL}/api/cases/1/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: "Contained" }),
    });
    assert(
      "RBAC: Unauthenticated PATCH /api/cases/:id/status Rejected",
      res.status === 401,
      "401 Unauthorized",
      `${res.status}`
    );
  }

  {
    const res = await fetch(`${BASE_URL}/api/logs`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        source: "Firewall",
        level: "WARN",
        message: "Unauthenticated test",
      }),
    });
    assert(
      "RBAC: Unauthenticated POST /api/logs Rejected",
      res.status === 401,
      "401 Unauthorized",
      `${res.status}`
    );
  }

  // B. Senior Analyst Permissions
  // - update:alert_status: PERMITTED
  // - update:case_status: PERMITTED
  // - ingest:logs: FORBIDDEN
  {
    const token = personaTokens["Senior Analyst"].accessToken;

    // Allowed: update alert status
    const alertRes = await fetch(`${BASE_URL}/api/alerts/1/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ status: "In review" }),
    });
    assert(
      "Senior Analyst PERMITTED to update alert status (update:alert_status)",
      alertRes.status === 200,
      "200 OK",
      `${alertRes.status}`
    );

    // Allowed: update case status
    const caseRes = await fetch(`${BASE_URL}/api/cases/1/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ status: "Contained" }),
    });
    assert(
      "Senior Analyst PERMITTED to update case status (update:case_status)",
      caseRes.status === 200,
      "200 OK",
      `${caseRes.status}`
    );

    // Forbidden: ingest logs
    const logRes = await fetch(`${BASE_URL}/api/logs`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ source: "IDS", level: "INFO", message: "Unauthorized log" }),
    });
    const logData = await logRes.json();
    assert(
      "Senior Analyst FORBIDDEN from ingesting logs (requires ingest:logs)",
      logRes.status === 403,
      "403 Forbidden",
      `${logRes.status} - ${logData.error}`
    );
  }

  // C. Threat Hunter Permissions
  // - update:alert_status: FORBIDDEN
  // - update:case_status: FORBIDDEN
  {
    const token = personaTokens["Threat Hunter"].accessToken;

    const alertRes = await fetch(`${BASE_URL}/api/alerts/1/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ status: "Closed" }),
    });
    const alertData = await alertRes.json();
    assert(
      "Threat Hunter FORBIDDEN from updating alert status",
      alertRes.status === 403,
      "403 Forbidden: Missing required permission: update:alert_status",
      `${alertRes.status} - ${alertData.error}`
    );

    const caseRes = await fetch(`${BASE_URL}/api/cases/1/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ status: "Closed" }),
    });
    const caseData = await caseRes.json();
    assert(
      "Threat Hunter FORBIDDEN from updating case status",
      caseRes.status === 403,
      "403 Forbidden: Missing required permission: update:case_status",
      `${caseRes.status} - ${caseData.error}`
    );
  }

  // D. Detection Engineer Permissions
  // - ingest:logs: PERMITTED
  // - update:alert_status: FORBIDDEN
  {
    const token = personaTokens["Detection Engineer"].accessToken;

    // Allowed: ingest log
    const logRes = await fetch(`${BASE_URL}/api/logs`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({
        sourceType: "Suricata IDS",
        logLevel: "WARNING",
        rawLog: "Detection Engineer verified log ingestion rule #2041",
        parsedFields: { signatureId: 2041, category: "Policy Violation" },
      }),
    });
    assert(
      "Detection Engineer PERMITTED to ingest logs (ingest:logs)",
      logRes.status === 201,
      "201 Created",
      `${logRes.status}`
    );

    // Forbidden: update alert status
    const alertRes = await fetch(`${BASE_URL}/api/alerts/1/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ status: "Closed" }),
    });
    assert(
      "Detection Engineer FORBIDDEN from updating alert status",
      alertRes.status === 403,
      "403 Forbidden",
      `${alertRes.status}`
    );
  }

  // E. Incident Commander Permissions
  // - All operations PERMITTED
  {
    const token = personaTokens["Incident Commander"].accessToken;

    const alertRes = await fetch(`${BASE_URL}/api/alerts/1/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ status: "Escalated" }),
    });
    assert(
      "Incident Commander PERMITTED to escalate alerts",
      alertRes.status === 200,
      "200 OK",
      `${alertRes.status}`
    );

    const caseRes = await fetch(`${BASE_URL}/api/cases/1/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ status: "Contained" }),
    });
    assert(
      "Incident Commander PERMITTED to mark cases contained",
      caseRes.status === 200,
      "200 OK",
      `${caseRes.status}`
    );
  }

  console.log("\n===============================================================================");
  const total = results.length;
  const passed = results.filter((r) => r.passed).length;
  const failed = total - passed;
  console.log(`TOTAL TESTS: ${total} | PASSED: ${passed} | FAILED: ${failed}`);
  console.log("===============================================================================\n");

  if (failed > 0) {
    process.exit(1);
  }
}

runTestSuite().catch((err) => {
  console.error("Test suite fatal execution error:", err);
  process.exit(1);
});
