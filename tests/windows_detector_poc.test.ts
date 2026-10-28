/**
 * Automated Test Suite: Windows Log Detector POC (Phase 7 Sidecar)
 * 
 * Verifies:
 * 1. Successful Python microservice response & data extraction
 * 2. Malformed / invalid response handling without throwing
 * 3. Timeout handling via AbortController
 * 4. Service unavailability (ECONNREFUSED) graceful fallback
 * 5. Data bounding (clamping scores 0-100, capping findings)
 * 6. Shared service token enforcement
 * 7. Allowed extension filtering (.log, .txt, .json, .csv only)
 * 
 * Runs entirely with mocks. No live database or Python server required.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { PythonDetectorService } from "../server/services/pythonDetectorService";

describe("PythonDetectorService Unit Tests", () => {
  const originalEnv = { ...process.env };
  const originalFetch = global.fetch;

  beforeEach(() => {
    process.env.PYTHON_DETECTOR_ENABLED = "true";
    process.env.PYTHON_DETECTOR_URL = "http://127.0.0.1:8000";
    process.env.PYTHON_DETECTOR_SECRET = "test_shared_secret_abc123";
    process.env.PYTHON_DETECTOR_TIMEOUT_MS = "1000";
  });

  afterEach(() => {
    process.env = { ...originalEnv };
    global.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  // 1. Successful Analysis
  it("processes a valid detector response and extracts bounded findings", async () => {
    const mockReport = {
      filename: "security.log",
      threat_score: 85,
      risk_level: "HIGH",
      status: "Threats detected",
      severity_counts: { High: 2 },
      attack_chains: [
        {
          chain_name: "Privilege Escalation via LOLBin",
          severity: "HIGH",
          stages: ["Credential Access", "Execution"],
          summary: "Attack stages identified",
        },
      ],
      findings: [
        {
          rule_id: "WIN-CMD-T1059",
          title: "Encoded PowerShell Execution",
          severity: "High",
          mitre: "T1059.001 - PowerShell",
          evidence: "powershell -enc SQBFAFgA...",
          recommendation: "Investigate host",
        },
      ],
      mitre_matrix: [{ technique: "T1059.001", count: 1 }],
      recommendations: ["Isolate host"],
    };

    let capturedHeaders: HeadersInit | undefined;
    global.fetch = vi.fn().mockImplementation(async (_url, options) => {
      capturedHeaders = options?.headers;
      return {
        ok: true,
        status: 200,
        json: async () => mockReport,
      } as unknown as Response;
    });

    const result = await PythonDetectorService.analyzeLogs(
      "sample log content",
      "security.log"
    );

    expect(result.status).toBe("success");
    expect(result.enabled).toBe(true);
    expect(result.threatScore).toBe(85);
    expect(result.riskLevel).toBe("HIGH");
    expect(result.findingsCount).toBe(1);
    expect(result.findings?.[0].ruleId).toBe("WIN-CMD-T1059");
    expect(result.attackChains?.length).toBe(1);
    expect(result.attackChains?.[0].chainName).toBe("Privilege Escalation via LOLBin");

    // Verify token was passed in header
    expect(capturedHeaders).toBeDefined();
    expect((capturedHeaders as Record<string, string>)["X-Internal-Service-Key"]).toBe(
      "test_shared_secret_abc123"
    );
  });

  // 2. Malformed / Invalid JSON Response
  it("gracefully catches malformed/invalid JSON without throwing", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => {
        throw new SyntaxError("Unexpected token < in JSON at position 0");
      },
    } as unknown as Response);

    const result = await PythonDetectorService.analyzeLogs(
      "sample log content",
      "security.log"
    );

    expect(result.status).toBe("error");
    expect(result.message).toContain("Failed to parse Python detector response as valid JSON");
  });

  // 3. Timeout Handling via AbortController
  it("handles request timeout gracefully", async () => {
    global.fetch = vi.fn().mockImplementation(async () => {
      const err = new Error("The operation was aborted");
      err.name = "AbortError";
      throw err;
    });

    const result = await PythonDetectorService.analyzeLogs(
      "sample log content",
      "security.log"
    );

    expect(result.status).toBe("timeout");
    expect(result.message).toContain("timed out");
  });

  // 4. Service Unavailable (ECONNREFUSED)
  it("gracefully falls back when service is unreachable", async () => {
    global.fetch = vi.fn().mockRejectedValue(
      new Error("connect ECONNREFUSED 127.0.0.1:8000")
    );

    const result = await PythonDetectorService.analyzeLogs(
      "sample log content",
      "security.log"
    );

    expect(result.status).toBe("unavailable");
    expect(result.message).toContain("offline or unreachable");
  });

  // 5. Data Bounding & Sanitization
  it("bounds threat score to 0-100 and caps findings", () => {
    const rawData = {
      threat_score: 999, // Out of bounds
      risk_level: "CRITICAL",
      findings: Array.from({ length: 80 }, (_, i) => ({
        rule_id: `RULE-${i}`,
        title: `Finding ${i}`,
        severity: "High",
      })),
      attack_chains: Array.from({ length: 25 }, (_, i) => ({
        chain_name: `Chain ${i}`,
        severity: "CRITICAL",
      })),
    };

    const bounded = PythonDetectorService.validateAndBoundReport(rawData);

    expect(bounded.status).toBe("success");
    expect(bounded.threatScore).toBe(100); // Clamped to 100
    expect(bounded.findings?.length).toBe(50); // Capped at 50
    expect(bounded.attackChains?.length).toBe(10); // Capped at 10
  });

  // 6. Shared Token Enforcement
  it("skips analysis and logs warning if shared service token is missing", async () => {
    delete process.env.PYTHON_DETECTOR_SECRET;
    const fetchSpy = vi.fn();
    global.fetch = fetchSpy;

    const result = await PythonDetectorService.analyzeLogs(
      "sample log content",
      "security.log"
    );

    expect(result.status).toBe("skipped");
    expect(result.message).toBe("Shared service token not configured.");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  // 7. Allowed Extension Filtering
  it("rejects unsupported extensions before sending network requests", async () => {
    const fetchSpy = vi.fn();
    global.fetch = fetchSpy;

    // Supported extensions
    expect(PythonDetectorService.isEligibleFile("system.log")).toBe(true);
    expect(PythonDetectorService.isEligibleFile("events.txt")).toBe(true);
    expect(PythonDetectorService.isEligibleFile("audit.json")).toBe(true);
    expect(PythonDetectorService.isEligibleFile("export.csv")).toBe(true);

    // Unsupported extensions
    expect(PythonDetectorService.isEligibleFile("security.evtx")).toBe(false);
    expect(PythonDetectorService.isEligibleFile("security.xml")).toBe(false);
    expect(PythonDetectorService.isEligibleFile("malware.exe")).toBe(false);

    const result = await PythonDetectorService.analyzeLogs(
      "binary content",
      "security.evtx"
    );
    expect(result.status).toBe("skipped");
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
