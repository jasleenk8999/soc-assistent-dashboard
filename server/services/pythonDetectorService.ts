/**
 * Python Windows Log Detector Client Service (POC)
 * 
 * Provides optional threat enrichment for ingested Windows logs.
 * - Communicates with AI_SOC_Assistant over 127.0.0.1:8000
 * - Never throws or disrupts main log ingestion pipeline
 * - Validates, sanitizes, and bounds responses before returning
 * - Enforces strict timeout with AbortController
 * - Never logs or exposes the shared service token
 */

export interface PythonFinding {
  ruleId: string;
  title: string;
  severity: string;
  mitre: string;
  description: string;
  recordId: number;
  eventId: string;
  timestamp: string;
  computer: string;
  user: string;
  evidence: string;
  recommendation: string;
}

export interface PythonAttackChain {
  chainName: string;
  severity: string;
  stages: string[];
  summary: string;
}

export interface PythonMitreMatrixItem {
  technique: string;
  count: number;
}

export interface PythonLogEnrichment {
  status: "success" | "unavailable" | "skipped" | "error" | "timeout";
  enabled: boolean;
  threatScore?: number;
  riskLevel?: string;
  summaryStatus?: string;
  findingsCount?: number;
  findings?: PythonFinding[];
  attackChains?: PythonAttackChain[];
  mitreMatrix?: PythonMitreMatrixItem[];
  recommendations?: string[];
  message?: string;
}

export class PythonDetectorService {
  private static getServiceConfig() {
    const rawUrl = process.env.PYTHON_DETECTOR_URL || "http://127.0.0.1:8000";
    const secret = process.env.PYTHON_DETECTOR_SECRET?.trim() || "";
    const timeoutMs = parseInt(process.env.PYTHON_DETECTOR_TIMEOUT_MS || "4000", 10);
    const enabled = (process.env.PYTHON_DETECTOR_ENABLED || "true").toLowerCase() !== "false";

    return {
      baseUrl: rawUrl.replace(/\/+$/, ""),
      secret,
      timeoutMs: isNaN(timeoutMs) || timeoutMs <= 0 ? 4000 : timeoutMs,
      enabled,
    };
  }

  /**
   * Check if a filename is eligible for Python Windows Log detection.
   * POC strictly limits to .log, .txt, .json, .csv.
   */
  public static isEligibleFile(fileName: string): boolean {
    if (!fileName) return false;
    const lower = fileName.toLowerCase();
    return (
      lower.endsWith(".log") ||
      lower.endsWith(".txt") ||
      lower.endsWith(".json") ||
      lower.endsWith(".csv")
    );
  }

  /**
   * Analyzes log file content using the Python microservice.
   * On any failure (timeout, network down, bad JSON, bad schema), returns a safe fallback.
   */
  public static async analyzeLogs(
    fileBuffer: Buffer | string,
    fileName: string
  ): Promise<PythonLogEnrichment> {
    const config = this.getServiceConfig();

    if (!config.enabled) {
      return {
        status: "skipped",
        enabled: false,
        message: "Python detector is disabled via configuration.",
      };
    }

    if (!config.secret) {
      console.warn(
        "[PythonDetectorService] PYTHON_DETECTOR_SECRET is not configured. Skipping Python enrichment."
      );
      return {
        status: "skipped",
        enabled: false,
        message: "Shared service token not configured.",
      };
    }

    if (!this.isEligibleFile(fileName)) {
      return {
        status: "skipped",
        enabled: true,
        message: `File type not supported for Python detection POC. Supported: .log, .txt, .json, .csv`,
      };
    }

    const controller = new AbortController();
    const timeoutHandle = setTimeout(() => controller.abort(), config.timeoutMs);

    try {
      const boundary = `----SOCBoundary${Date.now()}`;
      const buffer = typeof fileBuffer === "string" ? Buffer.from(fileBuffer, "utf-8") : fileBuffer;

      // Construct multipart/form-data payload manually to avoid extra dependencies
      const prePayload = Buffer.from(
        `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${fileName}"\r\nContent-Type: application/octet-stream\r\n\r\n`
      );
      const postPayload = Buffer.from(`\r\n--${boundary}--\r\n`);
      const body = Buffer.concat([prePayload, buffer, postPayload]);

      const response = await fetch(`${config.baseUrl}/api/detect/windows`, {
        method: "POST",
        headers: {
          "Content-Type": `multipart/form-data; boundary=${boundary}`,
          "X-Internal-Service-Key": config.secret,
        },
        body,
        signal: controller.signal,
      });

      clearTimeout(timeoutHandle);

      if (!response.ok) {
        let errorText = "Unknown error";
        try {
          const errData = await response.json();
          errorText = errData.error || errData.message || response.statusText;
        } catch {
          errorText = `HTTP ${response.status} ${response.statusText}`;
        }

        console.warn(
          `[PythonDetectorService] Microservice returned status ${response.status}: ${errorText}`
        );

        return {
          status: response.status === 401 ? "error" : "unavailable",
          enabled: true,
          message: `Microservice error: ${errorText}`,
        };
      }

      // Validate JSON response
      let rawJson: any;
      try {
        rawJson = await response.json();
      } catch {
        console.warn("[PythonDetectorService] Microservice returned invalid JSON.");
        return {
          status: "error",
          enabled: true,
          message: "Failed to parse Python detector response as valid JSON.",
        };
      }

      return this.validateAndBoundReport(rawJson);
    } catch (err: any) {
      clearTimeout(timeoutHandle);

      if (err.name === "AbortError") {
        console.warn(
          `[PythonDetectorService] Analysis timed out after ${config.timeoutMs}ms.`
        );
        return {
          status: "timeout",
          enabled: true,
          message: `Python analysis timed out after ${config.timeoutMs}ms.`,
        };
      }

      console.warn(
        `[PythonDetectorService] Connection failed (${err.code || err.message}). Ingestion proceeding without enrichment.`
      );

      return {
        status: "unavailable",
        enabled: true,
        message: "Python detector service is currently offline or unreachable.",
      };
    }
  }

  /**
   * Validates and bounds the untrusted report from the Python service.
   */
  public static validateAndBoundReport(data: any): PythonLogEnrichment {
    if (!data || typeof data !== "object") {
      return {
        status: "error",
        enabled: true,
        message: "Invalid response format received from Python detector.",
      };
    }

    // Bound numeric threat score between 0 and 100
    const rawScore = Number(data.threat_score);
    const threatScore = isNaN(rawScore) ? 0 : Math.max(0, Math.min(100, Math.round(rawScore)));

    const riskLevel = typeof data.risk_level === "string" ? data.risk_level.slice(0, 30) : "UNKNOWN";
    const summaryStatus = typeof data.status === "string" ? data.status.slice(0, 200) : "";

    // Bound findings to maximum 50 records to prevent UI bloat
    const rawFindings = Array.isArray(data.findings) ? data.findings.slice(0, 50) : [];
    const findings: PythonFinding[] = rawFindings.map((f: any) => ({
      ruleId: String(f.rule_id || "UNKNOWN").slice(0, 50),
      title: String(f.title || "Suspicious Finding").slice(0, 150),
      severity: String(f.severity || "Medium").slice(0, 20),
      mitre: String(f.mitre || "T1059").slice(0, 100),
      description: String(f.description || "").slice(0, 300),
      recordId: Number(f.record_id) || 0,
      eventId: String(f.event_id || "N/A").slice(0, 20),
      timestamp: String(f.timestamp || "").slice(0, 50),
      computer: String(f.computer || "").slice(0, 100),
      user: String(f.user || "").slice(0, 100),
      evidence: String(f.evidence || "").slice(0, 300),
      recommendation: String(f.recommendation || "").slice(0, 300),
    }));

    // Bound attack chains to maximum 10 items
    const rawChains = Array.isArray(data.attack_chains) ? data.attack_chains.slice(0, 10) : [];
    const attackChains: PythonAttackChain[] = rawChains.map((c: any) => ({
      chainName: String(c.chain_name || "Attack Progression").slice(0, 150),
      severity: String(c.severity || "HIGH").slice(0, 20),
      stages: Array.isArray(c.stages) ? c.stages.map((s: any) => String(s).slice(0, 100)) : [],
      summary: String(c.summary || "").slice(0, 300),
    }));

    // Bound MITRE matrix items to maximum 20 items
    const rawMatrix = Array.isArray(data.mitre_matrix) ? data.mitre_matrix.slice(0, 20) : [];
    const mitreMatrix: PythonMitreMatrixItem[] = rawMatrix.map((m: any) => ({
      technique: String(m.technique || "").slice(0, 100),
      count: Number(m.count) || 0,
    }));

    // Bound recommendations to maximum 10 items
    const recommendations = Array.isArray(data.recommendations)
      ? data.recommendations.slice(0, 10).map((r: any) => String(r).slice(0, 250))
      : [];

    return {
      status: "success",
      enabled: true,
      threatScore,
      riskLevel,
      summaryStatus,
      findingsCount: Array.isArray(data.findings) ? data.findings.length : findings.length,
      findings,
      attackChains,
      mitreMatrix,
      recommendations,
    };
  }
}
