/**
 * Threat Intelligence Service (Phase 6)
 *
 * Modular multi-provider threat intelligence enrichment engine supporting:
 *   1. AbuseIPDB (IP reputation and abuse reports)
 *   2. VirusTotal (IPs, domains, URLs, and file hashes)
 *   3. AlienVault OTX (IPs, domains, URLs, and file hashes)
 *
 * Key Architecture & Safety Features:
 *   - Offline/Zero-Key Resilience: Operates seamlessly without external API keys.
 *   - PostgreSQL Caching: Deduplicates external lookups with configurable TTL (default 24h).
 *   - SSRF Protection: Never fetches or visits user-supplied URLs directly; queries vendor metadata APIs only.
 *   - Concurrent Request Deduplication: Coalesces simultaneous in-flight queries for identical indicators.
 *   - Zero Secret Leakage: API keys are read exclusively server-side and never returned in responses.
 */

import { eq, desc, inArray } from "drizzle-orm";
import { db } from "../db/index";
import { threatIntelCache, alerts, logs } from "../db/schema";

export type IndicatorType = "ip" | "domain" | "url" | "hash";

export type ThreatVerdict = "Malicious" | "Suspicious" | "Clean" | "Unknown";

export interface ProviderVerdict {
  provider: "AbuseIPDB" | "VirusTotal" | "AlienVault OTX";
  status: "success" | "unconfigured" | "rate_limited" | "error" | "not_supported";
  verdict: ThreatVerdict;
  reputationScore?: number; // 0-100 (higher = worse)
  detectionsCount?: number;
  totalEngines?: number;
  details?: string;
  rawAttributes?: Record<string, any>;
  retrievedAt: string;
}

export interface ThreatIntelResult {
  id?: number;
  indicator: string;
  indicatorType: IndicatorType;
  verdict: ThreatVerdict;
  reputationScore: number; // 0-100
  detectionsCount: number;
  totalEngines: number;
  confidence: "High" | "Medium" | "Low" | "Unassessed";
  associatedContext: string[];
  feedVerdicts: ProviderVerdict[];
  source: "database_cache" | "live_feed" | "rule_engine";
  isCached: boolean;
  isStale: boolean;
  firstSeen: string;
  lastSeen: string;
  createdAt?: string;
}

export interface ProviderStatusInfo {
  id: "abuseipdb" | "virustotal" | "alienvault";
  name: string;
  configured: boolean;
  supportedTypes: IndicatorType[];
  rateLimitInfo: string;
  description: string;
}

// Configurable constants
const DEFAULT_TIMEOUT_MS = parseInt(process.env.THREAT_INTEL_TIMEOUT_MS || "8000", 10);
const CACHE_TTL_HOURS = parseInt(process.env.THREAT_INTEL_CACHE_TTL_HOURS || "24", 10);
const CACHE_TTL_MS = CACHE_TTL_HOURS * 60 * 60 * 1000;

// In-flight request deduplication map
const inFlightRequests = new Map<string, Promise<ThreatIntelResult>>();

// ---------------------------------------------------------------------------
// 1. API Key Validation & Providers Status
// ---------------------------------------------------------------------------

function isValidKey(key: string | undefined): key is string {
  if (!key) return false;
  const trimmed = key.trim();
  if (!trimmed) return false;
  if (
    trimmed.startsWith("your_") ||
    trimmed.includes("api_key_here") ||
    trimmed === "placeholder" ||
    trimmed === "changeme"
  ) {
    return false;
  }
  return true;
}

export function getProviderStatus(): ProviderStatusInfo[] {
  return [
    {
      id: "abuseipdb",
      name: "AbuseIPDB",
      configured: isValidKey(process.env.ABUSEIPDB_API_KEY),
      supportedTypes: ["ip"],
      rateLimitInfo: "Free tier: 1,000 queries/day",
      description: "IP address reputation, abuse reports, and ISP metadata.",
    },
    {
      id: "virustotal",
      name: "VirusTotal",
      configured: isValidKey(process.env.VIRUSTOTAL_API_KEY),
      supportedTypes: ["ip", "domain", "url", "hash"],
      rateLimitInfo: "Public API: 4 requests/min, 500/day",
      description: "Multi-antivirus scanning engines, domain/URL categorizations, and file hashes.",
    },
    {
      id: "alienvault",
      name: "AlienVault OTX",
      configured: isValidKey(process.env.ALIENVAULT_OTX_API_KEY),
      supportedTypes: ["ip", "domain", "url", "hash"],
      rateLimitInfo: "Community tier: generous hourly quotas",
      description: "Crowdsourced open threat exchange pulses and adversary infrastructure tracking.",
    },
  ];
}

// ---------------------------------------------------------------------------
// 2. Normalization & Validation (with SSRF Defense)
// ---------------------------------------------------------------------------

const IPV4_REGEX = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
const IPV6_REGEX = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^::1$|^([0-9a-fA-F]{1,4}:){1,7}:$|^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$/;
const MD5_REGEX = /^[a-fA-F0-9]{32}$/;
const SHA1_REGEX = /^[a-fA-F0-9]{40}$/;
const SHA256_REGEX = /^[a-fA-F0-9]{64}$/;
const DOMAIN_REGEX = /^(?!:\/\/)([a-zA-Z0-9-_]+\.)+[a-zA-Z]{2,}$/;

export function validateAndNormalizeIndicator(
  rawInput: string,
  explicitType?: string
): { valid: boolean; normalized: string; type: IndicatorType; error?: string } {
  if (!rawInput || typeof rawInput !== "string") {
    return { valid: false, normalized: "", type: "ip", error: "Indicator cannot be empty" };
  }

  let cleaned = rawInput.trim();

  // Strip wrapping quotes or brackets if present (e.g., [.] or hxxp)
  cleaned = cleaned.replace(/\[\.\]/g, ".").replace(/^hxxp/i, "http");

  // Remove port if IPv4 with port: 1.2.3.4:8080
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$/.test(cleaned)) {
    cleaned = cleaned.split(":")[0];
  }

  // Protocol scheme safety (SSRF protection: reject non-HTTP/HTTPS protocols like ftp, file, javascript)
  if (cleaned.includes("://")) {
    if (!cleaned.startsWith("http://") && !cleaned.startsWith("https://")) {
      return { valid: false, normalized: "", type: "url", error: "Non-HTTP protocol schemes are rejected for security" };
    }
  }
  if (
    /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(cleaned) &&
    !cleaned.startsWith("http://") &&
    !cleaned.startsWith("https://") &&
    !IPV6_REGEX.test(cleaned)
  ) {
    return { valid: false, normalized: "", type: "url", error: "Unsupported or unsafe protocol scheme" };
  }

  // 1. Check IP address
  if (IPV4_REGEX.test(cleaned) || IPV6_REGEX.test(cleaned)) {
    return { valid: true, normalized: cleaned.toLowerCase(), type: "ip" };
  }

  // 2. Check File Hash (MD5, SHA1, SHA256)
  if (MD5_REGEX.test(cleaned) || SHA1_REGEX.test(cleaned) || SHA256_REGEX.test(cleaned)) {
    return { valid: true, normalized: cleaned.toLowerCase(), type: "hash" };
  }

  // 3. Check URL (must be valid HTTP/HTTPS)
  if (cleaned.startsWith("http://") || cleaned.startsWith("https://")) {
    try {
      const parsed = new URL(cleaned);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        return { valid: false, normalized: "", type: "url", error: "Only HTTP/HTTPS URLs are supported" };
      }
      return { valid: true, normalized: parsed.href, type: "url" };
    } catch {
      return { valid: false, normalized: "", type: "url", error: "Malformed URL structure" };
    }
  }

  // 4. Check Domain
  // Strip protocol if user pasted http://domain without path
  const strippedDomain = cleaned.replace(/^[a-zA-Z]+:\/\//, "").replace(/\/.*$/, "").toLowerCase();
  if (DOMAIN_REGEX.test(strippedDomain)) {
    return { valid: true, normalized: strippedDomain, type: "domain" };
  }

  // If explicitType was passed, attempt fallback check
  if (explicitType === "hash" && /^[a-fA-F0-9]{32,64}$/.test(cleaned)) {
    return { valid: true, normalized: cleaned.toLowerCase(), type: "hash" };
  }

  return {
    valid: false,
    normalized: cleaned,
    type: "ip",
    error: `Invalid indicator format. Must be an IPv4/IPv6, Domain, URL, or MD5/SHA1/SHA256 hash.`,
  };
}

// ---------------------------------------------------------------------------
// 3. Provider Implementations
// ---------------------------------------------------------------------------

/**
 * Query AbuseIPDB API v2
 * Note: AbuseIPDB only supports IP addresses.
 */
async function queryAbuseIPDB(ip: string): Promise<ProviderVerdict> {
  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!isValidKey(apiKey)) {
    return {
      provider: "AbuseIPDB",
      status: "unconfigured",
      verdict: "Unknown",
      details: "AbuseIPDB API key not configured in environment.",
      retrievedAt: new Date().toISOString(),
    };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);

  try {
    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`;
    const res = await fetch(url, {
      method: "GET",
      headers: {
        Key: apiKey.trim(),
        Accept: "application/json",
      },
      signal: controller.signal,
    });

    if (res.status === 429) {
      return {
        provider: "AbuseIPDB",
        status: "rate_limited",
        verdict: "Unknown",
        details: "AbuseIPDB API rate limit exceeded (HTTP 429).",
        retrievedAt: new Date().toISOString(),
      };
    }

    if (!res.ok) {
      const errorBody = await res.text().catch(() => "");
      return {
        provider: "AbuseIPDB",
        status: "error",
        verdict: "Unknown",
        details: `AbuseIPDB HTTP ${res.status}: ${errorBody.slice(0, 150)}`,
        retrievedAt: new Date().toISOString(),
      };
    }

    const json: any = await res.json();
    const data = json?.data;
    if (!data) {
      return {
        provider: "AbuseIPDB",
        status: "error",
        verdict: "Unknown",
        details: "Malformed response structure from AbuseIPDB",
        retrievedAt: new Date().toISOString(),
      };
    }

    const score = Number(data.abuseConfidenceScore ?? 0);
    const totalReports = Number(data.totalReports ?? 0);
    const isWhitelisted = Boolean(data.isWhitelisted);

    let verdict: ThreatVerdict = "Clean";
    if (isWhitelisted) {
      verdict = "Clean";
    } else if (score >= 70 || totalReports >= 15) {
      verdict = "Malicious";
    } else if (score >= 25 || totalReports >= 3) {
      verdict = "Suspicious";
    }

    return {
      provider: "AbuseIPDB",
      status: "success",
      verdict,
      reputationScore: score,
      detectionsCount: totalReports,
      totalEngines: 100,
      details: `Abuse score: ${score}%, Reports: ${totalReports}. ISP: ${data.isp ?? "Unknown"}, Country: ${data.countryCode ?? "N/A"}${data.domain ? `, Domain: ${data.domain}` : ""}.`,
      rawAttributes: {
        abuseConfidenceScore: score,
        totalReports,
        countryCode: data.countryCode,
        isp: data.isp,
        usageType: data.usageType,
        domain: data.domain,
        isWhitelisted,
      },
      retrievedAt: new Date().toISOString(),
    };
  } catch (err: any) {
    const isTimeout = err?.name === "AbortError";
    return {
      provider: "AbuseIPDB",
      status: "error",
      verdict: "Unknown",
      details: isTimeout ? `Request timed out after ${DEFAULT_TIMEOUT_MS}ms` : err?.message || "Network error",
      retrievedAt: new Date().toISOString(),
    };
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Query VirusTotal API v3
 * Supports IP, Domain, Hash, and URL.
 * SSRF defense: never fetches the URL, only queries VirusTotal's base64url metadata endpoint.
 */
async function queryVirusTotal(indicator: string, type: IndicatorType): Promise<ProviderVerdict> {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!isValidKey(apiKey)) {
    return {
      provider: "VirusTotal",
      status: "unconfigured",
      verdict: "Unknown",
      details: "VirusTotal API key not configured in environment.",
      retrievedAt: new Date().toISOString(),
    };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);

  try {
    let endpoint = "";
    if (type === "ip") {
      endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(indicator)}`;
    } else if (type === "domain") {
      endpoint = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(indicator)}`;
    } else if (type === "hash") {
      endpoint = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(indicator)}`;
    } else if (type === "url") {
      // VirusTotal URL IDs are base64url encoded without trailing padding
      const urlId = Buffer.from(indicator).toString("base64url").replace(/=/g, "");
      endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;
    }

    const res = await fetch(endpoint, {
      method: "GET",
      headers: {
        "x-apikey": apiKey.trim(),
        Accept: "application/json",
      },
      signal: controller.signal,
    });

    if (res.status === 429) {
      return {
        provider: "VirusTotal",
        status: "rate_limited",
        verdict: "Unknown",
        details: "VirusTotal rate limit reached (HTTP 429).",
        retrievedAt: new Date().toISOString(),
      };
    }

    if (res.status === 404) {
      return {
        provider: "VirusTotal",
        status: "success",
        verdict: "Unknown",
        reputationScore: 0,
        detectionsCount: 0,
        totalEngines: 0,
        details: "Indicator not found in VirusTotal dataset (unseen/new).",
        retrievedAt: new Date().toISOString(),
      };
    }

    if (!res.ok) {
      const errText = await res.text().catch(() => "");
      return {
        provider: "VirusTotal",
        status: "error",
        verdict: "Unknown",
        details: `VirusTotal HTTP ${res.status}: ${errText.slice(0, 150)}`,
        retrievedAt: new Date().toISOString(),
      };
    }

    const json: any = await res.json();
    const attributes = json?.data?.attributes;
    if (!attributes) {
      return {
        provider: "VirusTotal",
        status: "error",
        verdict: "Unknown",
        details: "Missing attributes field in VirusTotal response",
        retrievedAt: new Date().toISOString(),
      };
    }

    const stats = attributes.last_analysis_stats || {};
    const malicious = Number(stats.malicious || 0);
    const suspicious = Number(stats.suspicious || 0);
    const harmless = Number(stats.harmless || 0);
    const undetected = Number(stats.undetected || 0);
    const totalEngines = malicious + suspicious + harmless + undetected;

    let verdict: ThreatVerdict = "Clean";
    if (malicious >= 3) {
      verdict = "Malicious";
    } else if (malicious >= 1 || suspicious >= 2) {
      verdict = "Suspicious";
    } else if (malicious === 0 && (harmless > 0 || undetected > 0)) {
      verdict = "Clean";
    } else {
      verdict = "Unknown";
    }

    // Normalized reputation score (0-100)
    const reputationScore = totalEngines > 0 ? Math.round((malicious / totalEngines) * 100) : 0;

    return {
      provider: "VirusTotal",
      status: "success",
      verdict,
      reputationScore,
      detectionsCount: malicious,
      totalEngines,
      details: `${malicious}/${totalEngines} security vendors flagged this as malicious (${suspicious} suspicious).`,
      rawAttributes: {
        stats,
        reputation: attributes.reputation,
        asOwner: attributes.as_owner,
        country: attributes.country,
      },
      retrievedAt: new Date().toISOString(),
    };
  } catch (err: any) {
    const isTimeout = err?.name === "AbortError";
    return {
      provider: "VirusTotal",
      status: "error",
      verdict: "Unknown",
      details: isTimeout ? `Request timed out after ${DEFAULT_TIMEOUT_MS}ms` : err?.message || "Network error",
      retrievedAt: new Date().toISOString(),
    };
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Query AlienVault OTX API v1
 * Supports IP, Domain, Hash, and URL.
 */
async function queryAlienVaultOTX(indicator: string, type: IndicatorType): Promise<ProviderVerdict> {
  const apiKey = process.env.ALIENVAULT_OTX_API_KEY;
  if (!isValidKey(apiKey)) {
    return {
      provider: "AlienVault OTX",
      status: "unconfigured",
      verdict: "Unknown",
      details: "AlienVault OTX API key not configured in environment.",
      retrievedAt: new Date().toISOString(),
    };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);

  try {
    let endpoint = "";
    if (type === "ip") {
      const section = indicator.includes(":") ? "IPv6" : "IPv4";
      endpoint = `https://otx.alienvault.com/api/v1/indicators/${section}/${encodeURIComponent(indicator)}/general`;
    } else if (type === "domain") {
      endpoint = `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(indicator)}/general`;
    } else if (type === "hash") {
      endpoint = `https://otx.alienvault.com/api/v1/indicators/file/${encodeURIComponent(indicator)}/general`;
    } else if (type === "url") {
      endpoint = `https://otx.alienvault.com/api/v1/indicators/url/${encodeURIComponent(indicator)}/general`;
    }

    const res = await fetch(endpoint, {
      method: "GET",
      headers: {
        "X-OTX-API-KEY": apiKey.trim(),
        Accept: "application/json",
      },
      signal: controller.signal,
    });

    if (res.status === 429) {
      return {
        provider: "AlienVault OTX",
        status: "rate_limited",
        verdict: "Unknown",
        details: "AlienVault OTX rate limit reached (HTTP 429).",
        retrievedAt: new Date().toISOString(),
      };
    }

    if (res.status === 404) {
      return {
        provider: "AlienVault OTX",
        status: "success",
        verdict: "Unknown",
        reputationScore: 0,
        detectionsCount: 0,
        totalEngines: 0,
        details: "No active threat pulses recorded for this indicator in AlienVault OTX.",
        retrievedAt: new Date().toISOString(),
      };
    }

    if (!res.ok) {
      const errText = await res.text().catch(() => "");
      return {
        provider: "AlienVault OTX",
        status: "error",
        verdict: "Unknown",
        details: `AlienVault OTX HTTP ${res.status}: ${errText.slice(0, 150)}`,
        retrievedAt: new Date().toISOString(),
      };
    }

    const json: any = await res.json();
    const pulseCount = Number(json?.pulse_info?.count ?? 0);
    const pulses = Array.isArray(json?.pulse_info?.pulses) ? json.pulse_info.pulses : [];
    const pulseNames = pulses.slice(0, 3).map((p: any) => p.name).filter(Boolean);

    let verdict: ThreatVerdict = "Clean";
    if (pulseCount >= 5) {
      verdict = "Malicious";
    } else if (pulseCount >= 1) {
      verdict = "Suspicious";
    }

    const reputationScore = Math.min(100, pulseCount * 20);

    return {
      provider: "AlienVault OTX",
      status: "success",
      verdict,
      reputationScore,
      detectionsCount: pulseCount,
      totalEngines: 50,
      details: pulseCount > 0
        ? `Associated with ${pulseCount} threat pulse(s)${pulseNames.length ? `: ${pulseNames.join("; ")}` : ""}.`
        : "No malicious threat pulses reported in AlienVault OTX.",
      rawAttributes: {
        pulseCount,
        pulses: pulseNames,
        countryName: json?.country_name,
      },
      retrievedAt: new Date().toISOString(),
    };
  } catch (err: any) {
    const isTimeout = err?.name === "AbortError";
    return {
      provider: "AlienVault OTX",
      status: "error",
      verdict: "Unknown",
      details: isTimeout ? `Request timed out after ${DEFAULT_TIMEOUT_MS}ms` : err?.message || "Network error",
      retrievedAt: new Date().toISOString(),
    };
  } finally {
    clearTimeout(timeout);
  }
}

// ---------------------------------------------------------------------------
// 4. Result Synthesis & Consolidation
// ---------------------------------------------------------------------------

function synthesizeResults(
  indicator: string,
  type: IndicatorType,
  providerVerdicts: ProviderVerdict[]
): {
  verdict: ThreatVerdict;
  reputationScore: number;
  detectionsCount: number;
  totalEngines: number;
  confidence: "High" | "Medium" | "Low" | "Unassessed";
  associatedContext: string[];
} {
  const successfulFeeds = providerVerdicts.filter((p) => p.status === "success");

  if (successfulFeeds.length === 0) {
    return {
      verdict: "Unknown",
      reputationScore: 0,
      detectionsCount: 0,
      totalEngines: 0,
      confidence: "Unassessed",
      associatedContext: ["Live threat intelligence feeds unconfigured or unavailable."],
    };
  }

  const isMalicious = successfulFeeds.some((p) => p.verdict === "Malicious");
  const isSuspicious = successfulFeeds.some((p) => p.verdict === "Suspicious");
  const isClean = successfulFeeds.some((p) => p.verdict === "Clean");

  let overallVerdict: ThreatVerdict = "Unknown";
  if (isMalicious) overallVerdict = "Malicious";
  else if (isSuspicious) overallVerdict = "Suspicious";
  else if (isClean) overallVerdict = "Clean";

  // Highest reputation score reported across feeds
  const reputationScore = Math.max(0, ...successfulFeeds.map((p) => p.reputationScore ?? 0));
  const detectionsCount = successfulFeeds.reduce((acc, p) => acc + (p.detectionsCount ?? 0), 0);
  const totalEngines = successfulFeeds.reduce((acc, p) => acc + (p.totalEngines ?? 0), 0);

  let confidence: "High" | "Medium" | "Low" | "Unassessed" = "Medium";
  if (successfulFeeds.length >= 2 || (successfulFeeds.length === 1 && successfulFeeds[0].totalEngines && successfulFeeds[0].totalEngines > 50)) {
    confidence = "High";
  } else if (successfulFeeds.length === 1) {
    confidence = "Medium";
  } else {
    confidence = "Low";
  }

  const associatedContext: string[] = [];
  for (const feed of successfulFeeds) {
    if (feed.details) associatedContext.push(`[${feed.provider}] ${feed.details}`);
  }

  return {
    verdict: overallVerdict,
    reputationScore,
    detectionsCount,
    totalEngines,
    confidence,
    associatedContext,
  };
}

// ---------------------------------------------------------------------------
// 5. Main Lookup Method (with In-Flight Deduplication & DB Cache)
// ---------------------------------------------------------------------------

export async function lookupThreatIntel(
  rawIndicator: string,
  options?: {
    forceRefresh?: boolean;
    explicitType?: string;
  }
): Promise<ThreatIntelResult> {
  const norm = validateAndNormalizeIndicator(rawIndicator, options?.explicitType);
  if (!norm.valid) {
    throw new Error(norm.error || "Invalid indicator format");
  }

  const indicator = norm.normalized;
  const indicatorType = norm.type;
  const forceRefresh = Boolean(options?.forceRefresh);

  // Check in-flight requests (prevent duplicate concurrent requests)
  if (inFlightRequests.has(indicator)) {
    return inFlightRequests.get(indicator)!;
  }

  const lookupPromise: Promise<ThreatIntelResult> = (async (): Promise<ThreatIntelResult> => {
    // 1. Check PostgreSQL cache
    const [cached] = await db
      .select()
      .from(threatIntelCache)
      .where(eq(threatIntelCache.indicator, indicator))
      .limit(1);

    const now = Date.now();
    const lastSeenTime = cached?.lastSeen ? new Date(cached.lastSeen).getTime() : 0;
    const isExpired = cached ? now - lastSeenTime > CACHE_TTL_MS : true;

    // Return fresh cache if not forced and not expired
    if (cached && !forceRefresh && !isExpired) {
      return {
        id: cached.id,
        indicator: cached.indicator,
        indicatorType: cached.indicatorType as IndicatorType,
        verdict: cached.verdict as ThreatVerdict,
        reputationScore: cached.reputationScore,
        detectionsCount: cached.detectionsCount,
        totalEngines: cached.totalEngines,
        confidence: (cached.confidence as any) || "High",
        associatedContext: Array.isArray(cached.associatedContext) ? (cached.associatedContext as string[]) : [],
        feedVerdicts: Array.isArray(cached.feedVerdicts) ? (cached.feedVerdicts as ProviderVerdict[]) : [],
        source: "database_cache" as const,
        isCached: true,
        isStale: false,
        firstSeen: cached.firstSeen ? new Date(cached.firstSeen).toISOString() : new Date().toISOString(),
        lastSeen: cached.lastSeen ? new Date(cached.lastSeen).toISOString() : new Date().toISOString(),
        createdAt: cached.createdAt ? new Date(cached.createdAt).toISOString() : undefined,
      };
    }

    // 2. Query enabled external providers
    const providers = getProviderStatus();
    const tasks: Promise<ProviderVerdict>[] = [];

    // AbuseIPDB (IPs only)
    if (indicatorType === "ip") {
      tasks.push(queryAbuseIPDB(indicator));
    } else {
      tasks.push(
        Promise.resolve({
          provider: "AbuseIPDB",
          status: "not_supported",
          verdict: "Unknown",
          details: `AbuseIPDB only supports IP addresses (indicator is ${indicatorType}).`,
          retrievedAt: new Date().toISOString(),
        })
      );
    }

    // VirusTotal
    tasks.push(queryVirusTotal(indicator, indicatorType));

    // AlienVault OTX
    tasks.push(queryAlienVaultOTX(indicator, indicatorType));

    const settled = await Promise.allSettled(tasks);
    const feedVerdicts: ProviderVerdict[] = settled.map((r, idx) => {
      if (r.status === "fulfilled") return r.value;
      const provName = idx === 0 ? "AbuseIPDB" : idx === 1 ? "VirusTotal" : "AlienVault OTX";
      return {
        provider: provName as any,
        status: "error",
        verdict: "Unknown",
        details: r.reason?.message || "Provider task rejected",
        retrievedAt: new Date().toISOString(),
      };
    });

    const anyConfigured = providers.some((p) => p.configured);

    // If no external providers are configured and we had an expired cache, return the cached record marked stale
    if (!anyConfigured && cached) {
      return {
        id: cached.id,
        indicator: cached.indicator,
        indicatorType: cached.indicatorType as IndicatorType,
        verdict: cached.verdict as ThreatVerdict,
        reputationScore: cached.reputationScore,
        detectionsCount: cached.detectionsCount,
        totalEngines: cached.totalEngines,
        confidence: (cached.confidence as any) || "Medium",
        associatedContext: Array.isArray(cached.associatedContext) ? (cached.associatedContext as string[]) : [],
        feedVerdicts,
        source: "database_cache" as const,
        isCached: true,
        isStale: isExpired,
        firstSeen: cached.firstSeen ? new Date(cached.firstSeen).toISOString() : new Date().toISOString(),
        lastSeen: cached.lastSeen ? new Date(cached.lastSeen).toISOString() : new Date().toISOString(),
      };
    }

    // Synthesize new findings
    const synthesis = synthesizeResults(indicator, indicatorType, feedVerdicts);

    // 3. Persist to PostgreSQL threat_intel_cache
    let savedRecord: typeof threatIntelCache.$inferSelect;
    const timestampNow = new Date();

    if (cached) {
      const [updated] = await db
        .update(threatIntelCache)
        .set({
          indicatorType,
          verdict: anyConfigured ? synthesis.verdict : cached.verdict,
          reputationScore: anyConfigured ? synthesis.reputationScore : cached.reputationScore,
          detectionsCount: anyConfigured ? synthesis.detectionsCount : cached.detectionsCount,
          totalEngines: anyConfigured ? synthesis.totalEngines : cached.totalEngines,
          confidence: anyConfigured ? synthesis.confidence : cached.confidence,
          associatedContext: anyConfigured ? synthesis.associatedContext : cached.associatedContext,
          feedVerdicts,
          lastSeen: timestampNow,
        })
        .where(eq(threatIntelCache.id, cached.id))
        .returning();
      savedRecord = updated;
    } else {
      const [inserted] = await db
        .insert(threatIntelCache)
        .values({
          indicator,
          indicatorType,
          verdict: synthesis.verdict,
          reputationScore: synthesis.reputationScore,
          detectionsCount: synthesis.detectionsCount,
          totalEngines: synthesis.totalEngines,
          confidence: synthesis.confidence,
          associatedContext: synthesis.associatedContext,
          feedVerdicts,
          firstSeen: timestampNow,
          lastSeen: timestampNow,
        })
        .returning();
      savedRecord = inserted;
    }

    return {
      id: savedRecord.id,
      indicator: savedRecord.indicator,
      indicatorType: savedRecord.indicatorType as IndicatorType,
      verdict: savedRecord.verdict as ThreatVerdict,
      reputationScore: savedRecord.reputationScore,
      detectionsCount: savedRecord.detectionsCount,
      totalEngines: savedRecord.totalEngines,
      confidence: (savedRecord.confidence as any) || "High",
      associatedContext: Array.isArray(savedRecord.associatedContext) ? (savedRecord.associatedContext as string[]) : [],
      feedVerdicts: Array.isArray(savedRecord.feedVerdicts) ? (savedRecord.feedVerdicts as ProviderVerdict[]) : [],
      source: (anyConfigured ? "live_feed" : "rule_engine") as "live_feed" | "rule_engine",
      isCached: false,
      isStale: false,
      firstSeen: savedRecord.firstSeen ? new Date(savedRecord.firstSeen).toISOString() : new Date().toISOString(),
      lastSeen: savedRecord.lastSeen ? new Date(savedRecord.lastSeen).toISOString() : new Date().toISOString(),
    };
  })();

  inFlightRequests.set(indicator, lookupPromise);
  try {
    return await lookupPromise;
  } finally {
    inFlightRequests.delete(indicator);
  }
}

// ---------------------------------------------------------------------------
// 6. Indicator Extraction from Alert & Correlated Logs
// ---------------------------------------------------------------------------

export interface ExtractedIndicator {
  indicator: string;
  type: IndicatorType;
  sourceContext: string;
}

export function extractAlertIndicators(alert: any, relatedLogs: any[] = []): ExtractedIndicator[] {
  const seen = new Set<string>();
  const extracted: ExtractedIndicator[] = [];

  const addIfValid = (candidate: any, context: string, explicitType?: IndicatorType) => {
    if (!candidate || typeof candidate !== "string") return;
    const res = validateAndNormalizeIndicator(candidate, explicitType);
    if (res.valid && !seen.has(res.normalized)) {
      seen.add(res.normalized);
      extracted.push({
        indicator: res.normalized,
        type: res.type,
        sourceContext: context,
      });
    }
  };

  // 1. Alert source & destination
  addIfValid(alert.source, "Alert Source Target");
  if (alert.destination) {
    addIfValid(alert.destination, "Alert Destination Target");
  }

  // 2. Alert evidence object
  if (alert.evidence && typeof alert.evidence === "object") {
    const ev = alert.evidence;
    addIfValid(ev.source_ip || ev.sourceIp || ev.src_ip || ev.ip, "Evidence Source IP");
    addIfValid(ev.dest_ip || ev.destinationIp || ev.dst_ip, "Evidence Destination IP");
    addIfValid(ev.domain || ev.hostname || ev.host, "Evidence Domain");
    addIfValid(ev.sha256 || ev.file_hash || ev.hash || ev.md5, "Evidence File Hash", "hash");
    addIfValid(ev.url || ev.request_url, "Evidence URL");
  }

  // 3. Correlated logs
  for (const log of relatedLogs.slice(0, 20)) {
    if (log.sourceIp) addIfValid(log.sourceIp, `Log #${log.id} Source IP`);
    if (log.destinationIp) addIfValid(log.destinationIp, `Log #${log.id} Dest IP`);
    if (log.parsedFields && typeof log.parsedFields === "object") {
      const pf = log.parsedFields;
      addIfValid(pf.domain || pf.host, `Log #${log.id} Domain`);
      addIfValid(pf.sha256 || pf.hash, `Log #${log.id} Hash`, "hash");
      addIfValid(pf.url, `Log #${log.id} URL`);
    }
  }

  return extracted;
}

/**
 * Retrieve threat intelligence for all indicators linked to an alert.
 */
export async function getAlertThreatIntel(alertId: number): Promise<{
  alertId: number;
  indicatorsCount: number;
  indicators: Array<ThreatIntelResult & { sourceContext: string }>;
  summary: {
    maliciousCount: number;
    suspiciousCount: number;
    cleanCount: number;
    unknownCount: number;
    highestReputationScore: number;
  };
}> {
  const [alert] = await db.select().from(alerts).where(eq(alerts.id, alertId)).limit(1);
  if (!alert) {
    throw new Error(`Alert #${alertId} not found`);
  }

  const logIds: number[] = Array.isArray(alert.relatedLogIds) ? (alert.relatedLogIds as number[]) : [];
  let relatedLogs: any[] = [];
  if (logIds.length > 0) {
    relatedLogs = await db.select().from(logs).where(inArray(logs.id, logIds.slice(0, 20)));
  }

  const extracted = extractAlertIndicators(alert, relatedLogs);

  // Look up intelligence for each indicator (uses cache where available)
  const intelList: Array<ThreatIntelResult & { sourceContext: string }> = [];

  for (const item of extracted) {
    try {
      const intel = await lookupThreatIntel(item.indicator, { forceRefresh: false, explicitType: item.type });
      intelList.push({
        ...intel,
        sourceContext: item.sourceContext,
      });
    } catch {
      // Ignore individual lookup errors so other indicators still resolve
    }
  }

  const summary = {
    maliciousCount: intelList.filter((i) => i.verdict === "Malicious").length,
    suspiciousCount: intelList.filter((i) => i.verdict === "Suspicious").length,
    cleanCount: intelList.filter((i) => i.verdict === "Clean").length,
    unknownCount: intelList.filter((i) => i.verdict === "Unknown").length,
    highestReputationScore: Math.max(0, ...intelList.map((i) => i.reputationScore)),
  };

  return {
    alertId,
    indicatorsCount: intelList.length,
    indicators: intelList,
    summary,
  };
}
