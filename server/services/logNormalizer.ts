/**
 * Log Normalizer Service
 * Normalizes multi-source security logs into a structured, vendor-neutral schema.
 *
 * Supported Source Types:
 * 1. Linux Syslog (RFC 3164 / RFC 5424 / auth.log / secure / auditd / sudo)
 * 2. Windows Event Logs (JSON / CSV export e.g. EventID 4625, 4624, 4672, 4728)
 * 3. Firewall Logs (iptables / pfSense / Fortinet / Palo Alto / generic key-value)
 * 4. Web Server Logs (Common Log Format, Combined Log Format, Apache, Nginx access/error)
 * 5. IDS/IPS Alerts (Suricata EVE JSON, Snort fast/full)
 */

export interface NormalizedLog {
  timestamp: Date;
  sourceType: string;
  sourceHost?: string;
  sourceIp?: string;
  destinationIp?: string;
  sourcePort?: number;
  destinationPort?: number;
  protocol?: string;
  username?: string;
  eventId?: string;
  eventCategory?: string;
  logLevel: string;
  rawLog: string;
  parsedFields: Record<string, any>;
  isThreat?: boolean;
  threatReason?: string;
}

export class LogNormalizer {
  /**
   * Main entrypoint to normalize any incoming log payload (object or raw text).
   */
  public static normalize(input: any, defaultSourceType = "Generic Log"): NormalizedLog {
    if (typeof input === "string") {
      return this.normalizeString(input, defaultSourceType);
    }

    if (typeof input === "object" && input !== null) {
      // If the object wraps a rawLog string (e.g. { sourceType: "web", rawLog: "..." })
      if (typeof input.rawLog === "string" && input.rawLog.trim().length > 0) {
        const fromRaw = this.normalizeString(input.rawLog, input.sourceType || defaultSourceType);
        return {
          timestamp: this.safeParseDate(input.timestamp) || fromRaw.timestamp,
          sourceType:
            input.sourceType && !["Generic Ingestion", "Generic Log"].includes(input.sourceType)
              ? input.sourceType
              : fromRaw.sourceType,
          sourceHost: input.sourceHost || fromRaw.sourceHost,
          sourceIp: this.extractValidIp(input.sourceIp) || fromRaw.sourceIp,
          destinationIp: this.extractValidIp(input.destinationIp) || fromRaw.destinationIp,
          sourcePort: this.safeParsePort(input.sourcePort) || fromRaw.sourcePort,
          destinationPort: this.safeParsePort(input.destinationPort) || fromRaw.destinationPort,
          protocol: (input.protocol ? String(input.protocol).toUpperCase() : undefined) || fromRaw.protocol,
          username: input.username || fromRaw.username,
          eventId: (input.eventId ? String(input.eventId) : undefined) || fromRaw.eventId,
          eventCategory: input.eventCategory || fromRaw.eventCategory,
          logLevel: this.normalizeLogLevel(input.logLevel || fromRaw.logLevel),
          rawLog: input.rawLog,
          parsedFields: { ...fromRaw.parsedFields, ...input.parsedFields },
          isThreat: input.isThreat !== undefined ? Boolean(input.isThreat) : fromRaw.isThreat,
          threatReason: input.threatReason || fromRaw.threatReason,
        };
      }

      return this.normalizeObject(input, defaultSourceType);
    }

    const raw = String(input || "");
    return {
      timestamp: new Date(),
      sourceType: defaultSourceType,
      logLevel: "INFO",
      rawLog: raw,
      parsedFields: {},
    };
  }

  /**
   * Normalizes pre-parsed object representations (e.g. JSON ingestion or Suricata EVE).
   */
  private static normalizeObject(obj: Record<string, any>, defaultSourceType: string): NormalizedLog {
    // 1. Suricata EVE JSON Detection
    if (obj.event_type || (obj.alert && obj.alert.signature)) {
      return this.normalizeSuricataEve(obj);
    }

    // 2. Windows Event Log JSON representation
    if (obj.EventID || obj.eventId || (obj.System && obj.System.EventID)) {
      return this.normalizeWindowsEventObject(obj);
    }

    // 3. Generic Object with partial normalized fields
    const rawLog = obj.rawLog || obj.message || obj.raw || JSON.stringify(obj);
    const timestamp = this.safeParseDate(obj.timestamp || obj.time || obj["@timestamp"]) || new Date();
    const sourceType = obj.sourceType || obj.source || obj.type || defaultSourceType;
    const sourceIp = this.extractValidIp(obj.sourceIp || obj.src_ip || obj.client_ip || obj.srcIp);
    const destinationIp = this.extractValidIp(obj.destinationIp || obj.dest_ip || obj.server_ip || obj.dstIp);
    const sourcePort = this.safeParsePort(obj.sourcePort || obj.src_port || obj.srcPort);
    const destinationPort = this.safeParsePort(obj.destinationPort || obj.dest_port || obj.dstPort);
    const protocol = obj.protocol || obj.proto || (obj.network ? obj.network.transport : undefined);
    const username = obj.username || obj.user || obj.accountName || obj.srcUser;
    const eventId = obj.eventId ? String(obj.eventId) : undefined;
    const eventCategory = obj.eventCategory || obj.category || (obj.event ? obj.event.category : undefined);
    const logLevel = this.normalizeLogLevel(obj.logLevel || obj.level || obj.severity || "INFO");

    const parsedFields: Record<string, any> = { ...obj };
    delete parsedFields.rawLog;

    return {
      timestamp,
      sourceType,
      sourceHost: obj.sourceHost || obj.host || obj.hostname,
      sourceIp,
      destinationIp,
      sourcePort,
      destinationPort,
      protocol: protocol ? String(protocol).toUpperCase() : undefined,
      username: username ? String(username) : undefined,
      eventId,
      eventCategory,
      logLevel,
      rawLog,
      parsedFields,
      isThreat: Boolean(obj.isThreat),
      threatReason: obj.threatReason,
    };
  }

  /**
   * Normalizes raw log string into structured fields based on source heuristics.
   */
  private static normalizeString(raw: string, defaultSourceType: string): NormalizedLog {
    const trimmed = raw.trim();

    // Try parsing as JSON first
    if ((trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
      try {
        const parsed = JSON.parse(trimmed);
        if (typeof parsed === "object" && parsed !== null) {
          return this.normalizeObject(parsed, defaultSourceType);
        }
      } catch {
        // Fall through to regex-based text parsing
      }
    }

    // 1. Web Server Access / Error Logs (Common/Combined Log Format)
    const clfMatch = trimmed.match(
      /^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"\s]+)(?:\s+HTTP\/[0-9.]+)?(?:")\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?/
    );
    if (clfMatch) {
      return this.normalizeWebLog(trimmed, clfMatch);
    }

    // 2. Linux Syslog (RFC 3164 e.g. "Oct 28 09:12:00 host process[123]: message")
    const syslogMatch = trimmed.match(
      /^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+([\w\.\-]+)\s+([\w\.\-]+)(?:\[(\d+)\])?:\s*(.*)$/
    );
    if (syslogMatch) {
      return this.normalizeSyslogRfc3164(trimmed, syslogMatch);
    }

    // 3. Linux Syslog RFC 5424 (e.g. "<34>1 2026-10-28T09:12:00Z host process 123 - - message")
    const rfc5424Match = trimmed.match(
      /^<\d+>\d\s+(\S+)\s+([\w\.\-]+)\s+([\w\.\-]+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$/
    );
    if (rfc5424Match) {
      return this.normalizeSyslogRfc5424(trimmed, rfc5424Match);
    }

    // 4. Firewall Key-Value Log (e.g. iptables / pfSense)
    if (trimmed.includes("SRC=") || trimmed.includes("DST=") || trimmed.includes("PROTO=")) {
      return this.normalizeFirewallLog(trimmed);
    }

    // 5. Generic String Fallback
    return this.normalizeGenericString(trimmed, defaultSourceType);
  }

  /**
   * Normalizes Suricata EVE JSON
   */
  private static normalizeSuricataEve(obj: Record<string, any>): NormalizedLog {
    const isAlert = obj.event_type === "alert" || Boolean(obj.alert);
    const alertData = obj.alert || {};
    const timestamp = this.safeParseDate(obj.timestamp) || new Date();

    return {
      timestamp,
      sourceType: "IDS/IPS",
      sourceHost: obj.host,
      sourceIp: this.extractValidIp(obj.src_ip),
      destinationIp: this.extractValidIp(obj.dest_ip),
      sourcePort: this.safeParsePort(obj.src_port),
      destinationPort: this.safeParsePort(obj.dest_port),
      protocol: obj.proto ? String(obj.proto).toUpperCase() : undefined,
      eventId: alertData.signature_id ? String(alertData.signature_id) : undefined,
      eventCategory: alertData.category || "Network Intrusion Detection",
      logLevel: isAlert ? (alertData.severity === 1 ? "CRITICAL" : alertData.severity === 2 ? "HIGH" : "WARN") : "INFO",
      rawLog: JSON.stringify(obj),
      parsedFields: {
        suricataSignature: alertData.signature,
        signatureId: alertData.signature_id,
        severityNumber: alertData.severity,
        action: alertData.action,
        flowId: obj.flow_id,
        appProto: obj.app_proto,
      },
      isThreat: isAlert,
      threatReason: alertData.signature || "IDS signature trigger",
    };
  }

  /**
   * Normalizes Windows Event Log JSON structure (e.g. Sysmon, Security Event Log)
   */
  private static normalizeWindowsEventObject(obj: Record<string, any>): NormalizedLog {
    const eventId = String(obj.EventID || obj.eventId || (obj.System && obj.System.EventID) || "");
    const eventData = obj.EventData || obj.eventData || {};
    const systemData = obj.System || {};

    const timestamp =
      this.safeParseDate(systemData.TimeCreated?.SystemTime || obj.TimeCreated || obj.timestamp) || new Date();
    const sourceHost = systemData.Computer || obj.Computer || obj.host;
    const sourceIp = this.extractValidIp(eventData.IpAddress || eventData.SourceIp || obj.sourceIp || obj.IpAddress);
    const destinationIp = this.extractValidIp(eventData.DestAddress || eventData.DestinationIp || obj.destinationIp || obj.DestAddress);
    const username = eventData.TargetUserName || eventData.SubjectUserName || obj.username || obj.TargetUserName || obj.SubjectUserName;
    const sourcePort = this.safeParsePort(eventData.IpPort || eventData.SourcePort || obj.sourcePort || obj.IpPort);

    let eventCategory = "Windows System";
    let isThreat = false;
    let threatReason: string | undefined;

    switch (eventId) {
      case "4625":
        eventCategory = "Authentication Failure";
        isThreat = true;
        threatReason = `Failed Windows logon attempt for user '${username || "unknown"}'`;
        break;
      case "4624":
        eventCategory = "Authentication Success";
        break;
      case "4672":
        eventCategory = "Privilege Assignment";
        break;
      case "4720":
        eventCategory = "User Account Management";
        break;
      case "4728":
        eventCategory = "Security Group Member Added";
        isThreat = true;
        threatReason = "Member added to security group (potential privilege escalation)";
        break;
      case "4688":
        eventCategory = "Process Creation";
        break;
    }

    return {
      timestamp,
      sourceType: "Windows Event",
      sourceHost,
      sourceIp,
      destinationIp,
      sourcePort,
      username,
      eventId,
      eventCategory,
      logLevel: eventId === "4625" ? "WARN" : "INFO",
      rawLog: JSON.stringify(obj),
      parsedFields: {
        logonType: eventData.LogonType,
        status: eventData.Status,
        subStatus: eventData.SubStatus,
        workstationName: eventData.WorkstationName,
        processName: eventData.ProcessName || eventData.NewProcessName,
      },
      isThreat,
      threatReason,
    };
  }

  /**
   * Normalizes Web Server Access Logs (CLF / Combined format)
   */
  private static normalizeWebLog(raw: string, match: RegExpMatchArray): NormalizedLog {
    const [, clientIp, , identd, dateStr, method, uri, statusCode, bytes, referer, userAgent] = match;

    const timestamp = this.safeParseDate(dateStr) || new Date();
    const status = parseInt(statusCode, 10);
    const sourceIp = this.extractValidIp(clientIp);

    // Extract query parameters if present
    let path = uri;
    let queryParams: Record<string, string> = {};
    if (uri.includes("?")) {
      const [p, q] = uri.split("?", 2);
      path = p;
      try {
        const sp = new URLSearchParams(q);
        sp.forEach((v, k) => {
          queryParams[k] = v;
        });
      } catch {
        // ignore malformed query strings
      }
    }

    const logLevel = status >= 500 ? "ERROR" : status >= 400 ? "WARN" : "INFO";

    return {
      timestamp,
      sourceType: "Web Server",
      sourceIp,
      destinationPort: 443, // Default web port
      protocol: "HTTP",
      username: identd !== "-" ? identd : undefined,
      eventCategory: "Web Access",
      logLevel,
      rawLog: raw,
      parsedFields: {
        httpMethod: method,
        uri,
        path,
        queryParams,
        httpStatus: status,
        bytesSent: bytes !== "-" ? parseInt(bytes, 10) : undefined,
        referer: referer && referer !== "-" ? referer : undefined,
        userAgent: userAgent && userAgent !== "-" ? userAgent : undefined,
      },
    };
  }

  /**
   * Normalizes Linux Syslog RFC 3164
   */
  private static normalizeSyslogRfc3164(raw: string, match: RegExpMatchArray): NormalizedLog {
    const [, dateStr, hostname, processName, pid, message] = match;

    const timestamp = this.safeParseDate(dateStr) || new Date();

    // If message contains firewall key-values (e.g. iptables/kernel logging via syslog)
    if (message.includes("SRC=") || message.includes("DST=") || processName === "kernel") {
      const fw = this.normalizeFirewallLog(raw);
      return {
        ...fw,
        timestamp,
        sourceHost: hostname,
      };
    }

    const sourceIp = this.findFirstIpInText(message);
    const username = this.findUsernameInText(message);

    let eventCategory = "System Log";
    let isThreat = false;
    let threatReason: string | undefined;

    // Detect SSH auth failure
    if (message.includes("Failed password") || message.includes("authentication failure")) {
      eventCategory = "Authentication Failure";
      isThreat = true;
      threatReason = `SSH authentication failure for user '${username || "unknown"}'`;
    } else if (message.includes("Accepted password") || message.includes("Accepted publickey")) {
      eventCategory = "Authentication Success";
    } else if (processName === "sudo" || message.includes("sudo:")) {
      eventCategory = "Privilege Escalation";
      if (message.includes("NOT in sudoers") || message.includes("incorrect password attempts")) {
        isThreat = true;
        threatReason = `Unauthorized sudo command attempt by user '${username || "unknown"}'`;
      }
    }

    return {
      timestamp,
      sourceType: "Linux Syslog",
      sourceHost: hostname,
      sourceIp,
      username,
      eventCategory,
      logLevel: isThreat ? "WARN" : "INFO",
      rawLog: raw,
      parsedFields: {
        processName,
        processId: pid ? parseInt(pid, 10) : undefined,
        syslogMessage: message,
      },
      isThreat,
      threatReason,
    };
  }

  /**
   * Normalizes Linux Syslog RFC 5424
   */
  private static normalizeSyslogRfc5424(raw: string, match: RegExpMatchArray): NormalizedLog {
    const [, dateStr, hostname, appName, procId, msgId, , message] = match;

    const timestamp = this.safeParseDate(dateStr) || new Date();
    const sourceIp = this.findFirstIpInText(message);
    const username = this.findUsernameInText(message);

    return {
      timestamp,
      sourceType: "Linux Syslog",
      sourceHost: hostname !== "-" ? hostname : undefined,
      sourceIp,
      username,
      eventId: msgId !== "-" ? msgId : undefined,
      eventCategory: "System Log",
      logLevel: "INFO",
      rawLog: raw,
      parsedFields: {
        appName: appName !== "-" ? appName : undefined,
        procId: procId !== "-" ? procId : undefined,
        message,
      },
    };
  }

  /**
   * Normalizes Key-Value Firewall Logs (iptables / pfSense)
   */
  private static normalizeFirewallLog(raw: string): NormalizedLog {
    const parsedFields: Record<string, string> = {};
    const tokens = raw.split(/\s+/);

    for (const token of tokens) {
      if (token.includes("=")) {
        const [k, v] = token.split("=", 2);
        parsedFields[k.trim()] = v.trim();
      }
    }

    const sourceIp = this.extractValidIp(parsedFields.SRC || parsedFields.src || parsedFields.source);
    const destinationIp = this.extractValidIp(parsedFields.DST || parsedFields.dst || parsedFields.destination);
    const sourcePort = this.safeParsePort(parsedFields.SPT || parsedFields.spt);
    const destinationPort = this.safeParsePort(parsedFields.DPT || parsedFields.dpt);
    const protocol = parsedFields.PROTO || parsedFields.proto;
    const action = parsedFields.ACTION || parsedFields.action || (raw.includes("DROP") ? "DROP" : raw.includes("ACCEPT") ? "ACCEPT" : undefined);

    return {
      timestamp: new Date(),
      sourceType: "Firewall",
      sourceIp,
      destinationIp,
      sourcePort,
      destinationPort,
      protocol: protocol ? protocol.toUpperCase() : undefined,
      eventCategory: "Network Traffic",
      logLevel: action === "DROP" || action === "REJECT" ? "WARN" : "INFO",
      rawLog: raw,
      parsedFields: {
        ...parsedFields,
        action,
      },
    };
  }

  /**
   * Fallback for generic text logs
   */
  private static normalizeGenericString(raw: string, defaultSourceType: string): NormalizedLog {
    const sourceIp = this.findFirstIpInText(raw);
    const username = this.findUsernameInText(raw);

    return {
      timestamp: new Date(),
      sourceType: defaultSourceType,
      sourceIp,
      username,
      logLevel: "INFO",
      rawLog: raw,
      parsedFields: {},
    };
  }

  // ---------------------------------------------------------------------------
  // Helper Parsers
  // ---------------------------------------------------------------------------

  public static safeParseDate(value: any): Date | null {
    if (!value) return null;
    if (value instanceof Date && !isNaN(value.getTime())) return value;

    // Handle Apache common date: "28/Oct/2026:10:00:00 +0000"
    if (typeof value === "string") {
      const apacheMatch = value.match(/^(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}:\d{2}:\d{2})\s+([+\-]\d{4})$/);
      if (apacheMatch) {
        const [, day, month, year, time, tz] = apacheMatch;
        const formatted = `${day} ${month} ${year} ${time} ${tz}`;
        const d = new Date(formatted);
        if (!isNaN(d.getTime())) return d;
      }

      // Handle standard ISO / Syslog strings
      const d = new Date(value);
      if (!isNaN(d.getTime())) return d;
    }

    return null;
  }

  public static extractValidIp(ip: any): string | undefined {
    if (!ip || typeof ip !== "string") return undefined;
    const trimmed = ip.trim();
    // IPv4 validation
    const ipv4Regex = /^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (ipv4Regex.test(trimmed)) return trimmed;

    // Basic IPv6 validation
    if (trimmed.includes(":") && trimmed.length <= 45) return trimmed;

    return undefined;
  }

  public static safeParsePort(port: any): number | undefined {
    if (port === undefined || port === null) return undefined;
    const num = parseInt(String(port), 10);
    if (!isNaN(num) && num >= 1 && num <= 65535) {
      return num;
    }
    return undefined;
  }

  public static normalizeLogLevel(level: string): string {
    const upper = String(level || "").toUpperCase();
    if (upper.includes("CRIT") || upper.includes("FATAL") || upper === "EMERG") return "CRITICAL";
    if (upper.includes("ERR") || upper.includes("FAIL")) return "ERROR";
    if (upper.includes("WARN")) return "WARN";
    if (upper.includes("DEBUG") || upper.includes("TRACE")) return "DEBUG";
    return "INFO";
  }

  private static findFirstIpInText(text: string): string | undefined {
    const match = text.match(/\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/);
    return match ? match[0] : undefined;
  }

  private static findUsernameInText(text: string): string | undefined {
    const userMatch =
      text.match(/(?:for invalid user|for user|for\s+|user=|USER=|user\s+)([\w\.\-]+)/i) ||
      text.match(/([a-zA-Z0-9_\-\.]+)\s*:\s*user NOT in sudoers/i);

    if (userMatch && userMatch[1]) {
      const user = userMatch[1].trim();
      if (user && user !== "unknown" && user !== "none") {
        return user;
      }
    }
    return undefined;
  }

  /**
   * Parses raw file content (multi-line text, JSON, or CSV) into an array of NormalizedLog.
   */
  public static parseFileContent(content: string, defaultSourceType = "File Upload"): NormalizedLog[] {
    const trimmed = content.trim();
    if (!trimmed) return [];

    // 1. JSON Array
    if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
      try {
        const parsed = JSON.parse(trimmed);
        if (Array.isArray(parsed)) {
          return parsed.map((item) => this.normalize(item, defaultSourceType));
        }
      } catch {
        // Fall back to line-by-line
      }
    }

    // 2. Line-by-line parsing (Syslog, CLF, or NDJSON)
    const lines = trimmed.split(/\r?\n/).filter((l) => l.trim().length > 0);
    const results: NormalizedLog[] = [];

    // Check if CSV format (header with commas)
    if (lines.length > 1 && lines[0].includes(",") && (lines[0].toLowerCase().includes("time") || lines[0].toLowerCase().includes("event"))) {
      const headers = lines[0].split(",").map((h) => h.trim().replace(/^"|"$/g, ""));
      for (let i = 1; i < lines.length; i++) {
        const values = lines[i].split(",").map((v) => v.trim().replace(/^"|"$/g, ""));
        const rowObj: Record<string, string> = {};
        headers.forEach((h, idx) => {
          rowObj[h] = values[idx] || "";
        });
        results.push(this.normalize(rowObj, defaultSourceType));
      }
      return results;
    }

    for (const line of lines) {
      results.push(this.normalize(line, defaultSourceType));
    }

    return results;
  }
}
