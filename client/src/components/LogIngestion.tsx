/**
 * Log Ingestion and Security Telemetry Component (Phase 3)
 * Provides:
 * - Real-time filtered log query and inspection
 * - Manual log submission with pre-loaded attack templates
 * - Multi-format log file upload (.log, .txt, .json, .csv)
 * - Raw and normalized field inspector
 * - Live detection engine alert feedback
 */

import { useEffect, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
  Check,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Clock,
  Copy,
  FileCode,
  FileSearch,
  FileText,
  Filter,
  Info,
  Loader2,
  Plus,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  UploadCloud,
  X,
} from "lucide-react";
import { toast } from "sonner";
import { api, type AlertItem, type LogItem, type PythonLogEnrichment } from "@/lib/api";
import { useAuth } from "@/contexts/AuthContext";

export function LogIngestion() {
  const { user, checkPermission } = useAuth();

  // Logs stream state
  const [logsList, setLogsList] = useState<LogItem[]>([]);
  const [total, setTotal] = useState(0);
  const [sourceCounts, setSourceCounts] = useState<Record<string, number>>({});
  const [loading, setLoading] = useState(true);

  // Filters & Pagination
  const [search, setSearch] = useState("");
  const [sourceType, setSourceType] = useState("All");
  const [logLevel, setLogLevel] = useState("All");
  const [isThreat, setIsThreat] = useState("All");
  const [page, setPage] = useState(1);
  const limit = 25;

  // Selected log for detailed inspection drawer
  const [selectedLog, setSelectedLog] = useState<LogItem | null>(null);
  const [selectedLogAlerts, setSelectedLogAlerts] = useState<AlertItem[]>([]);
  const [loadingDetail, setLoadingDetail] = useState(false);

  // Modals
  const [manualModalOpen, setManualModalOpen] = useState(false);
  const [uploadModalOpen, setUploadModalOpen] = useState(false);

  // Manual submission form state
  const [manualSourceType, setManualSourceType] = useState("Linux Syslog");
  const [manualRawLog, setManualRawLog] = useState("");
  const [submittingManual, setSubmittingManual] = useState(false);
  const [lastSubmissionResult, setLastSubmissionResult] = useState<{
    log: LogItem;
    alerts: AlertItem[];
  } | null>(null);

  // File upload form state
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadSourceType, setUploadSourceType] = useState("Generic Log File");
  const [uploading, setUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState<{
    fileName: string;
    logsIngested: number;
    alertsGeneratedCount: number;
    pythonAnalysis?: PythonLogEnrichment;
  } | null>(null);
  const [showPythonDetails, setShowPythonDetails] = useState(false);

  const fetchLogs = async () => {
    try {
      setLoading(true);
      const offset = (page - 1) * limit;
      const res = await api.getLogs({
        search,
        sourceType,
        logLevel,
        isThreat,
        limit,
        offset,
      });
      setLogsList(res.items);
      setTotal(res.total);
      setSourceCounts(res.sourceCounts);
    } catch (err: any) {
      console.error("Failed to fetch logs:", err);
      toast.error(err.message || "Failed to query logs from PostgreSQL");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [search, sourceType, logLevel, isThreat, page]);

  const handleInspectLog = async (log: LogItem) => {
    setSelectedLog(log);
    try {
      setLoadingDetail(true);
      const res = await api.getLogById(log.id);
      setSelectedLogAlerts(res.relatedAlerts || []);
    } catch {
      setSelectedLogAlerts([]);
    } finally {
      setLoadingDetail(false);
    }
  };

  // Pre-configured attack templates for analysts
  const templates = [
    {
      name: "SSH Brute Force Failure",
      sourceType: "Linux Syslog",
      rawLog:
        "Oct 28 11:15:30 edge-gateway-01 sshd[28491]: Failed password for invalid user admin from 198.51.100.42 port 48192 ssh2",
    },
    {
      name: "SQL Injection (' OR 1=1)",
      sourceType: "Web Server",
      rawLog:
        '198.51.100.42 - - [28/Oct/2026:11:16:02 +0000] "GET /api/users?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 200 4821 "-" "sqlmap/1.7#stable"',
    },
    {
      name: "XSS Script Injection",
      sourceType: "Web Server",
      rawLog:
        '198.51.100.42 - - [28/Oct/2026:11:16:45 +0000] "GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1" 200 1420 "-" "Mozilla/5.0"',
    },
    {
      name: "Firewall Reconnaissance Probe",
      sourceType: "Firewall",
      rawLog:
        "SRC=198.51.100.42 DST=10.0.1.20 PROTO=TCP SPT=54210 DPT=445 ACTION=DROP",
    },
    {
      name: "Unauthorized Sudo Escalation",
      sourceType: "Linux Syslog",
      rawLog:
        "Oct 28 11:18:10 prod-app-srv sudo: webguest : user NOT in sudoers ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
    },
    {
      name: "Windows Logon Failure (4625)",
      sourceType: "Windows Event",
      rawLog: JSON.stringify({
        EventID: "4625",
        TimeCreated: new Date().toISOString(),
        Computer: "DC-01.corp.internal",
        EventData: {
          TargetUserName: "Administrator",
          IpAddress: "198.51.100.42",
          IpPort: "52140",
          LogonType: "3",
          Status: "0xc000006d",
        },
      }),
    },
    {
      name: "Auth Success Following Failures",
      sourceType: "Linux Syslog",
      rawLog:
        "Oct 28 11:20:00 edge-gateway-01 sshd[29012]: Accepted password for admin from 198.51.100.42 port 49102 ssh2",
    },
  ];

  const handleApplyTemplate = (tmpl: (typeof templates)[0]) => {
    setManualSourceType(tmpl.sourceType);
    setManualRawLog(tmpl.rawLog);
  };

  const handleManualSubmit = async () => {
    if (!manualRawLog.trim()) {
      toast.error("Please enter a raw log payload or choose a template.");
      return;
    }

    if (!checkPermission("ingest:logs")) {
      toast.error("Forbidden: Your active role lacks 'ingest:logs' permission.");
      return;
    }

    try {
      setSubmittingManual(true);
      setLastSubmissionResult(null);

      const res = await api.ingestLog({
        sourceType: manualSourceType,
        rawLog: manualRawLog.trim(),
      });

      setLastSubmissionResult({
        log: res.log,
        alerts: res.alertsGenerated || [],
      });

      if (res.alertsGenerated && res.alertsGenerated.length > 0) {
        toast.warning(
          `Log ingested! Triggered ${res.alertsGenerated.length} security alert(s): ${res.alertsGenerated
            .map((a) => a.title)
            .join("; ")}`
        );
      } else {
        toast.success(`Log #${res.log.id} successfully ingested and normalized.`);
      }

      fetchLogs();
    } catch (err: any) {
      toast.error(err.message || "Failed to ingest log");
    } finally {
      setSubmittingManual(false);
    }
  };

  const handleFileUpload = async () => {
    if (!selectedFile) {
      toast.error("Please select a log file to upload.");
      return;
    }

    if (!checkPermission("ingest:logs")) {
      toast.error("Forbidden: Your active role lacks 'ingest:logs' permission.");
      return;
    }

    try {
      setUploading(true);
      setUploadResult(null);

      const res = await api.uploadLogFile(selectedFile, uploadSourceType);
      setUploadResult({
        fileName: res.fileName,
        logsIngested: res.logsIngested,
        alertsGeneratedCount: res.alertsGeneratedCount,
        pythonAnalysis: res.pythonAnalysis,
      });

      toast.success(
        `File processed: Ingested ${res.logsIngested} logs; Generated ${res.alertsGeneratedCount} alerts.`
      );
      fetchLogs();
    } catch (err: any) {
      toast.error(err.message || "Failed to upload log file");
    } finally {
      setUploading(false);
    }
  };

  const totalPages = Math.ceil(total / limit) || 1;

  return (
    <div className="space-y-5 px-4 py-6 md:px-7">
      {/* Top Telemetry Metric Cards */}
      <div className="grid gap-3 sm:grid-cols-4">
        <div className="rounded-xl border border-white/[0.08] bg-[#14181b] p-4">
          <div className="flex items-center justify-between">
            <span className="font-display text-[10px] font-semibold uppercase tracking-wider text-slate-500">
              Total Ingested Logs
            </span>
            <Terminal size={15} className="text-[#b7f960]" />
          </div>
          <p className="mt-2 font-display text-2xl font-bold text-slate-100">{total}</p>
          <span className="text-[11px] text-slate-500">Persisted in PostgreSQL</span>
        </div>

        <div className="rounded-xl border border-white/[0.08] bg-[#14181b] p-4">
          <div className="flex items-center justify-between">
            <span className="font-display text-[10px] font-semibold uppercase tracking-wider text-slate-500">
              Threat Flags Surfaced
            </span>
            <ShieldAlert size={15} className="text-[#e16c5c]" />
          </div>
          <p className="mt-2 font-display text-2xl font-bold text-[#e16c5c]">
            {logsList.filter((l) => l.isThreat).length}
          </p>
          <span className="text-[11px] text-slate-500">In current query view</span>
        </div>

        <div className="rounded-xl border border-white/[0.08] bg-[#14181b] p-4">
          <div className="flex items-center justify-between">
            <span className="font-display text-[10px] font-semibold uppercase tracking-wider text-slate-500">
              Active Source Types
            </span>
            <Filter size={15} className="text-[#6fb6cc]" />
          </div>
          <p className="mt-2 font-display text-2xl font-bold text-slate-100">
            {Object.keys(sourceCounts).length || 5}
          </p>
          <span className="text-[11px] text-slate-500">Syslog, Win, Web, FW, IDS</span>
        </div>

        <div className="rounded-xl border border-white/[0.08] bg-[#14181b] p-4">
          <div className="flex items-center justify-between">
            <span className="font-display text-[10px] font-semibold uppercase tracking-wider text-slate-500">
              Detection Pipeline
            </span>
            <span className="h-2 w-2 rounded-full bg-[#b7f960] shadow-[0_0_8px_#b7f960]" />
          </div>
          <p className="mt-2 font-display text-2xl font-bold text-[#b7f960]">Deterministic</p>
          <span className="text-[11px] text-slate-500">6 Active Correlated Rules</span>
        </div>
      </div>

      {/* Control Actions Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          {["All", "Linux Syslog", "Windows Event", "Web Server", "Firewall", "IDS/IPS"].map((src) => (
            <button
              key={src}
              onClick={() => {
                setSourceType(src);
                setPage(1);
              }}
              className={`rounded-lg px-3 py-1.5 font-display text-[10px] font-semibold uppercase tracking-wider transition ${
                sourceType === src
                  ? "bg-[#b7f960]/15 text-[#b7f960] border border-[#b7f960]/30"
                  : "bg-white/[0.035] text-slate-400 hover:text-slate-200"
              }`}
            >
              {src} {sourceCounts[src] ? `(${sourceCounts[src]})` : ""}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setManualModalOpen(true)}
            className="flex items-center gap-1.5 rounded-lg border border-white/[0.1] bg-white/[0.04] px-3 py-1.5 font-display text-xs font-semibold text-slate-200 transition hover:bg-white/[0.08]"
          >
            <Plus size={14} className="text-[#b7f960]" /> Manual Log Submission
          </button>
          <button
            onClick={() => setUploadModalOpen(true)}
            className="flex items-center gap-1.5 rounded-lg border border-[#b7f960]/30 bg-[#b7f960]/10 px-3 py-1.5 font-display text-xs font-semibold text-[#b7f960] transition hover:bg-[#b7f960]/20"
          >
            <UploadCloud size={14} /> Upload Log File
          </button>
          <button
            onClick={fetchLogs}
            title="Refresh stream"
            className="rounded-lg border border-white/[0.1] bg-white/[0.04] p-1.5 text-slate-400 transition hover:bg-white/[0.08] hover:text-slate-200"
          >
            <RefreshCw size={14} />
          </button>
        </div>
      </div>

      {/* Search and Secondary Filter Rail */}
      <div className="flex flex-col gap-3 rounded-xl border border-white/[0.08] bg-[#14181b] p-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="relative flex-1">
          <Search size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
            placeholder="Search raw log message, IP, port, host, or username..."
            className="h-9 w-full rounded-lg border border-white/[0.08] bg-black/20 pl-9 pr-3 text-xs text-slate-200 outline-none placeholder:text-slate-500 focus:border-[#b7f960]/40"
          />
        </div>

        <div className="flex items-center gap-2">
          <select
            value={logLevel}
            onChange={(e) => {
              setLogLevel(e.target.value);
              setPage(1);
            }}
            className="h-9 rounded-lg border border-white/[0.08] bg-black/20 px-3 text-xs text-slate-300 outline-none focus:border-[#b7f960]/40"
          >
            <option value="All">All Levels</option>
            <option value="INFO">INFO</option>
            <option value="WARN">WARN</option>
            <option value="ERROR">ERROR</option>
            <option value="CRITICAL">CRITICAL</option>
          </select>

          <select
            value={isThreat}
            onChange={(e) => {
              setIsThreat(e.target.value);
              setPage(1);
            }}
            className="h-9 rounded-lg border border-white/[0.08] bg-black/20 px-3 text-xs text-slate-300 outline-none focus:border-[#b7f960]/40"
          >
            <option value="All">All Logs</option>
            <option value="true">Threats Only</option>
            <option value="false">Benign Only</option>
          </select>
        </div>
      </div>

      {/* Main Logs Table */}
      <div className="overflow-hidden rounded-xl border border-white/[0.08] bg-[#14181b]">
        {loading ? (
          <div className="flex items-center justify-center p-16 text-slate-400">
            <Loader2 className="mr-2 animate-spin text-[#b7f960]" size={20} />
            Loading security log stream from PostgreSQL...
          </div>
        ) : logsList.length === 0 ? (
          <div className="p-16 text-center text-slate-400">
            <Terminal size={32} className="mx-auto text-slate-500" />
            <p className="mt-3 font-semibold text-slate-200">No logs match the current query criteria.</p>
            <p className="mt-1 text-xs text-slate-500">
              Try adjusting your search terms, source type, or submit a test log via the action buttons above.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="border-b border-white/[0.08] bg-black/30 font-display text-[10px] uppercase tracking-wider text-slate-500">
                <tr>
                  <th className="py-3 pl-4 pr-2">ID & Time</th>
                  <th className="px-2 py-3">Source Type</th>
                  <th className="px-2 py-3">Source → Destination</th>
                  <th className="px-2 py-3">User / Event</th>
                  <th className="px-2 py-3">Level</th>
                  <th className="px-2 py-3">Threat</th>
                  <th className="px-2 py-3">Raw Log Preview</th>
                  <th className="py-3 pl-2 pr-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.05]">
                {logsList.map((item) => (
                  <tr
                    key={item.id}
                    className={`transition hover:bg-white/[0.03] ${
                      item.isThreat ? "bg-red-500/[0.03]" : ""
                    }`}
                  >
                    <td className="py-3 pl-4 pr-2 font-mono text-[11px] text-slate-400">
                      <span className="text-slate-200 font-semibold">#{item.id}</span>
                      <br />
                      <span className="text-[10px]">
                        {new Date(item.timestamp).toLocaleTimeString([], {
                          hour: "2-digit",
                          minute: "2-digit",
                          second: "2-digit",
                        })}
                      </span>
                    </td>

                    <td className="px-2 py-3">
                      <span className="rounded bg-white/[0.06] px-2 py-0.5 font-display text-[9px] font-semibold text-slate-300">
                        {item.sourceType}
                      </span>
                    </td>

                    <td className="px-2 py-3 font-mono text-[11px]">
                      {item.sourceIp || item.sourceHost || "-"}
                      {item.destinationIp && (
                        <span className="text-slate-500">
                          {" "}
                          → {item.destinationIp}
                          {item.destinationPort ? `:${item.destinationPort}` : ""}
                        </span>
                      )}
                    </td>

                    <td className="px-2 py-3 font-mono text-[11px] text-slate-300">
                      {item.username ? (
                        <span className="text-slate-200">{item.username}</span>
                      ) : item.eventId ? (
                        <span className="text-slate-400">ID: {item.eventId}</span>
                      ) : (
                        <span className="text-slate-600">-</span>
                      )}
                    </td>

                    <td className="px-2 py-3">
                      <span
                        className={`rounded px-1.5 py-0.5 font-display text-[9px] font-bold ${
                          item.logLevel === "CRITICAL" || item.logLevel === "ERROR"
                            ? "bg-red-500/20 text-red-300"
                            : item.logLevel === "WARN"
                            ? "bg-amber-500/20 text-amber-300"
                            : "bg-slate-700/30 text-slate-300"
                        }`}
                      >
                        {item.logLevel}
                      </span>
                    </td>

                    <td className="px-2 py-3">
                      {item.isThreat ? (
                        <span className="inline-flex items-center gap-1 rounded bg-red-500/15 px-2 py-0.5 font-display text-[9px] font-bold uppercase tracking-wider text-red-300 border border-red-500/30">
                          <AlertTriangle size={10} /> Threat
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 rounded bg-slate-800/40 px-1.5 py-0.5 font-display text-[9px] text-slate-500">
                          Normal
                        </span>
                      )}
                    </td>

                    <td className="max-w-md truncate px-2 py-3 font-mono text-[11px] text-slate-400">
                      {item.rawLog}
                    </td>

                    <td className="py-3 pl-2 pr-4 text-right">
                      <button
                        onClick={() => handleInspectLog(item)}
                        className="rounded border border-white/[0.08] bg-white/[0.03] px-2.5 py-1 text-[11px] font-medium text-slate-300 transition hover:bg-white/[0.08] hover:text-[#b7f960]"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Bar */}
        <div className="flex items-center justify-between border-t border-white/[0.08] bg-black/20 px-4 py-3 text-xs text-slate-400">
          <span>
            Showing {logsList.length} of {total} total logs (Page {page} of {totalPages})
          </span>
          <div className="flex items-center gap-1.5">
            <button
              disabled={page <= 1}
              onClick={() => setPage((p) => Math.max(p - 1, 1))}
              className="rounded border border-white/[0.08] bg-white/[0.02] p-1.5 disabled:opacity-40"
            >
              <ChevronLeft size={14} />
            </button>
            <button
              disabled={page >= totalPages}
              onClick={() => setPage((p) => p + 1)}
              className="rounded border border-white/[0.08] bg-white/[0.02] p-1.5 disabled:opacity-40"
            >
              <ChevronRight size={14} />
            </button>
          </div>
        </div>
      </div>

      {/* Log Detail Inspector Modal */}
      {selectedLog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-md animate-in fade-in duration-200">
          <div className="relative flex max-h-[90vh] w-full max-w-3xl flex-col overflow-hidden rounded-2xl border border-white/[0.12] bg-[#121619] shadow-2xl">
            <div className="flex items-center justify-between border-b border-white/[0.08] bg-[#171c20] p-4">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-display text-sm font-semibold text-slate-100">
                    Log Inspection #{selectedLog.id}
                  </span>
                  <span className="rounded bg-white/[0.06] px-2 py-0.5 font-display text-[9px] uppercase tracking-wider text-slate-300">
                    {selectedLog.sourceType}
                  </span>
                  {selectedLog.isThreat && (
                    <span className="rounded border border-red-500/30 bg-red-500/20 px-2 py-0.5 font-display text-[9px] font-bold text-red-300">
                      Threat Match
                    </span>
                  )}
                </div>
                <p className="mt-0.5 text-xs text-slate-400">
                  Ingested: {new Date(selectedLog.createdAt).toLocaleString()}
                </p>
              </div>
              <button
                onClick={() => setSelectedLog(null)}
                className="rounded-lg p-1.5 text-slate-400 hover:bg-white/[0.08] hover:text-white"
              >
                <X size={18} />
              </button>
            </div>

            <div className="flex-1 space-y-4 overflow-y-auto p-5 text-xs text-slate-300">
              {/* Threat Reason Banner */}
              {selectedLog.isThreat && (
                <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-3.5 text-red-300">
                  <p className="font-display text-[10px] font-bold uppercase tracking-wider">
                    Detection Triggered
                  </p>
                  <p className="mt-1 font-medium">{selectedLog.threatReason || "Malicious activity identified."}</p>
                </div>
              )}

              {/* Normalized Fields Grid */}
              <div className="rounded-xl border border-white/[0.08] bg-black/30 p-4">
                <p className="font-display text-[10px] font-bold uppercase tracking-wider text-slate-500">
                  Normalized Common Schema
                </p>
                <div className="mt-3 grid gap-2.5 sm:grid-cols-3">
                  <div>
                    <span className="text-[10px] uppercase text-slate-500">Source IP</span>
                    <p className="font-mono text-slate-200">{selectedLog.sourceIp || "None"}</p>
                  </div>
                  <div>
                    <span className="text-[10px] uppercase text-slate-500">Destination IP</span>
                    <p className="font-mono text-slate-200">{selectedLog.destinationIp || "None"}</p>
                  </div>
                  <div>
                    <span className="text-[10px] uppercase text-slate-500">Ports (Src / Dst)</span>
                    <p className="font-mono text-slate-200">
                      {selectedLog.sourcePort || "-"}:{selectedLog.destinationPort || "-"}
                    </p>
                  </div>
                  <div>
                    <span className="text-[10px] uppercase text-slate-500">User</span>
                    <p className="font-mono text-slate-200">{selectedLog.username || "None"}</p>
                  </div>
                  <div>
                    <span className="text-[10px] uppercase text-slate-500">Event ID</span>
                    <p className="font-mono text-slate-200">{selectedLog.eventId || "None"}</p>
                  </div>
                  <div>
                    <span className="text-[10px] uppercase text-slate-500">Event Category</span>
                    <p className="font-mono text-slate-200">{selectedLog.eventCategory || "None"}</p>
                  </div>
                </div>
              </div>

              {/* Raw Log */}
              <div>
                <div className="flex items-center justify-between">
                  <span className="font-display text-[10px] font-bold uppercase tracking-wider text-slate-500">
                    Original Raw Log
                  </span>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(selectedLog.rawLog);
                      toast.success("Raw log copied to clipboard");
                    }}
                    className="flex items-center gap-1 text-[11px] text-[#b7f960] hover:underline"
                  >
                    <Copy size={12} /> Copy
                  </button>
                </div>
                <pre className="mt-1.5 max-h-40 overflow-x-auto rounded-lg border border-white/[0.08] bg-[#0a0d0f] p-3 font-mono text-[11px] text-slate-300">
                  {selectedLog.rawLog}
                </pre>
              </div>

              {/* Parsed Fields JSON */}
              {selectedLog.parsedFields && Object.keys(selectedLog.parsedFields).length > 0 && (
                <div>
                  <span className="font-display text-[10px] font-bold uppercase tracking-wider text-slate-500">
                    Parsed Vendor Fields (JSONB)
                  </span>
                  <pre className="mt-1.5 max-h-40 overflow-x-auto rounded-lg border border-white/[0.08] bg-[#0a0d0f] p-3 font-mono text-[11px] text-slate-300">
                    {JSON.stringify(selectedLog.parsedFields, null, 2)}
                  </pre>
                </div>
              )}

              {/* Linked Alerts */}
              {selectedLogAlerts.length > 0 && (
                <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-3.5">
                  <p className="font-display text-[10px] font-bold uppercase tracking-wider text-amber-300">
                    Linked Security Alerts ({selectedLogAlerts.length})
                  </p>
                  <div className="mt-2 space-y-1.5">
                    {selectedLogAlerts.map((a) => (
                      <div
                        key={a.id}
                        className="flex items-center justify-between rounded-lg bg-black/30 p-2 text-xs"
                      >
                        <span className="font-semibold text-slate-200">{a.title}</span>
                        <span className="rounded bg-amber-500/20 px-1.5 py-0.5 font-display text-[9px] font-bold text-amber-300">
                          {a.severity}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="border-t border-white/[0.08] bg-[#171c20] p-3 text-right">
              <button
                onClick={() => setSelectedLog(null)}
                className="rounded-lg border border-white/[0.1] bg-white/[0.04] px-4 py-1.5 text-xs font-semibold text-slate-200 hover:bg-white/[0.08]"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Manual Submission Modal */}
      {manualModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-md animate-in fade-in duration-200">
          <div className="relative flex max-h-[90vh] w-full max-w-2xl flex-col overflow-hidden rounded-2xl border border-white/[0.12] bg-[#121619] shadow-2xl">
            <div className="flex items-center justify-between border-b border-white/[0.08] bg-[#171c20] p-4">
              <div>
                <h3 className="font-display text-sm font-semibold text-slate-100">
                  Manual Security Log Ingestion
                </h3>
                <p className="text-xs text-slate-400">
                  Submit a log line to test parsing and trigger deterministic detection engine rules.
                </p>
              </div>
              <button
                onClick={() => setManualModalOpen(false)}
                className="rounded-lg p-1.5 text-slate-400 hover:bg-white/[0.08] hover:text-white"
              >
                <X size={18} />
              </button>
            </div>

            <div className="flex-1 space-y-4 overflow-y-auto p-5 text-xs text-slate-300">
              {/* Attack Templates Rail */}
              <div>
                <span className="font-display text-[10px] font-bold uppercase tracking-wider text-slate-500">
                  Load Pre-configured Security Scenario:
                </span>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {templates.map((tmpl) => (
                    <button
                      key={tmpl.name}
                      type="button"
                      onClick={() => handleApplyTemplate(tmpl)}
                      className="rounded border border-white/[0.08] bg-white/[0.03] px-2 py-1 text-[11px] text-slate-300 transition hover:border-[#b7f960]/40 hover:bg-[#b7f960]/10 hover:text-[#b7f960]"
                    >
                      {tmpl.name}
                    </button>
                  ))}
                </div>
              </div>

              {/* Source Type Selector */}
              <div>
                <label className="font-display text-[10px] font-bold uppercase tracking-wider text-slate-400">
                  Log Source Type
                </label>
                <select
                  value={manualSourceType}
                  onChange={(e) => setManualSourceType(e.target.value)}
                  className="mt-1 h-9 w-full rounded-lg border border-white/[0.1] bg-[#0a0d0f] px-3 text-xs text-slate-200 outline-none focus:border-[#b7f960]/40"
                >
                  <option value="Linux Syslog">Linux Syslog</option>
                  <option value="Windows Event">Windows Event</option>
                  <option value="Web Server">Web Server (Apache / Nginx)</option>
                  <option value="Firewall">Firewall (iptables / pfSense)</option>
                  <option value="IDS/IPS">IDS/IPS (Suricata EVE JSON)</option>
                </select>
              </div>

              {/* Raw Log Input */}
              <div>
                <label className="font-display text-[10px] font-bold uppercase tracking-wider text-slate-400">
                  Raw Log Payload (Text or JSON)
                </label>
                <textarea
                  rows={6}
                  value={manualRawLog}
                  onChange={(e) => setManualRawLog(e.target.value)}
                  placeholder="Paste raw log string or JSON object..."
                  className="mt-1 w-full rounded-lg border border-white/[0.1] bg-[#0a0d0f] p-3 font-mono text-xs text-slate-200 outline-none focus:border-[#b7f960]/40"
                />
              </div>

              {/* Live Detection Result Banner */}
              {lastSubmissionResult && (
                <div className="rounded-xl border border-white/[0.08] bg-black/30 p-3.5">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 size={16} className="text-[#b7f960]" />
                    <span className="font-display text-xs font-semibold text-slate-100">
                      Ingestion Success: Log #{lastSubmissionResult.log.id}
                    </span>
                  </div>

                  {lastSubmissionResult.alerts.length > 0 ? (
                    <div className="mt-2 space-y-1.5">
                      <p className="text-[11px] font-semibold text-red-400">
                        ⚡ {lastSubmissionResult.alerts.length} Detection Alert(s) Generated:
                      </p>
                      {lastSubmissionResult.alerts.map((a) => (
                        <div
                          key={a.id}
                          className="flex items-center justify-between rounded bg-red-500/10 p-2 text-xs border border-red-500/20"
                        >
                          <span className="font-medium text-slate-200">{a.title}</span>
                          <span className="rounded bg-red-500/20 px-1.5 py-0.5 font-display text-[9px] font-bold text-red-300">
                            {a.severity}
                          </span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="mt-1 text-[11px] text-slate-400">
                      No alert triggered for this event (classified as benign/normal telemetry).
                    </p>
                  )}
                </div>
              )}
            </div>

            <div className="flex items-center justify-between border-t border-white/[0.08] bg-[#171c20] p-4">
              <span className="text-[11px] text-slate-500">
                Requires role with <strong className="text-slate-400">ingest:logs</strong> (Detection Engineer)
              </span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setManualModalOpen(false)}
                  className="rounded-lg border border-white/[0.1] bg-white/[0.03] px-3.5 py-1.5 text-xs text-slate-300 hover:bg-white/[0.06]"
                >
                  Close
                </button>
                <button
                  type="button"
                  disabled={submittingManual}
                  onClick={handleManualSubmit}
                  className="flex items-center gap-1.5 rounded-lg border border-[#b7f960]/40 bg-[#b7f960] px-4 py-1.5 font-display text-xs font-semibold text-black transition hover:bg-[#c9f785] disabled:opacity-50"
                >
                  {submittingManual ? <Loader2 size={13} className="animate-spin" /> : <Terminal size={13} />}
                  Ingest & Run Rules
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* File Upload Modal */}
      {uploadModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-md animate-in fade-in duration-200">
          <div className="relative flex max-h-[90vh] w-full max-w-xl flex-col overflow-hidden rounded-2xl border border-white/[0.12] bg-[#121619] shadow-2xl">
            <div className="flex items-center justify-between border-b border-white/[0.08] bg-[#171c20] p-4">
              <div>
                <h3 className="font-display text-sm font-semibold text-slate-100">Upload Log File</h3>
                <p className="text-xs text-slate-400">
                  Batch ingest log files (.log, .txt, .json, .csv) up to 10MB into PostgreSQL.
                </p>
              </div>
              <button
                onClick={() => setUploadModalOpen(false)}
                className="rounded-lg p-1.5 text-slate-400 hover:bg-white/[0.08] hover:text-white"
              >
                <X size={18} />
              </button>
            </div>

            <div className="flex-1 space-y-4 overflow-y-auto p-5 text-xs text-slate-300">
              {/* Source Type Hint */}
              <div>
                <label className="font-display text-[10px] font-bold uppercase tracking-wider text-slate-400">
                  Source Type Hint
                </label>
                <select
                  value={uploadSourceType}
                  onChange={(e) => setUploadSourceType(e.target.value)}
                  className="mt-1 h-9 w-full rounded-lg border border-white/[0.1] bg-[#0a0d0f] px-3 text-xs text-slate-200 outline-none focus:border-[#b7f960]/40"
                >
                  <option value="Generic Log File">Auto-Detect / Generic</option>
                  <option value="Linux Syslog">Linux Syslog (auth.log / syslog)</option>
                  <option value="Windows Event">Windows Event Log (CSV / JSON)</option>
                  <option value="Web Server">Web Server (Apache / Nginx)</option>
                  <option value="Firewall">Firewall Telemetry</option>
                  <option value="IDS/IPS">IDS/IPS (Suricata EVE JSON)</option>
                </select>
              </div>

              {/* File Dropzone */}
              <div className="flex flex-col items-center justify-center rounded-xl border-2 border-dashed border-white/[0.12] bg-black/20 p-8 text-center transition hover:border-[#b7f960]/40">
                <UploadCloud size={32} className="text-[#b7f960]" />
                <p className="mt-3 font-semibold text-slate-200">
                  {selectedFile ? selectedFile.name : "Select or drag & drop a log file"}
                </p>
                <p className="mt-1 text-[11px] text-slate-500">
                  {selectedFile
                    ? `${(selectedFile.size / 1024).toFixed(1)} KB`
                    : "Supports .log, .txt, .json, and .csv files up to 10MB"}
                </p>

                <input
                  type="file"
                  id="logFileInput"
                  accept=".log,.txt,.json,.csv"
                  className="hidden"
                  onChange={(e) => {
                    if (e.target.files && e.target.files[0]) {
                      setSelectedFile(e.target.files[0]);
                    }
                  }}
                />
                <button
                  type="button"
                  onClick={() => document.getElementById("logFileInput")?.click()}
                  className="mt-4 rounded-lg border border-white/[0.1] bg-white/[0.04] px-3.5 py-1.5 font-display text-xs font-semibold text-slate-300 hover:bg-white/[0.08]"
                >
                  Browse Files
                </button>
              </div>

              {/* Upload Result */}
              {uploadResult && (
                <div className="space-y-2.5">
                  <div className="rounded-xl border border-[#b7f960]/30 bg-[#b7f960]/10 p-3.5 text-xs text-slate-200">
                    <div className="flex items-center gap-2">
                      <CheckCircle2 size={16} className="text-[#b7f960]" />
                      <span className="font-semibold text-[#b7f960]">Native Ingestion Complete!</span>
                    </div>
                    <p className="mt-1">
                      Processed <strong className="text-white">{uploadResult.fileName}</strong>: Ingested{" "}
                      <strong className="text-white">{uploadResult.logsIngested}</strong> records and
                      generated{" "}
                      <strong className="text-[#e16c5c]">{uploadResult.alertsGeneratedCount}</strong> real-time
                      security alerts in the database.
                    </p>
                  </div>

                  {/* Isolated Python AI Inspection Card (Sidecar POC) */}
                  {uploadResult.pythonAnalysis && (
                    <div className="rounded-xl border border-cyan-500/30 bg-[#0d1624] p-3.5 text-xs text-slate-200">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <ShieldAlert size={15} className="text-cyan-400" />
                          <span className="font-semibold text-cyan-300">
                            Python AI Threat Inspection (Sidecar POC)
                          </span>
                        </div>
                        <span className="rounded bg-cyan-950/80 px-2 py-0.5 text-[10px] font-medium text-cyan-300 border border-cyan-800">
                          Non-DB Advisory
                        </span>
                      </div>
                      <p className="mt-0.5 text-[10px] text-slate-400">
                        Advisory analysis flags preliminary bursts (≥5 attempts) without altering the database alert threshold (≥10 attempts/3m).
                      </p>

                      {uploadResult.pythonAnalysis.status === "success" ? (
                        <div className="mt-2.5 space-y-2">
                          <div className="flex flex-wrap items-center gap-2 text-[11px]">
                            <span className="text-slate-400">Risk Level:</span>
                            <span
                              className={`rounded px-1.5 py-0.5 font-semibold uppercase ${
                                uploadResult.pythonAnalysis.riskLevel === "CRITICAL"
                                  ? "bg-red-500/20 text-red-300 border border-red-500/30"
                                  : uploadResult.pythonAnalysis.riskLevel === "HIGH"
                                  ? "bg-orange-500/20 text-orange-300 border border-orange-500/30"
                                  : uploadResult.pythonAnalysis.riskLevel === "MEDIUM"
                                  ? "bg-yellow-500/20 text-yellow-300 border border-yellow-500/30"
                                  : "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                              }`}
                            >
                              {uploadResult.pythonAnalysis.riskLevel || "CLEAN"}
                            </span>
                            <span className="text-slate-400 ml-2">Threat Score:</span>
                            <span className="font-mono font-bold text-white">
                              {uploadResult.pythonAnalysis.threatScore ?? 0}/100
                            </span>
                            <span className="text-slate-400 ml-2">Suspicious Findings:</span>
                            <span className="font-mono font-bold text-cyan-300">
                              {uploadResult.pythonAnalysis.findingsCount ?? 0}
                            </span>
                          </div>

                          {uploadResult.pythonAnalysis.attackChains &&
                            uploadResult.pythonAnalysis.attackChains.length > 0 && (
                              <div className="rounded-lg border border-red-500/20 bg-red-950/20 p-2 text-[11px]">
                                <div className="font-semibold text-red-300">
                                  Attack Progression Detected:
                                </div>
                                {uploadResult.pythonAnalysis.attackChains.map((chain, idx) => (
                                  <div key={idx} className="mt-1">
                                    <div className="text-slate-300 font-medium">{chain.chainName}</div>
                                    <div className="mt-0.5 flex flex-wrap gap-1 text-[10px] text-slate-400">
                                      {chain.stages.map((stg, sIdx) => (
                                        <span key={sIdx} className="rounded bg-black/40 px-1.5 py-0.5">
                                          {stg}
                                        </span>
                                      ))}
                                    </div>
                                  </div>
                                ))}
                              </div>
                            )}

                          {uploadResult.pythonAnalysis.findings &&
                            uploadResult.pythonAnalysis.findings.length > 0 && (
                              <div>
                                <button
                                  type="button"
                                  onClick={() => setShowPythonDetails(!showPythonDetails)}
                                  className="text-[11px] font-medium text-cyan-400 hover:text-cyan-300 underline"
                                >
                                  {showPythonDetails
                                    ? "Hide Python Findings Details"
                                    : `View ${uploadResult.pythonAnalysis.findings.length} Finding Details`}
                                </button>

                                {showPythonDetails && (
                                  <div className="mt-2 max-h-40 overflow-y-auto space-y-1.5 rounded-lg border border-white/[0.06] bg-black/40 p-2 text-[10px]">
                                    {uploadResult.pythonAnalysis.findings.map((f, idx) => (
                                      <div
                                        key={idx}
                                        className="border-b border-white/[0.04] pb-1.5 last:border-b-0"
                                      >
                                        <div className="flex items-center gap-1.5 font-semibold text-slate-200">
                                          <span className="text-cyan-400">[{f.severity}]</span>
                                          <span>{f.title}</span>
                                          <span className="text-slate-500">({f.mitre})</span>
                                        </div>
                                        {f.evidence && (
                                          <div className="font-mono text-slate-400 truncate">
                                            Evidence: {f.evidence}
                                          </div>
                                        )}
                                        {f.recommendation && (
                                          <div className="text-slate-400 mt-0.5">
                                            Action: {f.recommendation}
                                          </div>
                                        )}
                                      </div>
                                    ))}
                                  </div>
                                )}
                              </div>
                            )}
                        </div>
                      ) : (
                        <div className="mt-1.5 text-[11px] text-slate-400">
                          {uploadResult.pythonAnalysis.status === "skipped" && (
                            <span>Python inspection skipped: {uploadResult.pythonAnalysis.message}</span>
                          )}
                          {uploadResult.pythonAnalysis.status === "unavailable" && (
                            <span className="text-amber-400/90">
                              Python detector sidecar is currently unavailable. Normal ingestion completed unaffected.
                            </span>
                          )}
                          {uploadResult.pythonAnalysis.status === "timeout" && (
                            <span className="text-amber-400/90">
                              Python detector timed out. Normal ingestion completed unaffected.
                            </span>
                          )}
                          {uploadResult.pythonAnalysis.status === "error" && (
                            <span className="text-red-400/90">
                              Python detector returned an error: {uploadResult.pythonAnalysis.message}
                            </span>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="flex items-center justify-between border-t border-white/[0.08] bg-[#171c20] p-4">
              <span className="text-[11px] text-slate-500">Max upload limit: 10MB</span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setUploadModalOpen(false)}
                  className="rounded-lg border border-white/[0.1] bg-white/[0.03] px-3.5 py-1.5 text-xs text-slate-300 hover:bg-white/[0.06]"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  disabled={uploading || !selectedFile}
                  onClick={handleFileUpload}
                  className="flex items-center gap-1.5 rounded-lg border border-[#b7f960]/40 bg-[#b7f960] px-4 py-1.5 font-display text-xs font-semibold text-black transition hover:bg-[#c9f785] disabled:opacity-50"
                >
                  {uploading ? <Loader2 size={13} className="animate-spin" /> : <UploadCloud size={13} />}
                  Start Upload
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
