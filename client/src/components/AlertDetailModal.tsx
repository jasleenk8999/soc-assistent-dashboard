/**
 * Alert Detail & Evidence Audit Modal
 * Displays full detection auditability for an alert:
 * - Rule ID & Name
 * - Severity & Confidence
 * - Exact Matched Evidence
 * - Suggested Next Steps
 * - Originating / Triggering Logs fetched from PostgreSQL
 * - Working status update
 */

import { useEffect, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
  Bot,
  CheckCircle2,
  ChevronRight,
  Clock,
  Copy,
  ExternalLink,
  FileCode,
  FileText,
  Globe2,
  Info,
  ListFilter,
  Loader2,
  Radio,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  User,
  X,
} from "lucide-react";
import { toast } from "sonner";
import {
  api,
  type AlertItem,
  type LogItem,
  type IncidentExplanation,
  type AlertThreatIntelResponse,
  type ThreatIntelItem,
} from "@/lib/api";
import { useAuth } from "@/contexts/AuthContext";

interface AlertDetailModalProps {
  alert: AlertItem | null;
  isOpen: boolean;
  onClose: () => void;
  onStatusUpdated: () => void;
}

export function AlertDetailModal({
  alert,
  isOpen,
  onClose,
  onStatusUpdated,
}: AlertDetailModalProps) {
  const { checkPermission } = useAuth();
  const [triggeringLogs, setTriggeringLogs] = useState<LogItem[]>([]);
  const [loadingLogs, setLoadingLogs] = useState(false);
  const [selectedStatus, setSelectedStatus] = useState<string>(alert?.status || "Open");
  const [updatingStatus, setUpdatingStatus] = useState(false);
  const [activeTab, setActiveTab] = useState<"evidence" | "logs" | "explanation" | "intel">("evidence");

  // Phase 5 AI Incident Explanation State
  const [explanation, setExplanation] = useState<IncidentExplanation | null>(null);
  const [loadingExplanation, setLoadingExplanation] = useState(false);
  const [generatingExplanation, setGeneratingExplanation] = useState(false);
  const [explanationError, setExplanationError] = useState<string | null>(null);

  // Phase 6 Threat Intelligence State
  const [threatIntelData, setThreatIntelData] = useState<AlertThreatIntelResponse | null>(null);
  const [loadingIntel, setLoadingIntel] = useState(false);
  const [refreshingIndicator, setRefreshingIndicator] = useState<string | null>(null);

  useEffect(() => {
    if (alert) {
      setSelectedStatus(alert.status);
      setExplanation(null);
      setExplanationError(null);
      setThreatIntelData(null);
      if (alert.relatedLogIds && alert.relatedLogIds.length > 0) {
        fetchTriggeringLogs(alert.id);
      } else {
        setTriggeringLogs([]);
      }
      fetchExplanation(alert.id);
      fetchThreatIntel(alert.id);
    }
  }, [alert]);

  const fetchThreatIntel = async (alertId: number) => {
    if (!checkPermission("read:threat_intel")) return;
    try {
      setLoadingIntel(true);
      const res = await api.getAlertThreatIntel(alertId);
      setThreatIntelData(res);
    } catch (err: any) {
      console.warn("Could not fetch alert threat intelligence:", err);
    } finally {
      setLoadingIntel(false);
    }
  };

  const handleRefreshIndicator = async (indicator: string, type: string) => {
    if (!alert) return;
    try {
      setRefreshingIndicator(indicator);
      await api.lookupThreatIntelPost({ indicator, indicatorType: type, forceRefresh: true });
      await fetchThreatIntel(alert.id);
      toast.success(`Refreshed threat intelligence for ${indicator}`);
    } catch (err: any) {
      toast.error(err.message || `Failed to refresh ${indicator}`);
    } finally {
      setRefreshingIndicator(null);
    }
  };

  const fetchTriggeringLogs = async (alertId: number) => {
    try {
      setLoadingLogs(true);
      const res = await api.getAlertLogs(alertId);
      setTriggeringLogs(res.logs || []);
    } catch (err: any) {
      console.error("Failed to fetch triggering logs:", err);
      // Non-fatal, keep alert view accessible
    } finally {
      setLoadingLogs(false);
    }
  };

  const fetchExplanation = async (alertId: number) => {
    if (!checkPermission("read:explanation")) return;
    try {
      setLoadingExplanation(true);
      const res = await api.getAlertExplanation(alertId);
      setExplanation(res.explanation);
    } catch (err: any) {
      console.warn("Could not fetch saved explanation:", err);
    } finally {
      setLoadingExplanation(false);
    }
  };

  const handleGenerateExplanation = async (forceRegenerate = false) => {
    if (!alert) return;
    if (!checkPermission("generate:explanation")) {
      toast.error("Forbidden: Your role lacks permission 'generate:explanation'.");
      return;
    }

    try {
      setGeneratingExplanation(true);
      setExplanationError(null);
      setActiveTab("explanation");
      const res = await api.explainAlert(alert.id, { forceRegenerate });
      setExplanation(res.explanation);
      if (res.reused) {
        toast.info("Retrieved valid saved explanation.");
      } else {
        toast.success(
          res.explanation.provider === "fallback"
            ? "Generated structured evidence-grounded incident explanation."
            : `Generated AI explanation using ${res.explanation.provider}.`
        );
      }
    } catch (err: any) {
      const msg = err.message || "Failed to generate incident explanation";
      setExplanationError(msg);
      toast.error(msg);
    } finally {
      setGeneratingExplanation(false);
    }
  };

  const handleStatusChange = async (newStatus: string) => {
    if (!alert) return;
    if (!checkPermission("update:alert_status")) {
      toast.error("Forbidden: Your role lacks permission 'update:alert_status'.");
      return;
    }

    try {
      setUpdatingStatus(true);
      await api.updateAlertStatus(alert.id, newStatus);
      setSelectedStatus(newStatus);
      toast.success(`Alert #${alert.id} status updated to '${newStatus}'`);
      onStatusUpdated();
    } catch (err: any) {
      toast.error(err.message || "Failed to update alert status");
    } finally {
      setUpdatingStatus(false);
    }
  };

  if (!isOpen || !alert) return null;

  const isRealDetection = Boolean(alert.ruleId);
  const evidenceObj = typeof alert.evidence === "object" && alert.evidence !== null ? alert.evidence : {};

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-md animate-in fade-in duration-200">
      <div className="relative flex max-h-[90vh] w-full max-w-4xl flex-col overflow-hidden rounded-2xl border border-white/[0.12] bg-[#121619] shadow-2xl">
        {/* Header Bar */}
        <div className="flex items-start justify-between border-b border-white/[0.08] bg-[#171c20] p-5">
          <div className="min-w-0 flex-1 pr-4">
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={`rounded px-2 py-0.5 font-display text-[10px] font-bold uppercase tracking-wider ${
                  alert.severity === "Critical"
                    ? "bg-red-500/20 text-red-400 border border-red-500/30"
                    : alert.severity === "High"
                    ? "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                    : "bg-cyan-500/20 text-cyan-400 border border-cyan-500/30"
                }`}
              >
                {alert.severity}
              </span>

              {isRealDetection ? (
                <span className="rounded border border-[#b7f960]/30 bg-[#b7f960]/10 px-2 py-0.5 font-display text-[10px] font-semibold text-[#b7f960]">
                  Live Detection Engine ({alert.ruleId})
                </span>
              ) : (
                <span className="rounded border border-slate-600/40 bg-slate-800/40 px-2 py-0.5 font-display text-[10px] text-slate-400">
                  Demonstration Seeded Record
                </span>
              )}

              <span className="font-display text-[10px] uppercase tracking-wider text-slate-400">
                Confidence: {alert.confidence}%
              </span>
            </div>

            <h2 className="mt-2 text-lg font-semibold tracking-tight text-slate-100 md:text-xl">
              {alert.title}
            </h2>
            <p className="mt-1 text-xs text-slate-400">
              Source: <span className="font-mono text-slate-200">{alert.source}</span>
              {alert.destination && (
                <>
                  {" "}
                  → Destination: <span className="font-mono text-slate-200">{alert.destination}</span>
                </>
              )}
              {" · "}
              {alert.tactic} {alert.technique ? `(${alert.technique})` : ""}
            </p>
          </div>

          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 transition hover:bg-white/[0.08] hover:text-white"
          >
            <X size={18} />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-3 border-b border-white/[0.08] bg-[#14181b] px-5 py-2.5">
          <button
            onClick={() => setActiveTab("evidence")}
            className={`flex items-center gap-2 rounded-lg px-3 py-1.5 font-display text-xs font-semibold uppercase tracking-wider transition ${
              activeTab === "evidence"
                ? "bg-[#b7f960]/15 text-[#b7f960]"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <ShieldAlert size={14} /> Rule & Evidence
          </button>
          <button
            onClick={() => setActiveTab("logs")}
            className={`flex items-center gap-2 rounded-lg px-3 py-1.5 font-display text-xs font-semibold uppercase tracking-wider transition ${
              activeTab === "logs"
                ? "bg-[#b7f960]/15 text-[#b7f960]"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Terminal size={14} /> Triggering Logs ({alert.relatedLogIds?.length || triggeringLogs.length})
          </button>
          <button
            onClick={() => setActiveTab("explanation")}
            className={`flex items-center gap-2 rounded-lg px-3 py-1.5 font-display text-xs font-semibold uppercase tracking-wider transition ${
              activeTab === "explanation"
                ? "bg-[#b7f960]/15 text-[#b7f960]"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Sparkles size={14} /> AI Incident Brief
            {explanation && (
              <span
                className={`ml-1 rounded px-1.5 py-0.5 font-mono text-[9px] font-semibold uppercase ${
                  explanation.isStale
                    ? "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                    : "bg-[#b7f960]/20 text-[#b7f960] border border-[#b7f960]/30"
                }`}
              >
                {explanation.isStale ? "Stale" : "Saved"}
              </span>
            )}
          </button>
          <button
            onClick={() => {
              setActiveTab("intel");
              if (!threatIntelData && alert) fetchThreatIntel(alert.id);
            }}
            className={`flex items-center gap-2 rounded-lg px-3 py-1.5 font-display text-xs font-semibold uppercase tracking-wider transition ${
              activeTab === "intel"
                ? "bg-[#b7f960]/15 text-[#b7f960]"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Globe2 size={14} /> Threat Intel
            {threatIntelData && threatIntelData.indicatorsCount > 0 && (
              <span
                className={`ml-1 rounded px-1.5 py-0.5 font-mono text-[9px] font-semibold uppercase ${
                  threatIntelData.summary.maliciousCount > 0
                    ? "bg-rose-500/20 text-rose-300 border border-rose-500/30"
                    : "bg-white/10 text-slate-300"
                }`}
              >
                {threatIntelData.indicatorsCount}
              </span>
            )}
          </button>

          {/* Quick Status Selector */}
          <div className="ml-auto flex items-center gap-2">
            <span className="font-display text-[10px] uppercase tracking-wider text-slate-500">Status:</span>
            <select
              value={selectedStatus}
              disabled={updatingStatus}
              onChange={(e) => handleStatusChange(e.target.value)}
              className="rounded-md border border-white/[0.12] bg-[#0d1012] px-2.5 py-1 text-xs font-medium text-slate-200 outline-none focus:border-[#b7f960]/50"
            >
              <option value="Open">Open</option>
              <option value="In review">In review</option>
              <option value="Escalated">Escalated</option>
              <option value="Contained">Contained</option>
              <option value="Resolved">Resolved</option>
            </select>
          </div>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-5 text-sm text-slate-300">
          {activeTab === "evidence" && (
            <div className="space-y-5">
              {/* Quick AI Explanation Banner */}
              <div className="flex flex-col gap-3 rounded-xl border border-[#b7f960]/20 bg-[#b7f960]/5 p-4 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <Sparkles size={14} className="text-[#b7f960]" />
                    <p className="font-display text-[11px] font-semibold uppercase tracking-wider text-[#b7f960]">
                      AI-Assisted Incident Investigation (Phase 5)
                    </p>
                  </div>
                  <p className="mt-1 text-xs text-slate-300">
                    {explanation
                      ? `Structured analysis ready (${explanation.provider === "fallback" ? "Deterministic Rule-Grounded" : `AI Provider: ${explanation.provider}`}).`
                      : "Generate an evidence-grounded incident narrative, MITRE context, and analyst action checklist."}
                  </p>
                </div>
                <button
                  onClick={() => {
                    setActiveTab("explanation");
                    if (!explanation && !generatingExplanation && checkPermission("generate:explanation")) {
                      handleGenerateExplanation(false);
                    }
                  }}
                  className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-[#b7f960]/40 bg-[#b7f960] px-3.5 py-2 font-display text-[10px] font-bold uppercase tracking-wider text-[#121619] transition hover:bg-[#ccff88]"
                >
                  <Sparkles size={13} />
                  {explanation ? "View AI Brief" : "Generate AI Brief"}
                </button>
              </div>

              {/* Description */}
              <div className="rounded-xl border border-white/[0.08] bg-black/20 p-4">
                <p className="font-display text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                  Detection Summary
                </p>
                <p className="mt-1.5 leading-relaxed text-slate-200">
                  {alert.description || "Deterministic rule evaluation matched telemetry signature."}
                </p>
              </div>

              {/* Matched Evidence Grid */}
              <div className="rounded-xl border border-white/[0.08] bg-black/20 p-4">
                <div className="flex items-center justify-between">
                  <p className="font-display text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                    Audit Evidence & Match Details
                  </p>
                  <span className="font-mono text-[10px] text-slate-500">
                    Rule ID: {alert.ruleId || "LEGACY-DEMO"}
                  </span>
                </div>

                <div className="mt-3 grid gap-3 sm:grid-cols-2">
                  <div className="rounded-lg border border-white/[0.06] bg-black/30 p-3">
                    <span className="font-display text-[10px] uppercase text-slate-500">Detection Rule</span>
                    <p className="mt-0.5 font-medium text-slate-200">{alert.ruleName || alert.title}</p>
                  </div>
                  <div className="rounded-lg border border-white/[0.06] bg-black/30 p-3">
                    <span className="font-display text-[10px] uppercase text-slate-500">Confidence Score</span>
                    <p className="mt-0.5 font-medium text-[#b7f960]">{alert.confidence}% (Deterministic Match)</p>
                  </div>
                  <div className="rounded-lg border border-white/[0.06] bg-black/30 p-3">
                    <span className="font-display text-[10px] uppercase text-slate-500">MITRE ATT&CK Tactic</span>
                    <p className="mt-0.5 font-medium text-slate-200">{alert.tactic}</p>
                  </div>
                  <div className="rounded-lg border border-white/[0.06] bg-black/30 p-3">
                    <span className="font-display text-[10px] uppercase text-slate-500">MITRE ATT&CK Technique</span>
                    <p className="mt-0.5 font-medium text-slate-200">{alert.technique || "N/A"}</p>
                  </div>
                </div>

                {/* Raw Evidence Payload */}
                <div className="mt-4">
                  <span className="font-display text-[10px] uppercase text-slate-500">
                    Structured Evidence Data
                  </span>
                  <pre className="mt-1.5 max-h-48 overflow-x-auto rounded-lg border border-white/[0.06] bg-[#0a0d0f] p-3 font-mono text-[11px] text-slate-300">
                    {JSON.stringify(evidenceObj, null, 2)}
                  </pre>
                </div>
              </div>

              {/* Suggested Next Steps */}
              {alert.suggestedNextSteps && (
                <div className="rounded-xl border border-[#b7f960]/20 bg-[#b7f960]/5 p-4">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 size={15} className="text-[#b7f960]" />
                    <p className="font-display text-[11px] font-semibold uppercase tracking-wider text-[#b7f960]">
                      Suggested Investigative Next Steps
                    </p>
                  </div>
                  <pre className="mt-2 whitespace-pre-wrap font-sans text-xs leading-relaxed text-slate-200">
                    {alert.suggestedNextSteps}
                  </pre>
                </div>
              )}
            </div>
          )}

          {activeTab === "logs" && (
            <div className="space-y-3">
              {loadingLogs ? (
                <div className="flex items-center justify-center p-12 text-slate-400">
                  <Loader2 className="mr-2 animate-spin text-[#b7f960]" size={18} />
                  Fetching linked logs from PostgreSQL...
                </div>
              ) : triggeringLogs.length === 0 ? (
                <div className="rounded-xl border border-white/[0.08] bg-black/20 p-8 text-center text-slate-400">
                  <Terminal size={24} className="mx-auto text-slate-500" />
                  <p className="mt-2 font-medium">No direct raw logs linked to this alert record.</p>
                  <p className="mt-1 text-xs text-slate-500">
                    (Seeded Phase 1 alerts were generated prior to Phase 3 log ingestion telemetry).
                  </p>
                </div>
              ) : (
                <div className="space-y-3">
                  <p className="font-display text-[11px] uppercase tracking-wider text-slate-400">
                    Showing {triggeringLogs.length} Triggering Security Event(s)
                  </p>
                  {triggeringLogs.map((log) => (
                    <div
                      key={log.id}
                      className="rounded-xl border border-white/[0.08] bg-black/30 p-3.5 transition hover:border-white/[0.15]"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] pb-2 text-[11px]">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-[#b7f960]">Log #{log.id}</span>
                          <span className="rounded bg-white/[0.06] px-1.5 py-0.5 font-display text-[10px] text-slate-300">
                            {log.sourceType}
                          </span>
                          <span className="rounded bg-red-500/15 px-1.5 py-0.5 font-display text-[10px] text-red-300">
                            {log.logLevel}
                          </span>
                        </div>
                        <span className="font-mono text-slate-500">
                          {new Date(log.timestamp).toLocaleString()}
                        </span>
                      </div>

                      <div className="mt-2 flex flex-wrap gap-4 text-xs text-slate-400">
                        {log.sourceIp && (
                          <span>
                            Src IP: <strong className="font-mono text-slate-200">{log.sourceIp}</strong>
                          </span>
                        )}
                        {log.destinationIp && (
                          <span>
                            Dst IP: <strong className="font-mono text-slate-200">{log.destinationIp}</strong>
                          </span>
                        )}
                        {log.destinationPort && (
                          <span>
                            Dst Port: <strong className="font-mono text-slate-200">{log.destinationPort}</strong>
                          </span>
                        )}
                        {log.username && (
                          <span>
                            User: <strong className="font-mono text-slate-200">{log.username}</strong>
                          </span>
                        )}
                        {log.eventId && (
                          <span>
                            Event ID: <strong className="font-mono text-slate-200">{log.eventId}</strong>
                          </span>
                        )}
                      </div>

                      <pre className="mt-2.5 overflow-x-auto rounded bg-[#090b0d] p-2.5 font-mono text-[11px] text-slate-300">
                        {log.rawLog}
                      </pre>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === "explanation" && (
            <div className="space-y-4">
              {/* Generating Loader */}
              {generatingExplanation ? (
                <div className="flex flex-col items-center justify-center rounded-2xl border border-white/[0.08] bg-black/20 p-14 text-center">
                  <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-[#b7f960]/10 text-[#b7f960]">
                    <Loader2 size={24} className="animate-spin text-[#b7f960]" />
                  </div>
                  <h4 className="mt-4 font-display text-sm font-semibold uppercase tracking-wider text-white">
                    Generating Evidence-Grounded Explanation...
                  </h4>
                  <p className="mt-1.5 max-w-md text-xs leading-relaxed text-slate-400">
                    Correlating alert rule conditions, MITRE techniques, and triggering logs into a structured 9-section analyst brief.
                  </p>
                </div>
              ) : explanation ? (
                <div className="space-y-4">
                  {/* Explanation Metadata Bar */}
                  <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-white/[0.08] bg-black/25 px-4 py-3">
                    <div className="flex flex-wrap items-center gap-2">
                      {explanation.provider === "fallback" ? (
                        <span className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 font-display text-[10px] font-semibold uppercase tracking-wider text-amber-300">
                          Deterministic Fallback (Rule-Grounded)
                        </span>
                      ) : (
                        <span className="rounded border border-[#b7f960]/30 bg-[#b7f960]/10 px-2 py-0.5 font-display text-[10px] font-semibold uppercase tracking-wider text-[#b7f960]">
                          AI Provider: {explanation.provider} {explanation.model ? `(${explanation.model})` : ""}
                        </span>
                      )}

                      {explanation.isStale && (
                        <span className="rounded border border-amber-500/30 bg-amber-500/15 px-2 py-0.5 font-display text-[10px] font-semibold uppercase tracking-wider text-amber-300">
                          ⚠️ Alert evidence changed since generation
                        </span>
                      )}

                      <span className="font-mono text-[10px] text-slate-400">
                        Updated: {new Date(explanation.updatedAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                        {explanation.generatedByUserName ? ` · Analyst: ${explanation.generatedByUserName}` : ""}
                      </span>
                    </div>

                    <button
                      onClick={() => handleGenerateExplanation(true)}
                      disabled={generatingExplanation || !checkPermission("generate:explanation")}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.1] bg-white/[0.04] px-3 py-1 font-display text-[10px] font-semibold uppercase tracking-wider text-slate-300 transition hover:bg-white/[0.08] hover:text-white disabled:opacity-50"
                    >
                      <RefreshCw size={12} className={generatingExplanation ? "animate-spin" : ""} />
                      Regenerate
                    </button>
                  </div>

                  {explanation.errorMessage && (
                    <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-200">
                      <strong>Notice:</strong> {explanation.errorMessage}
                    </div>
                  )}

                  {/* 1. Executive Summary */}
                  <div className="rounded-xl border border-white/[0.08] bg-black/20 p-4">
                    <div className="flex items-center gap-2">
                      <Bot size={15} className="text-[#b7f960]" />
                      <p className="font-display text-[11px] font-semibold uppercase tracking-wider text-[#b7f960]">
                        1. Executive Summary
                      </p>
                    </div>
                    <div className="mt-2 border-l-2 border-[#b7f960] pl-3.5">
                      <p className="leading-relaxed text-slate-100 font-medium">
                        {explanation.executiveSummary}
                      </p>
                    </div>
                  </div>

                  {/* 2 & 4. Why Triggered & MITRE Context */}
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div className="rounded-xl border border-white/[0.08] bg-black/20 p-4">
                      <p className="font-display text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                        2. Why It Triggered
                      </p>
                      <p className="mt-1.5 text-xs leading-relaxed text-slate-200">
                        {explanation.whyItTriggered}
                      </p>
                    </div>

                    <div className="rounded-xl border border-white/[0.08] bg-black/20 p-4">
                      <p className="font-display text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                        4. MITRE ATT&CK Context
                      </p>
                      <p className="mt-1.5 text-xs leading-relaxed text-slate-200">
                        {explanation.mitreContext}
                      </p>
                    </div>
                  </div>

                  {/* 3. Evidence Narrative */}
                  <div className="rounded-xl border border-white/[0.08] bg-black/20 p-4">
                    <p className="font-display text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                      3. Evidence Narrative
                    </p>
                    <p className="mt-1.5 text-xs leading-relaxed text-slate-200">
                      {explanation.evidenceNarrative}
                    </p>
                  </div>

                  {/* 5 & 6. Potential Impact & Confidence / Uncertainty */}
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div className="rounded-xl border border-white/[0.08] bg-black/20 p-4">
                      <p className="font-display text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                        5. Potential Impact
                      </p>
                      <p className="mt-1.5 text-xs leading-relaxed text-slate-200">
                        {explanation.potentialImpact}
                      </p>
                    </div>

                    <div className="rounded-xl border border-white/[0.08] bg-black/20 p-4">
                      <p className="font-display text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                        6. Confidence & Uncertainty
                      </p>
                      <p className="mt-1.5 text-xs leading-relaxed text-slate-200">
                        {explanation.confidenceAndUncertainty}
                      </p>
                    </div>
                  </div>

                  {/* 7. Actionable Investigation Steps */}
                  <div className="rounded-xl border border-[#b7f960]/20 bg-[#b7f960]/5 p-4">
                    <div className="flex items-center gap-2">
                      <CheckCircle2 size={15} className="text-[#b7f960]" />
                      <p className="font-display text-[11px] font-semibold uppercase tracking-wider text-[#b7f960]">
                        7. Actionable Investigation Steps
                      </p>
                    </div>
                    <pre className="mt-2 whitespace-pre-wrap font-sans text-xs leading-relaxed text-slate-200">
                      {explanation.investigationSteps}
                    </pre>
                  </div>

                  {/* 8 & 9. Containment & Missing Evidence */}
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div className="rounded-xl border border-white/[0.08] bg-black/20 p-4">
                      <p className="font-display text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                        8. Containment Considerations
                      </p>
                      <p className="mt-1.5 text-xs leading-relaxed text-slate-200">
                        {explanation.containmentConsiderations}
                      </p>
                    </div>

                    <div className="rounded-xl border border-white/[0.08] bg-black/20 p-4">
                      <p className="font-display text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                        9. Missing Evidence
                      </p>
                      <p className="mt-1.5 text-xs leading-relaxed text-slate-200">
                        {explanation.missingEvidence}
                      </p>
                    </div>
                  </div>
                </div>
              ) : (
                /* Empty state when no explanation has been generated yet */
                <div className="flex flex-col items-center justify-center rounded-2xl border border-white/[0.08] bg-black/20 p-12 text-center">
                  <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-[#b7f960]/10 text-[#b7f960]">
                    <Bot size={22} />
                  </div>
                  <h4 className="mt-3.5 font-display text-sm font-semibold text-white">
                    No Incident Explanation Generated Yet
                  </h4>
                  <p className="mt-1.5 max-w-md text-xs leading-relaxed text-slate-400">
                    Generate an evidence-grounded incident brief for Alert #{alert.id}.
                    The assistant correlates the detection rule, MITRE techniques, and triggering logs into 9 structured findings for SOC analysts.
                  </p>

                  {checkPermission("generate:explanation") ? (
                    <button
                      onClick={() => handleGenerateExplanation(false)}
                      className="mt-5 inline-flex items-center gap-2 rounded-lg border border-[#b7f960]/40 bg-[#b7f960] px-4 py-2 font-display text-xs font-bold uppercase tracking-wider text-[#121619] transition hover:bg-[#ccff88]"
                    >
                      <Sparkles size={14} /> Generate AI Incident Brief
                    </button>
                  ) : (
                    <p className="mt-4 rounded-md border border-white/[0.08] bg-white/[0.03] px-3 py-1.5 text-[11px] text-slate-400">
                      Your current role does not have permission to generate explanations (`generate:explanation`).
                    </p>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Tab 4: Threat Intelligence */}
          {activeTab === "intel" && (
            <div className="space-y-5 p-6">
              {/* Header / Summary Bar */}
              <div className="flex flex-col gap-4 rounded-xl border border-white/[0.08] bg-[#14181b] p-4 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <Globe2 className="text-[#b7f960]" size={18} />
                    <h3 className="font-display text-sm font-semibold uppercase tracking-wider text-slate-100">
                      Correlated Threat Intelligence
                    </h3>
                  </div>
                  <p className="mt-1 text-xs text-slate-400">
                    Live and cached reputation scoring across AbuseIPDB, VirusTotal, and AlienVault OTX feeds.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => alert && fetchThreatIntel(alert.id)}
                    disabled={loadingIntel}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.1] bg-white/[0.04] px-3 py-1.5 font-display text-xs font-semibold text-slate-300 transition hover:bg-white/[0.08] hover:text-white disabled:opacity-50"
                  >
                    <RefreshCw className={loadingIntel ? "animate-spin" : ""} size={12} />
                    Refresh Intel
                  </button>
                </div>
              </div>

              {/* Status summary metrics */}
              {threatIntelData && threatIntelData.indicatorsCount > 0 && (
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                  <div className="rounded-lg border border-white/[0.08] bg-black/20 p-3">
                    <span className="font-display text-[10px] uppercase tracking-wider text-slate-500">Indicators Extracted</span>
                    <p className="mt-1 font-display text-lg font-bold text-slate-200">{threatIntelData.indicatorsCount}</p>
                  </div>
                  <div className="rounded-lg border border-rose-500/20 bg-rose-500/10 p-3">
                    <span className="font-display text-[10px] uppercase tracking-wider text-rose-300">Malicious Flagged</span>
                    <p className="mt-1 font-display text-lg font-bold text-rose-400">{threatIntelData.summary.maliciousCount}</p>
                  </div>
                  <div className="rounded-lg border border-amber-500/20 bg-amber-500/10 p-3">
                    <span className="font-display text-[10px] uppercase tracking-wider text-amber-300">Suspicious / Probing</span>
                    <p className="mt-1 font-display text-lg font-bold text-amber-400">{threatIntelData.summary.suspiciousCount}</p>
                  </div>
                  <div className="rounded-lg border border-[#b7f960]/20 bg-[#b7f960]/10 p-3">
                    <span className="font-display text-[10px] uppercase tracking-wider text-[#b7f960]">Max Reputation</span>
                    <p className="mt-1 font-display text-lg font-bold text-[#b7f960]">{threatIntelData.summary.highestReputationScore}/100</p>
                  </div>
                </div>
              )}

              {loadingIntel ? (
                <div className="flex flex-col items-center justify-center py-12 text-slate-500">
                  <Loader2 className="animate-spin text-[#b7f960]" size={24} />
                  <span className="mt-2 text-xs">Querying threat intelligence feeds and local cache...</span>
                </div>
              ) : threatIntelData && threatIntelData.indicators.length > 0 ? (
                <div className="space-y-4">
                  {threatIntelData.indicators.map((item, idx) => (
                    <div
                      key={`${item.indicator}-${idx}`}
                      className="rounded-xl border border-white/[0.08] bg-[#121619] p-4 transition hover:border-white/[0.14]"
                    >
                      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="rounded bg-white/10 px-2 py-0.5 font-mono text-[10px] font-semibold uppercase text-slate-300">
                              {item.indicatorType}
                            </span>
                            <span className="font-mono text-sm font-bold text-slate-100">{item.indicator}</span>
                            <span className="text-[11px] text-slate-500">({item.sourceContext})</span>
                          </div>
                          {item.isCached && (
                            <div className="mt-1 flex items-center gap-2 text-[10px] text-slate-500">
                              <span>Cached from database</span>
                              <span>•</span>
                              <span>Last seen: {new Date(item.lastSeen || item.createdAt || Date.now()).toLocaleString()}</span>
                            </div>
                          )}
                        </div>

                        <div className="flex items-center gap-2">
                          <span
                            className={`rounded-lg border px-2.5 py-1 font-display text-[10px] font-bold uppercase tracking-wider ${
                              item.verdict === "Malicious"
                                ? "border-rose-500/40 bg-rose-500/15 text-rose-300"
                                : item.verdict === "Suspicious"
                                ? "border-amber-500/40 bg-amber-500/15 text-amber-300"
                                : item.verdict === "Clean"
                                ? "border-[#b7f960]/40 bg-[#b7f960]/15 text-[#b7f960]"
                                : "border-slate-600/40 bg-slate-800/40 text-slate-400"
                            }`}
                          >
                            {item.verdict}
                          </span>
                          <button
                            onClick={() => handleRefreshIndicator(item.indicator, item.indicatorType)}
                            disabled={refreshingIndicator === item.indicator}
                            title="Force live lookup across external feeds"
                            className="inline-flex items-center gap-1 rounded-md border border-white/[0.1] bg-white/[0.04] p-1.5 text-slate-400 transition hover:bg-white/[0.08] hover:text-slate-200 disabled:opacity-50"
                          >
                            <RefreshCw
                              className={refreshingIndicator === item.indicator ? "animate-spin text-[#b7f960]" : ""}
                              size={12}
                            />
                          </button>
                        </div>
                      </div>

                      {/* Reputation Bar */}
                      <div className="mt-3">
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="text-slate-400">Reputation Risk Score</span>
                          <span
                            className={`font-mono font-semibold ${
                              item.reputationScore >= 70
                                ? "text-rose-400"
                                : item.reputationScore >= 25
                                ? "text-amber-400"
                                : "text-[#b7f960]"
                            }`}
                          >
                            {item.reputationScore}/100
                          </span>
                        </div>
                        <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-white/[0.06]">
                          <div
                            className={`h-full transition-all duration-500 ${
                              item.reputationScore >= 70
                                ? "bg-rose-500"
                                : item.reputationScore >= 25
                                ? "bg-amber-400"
                                : "bg-[#b7f960]"
                            }`}
                            style={{ width: `${Math.max(item.reputationScore, 4)}%` }}
                          />
                        </div>
                      </div>

                      {/* Feed breakdown grid */}
                      <div className="mt-4 grid gap-2 sm:grid-cols-3">
                        {Array.isArray(item.feedVerdicts) && item.feedVerdicts.length > 0 ? (
                          item.feedVerdicts.map((feed: any, fIdx: number) => {
                            const pName = feed.provider || feed.source || "Feed";
                            const pStatus = feed.status || "Unknown";
                            const isConfigRequired = pStatus === "unconfigured" || pStatus === "Config Required";
                            const isRateLimited = pStatus === "rate_limited";
                            const isSuccess = pStatus === "success";

                            return (
                              <div
                                key={fIdx}
                                className="rounded-lg border border-white/[0.06] bg-black/25 p-2.5 text-xs"
                              >
                                <div className="flex items-center justify-between">
                                  <span className="font-display text-[10px] font-semibold uppercase tracking-wider text-slate-300">
                                    {pName}
                                  </span>
                                  <span
                                    className={`font-mono text-[9px] font-bold uppercase ${
                                      isSuccess
                                        ? feed.verdict === "Malicious"
                                          ? "text-rose-400"
                                          : feed.verdict === "Suspicious"
                                          ? "text-amber-400"
                                          : feed.verdict === "Clean"
                                          ? "text-[#b7f960]"
                                          : "text-slate-400"
                                        : isConfigRequired
                                        ? "text-slate-500"
                                        : isRateLimited
                                        ? "text-amber-400"
                                        : "text-slate-400"
                                    }`}
                                  >
                                    {isSuccess ? feed.verdict : isConfigRequired ? "No Key" : isRateLimited ? "Quota Met" : pStatus}
                                  </span>
                                </div>
                                <p className="mt-1 text-[11px] leading-tight text-slate-400 line-clamp-2">
                                  {feed.details || feed.detail || (isConfigRequired ? "API key not configured in .env" : "Awaiting assessment")}
                                </p>
                              </div>
                            );
                          })
                        ) : (
                          <div className="col-span-3 text-center text-xs text-slate-500">
                            No provider records attached.
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="rounded-xl border border-white/[0.08] bg-[#121619] p-8 text-center text-slate-400">
                  <ShieldCheck className="mx-auto text-[#b7f960] mb-2" size={26} />
                  <h4 className="font-display text-sm font-semibold text-slate-200">No External Indicators</h4>
                  <p className="mt-1 text-xs text-slate-500">
                    No public IP addresses, domains, URLs, or file hashes were found in this alert's evidence or triggering logs.
                  </p>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between border-t border-white/[0.08] bg-[#14181b] px-5 py-3">
          <span className="text-xs text-slate-500">
            Created: {new Date(alert.createdAt).toLocaleString()}
          </span>
          <button
            onClick={onClose}
            className="rounded-lg border border-white/[0.1] bg-white/[0.04] px-4 py-1.5 font-display text-xs font-semibold text-slate-300 transition hover:bg-white/[0.08] hover:text-white"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
}
