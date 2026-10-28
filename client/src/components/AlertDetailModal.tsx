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
  CheckCircle2,
  ChevronRight,
  Clock,
  Copy,
  ExternalLink,
  FileCode,
  FileText,
  Info,
  ListFilter,
  Loader2,
  Radio,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  User,
  X,
} from "lucide-react";
import { toast } from "sonner";
import { api, type AlertItem, type LogItem } from "@/lib/api";
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
  const [activeTab, setActiveTab] = useState<"evidence" | "logs">("evidence");

  useEffect(() => {
    if (alert) {
      setSelectedStatus(alert.status);
      if (alert.relatedLogIds && alert.relatedLogIds.length > 0) {
        fetchTriggeringLogs(alert.id);
      } else {
        setTriggeringLogs([]);
      }
    }
  }, [alert]);

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
