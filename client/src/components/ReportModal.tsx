/**
 * Report Viewer & Creation Modal (Phase 8)
 * 
 * Supports:
 * 1. Generating new Executive, Technical, and Operational reports from real case telemetry.
 * 2. In-depth inspection of generated reports with timeline, evidence, and case links.
 * 3. Status transitions (Draft -> Review -> Published).
 * 4. Multi-format export: JSON, Markdown, and Printable HTML/PDF.
 */

import { useEffect, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
  Check,
  CheckCircle2,
  Clock,
  Download,
  ExternalLink,
  FileSearch,
  FileText,
  Loader2,
  Printer,
  ShieldAlert,
  Sparkles,
  X,
} from "lucide-react";
import { toast } from "sonner";
import { api, type CaseItem, type ReportItem } from "@/lib/api";

interface ReportModalProps {
  reportId: number | null;
  isOpen: boolean;
  isCreateMode?: boolean;
  initialTemplate?: "Executive incident report" | "Technical investigation report" | "Operational summary";
  onClose: () => void;
  onReportGenerated?: (newReport: ReportItem) => void;
  onStatusUpdated?: () => void;
}

export function ReportModal({
  reportId,
  isOpen,
  isCreateMode = false,
  initialTemplate,
  onClose,
  onReportGenerated,
  onStatusUpdated,
}: ReportModalProps) {
  // State for Report Details
  const [report, setReport] = useState<(ReportItem & { linkedCase?: any }) | null>(null);
  const [loading, setLoading] = useState(false);
  const [updatingStatus, setUpdatingStatus] = useState(false);

  // State for Create Mode
  const [casesList, setCasesList] = useState<CaseItem[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState<number | undefined>(undefined);
  const [reportType, setReportType] = useState<
    "Executive incident report" | "Technical investigation report" | "Operational summary"
  >(initialTemplate || "Executive incident report");
  const [customTitle, setCustomTitle] = useState("");
  const [generating, setGenerating] = useState(false);

  // Sync initial template if changed
  useEffect(() => {
    if (initialTemplate) {
      setReportType(initialTemplate);
    }
  }, [initialTemplate]);

  // Load existing report or cases on open
  useEffect(() => {
    if (!isOpen) {
      setReport(null);
      return;
    }

    if (isCreateMode) {
      api.getCases()
        .then((res) => {
          setCasesList(res.items);
          if (res.items.length > 0) {
            setSelectedCaseId(res.items[0].id);
          }
        })
        .catch((err) => console.error("Failed to load cases:", err));
    } else if (reportId) {
      setLoading(true);
      api.getReportById(reportId)
        .then((res) => setReport(res))
        .catch((err) => {
          console.error("Failed to fetch report:", err);
          toast.error("Failed to load report details");
        })
        .finally(() => setLoading(false));
    }
  }, [isOpen, isCreateMode, reportId]);

  if (!isOpen) return null;

  const handleGenerate = async () => {
    try {
      setGenerating(true);
      const res = await api.generateReport({
        reportType,
        caseId: reportType === "Operational summary" ? undefined : selectedCaseId,
        title: customTitle.trim() || undefined,
      });

      toast.success(res.message || `Report ${res.report.reportCode} generated.`);
      if (onReportGenerated) {
        onReportGenerated(res.report);
      }
      onClose();
    } catch (err: any) {
      toast.error(err.message || "Failed to generate report");
    } finally {
      setGenerating(false);
    }
  };

  const handleUpdateStatus = async (newStatus: "Draft" | "Review" | "Published") => {
    if (!report) return;
    try {
      setUpdatingStatus(true);
      const res = await api.updateReportStatus(report.id, newStatus);
      setReport((prev) => (prev ? { ...prev, status: res.report.status } : null));
      toast.success(`Report status updated to ${newStatus}.`);
      if (onStatusUpdated) onStatusUpdated();
    } catch (err: any) {
      toast.error(err.message || "Failed to update status");
    } finally {
      setUpdatingStatus(false);
    }
  };

  const handleDownload = (format: "json" | "markdown" | "html") => {
    if (!report) return;
    const exportUrl = `/api/reports/${report.id}/export?format=${format}`;
    if (format === "html") {
      window.open(exportUrl, "_blank");
    } else {
      const link = document.createElement("a");
      link.href = exportUrl;
      link.setAttribute("download", `report-${report.reportCode}.${format === "json" ? "json" : "md"}`);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    }
  };

  const c = (report?.contentJson as Record<string, any>) || {};

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-sm">
      <div className="flex max-h-[90vh] w-full max-w-4xl flex-col overflow-hidden rounded-2xl border border-white/[0.1] bg-[#14181b] shadow-2xl">
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-white/[0.08] px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-[#b7f960]/20 bg-[#b7f960]/10 text-[#b7f960]">
              <FileText size={18} />
            </div>
            <div>
              <h2 className="font-display text-base font-semibold text-slate-100">
                {isCreateMode ? "Generate Security Document" : report?.title || "Report Inspection"}
              </h2>
              <p className="text-[11px] text-slate-400">
                {isCreateMode
                  ? "Synthesize operational and forensic telemetry from PostgreSQL"
                  : `${report?.reportCode || "REPORT"} · ${report?.reportType || ""}`}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 hover:bg-white/[0.05] hover:text-white"
          >
            <X size={18} />
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {isCreateMode ? (
            /* CREATE MODE FORM */
            <div className="space-y-5">
              <div>
                <label className="block font-display text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-2">
                  1. Select Report Template
                </label>
                <div className="grid gap-3 sm:grid-cols-3">
                  {[
                    {
                      type: "Executive incident report",
                      title: "Executive Brief",
                      desc: "High-level impact, containment status, and leadership decisions.",
                      icon: Sparkles,
                    },
                    {
                      type: "Technical investigation report",
                      title: "Technical Forensic",
                      desc: "Deep forensic evidence trail, timeline, and MITRE mapping.",
                      icon: ShieldAlert,
                    },
                    {
                      type: "Operational summary",
                      title: "Posture Summary",
                      desc: "Fleet-wide telemetry metrics, coverage score, and active cases.",
                      icon: FileSearch,
                    },
                  ].map((tpl) => {
                    const Icon = tpl.icon;
                    const isSelected = reportType === tpl.type;
                    return (
                      <button
                        key={tpl.type}
                        type="button"
                        onClick={() => setReportType(tpl.type as any)}
                        className={`rounded-xl border p-4 text-left transition ${
                          isSelected
                            ? "border-[#b7f960] bg-[#b7f960]/10"
                            : "border-white/[0.08] bg-[#171c20] hover:border-white/[0.15]"
                        }`}
                      >
                        <div className={`flex h-8 w-8 items-center justify-center rounded-lg ${
                          isSelected ? "bg-[#b7f960] text-black" : "bg-white/[0.05] text-slate-400"
                        }`}>
                          <Icon size={16} />
                        </div>
                        <div className="mt-3 font-display text-sm font-semibold text-slate-100">
                          {tpl.title}
                        </div>
                        <div className="mt-1 text-[11px] text-slate-400">{tpl.desc}</div>
                      </button>
                    );
                  })}
                </div>
              </div>

              {reportType !== "Operational summary" && (
                <div>
                  <label className="block font-display text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-2">
                    2. Link Active Incident Case
                  </label>
                  {casesList.length > 0 ? (
                    <select
                      value={selectedCaseId}
                      onChange={(e) => setSelectedCaseId(Number(e.target.value))}
                      className="w-full rounded-xl border border-white/[0.08] bg-[#171c20] px-4 py-2.5 text-xs text-slate-200 focus:border-[#b7f960] focus:outline-none"
                    >
                      {casesList.map((c) => (
                        <option key={c.id} value={c.id}>
                          {c.caseNumber}: {c.title} ({c.severity} · {c.affectedAsset})
                        </option>
                      ))}
                    </select>
                  ) : (
                    <div className="rounded-xl border border-white/[0.08] bg-[#171c20] p-3 text-xs text-slate-400">
                      No active cases found. Baseline telemetry will be synthesized.
                    </div>
                  )}
                </div>
              )}

              <div>
                <label className="block font-display text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-2">
                  3. Custom Report Title (Optional)
                </label>
                <input
                  type="text"
                  placeholder="e.g. Q4 Executive Incident Containment Brief"
                  value={customTitle}
                  onChange={(e) => setCustomTitle(e.target.value)}
                  className="w-full rounded-xl border border-white/[0.08] bg-[#171c20] px-4 py-2.5 text-xs text-slate-200 placeholder-slate-600 focus:border-[#b7f960] focus:outline-none"
                />
              </div>

              <div className="rounded-xl border border-cyan-500/30 bg-cyan-950/20 p-3 text-xs text-slate-300">
                <span className="font-semibold text-cyan-300">Data Integrity Notice:</span> Document generation automatically retrieves confirmed alerts, affected entities, and telemetry metrics from PostgreSQL.
              </div>
            </div>
          ) : loading ? (
            <div className="p-12 text-center text-slate-500">
              <Loader2 className="animate-spin mx-auto mb-3 text-[#b7f960]" size={22} />
              Loading report document from database...
            </div>
          ) : report ? (
            /* PREVIEW MODE */
            <div className="space-y-6">
              {/* Top Meta Strip */}
              <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-white/[0.08] bg-[#171c20] p-4">
                <div>
                  <span className="text-[10px] font-medium text-slate-500">CLASSIFICATION</span>
                  <div className="font-mono text-xs font-semibold text-amber-400">
                    {c.classification || "CONFIDENTIAL // TLP:AMBER"}
                  </div>
                </div>
                <div>
                  <span className="text-[10px] font-medium text-slate-500">REPORT CODE</span>
                  <div className="font-mono text-xs font-bold text-white">{report.reportCode}</div>
                </div>
                <div>
                  <span className="text-[10px] font-medium text-slate-500">REPORT TYPE</span>
                  <div className="text-xs font-semibold text-slate-200">{report.reportType}</div>
                </div>
                <div>
                  <span className="text-[10px] font-medium text-slate-500">STATUS</span>
                  <div className="flex items-center gap-1.5 mt-0.5">
                    <span className={`rounded-sm px-2 py-0.5 font-display text-[10px] font-semibold uppercase ${
                      report.status === "Published"
                        ? "bg-[#b7f960]/10 text-[#b7f960] border border-[#b7f960]/30"
                        : report.status === "Review"
                        ? "bg-[#d9aa58]/10 text-[#f0c97f] border border-[#d9aa58]/30"
                        : "bg-white/[0.06] text-slate-400 border border-white/[0.1]"
                    }`}>
                      {report.status}
                    </span>
                  </div>
                </div>
              </div>

              {/* Status Transition Control Strip */}
              <div className="flex items-center justify-between rounded-xl border border-white/[0.06] bg-black/30 px-4 py-2.5 text-xs text-slate-400">
                <span>Transition Document Lifecycle:</span>
                <div className="flex items-center gap-2">
                  {(["Draft", "Review", "Published"] as const).map((st) => (
                    <button
                      key={st}
                      type="button"
                      disabled={updatingStatus || report.status === st}
                      onClick={() => handleUpdateStatus(st)}
                      className={`rounded-lg px-2.5 py-1 text-[11px] font-medium transition ${
                        report.status === st
                          ? "bg-white/[0.15] text-white font-semibold"
                          : "bg-white/[0.03] text-slate-400 hover:bg-white/[0.08] hover:text-slate-200 disabled:opacity-40"
                      }`}
                    >
                      {st}
                    </button>
                  ))}
                </div>
              </div>

              {/* Linked Case Badge if available */}
              {report.linkedCase && (
                <div className="rounded-xl border border-white/[0.08] bg-[#171c20] p-4 text-xs">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <ShieldAlert size={14} className="text-[#b7f960]" />
                      <span className="font-semibold text-slate-200">
                        Linked Investigation: {report.linkedCase.caseNumber}
                      </span>
                    </div>
                    <span className="text-slate-500 text-[11px]">
                      Asset: {report.linkedCase.affectedAsset} · Entity: {report.linkedCase.primaryEntity}
                    </span>
                  </div>
                </div>
              )}

              {/* SECTION: Executive Incident Report */}
              {report.reportType === "Executive incident report" && (
                <div className="space-y-4">
                  <div className="rounded-xl border border-white/[0.08] bg-[#171c20] p-4">
                    <h3 className="font-display text-xs font-semibold uppercase tracking-wider text-[#b7f960] mb-2">
                      1. Executive Summary
                    </h3>
                    <p className="text-xs text-slate-300 leading-relaxed">
                      {c.executiveSummary || "No executive summary provided."}
                    </p>
                  </div>

                  {c.businessImpact && (
                    <div className="grid gap-3 sm:grid-cols-3">
                      <div className="rounded-xl border border-white/[0.08] bg-[#171c20] p-3 text-xs">
                        <div className="text-[10px] text-slate-500 uppercase">Impact Rating</div>
                        <div className="font-semibold text-red-300 mt-1">{c.businessImpact.impactRating}</div>
                      </div>
                      <div className="rounded-xl border border-white/[0.08] bg-[#171c20] p-3 text-xs">
                        <div className="text-[10px] text-slate-500 uppercase">Operational Status</div>
                        <div className="font-semibold text-emerald-400 mt-1">{c.businessImpact.operationalDisruption}</div>
                      </div>
                      <div className="rounded-xl border border-white/[0.08] bg-[#171c20] p-3 text-xs">
                        <div className="text-[10px] text-slate-500 uppercase">Regulatory Disclosure</div>
                        <div className="font-semibold text-slate-300 mt-1">{c.businessImpact.regulatoryNotification}</div>
                      </div>
                    </div>
                  )}

                  {Array.isArray(c.containmentActions) && (
                    <div className="rounded-xl border border-white/[0.08] bg-[#171c20] p-4 text-xs">
                      <h3 className="font-display text-xs font-semibold uppercase tracking-wider text-slate-200 mb-2">
                        2. Verified Containment Actions
                      </h3>
                      <ul className="space-y-1.5 text-slate-300">
                        {c.containmentActions.map((act: string, idx: number) => (
                          <li key={idx} className="flex items-start gap-2">
                            <CheckCircle2 size={13} className="text-[#b7f960] shrink-0 mt-0.5" />
                            <span>{act}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {Array.isArray(c.leadershipDecisionsRequested) && (
                    <div className="rounded-xl border border-amber-500/20 bg-amber-950/20 p-4 text-xs">
                      <h3 className="font-display text-xs font-semibold uppercase tracking-wider text-amber-300 mb-2">
                        3. Decisions Requested from Leadership
                      </h3>
                      <ul className="space-y-1.5 text-slate-300">
                        {c.leadershipDecisionsRequested.map((dec: string, idx: number) => (
                          <li key={idx} className="flex items-start gap-2">
                            <span className="font-mono text-amber-400 font-bold">•</span>
                            <span>{dec}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}

              {/* SECTION: Technical Investigation Report */}
              {report.reportType === "Technical investigation report" && (
                <div className="space-y-4">
                  <div className="rounded-xl border border-white/[0.08] bg-[#171c20] p-4">
                    <h3 className="font-display text-xs font-semibold uppercase tracking-wider text-cyan-400 mb-2">
                      1. Technical Forensic Summary
                    </h3>
                    <p className="text-xs text-slate-300 leading-relaxed">
                      {c.technicalSummary || "Forensic analysis of verified telemetry."}
                    </p>
                  </div>

                  <div className="grid gap-3 sm:grid-cols-4">
                    <div className="rounded-xl border border-white/[0.08] bg-[#171c20] p-3 text-xs">
                      <div className="text-[10px] text-slate-500 uppercase">MITRE Technique</div>
                      <div className="font-mono font-semibold text-cyan-300 mt-1">{c.mitreTechnique || "T1110"}</div>
                    </div>
                    <div className="rounded-xl border border-white/[0.08] bg-[#171c20] p-3 text-xs">
                      <div className="text-[10px] text-slate-500 uppercase">MITRE Tactic</div>
                      <div className="font-semibold text-slate-300 mt-1 truncate">{c.mitreTactic || "TA0006"}</div>
                    </div>
                    <div className="rounded-xl border border-white/[0.08] bg-[#171c20] p-3 text-xs">
                      <div className="text-[10px] text-slate-500 uppercase">Target Asset</div>
                      <div className="font-semibold text-slate-300 mt-1 truncate">{c.affectedAsset || "Infrastructure"}</div>
                    </div>
                    <div className="rounded-xl border border-white/[0.08] bg-[#171c20] p-3 text-xs">
                      <div className="text-[10px] text-slate-500 uppercase">AI Confidence</div>
                      <div className="font-mono font-semibold text-[#b7f960] mt-1">{c.confidence || "92.5"}%</div>
                    </div>
                  </div>

                  {Array.isArray(c.timeline) && c.timeline.length > 0 && (
                    <div className="rounded-xl border border-white/[0.08] bg-[#171c20] p-4 text-xs">
                      <h3 className="font-display text-xs font-semibold uppercase tracking-wider text-slate-200 mb-3">
                        2. Sequence of Events
                      </h3>
                      <div className="space-y-2">
                        {c.timeline.map((t: any, idx: number) => (
                          <div key={idx} className="flex items-center justify-between border-b border-white/[0.04] pb-1.5 last:border-b-0">
                            <div className="flex items-center gap-2">
                              <span className="font-mono text-[10px] text-cyan-400 bg-cyan-950/60 px-1.5 py-0.5 rounded">
                                {t.time}
                              </span>
                              <span className="text-slate-300">{t.title}</span>
                            </div>
                            <span className="text-[10px] text-slate-500 font-medium">{t.status}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {Array.isArray(c.remediationPlaybook) && (
                    <div className="rounded-xl border border-white/[0.08] bg-[#171c20] p-4 text-xs">
                      <h3 className="font-display text-xs font-semibold uppercase tracking-wider text-slate-200 mb-2">
                        3. Technical Remediation Playbook
                      </h3>
                      <ol className="space-y-1.5 text-slate-300 list-decimal list-inside">
                        {c.remediationPlaybook.map((st: string, idx: number) => (
                          <li key={idx} className="leading-relaxed">{st}</li>
                        ))}
                      </ol>
                    </div>
                  )}
                </div>
              )}

              {/* SECTION: Operational Summary */}
              {report.reportType === "Operational summary" && (
                <div className="space-y-4">
                  <div className="grid gap-3 sm:grid-cols-4">
                    <div className="rounded-xl border border-[#b7f960]/30 bg-[#b7f960]/10 p-3 text-xs">
                      <div className="text-[10px] text-slate-400 uppercase">Coverage Score</div>
                      <div className="font-display text-lg font-bold text-[#b7f960] mt-1">{c.postureScore || 94.5}%</div>
                    </div>
                    <div className="rounded-xl border border-white/[0.08] bg-[#171c20] p-3 text-xs">
                      <div className="text-[10px] text-slate-500 uppercase">Ingested Events</div>
                      <div className="font-mono text-lg font-bold text-slate-200 mt-1">
                        {c.telemetry?.totalEventsIngested?.toLocaleString() || 0}
                      </div>
                    </div>
                    <div className="rounded-xl border border-white/[0.08] bg-[#171c20] p-3 text-xs">
                      <div className="text-[10px] text-slate-500 uppercase">Triggered Alerts</div>
                      <div className="font-mono text-lg font-bold text-amber-400 mt-1">
                        {c.telemetry?.totalAlertsTriggered?.toLocaleString() || 0}
                      </div>
                    </div>
                    <div className="rounded-xl border border-white/[0.08] bg-[#171c20] p-3 text-xs">
                      <div className="text-[10px] text-slate-500 uppercase">Active Cases</div>
                      <div className="font-mono text-lg font-bold text-cyan-300 mt-1">
                        {c.telemetry?.activeInvestigations || 0}
                      </div>
                    </div>
                  </div>

                  {c.telemetry?.severityBreakdown && (
                    <div className="rounded-xl border border-white/[0.08] bg-[#171c20] p-4 text-xs">
                      <h3 className="font-display text-xs font-semibold uppercase tracking-wider text-slate-200 mb-3">
                        Alert Breakdown by Severity
                      </h3>
                      <div className="grid grid-cols-4 gap-2 text-center">
                        <div className="rounded bg-red-950/40 border border-red-500/20 p-2">
                          <div className="text-[10px] text-red-300">Critical</div>
                          <div className="font-bold text-red-400 text-sm mt-0.5">{c.telemetry.severityBreakdown.critical}</div>
                        </div>
                        <div className="rounded bg-orange-950/40 border border-orange-500/20 p-2">
                          <div className="text-[10px] text-orange-300">High</div>
                          <div className="font-bold text-orange-400 text-sm mt-0.5">{c.telemetry.severityBreakdown.high}</div>
                        </div>
                        <div className="rounded bg-yellow-950/40 border border-yellow-500/20 p-2">
                          <div className="text-[10px] text-yellow-300">Medium</div>
                          <div className="font-bold text-yellow-400 text-sm mt-0.5">{c.telemetry.severityBreakdown.medium}</div>
                        </div>
                        <div className="rounded bg-slate-900 border border-white/[0.08] p-2">
                          <div className="text-[10px] text-slate-400">Low</div>
                          <div className="font-bold text-slate-300 text-sm mt-0.5">{c.telemetry.severityBreakdown.low}</div>
                        </div>
                      </div>
                    </div>
                  )}

                  {Array.isArray(c.strategicRecommendations) && (
                    <div className="rounded-xl border border-white/[0.08] bg-[#171c20] p-4 text-xs">
                      <h3 className="font-display text-xs font-semibold uppercase tracking-wider text-slate-200 mb-2">
                        Operational Posture Recommendations
                      </h3>
                      <ul className="space-y-1.5 text-slate-300">
                        {c.strategicRecommendations.map((rec: string, idx: number) => (
                          <li key={idx} className="flex items-start gap-2">
                            <span className="font-bold text-[#b7f960]">•</span>
                            <span>{rec}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}
            </div>
          ) : (
            <div className="p-8 text-center text-slate-500">Report details not found.</div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="flex flex-wrap items-center justify-between border-t border-white/[0.08] bg-[#171c20] px-6 py-4">
          {isCreateMode ? (
            <>
              <span className="text-[11px] text-slate-500">
                Synthesized directly from live incident records
              </span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={onClose}
                  className="rounded-lg border border-white/[0.1] bg-white/[0.03] px-4 py-2 text-xs text-slate-300 hover:bg-white/[0.06]"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  disabled={generating}
                  onClick={handleGenerate}
                  className="flex items-center gap-1.5 rounded-lg border border-[#b7f960]/40 bg-[#b7f960] px-5 py-2 font-display text-xs font-semibold text-black hover:bg-[#c9f785] disabled:opacity-50"
                >
                  {generating ? (
                    <>
                      <Loader2 size={13} className="animate-spin" /> Generating...
                    </>
                  ) : (
                    <>
                      <Sparkles size={13} /> Generate Document
                    </>
                  )}
                </button>
              </div>
            </>
          ) : (
            <>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => handleDownload("json")}
                  className="flex items-center gap-1.5 rounded-lg border border-white/[0.1] bg-white/[0.03] px-3 py-1.5 text-xs text-slate-300 hover:bg-white/[0.06]"
                >
                  <Download size={13} /> JSON
                </button>
                <button
                  type="button"
                  onClick={() => handleDownload("markdown")}
                  className="flex items-center gap-1.5 rounded-lg border border-white/[0.1] bg-white/[0.03] px-3 py-1.5 text-xs text-slate-300 hover:bg-white/[0.06]"
                >
                  <Download size={13} /> Markdown
                </button>
                <button
                  type="button"
                  onClick={() => handleDownload("html")}
                  className="flex items-center gap-1.5 rounded-lg border border-[#b7f960]/30 bg-[#b7f960]/10 px-3 py-1.5 text-xs font-semibold text-[#b7f960] hover:bg-[#b7f960]/20"
                >
                  <Printer size={13} /> Print / Save PDF
                </button>
              </div>

              <button
                type="button"
                onClick={onClose}
                className="rounded-lg border border-white/[0.1] bg-white/[0.03] px-4 py-1.5 text-xs text-slate-300 hover:bg-white/[0.06]"
              >
                Close
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
