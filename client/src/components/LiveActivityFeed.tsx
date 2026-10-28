import React, { useState } from "react";
import { useLocation } from "wouter";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock3,
  ExternalLink,
  FileCode2,
  Radio,
  RefreshCw,
  ShieldAlert,
  Terminal,
  Wifi,
  WifiOff,
  Zap,
} from "lucide-react";
import { useRealtime } from "@/contexts/RealtimeContext";
import type { SecurityEvent } from "@shared/events";

interface LiveActivityFeedProps {
  maxItems?: number;
  className?: string;
  showFilters?: boolean;
}

export function LiveActivityFeed({
  maxItems = 15,
  className = "",
  showFilters = true,
}: LiveActivityFeedProps) {
  const [, setLocation] = useLocation();
  const { status, activityEvents, lastHeartbeat, reconnect } = useRealtime();
  const [filterType, setFilterType] = useState<"all" | "alerts" | "status" | "logs">("all");

  const filteredEvents = activityEvents.filter((ev) => {
    if (filterType === "alerts") return ev.type === "alert.created" || ev.type === "alert.updated";
    if (filterType === "status") return ev.type === "alert.status_changed";
    if (filterType === "logs") return ev.type === "log.ingested" || ev.type === "logs.bulk_ingested";
    return true;
  }).slice(0, maxItems);

  const getStatusBadge = () => {
    switch (status) {
      case "connected":
        return (
          <div className="flex items-center gap-1.5 rounded-full border border-[#b7f960]/30 bg-[#b7f960]/10 px-2.5 py-0.5 text-[10px] font-semibold text-[#c9f785]">
            <span className="status-pulse h-1.5 w-1.5 rounded-full bg-[#b7f960]" />
            <span className="font-display uppercase tracking-wider">Stream Live</span>
          </div>
        );
      case "reconnecting":
        return (
          <div className="flex items-center gap-1.5 rounded-full border border-[#d9aa58]/30 bg-[#d9aa58]/10 px-2.5 py-0.5 text-[10px] font-semibold text-[#f0c97f]">
            <RefreshCw className="h-2.5 w-2.5 animate-spin" />
            <span className="font-display uppercase tracking-wider">Reconnecting</span>
          </div>
        );
      case "auth_required":
        return (
          <div className="flex items-center gap-1.5 rounded-full border border-[#e16c5c]/30 bg-[#e16c5c]/10 px-2.5 py-0.5 text-[10px] font-semibold text-[#ff9a8d]">
            <WifiOff className="h-2.5 w-2.5" />
            <span className="font-display uppercase tracking-wider">Auth Required</span>
          </div>
        );
      case "disconnected":
      default:
        return (
          <button
            onClick={reconnect}
            className="flex items-center gap-1.5 rounded-full border border-slate-700 bg-slate-800/80 px-2.5 py-0.5 text-[10px] font-semibold text-slate-400 hover:text-slate-200 transition"
          >
            <WifiOff className="h-2.5 w-2.5" />
            <span className="font-display uppercase tracking-wider">Offline (Reconnect)</span>
          </button>
        );
    }
  };

  const renderEventItem = (event: SecurityEvent) => {
    const timeFormatted = new Date(event.timestamp).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });

    if (event.type === "alert.created" || event.type === "alert.updated") {
      const isCritical = event.data.severity === "Critical";
      const isHigh = event.data.severity === "High";
      const sevColor = isCritical
        ? "text-[#ff9a8d] border-[#e16c5c]/40 bg-[#e16c5c]/10"
        : isHigh
        ? "text-[#f0c97f] border-[#d9aa58]/40 bg-[#d9aa58]/10"
        : "text-[#a7ddea] border-[#6fb6cc]/40 bg-[#6fb6cc]/10";
      const tacticName = "tactic" in event.data ? (event.data as any).tactic : "Alert";

      return (
        <div
          key={event.id}
          onClick={() => setLocation("/alerts")}
          className="group relative flex cursor-pointer items-start gap-3 rounded-lg border border-white/[0.04] bg-white/[0.015] p-3 transition hover:border-white/[0.12] hover:bg-white/[0.04]"
        >
          <div className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-white/[0.08] bg-black/40 text-slate-300">
            <ShieldAlert size={14} className={isCritical ? "text-[#ff9a8d]" : isHigh ? "text-[#f0c97f]" : "text-[#b7f960]"} />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className={`inline-flex rounded border px-1.5 py-0.5 font-display text-[9px] font-bold uppercase tracking-wider ${sevColor}`}>
                {event.data.severity}
              </span>
              <span className="font-display text-[10px] font-semibold tracking-wider text-slate-400">
                {event.data.ruleId || "DETECTION"}
              </span>
              <span className="text-[10px] text-slate-500">·</span>
              <span className="text-[10px] text-slate-400">{tacticName}</span>
              <span className="ml-auto font-mono text-[10px] text-slate-500">{timeFormatted}</span>
            </div>
            <p className="mt-1 truncate text-[12px] font-medium text-slate-200 group-hover:text-white">
              {event.data.title}
            </p>
            <div className="mt-1 flex items-center justify-between text-[10px] text-slate-500">
              <span className="truncate font-mono">{event.data.source || "Network"} {event.data.destination ? `→ ${event.data.destination}` : ""}</span>
              <span className="flex items-center gap-1 text-[#b7f960] opacity-0 transition group-hover:opacity-100">
                Investigate <ArrowRight size={10} />
              </span>
            </div>
          </div>
        </div>
      );
    }

    if (event.type === "alert.status_changed") {
      return (
        <div
          key={event.id}
          onClick={() => setLocation("/alerts")}
          className="group relative flex cursor-pointer items-start gap-3 rounded-lg border border-white/[0.04] bg-white/[0.015] p-3 transition hover:border-white/[0.12] hover:bg-white/[0.04]"
        >
          <div className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-purple-500/30 bg-purple-500/10 text-purple-300">
            <CheckCircle2 size={14} />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="inline-flex rounded border border-purple-500/30 bg-purple-500/10 px-1.5 py-0.5 font-display text-[9px] font-bold uppercase tracking-wider text-purple-300">
                Triage Transition
              </span>
              <span className="font-mono text-[10px] text-slate-400">#{event.data.alertId}</span>
              <span className="ml-auto font-mono text-[10px] text-slate-500">{timeFormatted}</span>
            </div>
            <p className="mt-1 text-[12px] text-slate-300">
              Status updated from <span className="font-semibold text-slate-400">{event.data.previousStatus}</span> to{" "}
              <span className="font-semibold text-[#b7f960]">{event.data.newStatus}</span>
            </p>
            <p className="mt-0.5 text-[10px] text-slate-500">
              Updated by {event.data.actor?.fullName || "Analyst"} ({event.data.actor?.role || "SOC"})
            </p>
          </div>
        </div>
      );
    }

    if (event.type === "log.ingested") {
      const isThreat = event.data.isThreat;
      return (
        <div
          key={event.id}
          onClick={() => setLocation("/logs")}
          className="group relative flex cursor-pointer items-start gap-3 rounded-lg border border-white/[0.04] bg-white/[0.015] p-3 transition hover:border-white/[0.12] hover:bg-white/[0.04]"
        >
          <div className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-blue-500/30 bg-blue-500/10 text-blue-300">
            <Terminal size={14} />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className={`inline-flex rounded border px-1.5 py-0.5 font-display text-[9px] font-bold uppercase tracking-wider ${
                isThreat ? "border-amber-500/40 bg-amber-500/10 text-amber-300" : "border-blue-500/30 bg-blue-500/10 text-blue-300"
              }`}>
                {isThreat ? "Threat Log" : "Log Ingested"}
              </span>
              <span className="font-mono text-[10px] text-slate-400">{event.data.sourceType || "syslog"}</span>
              <span className="ml-auto font-mono text-[10px] text-slate-500">{timeFormatted}</span>
            </div>
            <p className="mt-1 truncate text-[12px] text-slate-300">
              {event.data.threatReason || `Log from ${event.data.sourceIp || "host"}`}
            </p>
            <p className="mt-0.5 font-mono text-[10px] text-slate-500">
              {event.data.logLevel || "info"} · Rule checks evaluated
            </p>
          </div>
        </div>
      );
    }

    if (event.type === "logs.bulk_ingested") {
      return (
        <div
          key={event.id}
          onClick={() => setLocation("/logs")}
          className="group relative flex cursor-pointer items-start gap-3 rounded-lg border border-white/[0.04] bg-white/[0.015] p-3 transition hover:border-white/[0.12] hover:bg-white/[0.04]"
        >
          <div className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-emerald-500/30 bg-emerald-500/10 text-emerald-300">
            <FileCode2 size={14} />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="inline-flex rounded border border-emerald-500/30 bg-emerald-500/10 px-1.5 py-0.5 font-display text-[9px] font-bold uppercase tracking-wider text-emerald-300">
                Bulk Ingest Batch
              </span>
              <span className="font-mono text-[10px] text-slate-400">{event.data.source}</span>
              <span className="ml-auto font-mono text-[10px] text-slate-500">{timeFormatted}</span>
            </div>
            <p className="mt-1 text-[12px] text-slate-300">
              Successfully processed <strong className="text-white">{event.data.ingestedCount}</strong> records
              {event.data.alertsGeneratedCount > 0 ? (
                <> · Surfaced <strong className="text-[#ff9a8d]">{event.data.alertsGeneratedCount} alerts</strong></>
              ) : " · No threat alerts triggered"}
            </p>
            {event.data.fileName && (
              <p className="mt-0.5 font-mono text-[10px] text-slate-500 truncate">
                Source file: {event.data.fileName}
              </p>
            )}
          </div>
        </div>
      );
    }

    return null;
  };

  return (
    <div className={`rounded-xl border border-white/[0.08] bg-[#0d1012] p-4 md:p-5 ${className}`}>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between border-b border-white/[0.08] pb-3.5">
        <div>
          <div className="flex items-center gap-2">
            <Zap className="h-4 w-4 text-[#b7f960]" />
            <h3 className="font-display text-[15px] font-semibold text-slate-100">Live Telemetry Feed</h3>
          </div>
          <p className="mt-0.5 text-[11px] text-slate-400">
            Real-time event stream from PostgreSQL detection engine
          </p>
        </div>
        <div className="flex items-center gap-2">
          {getStatusBadge()}
          {lastHeartbeat && (
            <span className="hidden font-mono text-[9px] text-slate-500 lg:inline-block" title="Last server heartbeat">
              HB: {lastHeartbeat.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
            </span>
          )}
        </div>
      </div>

      {showFilters && (
        <div className="flex items-center gap-1.5 py-2.5 border-b border-white/[0.04]">
          <button
            onClick={() => setFilterType("all")}
            className={`rounded-md px-2.5 py-1 font-display text-[10px] font-medium transition ${
              filterType === "all" ? "bg-white/[0.08] text-[#b7f960]" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            All Events
          </button>
          <button
            onClick={() => setFilterType("alerts")}
            className={`rounded-md px-2.5 py-1 font-display text-[10px] font-medium transition ${
              filterType === "alerts" ? "bg-white/[0.08] text-[#b7f960]" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            Alerts
          </button>
          <button
            onClick={() => setFilterType("status")}
            className={`rounded-md px-2.5 py-1 font-display text-[10px] font-medium transition ${
              filterType === "status" ? "bg-white/[0.08] text-[#b7f960]" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            Triage
          </button>
          <button
            onClick={() => setFilterType("logs")}
            className={`rounded-md px-2.5 py-1 font-display text-[10px] font-medium transition ${
              filterType === "logs" ? "bg-white/[0.08] text-[#b7f960]" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            Log Ingestion
          </button>
        </div>
      )}

      <div className="mt-3.5 space-y-2 max-h-[460px] overflow-y-auto pr-1">
        {filteredEvents.length > 0 ? (
          filteredEvents.map(renderEventItem)
        ) : (
          <div className="flex flex-col items-center justify-center py-10 text-center text-slate-500">
            <Radio className="h-8 w-8 text-slate-600 mb-2 opacity-60" />
            <p className="text-[12px] font-medium">Awaiting live telemetry events</p>
            <p className="mt-1 text-[10px] text-slate-600">Events will stream here automatically when logs or detections are processed</p>
          </div>
        )}
      </div>
    </div>
  );
}
