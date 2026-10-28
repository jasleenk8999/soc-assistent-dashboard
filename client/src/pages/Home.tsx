/** Signal Room control surface: persistent analyst rail, editorial data hierarchy, and calm verified-status semantics. */
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { useLocation } from "wouter";
import {
  Activity, ArrowRight, Bell, Bot, Check, ChevronDown, ChevronRight, CircleAlert, Clock3,
  FileCode2, FileSearch, FileText, Filter, Globe2, LayoutDashboard, Loader2, LogIn, LogOut,
  MoreHorizontal, Network, Plus, Radar, RefreshCw, Search, Settings2, ShieldAlert, ShieldCheck,
  SlidersHorizontal, Sparkles, TerminalSquare, UploadCloud, UserCheck, UsersRound, Wifi,
} from "lucide-react";
import { Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { toast } from "sonner";
import { useAuth } from "@/contexts/AuthContext";
import { LoginModal } from "@/components/LoginModal";
import { LogIngestion } from "@/components/LogIngestion";
import { AlertDetailModal } from "@/components/AlertDetailModal";
import { ROLES, ROLE_PERMISSIONS, type UserRole } from "@shared/auth";
import {
  api,
  type AlertItem,
  type CaseItem,
  type DashboardStats,
  type MalwareSampleItem,
  type NetworkFlowItem,
  type ReportItem,
  type ThreatIntelItem,
} from "@/lib/api";

const ASSETS = {
  logo: "/manus-storage/signal-room-logo_6a4bd273.png",
  atlas: "/manus-storage/signal-room-telemetry-atlas_f61b13e3.png",
  brief: "/manus-storage/ai-brief-artifact_26e8984d.png",
  orbit: "/manus-storage/threat-orbit-abstract_6c6dd034.png",
};

type Severity = "Critical" | "High" | "Medium" | "Low";

const routes = {
  overview: "/",
  alerts: "/alerts",
  logs: "/logs",
  investigation: "/investigation",
  network: "/network",
  malware: "/malware-lab",
  intel: "/threat-intel",
  team: "/team",
  reports: "/reports",
  settings: "/settings",
};

const commandNav = [
  { label: "Overview", href: routes.overview, icon: LayoutDashboard },
  { label: "Live alerts", href: routes.alerts, icon: ShieldAlert, badge: "Live" },
  { label: "Log Ingestion", href: routes.logs, icon: FileCode2, badge: "Live" },
  { label: "Investigation", href: routes.investigation, icon: Radar },
  { label: "Network", href: routes.network, icon: Network },
  { label: "Malware lab", href: routes.malware, icon: TerminalSquare },
  { label: "Threat Intel", href: routes.intel, icon: Globe2 },
];
const workspaceNav = [
  { label: "Team & roles", href: routes.team, icon: UsersRound },
  { label: "Reports", href: routes.reports, icon: FileText },
  { label: "Settings", href: routes.settings, icon: Settings2 },
];

function Meta({ children }: { children: ReactNode }) {
  return <span className="font-display text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">{children}</span>;
}

function Panel({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <section className={`panel rounded-xl ${className}`}>{children}</section>;
}

function ActionButton({
  children,
  onClick,
  tone = "muted",
  className = "",
  disabled = false,
}: {
  children: ReactNode;
  onClick?: () => void;
  tone?: "muted" | "lime" | "danger";
  className?: string;
  disabled?: boolean;
}) {
  const tones = {
    muted: "border-white/[0.1] bg-white/[0.035] text-slate-300 hover:bg-white/[0.08]",
    lime: "border-[#b7f960]/30 bg-[#b7f960] text-[#1a2513] hover:bg-[#ccff88]",
    danger: "border-[#e16c5c]/30 bg-[#e16c5c]/10 text-[#ff9b90] hover:bg-[#e16c5c]/18",
  };
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`inline-flex items-center justify-center gap-2 rounded-lg border px-3.5 py-2.5 font-display text-[10px] font-bold uppercase tracking-[0.1em] transition active:scale-[0.97] disabled:opacity-50 disabled:pointer-events-none ${tones[tone]} ${className}`}
    >
      {children}
    </button>
  );
}

function SeverityTag({ severity }: { severity: Severity }) {
  const style = {
    Critical: "border-[#e16c5c]/35 bg-[#e16c5c]/10 text-[#ff9a8d]",
    High: "border-[#d9aa58]/35 bg-[#d9aa58]/10 text-[#f0c97f]",
    Medium: "border-[#6fb6cc]/35 bg-[#6fb6cc]/10 text-[#a7ddea]",
    Low: "border-slate-500/35 bg-slate-500/10 text-slate-400",
  };
  return (
    <span className={`inline-flex rounded-sm border px-2 py-1 font-display text-[9px] font-semibold uppercase tracking-[0.14em] ${style[severity] || style.Low}`}>
      {severity}
    </span>
  );
}

function Metric({
  label,
  value,
  change,
  icon: Icon,
  tone = "lime",
}: {
  label: string;
  value: string;
  change: string;
  icon: typeof Activity;
  tone?: "lime" | "red" | "blue" | "amber";
}) {
  const colors = {
    lime: "border-[#b7f960]/20 bg-[#b7f960]/10 text-[#b7f960]",
    red: "border-[#e16c5c]/20 bg-[#e16c5c]/10 text-[#ff8f82]",
    blue: "border-[#6fb6cc]/20 bg-[#6fb6cc]/10 text-[#9bd5e6]",
    amber: "border-[#d9aa58]/20 bg-[#d9aa58]/10 text-[#eac272]",
  };
  return (
    <Panel className="panel-lift p-4">
      <div className="flex items-start justify-between">
        <div className={`flex h-9 w-9 items-center justify-center rounded-lg border ${colors[tone]}`}>
          <Icon size={17} />
        </div>
        <span className={`font-display text-[10px] font-semibold ${tone === "red" ? "text-[#ff8f82]" : "text-[#b7f960]"}`}>{change}</span>
      </div>
      <div className="mt-5">
        <Meta>{label}</Meta>
        <p className="mt-1.5 font-display text-2xl font-semibold tracking-tight text-slate-100">{value}</p>
      </div>
    </Panel>
  );
}

function PageHeader({ eyebrow, title, subtitle, actions }: { eyebrow: string; title: string; subtitle: string; actions?: ReactNode }) {
  return (
    <div className="flex flex-col gap-5 border-b border-white/[0.08] px-4 py-7 md:flex-row md:items-end md:justify-between md:px-7 md:py-8">
      <div>
        <Meta>{eyebrow}</Meta>
        <h1 className="mt-2 font-display text-3xl font-semibold tracking-[-0.04em] text-white md:text-[34px]">{title}</h1>
        <p className="mt-2 max-w-2xl text-[13px] leading-relaxed text-slate-400">{subtitle}</p>
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  );
}

const tooltipStyle = {
  background: "#192025",
  border: "1px solid rgba(255,255,255,0.1)",
  borderRadius: "8px",
  color: "#e7ebec",
  fontFamily: "Manrope",
  fontSize: "11px",
};

// ===========================================================================
// 1. OVERVIEW SCREEN (Connected to PostgreSQL Backend)
// ===========================================================================
function Overview() {
  const { user } = useAuth();
  const [period, setPeriod] = useState("24h");
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadStats = async (selectedPeriod: string) => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.getDashboardStats(selectedPeriod);
      setStats(data);
    } catch (err: any) {
      console.error("Failed to load dashboard stats:", err);
      setError(err.message || "Could not connect to PostgreSQL backend");
      toast.error("Failed to load live database telemetry");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadStats(period);
  }, [period]);

  const defaultAttackMix = [
    { name: "Credential", value: 37, color: "#e16c5c" },
    { name: "Network", value: 28, color: "#b7f960" },
    { name: "Web", value: 19, color: "#6fb6cc" },
    { name: "Other", value: 16, color: "#48555d" },
  ];

  const trendData = stats?.trend || [
    { time: "00", high: 11, medium: 25, low: 17 },
    { time: "04", high: 14, medium: 20, low: 25 },
    { time: "08", high: 10, medium: 34, low: 20 },
    { time: "12", high: 22, medium: 27, low: 31 },
    { time: "16", high: 17, medium: 42, low: 26 },
    { time: "20", high: 29, medium: 31, low: 22 },
    { time: "Now", high: 18, medium: 37, low: 29 },
  ];

  return (
    <>
      <section className="relative isolate overflow-hidden border-b border-white/[0.08] px-4 py-7 md:px-7 md:py-8">
        <div className="absolute inset-0 -z-10 bg-[linear-gradient(90deg,rgba(16,19,22,0.98)_0%,rgba(16,19,22,0.92)_48%,rgba(16,19,22,0.42)_100%)]" />
        <img src={ASSETS.atlas} alt="Abstract network telemetry atlas" className="absolute inset-0 -z-20 h-full w-full object-cover opacity-60" />
        <div className="absolute inset-0 -z-10 signal-grid opacity-50" />
        <div className="flex flex-col gap-5 xl:flex-row xl:items-end xl:justify-between">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="status-pulse h-2 w-2 rounded-full bg-[#b7f960]" />
              <Meta>Live security posture</Meta>
              <span className="font-display text-[10px] uppercase tracking-[0.14em] text-[#b7f960]">
                {error ? "Degraded" : "PostgreSQL Connected"}
              </span>
              {user && (
                <span className="rounded border border-[#b7f960]/30 bg-[#b7f960]/10 px-2 py-0.5 font-display text-[9px] uppercase tracking-wider text-[#b7f960]">
                  {user.role} · {user.fullName}
                </span>
              )}
            </div>
            <h1 className="mt-3 font-display text-3xl font-semibold tracking-[-0.04em] text-white md:text-[36px]">
              Good morning, {user?.fullName ? user.fullName.split(" ")[0] : "Analyst"}.<br />
              <span className="text-slate-400">Your perimeter is holding.</span>
            </h1>
            <p className="mt-3 max-w-xl text-[13px] leading-relaxed text-slate-400">
              The assistant processed{" "}
              <strong className="font-semibold text-slate-200">{stats?.metrics.eventsIngested || "1.24M"} events</strong>{" "}
              and surfaced{" "}
              <strong className="font-semibold text-[#ff9a8d]">{stats?.metrics.openAlerts ?? 5} open alerts</strong> requiring analyst attention.
            </p>
          </div>
          <Panel className="w-full max-w-[260px] border-white/[0.1] bg-[#101315]/70 p-3 backdrop-blur-md">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-[#b7f960]/10 text-[#b7f960]">
                <ShieldCheck size={19} />
              </div>
              <div>
                <Meta>Coverage score</Meta>
                <p className="mt-1 font-display text-xl font-semibold tracking-tight text-slate-100">
                  {stats?.metrics.coverageScore || 96}
                  <span className="text-sm text-[#b7f960]">/100</span>
                </p>
              </div>
              <ChevronRight className="ml-auto text-slate-500" size={17} />
            </div>
          </Panel>
        </div>
      </section>

      <div className="space-y-5 px-4 py-6 md:px-7 md:py-7">
        {error && (
          <div className="flex items-center justify-between rounded-lg border border-[#e16c5c]/35 bg-[#e16c5c]/10 p-3 text-[12px] text-[#ff9a8d]">
            <span className="flex items-center gap-2">
              <CircleAlert size={16} /> Backend status: {error}
            </span>
            <ActionButton tone="danger" onClick={() => loadStats(period)}>
              <RefreshCw size={12} /> Retry
            </ActionButton>
          </div>
        )}

        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <Metric
            icon={Activity}
            label="Events ingested"
            value={loading ? "..." : stats?.metrics.eventsIngested || "1.24M"}
            change="↗ 12.4%"
            tone="blue"
          />
          <Metric
            icon={ShieldAlert}
            label="Open alerts"
            value={loading ? "..." : String(stats?.metrics.openAlerts ?? 5).padStart(2, "0")}
            change="↗ Active"
            tone="red"
          />
          <Metric
            icon={Radar}
            label="Active attacks"
            value={loading ? "..." : String(stats?.metrics.activeAttacks ?? 3).padStart(2, "0")}
            change="↘ Ongoing"
            tone="amber"
          />
          <Metric
            icon={ShieldCheck}
            label="Detection health"
            value={loading ? "..." : stats?.metrics.detectionHealth || "98.7%"}
            change="↘ Verified"
            tone="lime"
          />
        </div>

        <div className="grid gap-5 2xl:grid-cols-[minmax(0,1.45fr)_minmax(360px,0.85fr)]">
          <Panel className="p-5 md:p-6">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <Meta>Threat volume</Meta>
                <h2 className="mt-1 font-display text-xl font-semibold tracking-tight text-slate-100">
                  Attack trend <span className="ml-2 font-display text-[10px] text-[#ff9589]">+18.4% <span className="font-normal text-slate-500">vs. prior period</span></span>
                </h2>
              </div>
              <div className="flex rounded-lg border border-white/[0.08] bg-black/10 p-1">
                {["24h", "7d", "30d"].map((item) => (
                  <button
                    key={item}
                    onClick={() => setPeriod(item)}
                    className={`rounded-md px-2.5 py-1.5 font-display text-[10px] font-semibold transition ${period === item ? "bg-white/[0.11] text-[#b7f960]" : "text-slate-500"}`}
                  >
                    {item}
                  </button>
                ))}
              </div>
            </div>
            <ChartThreat data={trendData} />
          </Panel>

          <Panel className="p-5 md:p-6">
            <div className="flex justify-between">
              <div>
                <Meta>Detection breakdown</Meta>
                <h2 className="mt-1 font-display text-xl font-semibold tracking-tight text-slate-100">Attack surface</h2>
              </div>
              <MoreHorizontal className="text-slate-500" size={18} />
            </div>
            <div className="relative mt-3 h-[195px]">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={stats?.attackMix || defaultAttackMix} dataKey="value" nameKey="name" innerRadius={57} outerRadius={77} paddingAngle={4} stroke="none">
                    {(stats?.attackMix || defaultAttackMix).map((e) => (
                      <Cell key={e.name} fill={e.color} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={tooltipStyle} />
                </PieChart>
              </ResponsiveContainer>
              <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
                <span className="font-display text-2xl font-semibold text-white">72</span>
                <Meta>Detections</Meta>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-x-5 gap-y-3 border-t border-white/[0.07] pt-4">
              {(stats?.attackMix || defaultAttackMix).map((item) => (
                <div key={item.name} className="flex items-center justify-between">
                  <span className="flex items-center gap-2 text-[11px] text-slate-400">
                    <i className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: item.color }} />
                    {item.name}
                  </span>
                  <span className="font-display text-[11px] text-slate-200">{item.value}%</span>
                </div>
              ))}
            </div>
          </Panel>
        </div>

        <div className="grid gap-5 xl:grid-cols-[minmax(0,1.3fr)_minmax(340px,0.7fr)]">
          <AlertQueue compact />
          <AIBrief />
        </div>
      </div>
    </>
  );
}

function ChartThreat({ data }: { data: Array<{ time: string; high: number; medium: number; low: number }> }) {
  return (
    <div className="mt-5 h-[248px]">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 8, right: 4, left: -24, bottom: 0 }}>
          <defs>
            <linearGradient id="high" x1="0" x2="0" y1="0" y2="1">
              <stop offset="0%" stopColor="#e16c5c" stopOpacity={0.35} />
              <stop offset="100%" stopColor="#e16c5c" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid vertical={false} stroke="rgba(255,255,255,0.065)" strokeDasharray="2 5" />
          <XAxis dataKey="time" tickLine={false} axisLine={false} tick={{ fill: "#738089", fontSize: 10, fontFamily: "Space Grotesk" }} dy={8} />
          <YAxis tickLine={false} axisLine={false} tick={{ fill: "#738089", fontSize: 10, fontFamily: "Space Grotesk" }} />
          <Tooltip cursor={{ stroke: "rgba(183,249,96,0.25)" }} contentStyle={tooltipStyle} />
          <Area type="monotone" dataKey="low" stroke="#6fb6cc" strokeWidth={1.7} fill="transparent" />
          <Area type="monotone" dataKey="medium" stroke="#d9aa58" strokeWidth={1.7} fill="transparent" />
          <Area type="monotone" dataKey="high" stroke="#e16c5c" strokeWidth={2} fill="url(#high)" />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

function AlertQueue({ compact = false }: { compact?: boolean }) {
  const [, setLocation] = useLocation();
  const [items, setItems] = useState<AlertItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .getAlerts()
      .then((res) => setItems(res.items))
      .catch((err) => console.error("AlertQueue fetch error:", err))
      .finally(() => setLoading(false));
  }, []);

  const displayedRows = compact ? items.slice(0, 4) : items;

  return (
    <Panel>
      <div className="flex flex-col gap-3 border-b border-white/[0.08] px-5 py-5 sm:flex-row sm:items-center sm:justify-between md:px-6">
        <div>
          <Meta>{compact ? "Priority queue" : "Live security queue"}</Meta>
          <h2 className="mt-1 font-display text-xl font-semibold tracking-tight text-slate-100">
            {compact ? "Investigations" : "Live alerts"}{" "}
            <span className="ml-2 rounded-md bg-[#e16c5c]/10 px-1.5 py-0.5 font-display text-[9px] text-[#ff9589]">
              {items.length} OPEN
            </span>
          </h2>
        </div>
        <ActionButton onClick={() => setLocation(routes.alerts)}>
          <Filter size={13} /> Manage queue
        </ActionButton>
      </div>

      {loading ? (
        <div className="flex items-center justify-center p-8 text-slate-500">
          <Loader2 className="animate-spin mr-2" size={16} /> Loading alerts from database...
        </div>
      ) : (
        <div className="divide-y divide-white/[0.07]">
          {displayedRows.map((alert) => (
            <button
              key={alert.id}
              onClick={() => {
                setLocation(routes.investigation);
                toast.info(`Opened investigation for #${alert.id}: ${alert.title}`);
              }}
              className="group flex w-full flex-col gap-3 px-5 py-4 text-left transition hover:bg-white/[0.025] md:flex-row md:items-center md:px-6"
            >
              <div
                className={`hidden h-8 w-0.5 rounded-full md:block ${
                  alert.severity === "Critical" ? "bg-[#e16c5c]" : alert.severity === "High" ? "bg-[#d9aa58]" : "bg-[#6fb6cc]"
                }`}
              />
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityTag severity={alert.severity} />
                  <span className="font-display text-[9px] uppercase tracking-[0.13em] text-slate-600">{alert.tactic}</span>
                </div>
                <p className="mt-2 truncate text-[13px] font-semibold text-slate-200">{alert.title}</p>
                <p className="mt-1 text-[10px] text-slate-500">{alert.source}</p>
              </div>
              <div className="flex shrink-0 items-center justify-between gap-2 text-[10px] text-slate-500 md:flex-col md:items-end">
                <span className="flex items-center gap-1">
                  <Clock3 size={11} />
                  {new Date(alert.createdAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                </span>
                <span className="font-display text-[9px] uppercase tracking-[0.1em] text-[#b7f960]">{alert.status}</span>
              </div>
            </button>
          ))}
          {!displayedRows.length && (
            <div className="p-8 text-center text-slate-500">
              <ShieldCheck className="mx-auto text-[#b7f960] mb-2" size={24} />
              No open alerts recorded in database.
            </div>
          )}
        </div>
      )}

      {compact && (
        <button
          onClick={() => setLocation(routes.alerts)}
          className="flex w-full items-center justify-center gap-2 border-t border-white/[0.08] py-3.5 font-display text-[10px] font-semibold uppercase tracking-[0.13em] text-slate-400 transition hover:bg-white/[0.035] hover:text-[#b7f960]"
        >
          View all alerts <ChevronRight size={13} />
        </button>
      )}
    </Panel>
  );
}

function AIBrief() {
  return (
    <Panel className="relative min-h-[380px] overflow-hidden">
      <img src={ASSETS.brief} alt="Abstract AI cyber analysis artifact" className="absolute inset-0 h-full w-full object-cover opacity-[0.30] mix-blend-screen" />
      <div className="absolute inset-0 bg-[linear-gradient(90deg,rgba(22,28,31,0.98)_0%,rgba(22,28,31,0.88)_53%,rgba(22,28,31,0.52)_100%)]" />
      <div className="relative z-10 p-5 md:p-6">
        <div className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-[#b7f960]/12 text-[#b7f960]">
            <Bot size={16} />
          </div>
          <div>
            <Meta>AI Brief</Meta>
            <p className="font-display text-[11px] font-semibold text-slate-200">Incident narration</p>
          </div>
        </div>
        <div className="mt-8 border-l-2 border-[#b7f960] pl-4">
          <p className="font-display text-[17px] font-semibold leading-snug tracking-[-0.02em] text-slate-100">
            Credential attack was contained before lateral movement.
          </p>
          <p className="mt-3 text-[12px] leading-relaxed text-slate-400">
            A rotating proxy IP attempted 100 failed VPN logins in 2 minutes. Conditional access blocked the source; no account was accessed.
          </p>
        </div>
        <div className="mt-6 grid grid-cols-2 gap-2">
          <div className="rounded-lg border border-white/[0.08] bg-black/15 p-2.5">
            <Meta>Confidence</Meta>
            <p className="mt-1 font-display text-sm font-semibold text-[#b7f960]">94.8%</p>
          </div>
          <div className="rounded-lg border border-white/[0.08] bg-black/15 p-2.5">
            <Meta>Mapped tactic</Meta>
            <p className="mt-1 font-display text-sm font-semibold text-slate-100">TA0006</p>
          </div>
        </div>
        <button
          onClick={() => toast.info("Phase 1 verified: Database connected. AI narration will be live in Phase 5.")}
          className="mt-5 flex items-center gap-2 font-display text-[10px] font-semibold uppercase tracking-[0.12em] text-[#b7f960]"
        >
          Review evidence trail <ArrowRight size={13} />
        </button>
      </div>
    </Panel>
  );
}

// ===========================================================================
// 2. LIVE ALERTS SCREEN (Connected to PostgreSQL Backend)
// ===========================================================================
function Alerts() {
  const [filter, setFilter] = useState<Severity | "All">("All");
  const [query, setQuery] = useState("");
  const [alertsList, setAlertsList] = useState<AlertItem[]>([]);
  const [selectedAlertForDetail, setSelectedAlertForDetail] = useState<AlertItem | null>(null);
  const [counts, setCounts] = useState<{ all: number; critical: number; high: number; medium: number; low: number; open: number }>({
    all: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    open: 0,
  });
  const [loading, setLoading] = useState(true);

  const fetchAlerts = async () => {
    try {
      setLoading(true);
      const res = await api.getAlerts({ severity: filter, search: query });
      setAlertsList(res.items);
      setCounts(res.counts);
    } catch (err: any) {
      console.error("Failed to fetch alerts:", err);
      toast.error(err.message || "Failed to query alerts from PostgreSQL");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, [filter, query]);

  const handleTriageFirst = async () => {
    const firstOpen = alertsList.find((a) => a.status === "Open");
    if (!firstOpen) {
      toast.info("No open alerts to triage.");
      return;
    }
    try {
      await api.updateAlertStatus(firstOpen.id, "In review");
      toast.success(`Triaged alert #${firstOpen.id}: Status changed to 'In review'`);
      fetchAlerts();
    } catch (err: any) {
      toast.error(err.message || "Failed to update alert status");
    }
  };

  return (
    <>
      <PageHeader
        eyebrow="Command center / event triage"
        title="Live alerts"
        subtitle="Prioritised detections assembled from endpoint, identity, network, and threat intelligence sources in PostgreSQL."
        actions={
          <>
            <ActionButton onClick={handleTriageFirst}>
              <Check size={14} /> Bulk triage
            </ActionButton>
            <ActionButton tone="lime" onClick={() => fetchAlerts()}>
              <RefreshCw size={14} /> Refresh alerts
            </ActionButton>
          </>
        }
      />
      <div className="space-y-5 px-4 py-6 md:px-7">
        <div className="grid gap-3 sm:grid-cols-3">
          <Metric icon={CircleAlert} label="Critical priority" value={String(counts.critical).padStart(2, "0")} change="Needs review" tone="red" />
          <Metric icon={Radar} label="Open in queue" value={String(counts.open).padStart(2, "0")} change="Live count" tone="amber" />
          <Metric icon={ShieldCheck} label="Total recorded" value={String(counts.all).padStart(2, "0")} change="In database" tone="lime" />
        </div>
        <Panel>
          <div className="flex flex-col gap-3 border-b border-white/[0.08] p-4 lg:flex-row lg:items-center lg:justify-between">
            <div className="flex flex-wrap gap-2">
              {(["All", "Critical", "High", "Medium", "Low"] as const).map((item) => (
                <button
                  onClick={() => setFilter(item)}
                  key={item}
                  className={`rounded-lg px-3 py-2 font-display text-[10px] font-semibold uppercase tracking-[0.1em] transition ${
                    filter === item ? "bg-[#b7f960]/12 text-[#b7f960]" : "bg-white/[0.035] text-slate-500 hover:text-slate-200"
                  }`}
                >
                  {item}
                  <span className="ml-1.5 opacity-60">
                    {item === "All"
                      ? counts.all
                      : item === "Critical"
                      ? counts.critical
                      : item === "High"
                      ? counts.high
                      : item === "Medium"
                      ? counts.medium
                      : counts.low}
                  </span>
                </button>
              ))}
            </div>
            <div className="relative">
              <Search size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search source, user, or detection"
                className="h-9 w-full rounded-lg border border-white/[0.08] bg-black/10 pl-9 pr-3 text-[11px] text-slate-200 outline-none placeholder:text-slate-600 focus:border-[#b7f960]/35 lg:w-64"
              />
            </div>
          </div>
          {loading ? (
            <div className="flex items-center justify-center p-12 text-slate-500">
              <Loader2 className="animate-spin mr-2" size={18} /> Querying alerts from PostgreSQL...
            </div>
          ) : (
            <div className="divide-y divide-white/[0.07]">
              {alertsList.map((item) => (
                <AlertRow
                  key={item.id}
                  item={item}
                  onStatusChange={fetchAlerts}
                  onInspect={(alert) => setSelectedAlertForDetail(alert)}
                />
              ))}
              {!alertsList.length && (
                <div className="p-12 text-center">
                  <ShieldCheck className="mx-auto text-[#b7f960]" size={28} />
                  <p className="mt-3 font-display text-sm font-semibold">No matching alerts found in database</p>
                </div>
              )}
            </div>
          )}
        </Panel>
      </div>

      <AlertDetailModal
        alert={selectedAlertForDetail}
        isOpen={Boolean(selectedAlertForDetail)}
        onClose={() => setSelectedAlertForDetail(null)}
        onStatusUpdated={() => {
          fetchAlerts();
          setSelectedAlertForDetail(null);
        }}
      />
    </>
  );
}

function AlertRow({
  item,
  onStatusChange,
  onInspect,
}: {
  item: AlertItem;
  onStatusChange: () => void;
  onInspect: (item: AlertItem) => void;
}) {
  const [, setLocation] = useLocation();

  const handleEscalate = async () => {
    try {
      await api.updateAlertStatus(item.id, "Escalated");
      toast.success(`Alert #${item.id} escalated in database`);
      onStatusChange();
    } catch (err: any) {
      toast.error(err.message || "Failed to update alert");
    }
  };

  return (
    <div className="flex flex-col gap-3 p-4 transition hover:bg-white/[0.025] md:flex-row md:items-center md:p-5">
      <div
        className={`h-1.5 w-1.5 rounded-full ${
          item.severity === "Critical" ? "bg-[#e16c5c]" : item.severity === "High" ? "bg-[#d9aa58]" : "bg-[#6fb6cc]"
        }`}
      />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityTag severity={item.severity} />
          <span className="font-display text-[9px] uppercase tracking-[0.13em] text-slate-600">{item.tactic}</span>
          <span className="font-display text-[9px] uppercase tracking-[0.13em] text-slate-500">{item.status}</span>
          {item.ruleId ? (
            <span className="rounded bg-cyan-950/60 border border-cyan-500/40 px-1.5 py-0.5 text-[8.5px] font-mono text-cyan-300">
              ⚡ {item.ruleId}
            </span>
          ) : (
            <span className="rounded bg-slate-800/60 border border-slate-700/40 px-1.5 py-0.5 text-[8.5px] font-mono text-slate-400">
              Demo Seed
            </span>
          )}
        </div>
        <p
          onClick={() => onInspect(item)}
          className="mt-2 text-[13px] font-semibold text-slate-200 hover:text-[#b7f960] cursor-pointer transition"
        >
          {item.title}
        </p>
        <p className="mt-1 text-[10px] text-slate-500 font-mono">
          SRC: {item.source} {item.destination ? `➔ DST: ${item.destination}` : ""}
        </p>
      </div>
      <div className="flex items-center justify-between gap-3">
        <span className="text-[10px] text-slate-500">
          {new Date(item.createdAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
        </span>
        <div className="flex items-center gap-2">
          <button
            onClick={() => onInspect(item)}
            className="rounded border border-[#b7f960]/30 bg-[#b7f960]/10 px-2 py-1 font-display text-[9px] font-semibold text-[#b7f960] hover:bg-[#b7f960]/20 flex items-center gap-1 transition"
          >
            <FileCode2 size={11} /> Evidence
          </button>
          {item.status === "Open" && (
            <button
              onClick={handleEscalate}
              className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-1 font-display text-[9px] font-semibold text-amber-300 hover:bg-amber-500/20"
            >
              Escalate
            </button>
          )}
          <ActionButton onClick={() => setLocation(routes.investigation)} className="py-2">
            Investigate <ChevronRight size={13} />
          </ActionButton>
        </div>
      </div>
    </div>
  );
}


// ===========================================================================
// 3. INVESTIGATION SCREEN (Connected to PostgreSQL Backend)
// ===========================================================================
function Investigation() {
  const { user } = useAuth();
  const [casesList, setCasesList] = useState<CaseItem[]>([]);
  const [selected, setSelected] = useState(0);
  const [loading, setLoading] = useState(true);

  const fetchCases = async () => {
    try {
      setLoading(true);
      const res = await api.getCases();
      setCasesList(res.items);
    } catch (err: any) {
      console.error("Failed to load cases:", err);
      toast.error("Failed to load cases from PostgreSQL");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCases();
  }, []);

  const activeCase = casesList[selected] || null;

  const handleMarkContained = async () => {
    if (!activeCase) return;
    try {
      await api.updateCaseStatus(activeCase.id, "Contained");
      toast.success(`Case ${activeCase.caseNumber} marked as 'Contained' in PostgreSQL`);
      fetchCases();
    } catch (err: any) {
      toast.error(err.message || "Failed to update case status");
    }
  };

  return (
    <>
      <PageHeader
        eyebrow="Command center / case workbench"
        title="Investigation"
        subtitle="Correlate evidence, understand attacker behavior, and document a defensible response from PostgreSQL database."
        actions={
          <>
            <ActionButton onClick={() => toast.info("Case sharing will be linked with user authorization in Phase 2.")}>
              <UsersRound size={14} /> Share case
            </ActionButton>
            <ActionButton tone="lime" onClick={handleMarkContained}>
              Mark contained
            </ActionButton>
          </>
        }
      />
      <div className="grid gap-5 px-4 py-6 xl:grid-cols-[300px_minmax(0,1fr)] md:px-7">
        <Panel className="h-fit">
          <div className="border-b border-white/[0.08] p-4">
            <Meta>Open cases</Meta>
            <p className="mt-1 font-display text-lg font-semibold">{String(casesList.length).padStart(2, "0")} active investigations</p>
          </div>
          {loading ? (
            <div className="p-4 text-center text-slate-500">
              <Loader2 className="animate-spin mx-auto mb-2" size={16} /> Loading cases...
            </div>
          ) : (
            <div className="p-2">
              {casesList.map((item, index) => (
                <button
                  onClick={() => setSelected(index)}
                  key={item.id}
                  className={`w-full rounded-lg p-3 text-left transition ${selected === index ? "bg-white/[0.08]" : "hover:bg-white/[0.035]"}`}
                >
                  <div className="flex items-center justify-between">
                    <span
                      className={`h-1.5 w-1.5 rounded-full ${
                        item.severity === "Critical" ? "bg-[#e16c5c]" : item.severity === "High" ? "bg-[#d9aa58]" : "bg-[#6fb6cc]"
                      }`}
                    />
                    <span className="font-display text-[9px] uppercase tracking-[0.1em] text-slate-500">{item.status}</span>
                  </div>
                  <p className="mt-2 text-[12px] font-semibold leading-snug text-slate-200">{item.title}</p>
                  <p className="mt-1 font-display text-[9px] uppercase tracking-[0.1em] text-slate-500">
                    {item.caseNumber} · {item.assignedUserName || user?.fullName || "Unassigned"}
                  </p>
                </button>
              ))}
            </div>
          )}
        </Panel>

        {activeCase ? (
          <div className="space-y-5">
            <Panel className="p-5 md:p-6">
              <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <SeverityTag severity={activeCase.severity} />
                    <Meta>{activeCase.caseNumber}</Meta>
                    <span className="rounded bg-white/[0.06] px-1.5 py-0.5 font-display text-[9px] text-[#b7f960]">{activeCase.status}</span>
                  </div>
                  <h2 className="mt-3 font-display text-2xl font-semibold tracking-[-0.035em]">{activeCase.title}</h2>
                  <p className="mt-2 text-[12px] text-slate-400">{activeCase.summary || "Detection correlated across identity and telemetry."}</p>
                </div>
                <div className="rounded-lg border border-[#b7f960]/25 bg-[#b7f960]/8 px-3 py-2">
                  <Meta>AI confidence</Meta>
                  <p className="mt-1 font-display text-lg font-semibold text-[#b7f960]">{activeCase.aiConfidence}%</p>
                </div>
              </div>
              <div className="mt-6 grid gap-3 sm:grid-cols-3">
                <EvidenceStat label="Affected asset" value={activeCase.affectedAsset} />
                <EvidenceStat label="Primary entity" value={activeCase.primaryEntity} />
                <EvidenceStat label="MITRE technique" value={activeCase.mitreTechnique} />
              </div>
            </Panel>

            <div className="grid gap-5 2xl:grid-cols-[minmax(0,1fr)_330px]">
              <Panel className="p-5 md:p-6">
                <Meta>Evidence timeline</Meta>
                <h3 className="mt-1 font-display text-lg font-semibold">What the assistant observed</h3>
                <div className="mt-6 space-y-0">
                  {activeCase.timeline?.map((entry, i) => (
                    <div key={i} className="relative flex gap-4 pb-6 last:pb-0">
                      <div className="flex flex-col items-center">
                        <span
                          className={`z-10 flex h-7 w-7 items-center justify-center rounded-full border ${
                            i === 0 ? "border-[#e16c5c]/45 bg-[#e16c5c]/12 text-[#ff9a8d]" : "border-white/[0.12] bg-white/[0.04] text-slate-400"
                          }`}
                        >
                          {i === 0 ? <CircleAlert size={13} /> : <Check size={13} />}
                        </span>
                        {i < (activeCase.timeline?.length || 0) - 1 && <span className="h-full w-px bg-white/[0.09]" />}
                      </div>
                      <div className="pt-1">
                        <p className="font-display text-[10px] uppercase tracking-[0.12em] text-slate-500">{entry.time}</p>
                        <p className="mt-1 text-[12px] leading-relaxed text-slate-300">{entry.title}</p>
                      </div>
                    </div>
                  ))}
                  {(!activeCase.timeline || !activeCase.timeline.length) && (
                    <p className="text-[12px] text-slate-500">No timeline entries recorded yet.</p>
                  )}
                </div>
              </Panel>
              <AIBrief />
            </div>
          </div>
        ) : (
          <Panel className="p-12 text-center text-slate-500">No active cases found in database.</Panel>
        )}
      </div>
    </>
  );
}

function EvidenceStat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-white/[0.08] bg-black/10 p-3">
      <Meta>{label}</Meta>
      <p className="mt-1 font-display text-[12px] font-semibold text-slate-200">{value}</p>
    </div>
  );
}

// ===========================================================================
// 4. NETWORK SCREEN (Connected to PostgreSQL Backend)
// ===========================================================================
function NetworkScreen() {
  const [flows, setFlows] = useState<NetworkFlowItem[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  const networkSeries = [
    { hour: "00", traffic: 210, baseline: 170 },
    { hour: "03", traffic: 260, baseline: 195 },
    { hour: "06", traffic: 230, baseline: 180 },
    { hour: "09", traffic: 340, baseline: 220 },
    { hour: "12", traffic: 298, baseline: 240 },
    { hour: "15", traffic: 420, baseline: 260 },
    { hour: "18", traffic: 376, baseline: 230 },
    { hour: "21", traffic: 510, baseline: 270 },
    { hour: "Now", traffic: 440, baseline: 250 },
  ];

  const fetchNetworkData = async () => {
    try {
      setLoading(true);
      const [flowsRes, statsRes] = await Promise.all([api.getNetworkFlows(), api.getNetworkStats()]);
      setFlows(flowsRes.flows);
      setStats(statsRes);
    } catch (err: any) {
      console.error("Failed to load network telemetry:", err);
      toast.error("Failed to fetch network telemetry from database");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchNetworkData();
  }, []);

  return (
    <>
      <PageHeader
        eyebrow="Command center / telemetry"
        title="Network"
        subtitle="Monitor flow behavior, identify anomalies, and trace traffic across protected environments from PostgreSQL."
        actions={
          <>
            <ActionButton onClick={() => toast.info("PCAP upload pipeline will be connected to Python Scapy parser in Phase 8.")}>
              <UploadCloud size={14} /> Analyze PCAP
            </ActionButton>
            <ActionButton tone="lime" onClick={fetchNetworkData}>
              Live traffic
            </ActionButton>
          </>
        }
      />
      <div className="space-y-5 px-4 py-6 md:px-7">
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <Metric icon={Wifi} label="Traffic today" value={stats?.trafficToday || "3.42 TB"} change="↗ 6.2%" tone="blue" />
          <Metric
            icon={CircleAlert}
            label="Anomalies"
            value={String(stats?.anomaliesCount ?? 2).padStart(2, "0")}
            change="2 priority"
            tone="red"
          />
          <Metric icon={Globe2} label="External peers" value={stats?.externalPeers || "1,284"} change="18 new" tone="amber" />
          <Metric icon={ShieldCheck} label="Encrypted flows" value={stats?.encryptedRatio || "93.4%"} change="↗ 1.1%" tone="lime" />
        </div>

        <div className="grid gap-5 2xl:grid-cols-[minmax(0,1.35fr)_minmax(350px,0.65fr)]">
          <Panel className="p-5 md:p-6">
            <div className="flex justify-between">
              <div>
                <Meta>Traffic baseline</Meta>
                <h2 className="mt-1 font-display text-xl font-semibold">Volume against expected behavior</h2>
              </div>
              <ActionButton onClick={() => toast.info("Traffic interval selector")}>
                24 hours <ChevronDown size={13} />
              </ActionButton>
            </div>
            <div className="mt-5 h-[270px]">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={networkSeries} margin={{ top: 8, right: 4, left: -24, bottom: 0 }}>
                  <defs>
                    <linearGradient id="traffic" x1="0" x2="0" y1="0" y2="1">
                      <stop offset="0%" stopColor="#6fb6cc" stopOpacity={0.35} />
                      <stop offset="100%" stopColor="#6fb6cc" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid vertical={false} stroke="rgba(255,255,255,0.065)" strokeDasharray="2 5" />
                  <XAxis dataKey="hour" tickLine={false} axisLine={false} tick={{ fill: "#738089", fontSize: 10 }} />
                  <YAxis tickLine={false} axisLine={false} tick={{ fill: "#738089", fontSize: 10 }} />
                  <Tooltip contentStyle={tooltipStyle} />
                  <Area type="monotone" dataKey="baseline" stroke="#64737b" strokeWidth={1.5} strokeDasharray="4 4" fill="transparent" name="Expected" />
                  <Area type="monotone" dataKey="traffic" stroke="#6fb6cc" strokeWidth={2} fill="url(#traffic)" name="Observed" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </Panel>

          <Panel className="p-5 md:p-6">
            <Meta>Detection signal</Meta>
            <h2 className="mt-1 font-display text-xl font-semibold">Outbound behavior</h2>
            <div className="mt-5 flex gap-5">
              <img src={ASSETS.orbit} alt="Abstract threat orbit" className="h-24 w-24 rounded-xl border border-white/[0.08] object-cover opacity-90" />
              <div>
                <p className="font-display text-2xl font-semibold text-white">2.8 GB</p>
                <p className="mt-1 text-[11px] leading-relaxed text-slate-500">Transferred from WS-FIN-042 to an unclassified destination.</p>
                <button onClick={() => toast.info("Flow trace inspector")} className="mt-3 font-display text-[10px] font-semibold uppercase tracking-[0.1em] text-[#b7f960]">
                  Inspect flow <ChevronRight className="inline" size={13} />
                </button>
              </div>
            </div>
            <div className="mt-6 space-y-3 border-t border-white/[0.08] pt-5">
              {[
                ["DDoS", stats?.signatures?.ddos || "No active signatures", "#b7f960"],
                ["Beaconing", stats?.signatures?.beaconing || "1 behavior review", "#d9aa58"],
                ["DNS tunneling", stats?.signatures?.dnsTunneling || "No active signatures", "#b7f960"],
              ].map(([name, value, color]) => (
                <div key={name} className="flex items-center justify-between">
                  <span className="text-[11px] text-slate-300">{name}</span>
                  <span className="flex items-center gap-1.5 font-display text-[10px] text-slate-500">
                    <i className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: color }} />
                    {value}
                  </span>
                </div>
              ))}
            </div>
          </Panel>
        </div>

        <Panel>
          <div className="flex items-center justify-between border-b border-white/[0.08] px-5 py-5">
            <div>
              <Meta>Observed flows</Meta>
              <h2 className="mt-1 font-display text-xl font-semibold">Priority network activity from PostgreSQL</h2>
            </div>
            <ActionButton onClick={() => toast.info("Filter active flows")}>
              <SlidersHorizontal size={13} /> Filter
            </ActionButton>
          </div>
          {loading ? (
            <div className="p-8 text-center text-slate-500">
              <Loader2 className="animate-spin mx-auto mb-2" size={18} /> Loading flows from PostgreSQL...
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-[700px] w-full text-left">
                <thead>
                  <tr className="border-b border-white/[0.07] font-display text-[9px] uppercase tracking-[0.13em] text-slate-500">
                    {["Source", "Destination", "Protocol", "Volume", "Risk", ""].map((h) => (
                      <th key={h} className="px-5 py-3 font-semibold">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {flows.map((flow) => (
                    <tr key={flow.id} className="border-b border-white/[0.06] text-[11px] text-slate-300 hover:bg-white/[0.025]">
                      <td className="px-5 py-4 font-semibold text-slate-200">
                        {flow.sourceHost} <span className="block text-[10px] font-normal text-slate-500">{flow.sourceIp}</span>
                      </td>
                      <td className="px-5 py-4 text-slate-400">{flow.destinationIp}</td>
                      <td className="px-5 py-4">
                        <span className="rounded-md bg-white/[0.06] px-2 py-1 font-display text-[9px]">{flow.protocol}</span>
                      </td>
                      <td className="px-5 py-4">{flow.volumeFormatted}</td>
                      <td className="px-5 py-4">
                        <SeverityTag severity={flow.risk} />
                      </td>
                      <td className="px-5 py-4">
                        <button
                          onClick={() => toast.info(`Tracing flow #${flow.id}: ${flow.sourceHost} ➜ ${flow.destinationIp}`)}
                          className="font-display text-[10px] font-semibold uppercase tracking-[0.1em] text-[#b7f960]"
                        >
                          Trace
                        </button>
                      </td>
                    </tr>
                  ))}
                  {!flows.length && (
                    <tr>
                      <td colSpan={6} className="p-8 text-center text-slate-500">
                        No network flows stored in database.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </div>
    </>
  );
}

// ===========================================================================
// 5. MALWARE LAB SCREEN (Connected to PostgreSQL Backend)
// ===========================================================================
function MalwareLab() {
  const [activeTab, setActiveTab] = useState("Queue");
  const [samples, setSamples] = useState<MalwareSampleItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .getMalwareSamples()
      .then((res) => setSamples(res.samples))
      .catch((err) => console.error("Malware fetch error:", err))
      .finally(() => setLoading(false));
  }, []);

  const latestSample = samples[0];

  return (
    <>
      <PageHeader
        eyebrow="Command center / binary analysis"
        title="Malware lab"
        subtitle="Classify suspicious binaries and explain behavior through static indicators and machine-learning verdicts in PostgreSQL."
        actions={
          <>
            <ActionButton onClick={() => toast.info("Hash lookup is connected to Threat Intel database.")}>
              <Search size={14} /> Hash lookup
            </ActionButton>
            <ActionButton tone="lime" onClick={() => toast.info("File upload will connect to Python pefile analyzer in Phase 7.")}>
              <UploadCloud size={14} /> Upload sample
            </ActionButton>
          </>
        }
      />
      <div className="space-y-5 px-4 py-6 md:px-7">
        <div className="grid gap-5 xl:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
          <Panel className="relative min-h-[300px] overflow-hidden">
            <div className="absolute inset-0 signal-grid opacity-40" />
            <div className="relative p-6">
              <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-[#b7f960]/25 bg-[#b7f960]/10 text-[#b7f960]">
                <FileCode2 size={21} />
              </div>
              <Meta>Sample intake</Meta>
              <h2 className="mt-2 font-display text-2xl font-semibold tracking-tight">Drop a suspicious binary</h2>
              <p className="mt-2 max-w-md text-[12px] leading-relaxed text-slate-400">
                Securely inspect PE headers, imports, entropy, and behavioral indicators. The backend database tracks all submissions.
              </p>
              <ActionButton tone="lime" onClick={() => toast.info("Sample intake will use safe static buffering in Phase 7.")} className="mt-6">
                <UploadCloud size={14} /> Select a file
              </ActionButton>
              <p className="mt-4 font-display text-[9px] uppercase tracking-[0.12em] text-slate-600">Supported: .exe · .dll · SHA256 · Max 100 MB</p>
            </div>
          </Panel>

          <Panel className="p-5 md:p-6">
            <Meta>Latest verdict from PostgreSQL</Meta>
            {latestSample ? (
              <>
                <div className="mt-2 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                  <div>
                    <h2 className="font-display text-xl font-semibold">{latestSample.filename}</h2>
                    <p className="mt-1 font-display text-[10px] uppercase tracking-[0.12em] text-slate-500">
                      SHA256 · {latestSample.sha256.slice(0, 12)}...{latestSample.sha256.slice(-8)}
                    </p>
                  </div>
                  <span className="rounded-lg border border-[#e16c5c]/35 bg-[#e16c5c]/10 px-3 py-2 font-display text-[10px] font-bold uppercase tracking-[0.11em] text-[#ff9a8d]">
                    {latestSample.verdict}
                  </span>
                </div>
                <div className="mt-5 grid grid-cols-3 gap-2">
                  <EvidenceStat label="Confidence" value={`${latestSample.confidence}%`} />
                  <EvidenceStat label="Model" value={latestSample.modelUsed} />
                  <EvidenceStat label="Risk score" value={`${latestSample.riskScore}/10`} />
                </div>
                <div className="mt-5 border-t border-white/[0.08] pt-5">
                  <Meta>Behavior indicators</Meta>
                  <div className="mt-3 flex flex-wrap gap-2">
                    {latestSample.indicators?.map((item: string) => (
                      <span key={item} className="rounded-md border border-[#e16c5c]/20 bg-[#e16c5c]/8 px-2 py-1.5 font-display text-[9px] uppercase tracking-[0.08em] text-[#ef978d]">
                        {item}
                      </span>
                    ))}
                  </div>
                </div>
              </>
            ) : (
              <p className="mt-4 text-[12px] text-slate-500">No malware records available.</p>
            )}
          </Panel>
        </div>

        <Panel>
          <div className="flex flex-col gap-3 border-b border-white/[0.08] px-5 py-5 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <Meta>Analysis workspace</Meta>
              <h2 className="mt-1 font-display text-xl font-semibold">Sample history in database</h2>
            </div>
            <div className="flex rounded-lg border border-white/[0.08] p-1">
              {["Queue", "Completed", "Quarantined"].map((tab) => (
                <button
                  onClick={() => setActiveTab(tab)}
                  key={tab}
                  className={`rounded-md px-3 py-1.5 font-display text-[10px] font-semibold ${tab === activeTab ? "bg-white/[0.09] text-[#b7f960]" : "text-slate-500"}`}
                >
                  {tab}
                </button>
              ))}
            </div>
          </div>
          {loading ? (
            <div className="p-8 text-center text-slate-500">
              <Loader2 className="animate-spin mx-auto mb-2" size={16} /> Loading samples...
            </div>
          ) : (
            <div className="divide-y divide-white/[0.07]">
              {samples.map((file) => (
                <div key={file.id} className="flex flex-col gap-3 px-5 py-4 sm:flex-row sm:items-center">
                  <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-white/[0.06] text-slate-400">
                    <FileCode2 size={17} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="font-display text-[12px] font-semibold text-slate-200">{file.filename}</p>
                    <p className="mt-1 font-display text-[9px] uppercase tracking-[0.12em] text-slate-500">
                      Static analysis · {new Date(file.createdAt).toLocaleDateString()}
                    </p>
                  </div>
                  <span className={`font-display text-[10px] font-semibold ${file.verdict === "Benign file" ? "text-[#b7f960]" : "text-[#ff9a8d]"}`}>
                    {file.verdict}
                  </span>
                  <span className="font-display text-[11px] text-slate-400">{file.confidence}%</span>
                  <button onClick={() => toast.info(`Viewing details for #${file.id}: ${file.filename}`)} className="font-display text-[10px] font-semibold uppercase tracking-[0.1em] text-[#b7f960]">
                    Details
                  </button>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>
    </>
  );
}

// ===========================================================================
// 6. THREAT INTEL SCREEN (Connected to PostgreSQL Backend)
// ===========================================================================
function ThreatIntel() {
  const [term, setTerm] = useState("185.220.101.45");
  const [result, setResult] = useState<ThreatIntelItem | null>(null);
  const [loading, setLoading] = useState(false);

  const lookup = async () => {
    if (!term.trim()) return;
    try {
      setLoading(true);
      const res = await api.lookupThreatIntel(term.trim());
      setResult(res.indicator);
      if (res.found) {
        toast.success(`Found ${term} in database threat cache.`);
      } else {
        toast.info(`Indicator assessed via backend rule layer.`);
      }
    } catch (err: any) {
      toast.error(err.message || "Failed to query threat intelligence");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    lookup();
  }, []);

  return (
    <>
      <PageHeader
        eyebrow="Command center / enrichment"
        title="Threat Intelligence"
        subtitle="Look up IPs, domains, URLs, and file hashes against database cache and verified external feeds."
        actions={
          <ActionButton onClick={() => toast.info("Feed management will be enabled in Phase 6.")}>
            <Settings2 size={14} /> Manage feeds
          </ActionButton>
        }
      />
      <div className="space-y-5 px-4 py-6 md:px-7">
        <Panel className="p-5 md:p-7">
          <div className="mx-auto max-w-3xl text-center">
            <div className="mx-auto flex h-11 w-11 items-center justify-center rounded-xl bg-[#b7f960]/10 text-[#b7f960]">
              <Globe2 size={21} />
            </div>
            <h2 className="mt-4 font-display text-2xl font-semibold tracking-tight">Investigate an indicator</h2>
            <p className="mt-2 text-[12px] text-slate-400">Search across database cache, VirusTotal, AbuseIPDB, and AlienVault OTX feeds.</p>
            <div className="mt-6 flex flex-col gap-2 sm:flex-row">
              <div className="relative flex-1">
                <Search size={16} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  value={term}
                  onChange={(e) => setTerm(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && lookup()}
                  className="h-11 w-full rounded-lg border border-white/[0.1] bg-black/20 pl-10 pr-3 text-[12px] text-slate-200 outline-none placeholder:text-slate-600 focus:border-[#b7f960]/35"
                  placeholder="IP, domain, URL, or SHA256"
                />
              </div>
              <ActionButton tone="lime" onClick={lookup} disabled={loading}>
                {loading ? <Loader2 className="animate-spin mr-1" size={14} /> : null}
                Search intelligence
              </ActionButton>
            </div>
            <div className="mt-4 flex flex-wrap justify-center gap-x-4 gap-y-2">
              {["IP address", "Domain", "URL", "File hash"].map((item) => (
                <span key={item} className="font-display text-[9px] uppercase tracking-[0.12em] text-slate-600">
                  {item}
                </span>
              ))}
            </div>
          </div>
        </Panel>

        {result && (
          <div className="grid gap-5 xl:grid-cols-[minmax(0,1.1fr)_minmax(320px,0.9fr)]">
            <Panel className="p-5 md:p-6">
              <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                <div>
                  <Meta>Indicator result</Meta>
                  <h2 className="mt-1 break-all font-display text-xl font-semibold">{result.indicator}</h2>
                  <p className="mt-2 text-[11px] text-slate-400">Type: {result.indicatorType}</p>
                </div>
                <span
                  className={`rounded-lg border px-3 py-2 font-display text-[10px] font-bold uppercase tracking-[0.1em] ${
                    result.verdict === "Malicious"
                      ? "border-[#e16c5c]/30 bg-[#e16c5c]/10 text-[#ff9a8d]"
                      : "border-slate-500/30 bg-slate-500/10 text-slate-400"
                  }`}
                >
                  {result.verdict}
                </span>
              </div>
              <div className="mt-6 grid gap-3 sm:grid-cols-3">
                <EvidenceStat label="Reputation" value={`${result.reputationScore}/100`} />
                <EvidenceStat label="Detections" value={`${result.detectionsCount} / ${result.totalEngines || 22}`} />
                <EvidenceStat label="Confidence" value={result.confidence} />
              </div>
              <div className="mt-5 border-t border-white/[0.08] pt-5">
                <Meta>Associated context</Meta>
                <div className="mt-3 grid gap-2 sm:grid-cols-2">
                  {result.associatedContext?.map((item: string) => (
                    <div key={item} className="flex items-center gap-2 rounded-lg bg-white/[0.035] p-2.5 text-[11px] text-slate-300">
                      <i className="h-1.5 w-1.5 rounded-full bg-[#e16c5c]" />
                      {item}
                    </div>
                  ))}
                </div>
              </div>
            </Panel>

            <Panel className="p-5 md:p-6">
              <Meta>Source consensus</Meta>
              <h2 className="mt-1 font-display text-xl font-semibold">Feed verdicts</h2>
              <div className="mt-5 space-y-3">
                {result.feedVerdicts?.map((feed: any) => (
                  <div key={feed.source} className="flex items-center gap-3 rounded-lg border border-white/[0.08] bg-black/10 p-3">
                    <div className="flex h-8 w-8 items-center justify-center rounded-md bg-white/[0.06] text-slate-400">
                      <Globe2 size={14} />
                    </div>
                    <div className="flex-1">
                      <p className="font-display text-[11px] font-semibold text-slate-200">{feed.source}</p>
                      <p className="mt-0.5 text-[10px] text-slate-500">{feed.detail}</p>
                    </div>
                    <span
                      className={`font-display text-[9px] uppercase tracking-[0.1em] ${
                        feed.status === "Config Required" ? "text-amber-400" : "text-[#ff9a8d]"
                      }`}
                    >
                      {feed.status}
                    </span>
                  </div>
                ))}
              </div>
            </Panel>
          </div>
        )}
      </div>
    </>
  );
}

// ===========================================================================
// 7. TEAM & ROLES SCREEN (Phase 2 RBAC & Active Roster)
// ===========================================================================
function TeamRoles() {
  const { user, login } = useAuth();
  const [switching, setSwitching] = useState<string | null>(null);

  const members = [
    { initials: "AR", name: "Avery Reed", email: "avery.reed@soc.local", role: "Senior Analyst" as UserRole, status: "On shift", queue: "4 cases", color: "#b7f960" },
    { initials: "MK", name: "Mina Kapoor", email: "mina.kapoor@soc.local", role: "Threat Hunter" as UserRole, status: "On shift", queue: "2 cases", color: "#6fb6cc" },
    { initials: "DL", name: "Darren Liu", email: "darren.liu@soc.local", role: "Incident Commander" as UserRole, status: "On call", queue: "1 escalation", color: "#d9aa58" },
    { initials: "JS", name: "Jordan Smith", email: "jordan.smith@soc.local", role: "Detection Engineer" as UserRole, status: "Offline", queue: "Rules & PCAP", color: "#74818a" },
  ];

  const handleSwitchPersona = async (email: string, name: string) => {
    try {
      setSwitching(email);
      await login({ email, password: "SocAnalyst2026!" });
      toast.success(`Switched active session to ${name}`);
    } catch (err: any) {
      toast.error(err.message || "Failed to switch persona");
    } finally {
      setSwitching(null);
    }
  };

  return (
    <>
      <PageHeader
        eyebrow="Workspace / Role-Based Access Control"
        title="Team & permissions"
        subtitle="Manage analyst coverage, active personas, and server-enforced RBAC policies in PostgreSQL."
        actions={
          <>
            <ActionButton onClick={() => toast.info("Displaying explicit RBAC matrix below.")}>
              <Settings2 size={14} /> View RBAC Matrix
            </ActionButton>
          </>
        }
      />
      <div className="space-y-5 px-4 py-6 md:px-7">
        <div className="grid gap-3 sm:grid-cols-3">
          <Metric icon={UsersRound} label="Active analysts" value="04" change="All roles ready" tone="lime" />
          <Metric icon={ShieldAlert} label="Assigned cases" value="07" change="2 escalated" tone="amber" />
          <Metric icon={ShieldCheck} label="Current identity" value={user?.fullName ? user.fullName.split(" ")[0] : "Guest"} change={user?.role || "Unauthenticated"} tone="blue" />
        </div>
        <div className="grid gap-5 2xl:grid-cols-[minmax(0,1.25fr)_minmax(360px,0.75fr)]">
          <Panel className="p-5 md:p-6">
            <div className="flex items-center justify-between">
              <div>
                <Meta>Analyst roster & personas</Meta>
                <h2 className="mt-1 font-display text-xl font-semibold">Active shift roster</h2>
              </div>
              <span className="font-display text-[10px] uppercase tracking-wider text-slate-500">
                Click any persona to authenticate
              </span>
            </div>
            <div className="mt-5 grid gap-3 sm:grid-cols-2">
              {members.map((member) => {
                const isActive = user?.email === member.email;
                return (
                  <button
                    key={member.email}
                    disabled={switching !== null}
                    onClick={() => handleSwitchPersona(member.email, member.name)}
                    className={`group rounded-xl border p-4 text-left transition ${
                      isActive
                        ? "border-[#b7f960]/50 bg-[#b7f960]/10 shadow-[0_0_20px_rgba(183,249,96,0.08)]"
                        : "border-white/[0.08] bg-black/10 hover:border-[#b7f960]/24 hover:bg-white/[0.035]"
                    }`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex h-10 w-10 items-center justify-center rounded-lg font-display text-[12px] font-bold" style={{ backgroundColor: `${member.color}1f`, color: member.color }}>
                        {member.initials}
                      </div>
                      <span className={`flex items-center gap-1.5 font-display text-[9px] uppercase tracking-[0.1em] ${isActive ? "text-[#b7f960] font-bold" : "text-slate-400"}`}>
                        <i className={`h-1.5 w-1.5 rounded-full ${isActive ? "bg-[#b7f960]" : "bg-slate-500"}`} />
                        {isActive ? "Active Persona" : member.status}
                      </span>
                    </div>
                    <p className="mt-4 font-display text-[13px] font-semibold text-slate-100">{member.name}</p>
                    <p className="mt-1 text-[10px] text-slate-400">{member.role}</p>
                    <div className="mt-4 flex items-center justify-between border-t border-white/[0.07] pt-3">
                      <span className="font-display text-[9px] uppercase tracking-[0.1em] text-slate-500">{member.email}</span>
                      <span className="font-display text-[10px] font-semibold text-[#b7f960]">
                        {switching === member.email ? "Switching..." : isActive ? "Current" : "Switch →"}
                      </span>
                    </div>
                  </button>
                );
              })}
            </div>
          </Panel>

          <Panel className="p-5 md:p-6">
            <Meta>Server-enforced RBAC</Meta>
            <h2 className="mt-1 font-display text-xl font-semibold">Permission Matrix</h2>
            <p className="mt-1 text-[11px] text-slate-400">
              Each endpoint verifies permissions on the server. Public registration assigns safe default: Senior Analyst.
            </p>
            <div className="mt-4 space-y-2.5">
              {ROLES.map((role) => {
                const isCurrentRole = user?.role === role;
                const permissions = ROLE_PERMISSIONS[role];
                return (
                  <div
                    key={role}
                    className={`rounded-lg border p-3 transition ${
                      isCurrentRole
                        ? "border-[#b7f960]/40 bg-[#b7f960]/8"
                        : "border-white/[0.08] bg-black/15"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <p className="font-display text-[11px] font-semibold text-slate-200">{role}</p>
                      {isCurrentRole && (
                        <span className="rounded bg-[#b7f960]/20 px-1.5 py-0.5 font-display text-[9px] font-bold uppercase tracking-wider text-[#b7f960]">
                          Your Role
                        </span>
                      )}
                    </div>
                    <div className="mt-2 flex flex-wrap gap-1">
                      {permissions.map((perm) => (
                        <span
                          key={perm}
                          className="rounded bg-white/[0.06] px-1.5 py-0.5 font-mono text-[9px] text-slate-300"
                        >
                          {perm}
                        </span>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          </Panel>
        </div>
      </div>
    </>
  );
}

// ===========================================================================
// 8. REPORTS SCREEN (Connected to PostgreSQL Backend)
// ===========================================================================
function Reports() {
  const [reportsList, setReportsList] = useState<ReportItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .getReports()
      .then((res) => setReportsList(res.items))
      .catch((err) => console.error("Reports fetch error:", err))
      .finally(() => setLoading(false));
  }, []);

  return (
    <>
      <PageHeader
        eyebrow="Workspace / reporting"
        title="Reports"
        subtitle="Build readable, evidence-backed incident reports and recurring posture summaries from PostgreSQL."
        actions={
          <>
            <ActionButton onClick={() => toast.info("PDF engine will be connected with pdfkit in Phase 9.")}>
              <FileText size={14} /> Export center
            </ActionButton>
            <ActionButton tone="lime" onClick={() => toast.info("New report creation dialog will open in Phase 9.")}>
              <Plus size={14} /> New report
            </ActionButton>
          </>
        }
      />
      <div className="space-y-5 px-4 py-6 md:px-7">
        <div className="grid gap-5 lg:grid-cols-3">
          {[
            ["Incident report", "Describe the event, evidence trail, MITRE mapping, and recommended containment.", ShieldAlert],
            ["Executive brief", "Summarize risk posture, business impact, and the decisions leadership needs to make.", Sparkles],
            ["Threat hunting", "Document hypotheses, investigative queries, findings, and monitoring recommendations.", FileSearch],
          ].map(([title, description, Icon]) => {
            const TileIcon = Icon as typeof ShieldAlert;
            return (
              <button key={title as string} onClick={() => toast.info(`${title} template selected.`)} className="panel panel-lift p-5 text-left">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-[#b7f960]/20 bg-[#b7f960]/10 text-[#b7f960]">
                  <TileIcon size={18} />
                </div>
                <h2 className="mt-5 font-display text-lg font-semibold">{title as string}</h2>
                <p className="mt-2 text-[11px] leading-relaxed text-slate-400">{description as string}</p>
                <span className="mt-5 inline-flex items-center gap-1.5 font-display text-[10px] font-semibold uppercase tracking-[0.1em] text-[#b7f960]">
                  Use template <ArrowRight size={13} />
                </span>
              </button>
            );
          })}
        </div>

        <Panel>
          <div className="flex flex-col gap-3 border-b border-white/[0.08] px-5 py-5 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <Meta>Report library</Meta>
              <h2 className="mt-1 font-display text-xl font-semibold">Recent documents in PostgreSQL</h2>
            </div>
            <div className="flex items-center gap-2">
              <ActionButton onClick={() => toast.info("Search report archive")}>
                <Search size={13} /> Search
              </ActionButton>
              <ActionButton onClick={() => toast.info("Filter reports")}>
                <Filter size={13} />
              </ActionButton>
            </div>
          </div>
          {loading ? (
            <div className="p-8 text-center text-slate-500">
              <Loader2 className="animate-spin mx-auto mb-2" size={16} /> Loading reports from database...
            </div>
          ) : (
            <div className="divide-y divide-white/[0.07]">
              {reportsList.map((rep) => (
                <div key={rep.id} className="flex flex-col gap-3 px-5 py-4 transition hover:bg-white/[0.025] md:flex-row md:items-center">
                  <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-white/[0.06] text-slate-400">
                    <FileText size={17} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <p className="font-display text-[12px] font-semibold text-slate-200">{rep.reportCode}</p>
                      <span
                        className={`rounded-sm px-1.5 py-0.5 font-display text-[9px] uppercase tracking-[0.1em] ${
                          rep.status === "Published"
                            ? "bg-[#b7f960]/10 text-[#b7f960]"
                            : rep.status === "Review"
                            ? "bg-[#d9aa58]/10 text-[#f0c97f]"
                            : "bg-white/[0.06] text-slate-400"
                        }`}
                      >
                        {rep.status}
                      </span>
                    </div>
                    <p className="mt-1 text-[11px] text-slate-400">{rep.title}</p>
                    <p className="mt-1 font-display text-[9px] uppercase tracking-[0.1em] text-slate-600">
                      {rep.reportType} · {new Date(rep.createdAt).toLocaleDateString()}
                    </p>
                  </div>
                  <div className="flex gap-2">
                    <ActionButton onClick={() => toast.info(`Previewing report ${rep.reportCode}`)} className="py-2">
                      Preview
                    </ActionButton>
                    <ActionButton onClick={() => toast.info(`PDF export will be enabled in Phase 9.`)} className="py-2">
                      <FileText size={13} /> Export
                    </ActionButton>
                  </div>
                </div>
              ))}
              {!reportsList.length && (
                <div className="p-8 text-center text-slate-500">No reports generated in database yet.</div>
              )}
            </div>
          )}
        </Panel>
      </div>
    </>
  );
}

// ===========================================================================
// 9. SETTINGS SCREEN
// ===========================================================================
function Settings() {
  const [tab, setTab] = useState("Integrations");
  const tabs = ["Integrations", "Detections", "Notifications", "Workspace"];
  const feeds = [
    ["VirusTotal", "Indicator enrichment", "Connected", "#b7f960"],
    ["AbuseIPDB", "IP reputation", "Connected", "#b7f960"],
    ["AlienVault OTX", "Threat pulses", "Needs key", "#d9aa58"],
    ["OpenPhish", "Phishing intelligence", "Connected", "#b7f960"],
  ] as const;

  return (
    <>
      <PageHeader
        eyebrow="Workspace / system configuration"
        title="Settings"
        subtitle="Configure intelligence sources, detection behavior, alert delivery, and shared workspace defaults."
        actions={
          <ActionButton tone="lime" onClick={() => toast.success("Settings saved to the database.")}>
            <Check size={14} /> Save changes
          </ActionButton>
        }
      />
      <div className="grid gap-5 px-4 py-6 xl:grid-cols-[230px_minmax(0,1fr)] md:px-7">
        <Panel className="h-fit p-2">
          {tabs.map((item) => (
            <button
              onClick={() => setTab(item)}
              key={item}
              className={`flex w-full items-center justify-between rounded-lg px-3 py-3 text-left transition ${
                tab === item ? "bg-white/[0.08] text-white" : "text-slate-500 hover:bg-white/[0.035] hover:text-slate-200"
              }`}
            >
              <span className="font-display text-[11px] font-semibold">{item}</span>
              <ChevronRight size={14} className={tab === item ? "text-[#b7f960]" : ""} />
            </button>
          ))}
        </Panel>
        <div className="space-y-5">
          {tab === "Integrations" && (
            <>
              <Panel className="p-5 md:p-6">
                <Meta>Intelligence ecosystem</Meta>
                <div className="mt-1 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
                  <div>
                    <h2 className="font-display text-xl font-semibold">Threat feed connections</h2>
                    <p className="mt-2 text-[12px] text-slate-400">Enrich sightings and indicator lookup results using trusted public and internal sources.</p>
                  </div>
                  <ActionButton onClick={() => toast.info("Integration catalog")}>
                    <Plus size={13} /> Add source
                  </ActionButton>
                </div>
                <div className="mt-6 divide-y divide-white/[0.07]">
                  {feeds.map(([name, description, status, color]) => (
                    <div key={name} className="flex flex-col gap-3 py-4 sm:flex-row sm:items-center">
                      <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-white/[0.05] text-slate-400">
                        <Globe2 size={16} />
                      </div>
                      <div className="flex-1">
                        <p className="font-display text-[12px] font-semibold text-slate-200">{name}</p>
                        <p className="mt-1 text-[10px] text-slate-500">{description}</p>
                      </div>
                      <span className="flex items-center gap-1.5 font-display text-[9px] uppercase tracking-[0.1em]" style={{ color }}>
                        <i className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: color }} />
                        {status}
                      </span>
                      <ActionButton onClick={() => toast.info(`${name} settings`)} className="py-2">
                        Configure
                      </ActionButton>
                    </div>
                  ))}
                </div>
              </Panel>
              <Panel className="p-5 md:p-6">
                <Meta>Collection health</Meta>
                <h2 className="mt-1 font-display text-xl font-semibold">Log ingestion status</h2>
                <div className="mt-5 grid gap-3 sm:grid-cols-2">
                  {[
                    ["Windows Event Logs", "Connected · 14,228 events/min"],
                    ["Linux Syslogs", "Connected · 5,631 events/min"],
                    ["Firewall Telemetry", "Connected · 3,276 events/min"],
                    ["Web Server Logs", "Connected · 8,410 events/min"],
                  ].map(([source, state]) => (
                    <div key={source} className="rounded-lg border border-white/[0.08] bg-black/10 p-3">
                      <p className="font-display text-[11px] font-semibold text-slate-200">{source}</p>
                      <p className="mt-1 text-[10px] text-slate-500">{state}</p>
                    </div>
                  ))}
                </div>
              </Panel>
            </>
          )}
          {tab === "Detections" && (
            <SettingsPlaceholder
              title="Detection controls"
              text="Manage severity thresholds, model confidence requirements, suppression rules, and ATT&CK mapping behavior."
              action="Create rule"
            />
          )}
          {tab === "Notifications" && (
            <SettingsPlaceholder
              title="Notification routes"
              text="Set escalation routing for email, Slack, SMS, and webhook workflows by severity and assignment."
              action="Add route"
            />
          )}
          {tab === "Workspace" && (
            <SettingsPlaceholder
              title="Workspace controls"
              text="Set organization name, retention posture, default investigation templates, and analyst operating timezone."
              action="Update workspace"
            />
          )}
        </div>
      </div>
    </>
  );
}

function SettingsPlaceholder({ title, text, action }: { title: string; text: string; action: string }) {
  return (
    <Panel className="p-5 md:p-6">
      <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-[#b7f960]/10 text-[#b7f960]">
        <Settings2 size={18} />
      </div>
      <Meta>Configuration</Meta>
      <h2 className="mt-2 font-display text-xl font-semibold">{title}</h2>
      <p className="mt-2 max-w-xl text-[12px] leading-relaxed text-slate-400">{text}</p>
      <div className="mt-6 grid gap-3 sm:grid-cols-2">
        {["Use recommended defaults", "Require analyst acknowledgement", "Record changes in audit trail", "Escalate high-confidence findings"].map(
          (item, index) => (
            <button
              key={item}
              onClick={() => toast.info(`${item} toggled.`)}
              className="flex items-center justify-between rounded-lg border border-white/[0.08] bg-black/10 p-3 text-left"
            >
              <span className="text-[11px] text-slate-300">{item}</span>
              <span className={`flex h-5 w-9 items-center rounded-full p-0.5 ${index % 2 ? "bg-white/[0.11] justify-start" : "bg-[#b7f960]/50 justify-end"}`}>
                <i className="h-4 w-4 rounded-full bg-white" />
              </span>
            </button>
          )
        )}
      </div>
      <ActionButton tone="lime" onClick={() => toast.info(`${action} flow opened.`)} className="mt-6">
        <Plus size={13} /> {action}
      </ActionButton>
    </Panel>
  );
}

// ===========================================================================
// MAIN HOME SHELL
// ===========================================================================
function Home() {
  const [location, setLocation] = useLocation();
  const { user, isAuthenticated, logout } = useAuth();
  const [loginModalOpen, setLoginModalOpen] = useState(false);
  const displayName = [...commandNav, ...workspaceNav].find((item) => item.href === location)?.label ?? "Overview";

  const renderScreen = () => {
    if (location === routes.alerts) return <Alerts />;
    if (location === routes.logs) return <LogIngestion />;
    if (location === routes.investigation) return <Investigation />;
    if (location === routes.network) return <NetworkScreen />;
    if (location === routes.malware) return <MalwareLab />;
    if (location === routes.intel) return <ThreatIntel />;
    if (location === routes.team) return <TeamRoles />;
    if (location === routes.reports) return <Reports />;
    if (location === routes.settings) return <Settings />;
    return <Overview />;
  };

  return (
    <div className="min-h-screen bg-[#101316] text-slate-100">
      <div className="flex min-h-screen">
        <aside className="sticky top-0 hidden h-screen w-[248px] shrink-0 flex-col border-r border-white/[0.08] bg-[#0d1012] px-4 py-5 md:flex">
          <button onClick={() => setLocation(routes.overview)} className="flex items-center gap-3 px-2 text-left">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[#b7f960] shadow-[0_0_28px_rgba(183,249,96,0.16)]">
              <img src={ASSETS.logo} alt="Signal Room logo" className="h-8 w-8 object-contain" />
            </div>
            <div>
              <p className="font-display text-[15px] font-semibold tracking-tight text-slate-100">Signal Room</p>
              <p className="mt-0.5 font-display text-[9px] font-medium uppercase tracking-[0.18em] text-slate-500">AI SOC Assistant</p>
            </div>
          </button>

          <NavGroup title="Command center" items={commandNav} location={location} onNavigate={setLocation} />
          <NavGroup title="Workspace" items={workspaceNav} location={location} onNavigate={setLocation} />

          <div className="mt-auto rounded-xl border border-white/[0.08] bg-[linear-gradient(145deg,rgba(37,47,52,0.72),rgba(19,24,27,0.9))] p-3.5">
            <div className="flex items-center gap-2">
              <span className="status-pulse h-2 w-2 rounded-full bg-[#b7f960]" />
              <span className="font-display text-[10px] font-semibold uppercase tracking-[0.13em] text-[#c9f785]">All systems operational</span>
            </div>
            <p className="mt-2 text-[11px] leading-relaxed text-slate-500">PostgreSQL online · Telemetry active</p>
          </div>

          {isAuthenticated && user ? (
            <div className="mt-5 border-t border-white/[0.07] px-2 pt-4">
              <div className="flex items-center gap-3">
                <div
                  className="flex h-8 w-8 items-center justify-center rounded-lg font-display text-[11px] font-bold"
                  style={{ backgroundColor: `${user.color || "#b7f960"}25`, color: user.color || "#b7f960" }}
                >
                  {user.initials || "SA"}
                </div>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-[12px] font-semibold text-slate-200">{user.fullName}</p>
                  <p className="truncate text-[10px] text-slate-400">{user.role}</p>
                </div>
              </div>
              <div className="mt-3 flex items-center gap-1.5">
                <button
                  onClick={() => setLoginModalOpen(true)}
                  className="flex-1 rounded-md border border-white/[0.08] bg-white/[0.03] px-2 py-1 text-center font-display text-[10px] text-slate-300 transition hover:bg-white/[0.08] hover:text-[#b7f960]"
                >
                  Switch Persona
                </button>
                <button
                  onClick={async () => {
                    await logout();
                    toast.info("Signed out of Signal Room");
                  }}
                  title="Sign out"
                  className="rounded-md border border-white/[0.08] bg-white/[0.03] p-1 text-slate-400 transition hover:bg-red-500/20 hover:text-red-300"
                >
                  <LogOut size={13} />
                </button>
              </div>
            </div>
          ) : (
            <div className="mt-5 border-t border-white/[0.07] px-2 pt-4">
              <button
                onClick={() => setLoginModalOpen(true)}
                className="flex w-full items-center justify-center gap-2 rounded-lg border border-[#b7f960]/30 bg-[#b7f960]/10 px-3 py-2 font-display text-[11px] font-medium text-[#b7f960] transition hover:bg-[#b7f960]/20"
              >
                <LogIn size={13} />
                Sign in / Switch Role
              </button>
            </div>
          )}
        </aside>

        <main className="min-w-0 flex-1">
          <header className="flex h-[70px] items-center justify-between border-b border-white/[0.08] px-4 md:px-7">
            <button onClick={() => setLocation(routes.overview)} className="flex items-center gap-2 md:hidden">
              <img src={ASSETS.logo} alt="" className="h-8 w-8 rounded-lg bg-[#b7f960] p-1" />
              <span className="font-display text-sm font-semibold">Signal Room</span>
            </button>
            <div className="hidden items-center gap-2 text-[12px] text-slate-500 md:flex">
              <span>Security Operations</span>
              <ChevronRight size={14} />
              <span className="font-medium text-slate-300">{displayName}</span>
            </div>
            <div className="ml-auto flex items-center gap-2 md:gap-3">
              <button onClick={() => toast.info("Global search")} className="hidden items-center gap-2 rounded-lg border border-white/[0.08] bg-white/[0.025] px-3 py-2 text-[11px] text-slate-500 lg:flex">
                <Search size={14} />
                <span>Search intelligence</span>
                <kbd className="ml-5 rounded border border-white/[0.08] px-1.5 py-0.5 font-display text-[9px]">⌘ K</kbd>
              </button>
              <button
                onClick={() => toast.info("No unread alerts")}
                className="relative flex h-9 w-9 items-center justify-center rounded-lg border border-white/[0.08] text-slate-400 transition hover:bg-white/[0.06] hover:text-slate-100"
              >
                <Bell size={17} />
                <span className="absolute right-2 top-2 h-1.5 w-1.5 rounded-full bg-[#e16c5c]" />
              </button>

              {isAuthenticated && user ? (
                <div className="hidden sm:flex items-center gap-2 rounded-lg border border-white/[0.08] bg-white/[0.03] px-2.5 py-1.5">
                  <div
                    className="h-2 w-2 rounded-full"
                    style={{ backgroundColor: user.color || "#b7f960" }}
                  />
                  <span className="font-display text-[11px] font-medium text-slate-300">
                    {user.fullName.split(" ")[0]} ({user.role})
                  </span>
                  <button
                    onClick={() => setLoginModalOpen(true)}
                    className="ml-1 text-[10px] text-slate-400 hover:text-[#b7f960]"
                    title="Switch active analyst persona"
                  >
                    Switch
                  </button>
                </div>
              ) : (
                <ActionButton tone="lime" onClick={() => setLoginModalOpen(true)}>
                  <LogIn size={14} /> Sign In
                </ActionButton>
              )}

              <ActionButton tone="lime" onClick={() => setLocation(routes.reports)} className="hidden sm:inline-flex">
                <FileText size={14} /> Generate report
              </ActionButton>
            </div>
          </header>
          {renderScreen()}
        </main>
      </div>

      <LoginModal isOpen={loginModalOpen} onClose={() => setLoginModalOpen(false)} />
    </div>
  );
}

function NavGroup({
  title,
  items,
  location,
  onNavigate,
}: {
  title: string;
  items: Array<{ label: string; href: string; icon: any; badge?: string }>;
  location: string;
  onNavigate: (to: string) => void;
}) {
  return (
    <div className="mt-10">
      <div className="px-2">
        <Meta>{title}</Meta>
      </div>
      <nav className="mt-3 space-y-1">
        {items.map(({ label, href, icon: Icon, badge }) => {
          const active = location === href;
          return (
            <button
              key={href}
              onClick={() => onNavigate(href)}
              className={`group flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left transition-all ${
                active ? "bg-white/[0.08] text-white" : "text-slate-400 hover:bg-white/[0.045] hover:text-slate-200"
              }`}
            >
              <Icon size={17} strokeWidth={active ? 2.2 : 1.7} className={active ? "text-[#b7f960]" : "text-slate-500 group-hover:text-slate-300"} />
              <span className="flex-1 text-[13px] font-medium">{label}</span>
              {badge && <span className="rounded-full bg-[#e16c5c] px-1.5 py-0.5 font-display text-[9px] font-bold text-white">{badge}</span>}
            </button>
          );
        })}
      </nav>
    </div>
  );
}

export default Home;
