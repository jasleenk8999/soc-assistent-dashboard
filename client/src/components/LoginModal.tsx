import { useState } from "react";
import { Lock, Mail, User, ShieldCheck, AlertCircle, Loader2, ArrowRight } from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";
import { toast } from "sonner";

interface LoginModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function LoginModal({ isOpen, onClose }: LoginModalProps) {
  const { login, register } = useAuth();
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [fullName, setFullName] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      if (mode === "login") {
        await login({ email, password });
      } else {
        await register({ email, password, fullName });
      }
      onClose();
    } catch (err: any) {
      setError(err.message || "Authentication failed. Please verify credentials.");
    } finally {
      setLoading(false);
    }
  };

  const handleQuickLogin = (demoEmail: string) => {
    setEmail(demoEmail);
    setPassword("SocAnalyst2026!");
    setMode("login");
    setError(null);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-md">
      <div className="w-full max-w-md rounded-2xl border border-white/[0.1] bg-[#12161a] p-6 shadow-2xl shadow-black/90">
        <div className="flex items-center justify-between border-b border-white/[0.08] pb-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-[#b7f960] text-black">
              <ShieldCheck size={20} />
            </div>
            <div>
              <h2 className="font-display text-lg font-semibold text-white">Signal Room Security</h2>
              <p className="font-display text-[10px] uppercase tracking-[0.14em] text-slate-500">
                Analyst Identity Verification
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1 text-slate-500 hover:bg-white/[0.06] hover:text-slate-200"
          >
            ✕
          </button>
        </div>

        {/* Mode Toggle Tabs */}
        <div className="mt-5 grid grid-cols-2 rounded-lg border border-white/[0.08] bg-black/20 p-1">
          <button
            type="button"
            onClick={() => {
              setMode("login");
              setError(null);
            }}
            className={`rounded-md py-1.5 font-display text-[11px] font-semibold transition ${
              mode === "login" ? "bg-white/[0.1] text-[#b7f960]" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            Sign In
          </button>
          <button
            type="button"
            onClick={() => {
              setMode("register");
              setError(null);
            }}
            className={`rounded-md py-1.5 font-display text-[11px] font-semibold transition ${
              mode === "register" ? "bg-white/[0.1] text-[#b7f960]" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            Register Analyst
          </button>
        </div>

        {error && (
          <div className="mt-4 flex items-center gap-2 rounded-lg border border-[#e16c5c]/35 bg-[#e16c5c]/10 p-3 text-[12px] text-[#ff9a8d]">
            <AlertCircle size={16} className="shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="mt-5 space-y-4">
          {mode === "register" && (
            <div>
              <label className="block font-display text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-400">
                Full Name
              </label>
              <div className="relative mt-1.5">
                <User size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  type="text"
                  required
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="e.g. Avery Reed"
                  className="h-10 w-full rounded-lg border border-white/[0.1] bg-black/20 pl-9 pr-3 text-[12px] text-slate-200 outline-none placeholder:text-slate-600 focus:border-[#b7f960]/50"
                />
              </div>
            </div>
          )}

          <div>
            <label className="block font-display text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-400">
              Email Address
            </label>
            <div className="relative mt-1.5">
              <Mail size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@soc.local"
                className="h-10 w-full rounded-lg border border-white/[0.1] bg-black/20 pl-9 pr-3 text-[12px] text-slate-200 outline-none placeholder:text-slate-600 focus:border-[#b7f960]/50"
              />
            </div>
          </div>

          <div>
            <label className="block font-display text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-400">
              Password {mode === "register" && <span className="text-[9px] text-slate-500">(Min 8 chars, A-Z, 0-9, symbol)</span>}
            </label>
            <div className="relative mt-1.5">
              <Lock size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="h-10 w-full rounded-lg border border-white/[0.1] bg-black/20 pl-9 pr-3 text-[12px] text-slate-200 outline-none placeholder:text-slate-600 focus:border-[#b7f960]/50"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="mt-2 flex h-10 w-full items-center justify-center gap-2 rounded-lg bg-[#b7f960] font-display text-[11px] font-bold uppercase tracking-[0.1em] text-[#12161a] transition hover:bg-[#ccff88] disabled:opacity-50"
          >
            {loading ? (
              <Loader2 className="animate-spin" size={16} />
            ) : mode === "login" ? (
              <>
                Authenticate <ArrowRight size={14} />
              </>
            ) : (
              <>
                Create Account <ArrowRight size={14} />
              </>
            )}
          </button>
        </form>

        {/* Quick Demo Persona Switcher */}
        <div className="mt-6 border-t border-white/[0.08] pt-4">
          <p className="font-display text-[9px] font-semibold uppercase tracking-[0.14em] text-slate-500">
            Quick Persona Switcher (Seeded Analysts)
          </p>
          <div className="mt-2.5 grid grid-cols-2 gap-2">
            {[
              { name: "Avery Reed", email: "avery.reed@soc.local", role: "Senior Analyst" },
              { name: "Mina Kapoor", email: "mina.kapoor@soc.local", role: "Threat Hunter" },
              { name: "Darren Liu", email: "darren.liu@soc.local", role: "Incident Commander" },
              { name: "Jordan Smith", email: "jordan.smith@soc.local", role: "Detection Eng." },
            ].map((p) => (
              <button
                key={p.email}
                type="button"
                onClick={() => handleQuickLogin(p.email)}
                className="flex flex-col rounded-lg border border-white/[0.08] bg-black/20 p-2 text-left transition hover:border-[#b7f960]/30 hover:bg-white/[0.035]"
              >
                <span className="truncate font-display text-[11px] font-semibold text-slate-200">{p.name}</span>
                <span className="font-display text-[9px] text-[#b7f960]">{p.role}</span>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
