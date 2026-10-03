import { useState, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import {
  Shield, Lock, Mail, Eye, EyeOff, AlertTriangle,
  CheckCircle2, XCircle, Loader2, KeyRound, UserPlus,
  LogIn, Fingerprint, ShieldCheck, ArrowRight
} from "lucide-react";

/* ─── Password strength rules ──────────────────────────────── */
const PASSWORD_RULES = [
  { id: "len",   label: "At least 8 characters",          test: (p) => p.length >= 8 },
  { id: "upper", label: "One uppercase letter (A‑Z)",     test: (p) => /[A-Z]/.test(p) },
  { id: "lower", label: "One lowercase letter (a‑z)",     test: (p) => /[a-z]/.test(p) },
  { id: "digit", label: "One digit (0‑9)",                test: (p) => /\d/.test(p) },
  { id: "spec",  label: "One special character (!@#$…)",  test: (p) => /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(p) },
];

const getStrength = (password) => {
  if (!password) return { score: 0, label: "", color: "" };
  const passed = PASSWORD_RULES.filter((r) => r.test(password)).length;
  if (passed <= 1) return { score: 1, label: "Weak", color: "#ef4444" };
  if (passed <= 2) return { score: 2, label: "Fair", color: "#f59e0b" };
  if (passed <= 3) return { score: 3, label: "Good", color: "#eab308" };
  if (passed === 4) return { score: 4, label: "Strong", color: "#22c55e" };
  return { score: 5, label: "Excellent", color: "#06b6d4" };
};

/* ─── Email validation ─────────────────────────────────────── */
const isValidEmail = (email) =>
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

/* ─── Component ────────────────────────────────────────────── */
function Login() {
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [error, setError] = useState("");
  const [successMsg, setSuccessMsg] = useState("");
  const [loading, setLoading] = useState(false);
  const [touched, setTouched] = useState({});
  const navigate = useNavigate();

  /* If already authenticated redirect to dashboard */
  useEffect(() => {
    const token = localStorage.getItem("token");
    const isLoggedIn = localStorage.getItem("isLoggedIn");
    if (token && isLoggedIn === "true") {
      navigate("/dashboard", { replace: true });
    }
  }, [navigate]);

  /* Derived validation state */
  const emailValid = isValidEmail(email);
  const strength = getStrength(password);
  const allRulesPass = PASSWORD_RULES.every((r) => r.test(password));
  const passwordsMatch = password === confirmPassword && confirmPassword.length > 0;

  const canSubmit = isRegister
    ? emailValid && allRulesPass && passwordsMatch && !loading
    : emailValid && password.length >= 1 && !loading;

  /* ── Submit ───────────────────────────────────────────────── */
  const handleSubmit = useCallback(
    async (e) => {
      e.preventDefault();
      setError("");
      setSuccessMsg("");

      if (!emailValid) {
        setError("Please enter a valid email address.");
        return;
      }

      if (isRegister && !allRulesPass) {
        setError("Password does not meet all security requirements.");
        return;
      }

      if (isRegister && !passwordsMatch) {
        setError("Passwords do not match.");
        return;
      }

      setLoading(true);
      const endpoint = isRegister
        ? "http://localhost:8000/auth/register"
        : "http://localhost:8000/auth/login";

      try {
        const response = await axios.post(endpoint, { email, password });

        setSuccessMsg(
          isRegister
            ? "Account created successfully! Redirecting to dashboard…"
            : "Authentication verified! Redirecting…"
        );

        setTimeout(() => {
          localStorage.setItem("isLoggedIn", "true");
          localStorage.setItem("userEmail", response.data.email);
          if (response.data.token) {
            localStorage.setItem("token", response.data.token);
          }
          setLoading(false);
          navigate("/dashboard");
        }, 900);
      } catch (err) {
        console.error("Auth error:", err);
        if (err.response?.data?.detail) {
          setError(err.response.data.detail);
        } else {
          setError(
            "Failed to connect to the authentication server. Ensure the backend is running."
          );
        }
        setLoading(false);
      }
    },
    [email, password, confirmPassword, isRegister, emailValid, allRulesPass, passwordsMatch, navigate]
  );

  /* ── Mode toggle (reset state) ─────────────────────────── */
  const toggleMode = () => {
    setIsRegister((prev) => !prev);
    setError("");
    setSuccessMsg("");
    setConfirmPassword("");
    setShowPassword(false);
    setShowConfirm(false);
    setTouched({});
  };

  /* ── Feature pills shown on the left panel ─────────────── */
  const features = [
    { icon: <Shield size={16} />,      text: "JWT Token Authentication" },
    { icon: <Fingerprint size={16} />, text: "PBKDF2‑SHA256 Password Hashing" },
    { icon: <ShieldCheck size={16} />, text: "Protected API Endpoints" },
    { icon: <KeyRound size={16} />,    text: "24‑Hour Token Expiry" },
  ];

  /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
  return (
    <div className="min-h-screen flex bg-slate-950 text-white font-sans relative overflow-hidden">
      {/* ── Background ambient glow ─────────────────────────── */}
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        <div className="absolute -top-40 -left-40 w-[500px] h-[500px] rounded-full bg-cyan-600/8 blur-[160px]" />
        <div className="absolute -bottom-40 -right-40 w-[500px] h-[500px] rounded-full bg-blue-600/8 blur-[160px]" />
        {/* Subtle grid */}
        <div
          className="absolute inset-0 opacity-[0.03]"
          style={{
            backgroundImage:
              "linear-gradient(rgba(148,163,184,0.4) 1px, transparent 1px), linear-gradient(90deg, rgba(148,163,184,0.4) 1px, transparent 1px)",
            backgroundSize: "60px 60px",
          }}
        />
      </div>

      {/* ══════════════ LEFT PANEL ═══════════════════════════ */}
      <div className="hidden lg:flex w-[480px] flex-col justify-between p-10 relative z-10 border-r border-slate-800/60">
        {/* Brand */}
        <div>
          <div className="flex items-center gap-3 mb-8">
            <div className="w-11 h-11 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
              <Shield size={22} className="text-white" />
            </div>
            <div>
              <h1 className="text-xl font-black tracking-wide leading-tight">
                THREATSHIELD <span className="text-cyan-400 font-semibold">AI</span>
              </h1>
              <p className="text-[10px] font-mono uppercase tracking-[0.2em] text-slate-500 mt-0.5">
                Unified Threat Detection Platform
              </p>
            </div>
          </div>

          {/* Headline */}
          <h2 className="text-3xl font-extrabold leading-tight text-white mb-3">
            AI-Powered Cyber
            <br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-400">
              Threat Intelligence
            </span>
          </h2>
          <p className="text-sm text-slate-400 leading-relaxed max-w-sm">
            Scan URLs, emails, and files against global threat intelligence feeds.
            Detect phishing, malware, and zero-day indicators in real time with machine learning analysis.
          </p>

          {/* Features */}
          <div className="mt-8 space-y-3">
            {features.map((f, i) => (
              <div
                key={i}
                className="flex items-center gap-3 text-sm text-slate-300 bg-slate-900/50 border border-slate-800/50 rounded-lg px-4 py-2.5"
              >
                <span className="text-cyan-400 shrink-0">{f.icon}</span>
                <span className="font-mono text-xs">{f.text}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Footer */}
        <div className="text-[11px] text-slate-600 font-mono space-y-1">
          <p>v1.0.0 — Semester 5 SGP Project</p>
          <p>© 2026 ThreatShield AI. All rights reserved.</p>
        </div>
      </div>

      {/* ══════════════ RIGHT PANEL (form) ═══════════════════ */}
      <div className="flex-1 flex items-center justify-center px-6 py-12 relative z-10">
        <div className="w-full max-w-[420px]">

          {/* Mobile brand (hidden on lg+) */}
          <div className="lg:hidden flex flex-col items-center mb-8">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 mb-3">
              <Shield size={24} className="text-white" />
            </div>
            <h1 className="text-xl font-black tracking-wide">
              THREATSHIELD <span className="text-cyan-400">AI</span>
            </h1>
            <p className="text-[10px] font-mono uppercase tracking-[0.2em] text-slate-500 mt-1">
              Unified Threat Detection
            </p>
          </div>

          {/* Card */}
          <div className="bg-slate-900/70 backdrop-blur-xl border border-slate-800 rounded-2xl shadow-2xl shadow-black/30">

            {/* Tab Switcher */}
            <div className="flex border-b border-slate-800">
              <button
                type="button"
                onClick={() => { if (isRegister) toggleMode(); }}
                className={`flex-1 py-3.5 text-sm font-mono font-semibold tracking-wide flex items-center justify-center gap-2 transition-all duration-200 rounded-tl-2xl ${
                  !isRegister
                    ? "text-cyan-400 border-b-2 border-cyan-400 bg-slate-800/30"
                    : "text-slate-500 hover:text-slate-300"
                }`}
              >
                <LogIn size={15} />
                SIGN IN
              </button>
              <button
                type="button"
                onClick={() => { if (!isRegister) toggleMode(); }}
                className={`flex-1 py-3.5 text-sm font-mono font-semibold tracking-wide flex items-center justify-center gap-2 transition-all duration-200 rounded-tr-2xl ${
                  isRegister
                    ? "text-cyan-400 border-b-2 border-cyan-400 bg-slate-800/30"
                    : "text-slate-500 hover:text-slate-300"
                }`}
              >
                <UserPlus size={15} />
                REGISTER
              </button>
            </div>

            {/* Form Body */}
            <form onSubmit={handleSubmit} className="p-6 space-y-5" noValidate>

              {/* ── Error banner ─── */}
              {error && (
                <div className="flex items-start gap-2.5 bg-red-500/8 border border-red-500/20 rounded-lg px-3.5 py-2.5">
                  <AlertTriangle size={16} className="text-red-400 shrink-0 mt-0.5" />
                  <p className="text-xs text-red-400 font-mono leading-relaxed">{error}</p>
                </div>
              )}

              {/* ── Success banner ── */}
              {successMsg && (
                <div className="flex items-start gap-2.5 bg-emerald-500/8 border border-emerald-500/20 rounded-lg px-3.5 py-2.5">
                  <CheckCircle2 size={16} className="text-emerald-400 shrink-0 mt-0.5" />
                  <p className="text-xs text-emerald-400 font-mono leading-relaxed">{successMsg}</p>
                </div>
              )}

              {/* ── Email field ──── */}
              <div>
                <label className="flex items-center gap-1.5 text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-1.5">
                  <Mail size={12} className="text-slate-500" />
                  Email Address
                </label>
                <div className="relative">
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    onBlur={() => setTouched((t) => ({ ...t, email: true }))}
                    className={`w-full bg-slate-950/80 border rounded-lg pl-4 pr-10 py-2.5 text-sm text-white font-mono placeholder:text-slate-600 focus:outline-none transition-all duration-200 ${
                      touched.email && !emailValid && email
                        ? "border-red-500/50 focus:border-red-400"
                        : "border-slate-800 focus:border-cyan-400 focus:shadow-[0_0_0_3px_rgba(6,182,212,0.1)]"
                    }`}
                    placeholder="analyst@organization.com"
                    autoComplete="email"
                  />
                  {touched.email && email && (
                    <span className="absolute right-3 top-1/2 -translate-y-1/2">
                      {emailValid ? (
                        <CheckCircle2 size={15} className="text-emerald-400" />
                      ) : (
                        <XCircle size={15} className="text-red-400" />
                      )}
                    </span>
                  )}
                </div>
                {touched.email && email && !emailValid && (
                  <p className="text-[10px] text-red-400 font-mono mt-1">Enter a valid email address</p>
                )}
              </div>

              {/* ── Password field ─ */}
              <div>
                <label className="flex items-center gap-1.5 text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-1.5">
                  <Lock size={12} className="text-slate-500" />
                  Password
                </label>
                <div className="relative">
                  <input
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    onBlur={() => setTouched((t) => ({ ...t, password: true }))}
                    className="w-full bg-slate-950/80 border border-slate-800 rounded-lg pl-4 pr-10 py-2.5 text-sm text-white font-mono placeholder:text-slate-600 focus:outline-none focus:border-cyan-400 focus:shadow-[0_0_0_3px_rgba(6,182,212,0.1)] transition-all duration-200"
                    placeholder="••••••••"
                    autoComplete={isRegister ? "new-password" : "current-password"}
                  />
                  <button
                    type="button"
                    tabIndex={-1}
                    onClick={() => setShowPassword((v) => !v)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition"
                  >
                    {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                  </button>
                </div>

                {/* ── Strength meter (register mode) ── */}
                {isRegister && password && (
                  <div className="mt-2.5 space-y-2">
                    {/* Bar */}
                    <div className="flex gap-1">
                      {[1, 2, 3, 4, 5].map((i) => (
                        <div
                          key={i}
                          className="h-1 flex-1 rounded-full transition-all duration-300"
                          style={{
                            backgroundColor:
                              i <= strength.score ? strength.color : "#1e293b",
                          }}
                        />
                      ))}
                    </div>
                    <p
                      className="text-[10px] font-mono font-semibold tracking-wide"
                      style={{ color: strength.color }}
                    >
                      Password Strength: {strength.label}
                    </p>

                    {/* Checklist */}
                    <div className="grid grid-cols-1 gap-1 mt-1">
                      {PASSWORD_RULES.map((rule) => {
                        const pass = rule.test(password);
                        return (
                          <div
                            key={rule.id}
                            className="flex items-center gap-1.5 text-[10px] font-mono"
                          >
                            {pass ? (
                              <CheckCircle2 size={11} className="text-emerald-400 shrink-0" />
                            ) : (
                              <XCircle size={11} className="text-slate-600 shrink-0" />
                            )}
                            <span className={pass ? "text-slate-300" : "text-slate-600"}>
                              {rule.label}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>

              {/* ── Confirm Password field ── */}
              {isRegister && (
                <div>
                  <label className="flex items-center gap-1.5 text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-1.5">
                    <KeyRound size={12} className="text-slate-500" />
                    Confirm Password
                  </label>
                  <div className="relative">
                    <input
                      type={showConfirm ? "text" : "password"}
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      onBlur={() => setTouched((t) => ({ ...t, confirm: true }))}
                      className={`w-full bg-slate-950/80 border rounded-lg pl-4 pr-10 py-2.5 text-sm text-white font-mono placeholder:text-slate-600 focus:outline-none transition-all duration-200 ${
                        touched.confirm && confirmPassword && !passwordsMatch
                          ? "border-red-500/50 focus:border-red-400"
                          : "border-slate-800 focus:border-cyan-400 focus:shadow-[0_0_0_3px_rgba(6,182,212,0.1)]"
                      }`}
                      placeholder="••••••••"
                      autoComplete="new-password"
                    />
                    <button
                      type="button"
                      tabIndex={-1}
                      onClick={() => setShowConfirm((v) => !v)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition"
                    >
                      {showConfirm ? <EyeOff size={15} /> : <Eye size={15} />}
                    </button>
                  </div>
                  {touched.confirm && confirmPassword && !passwordsMatch && (
                    <p className="text-[10px] text-red-400 font-mono mt-1">Passwords do not match</p>
                  )}
                  {touched.confirm && passwordsMatch && (
                    <p className="text-[10px] text-emerald-400 font-mono mt-1 flex items-center gap-1">
                      <CheckCircle2 size={10} /> Passwords match
                    </p>
                  )}
                </div>
              )}

              {/* ── Submit button ── */}
              <button
                type="submit"
                disabled={!canSubmit}
                className="w-full flex items-center justify-center gap-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:from-slate-700 disabled:to-slate-700 disabled:text-slate-500 text-slate-950 hover:text-black font-bold py-3 rounded-lg transition-all duration-200 font-mono text-sm uppercase tracking-wider shadow-lg shadow-cyan-500/15 disabled:shadow-none disabled:cursor-not-allowed mt-1"
              >
                {loading ? (
                  <>
                    <Loader2 size={16} className="animate-spin" />
                    <span>Authenticating…</span>
                  </>
                ) : isRegister ? (
                  <>
                    <UserPlus size={16} />
                    <span>Create Secure Account</span>
                  </>
                ) : (
                  <>
                    <LogIn size={16} />
                    <span>Authenticate & Access</span>
                  </>
                )}
              </button>
            </form>

            {/* Footer inside card */}
            <div className="border-t border-slate-800 px-6 py-3.5">
              <p className="text-center text-[11px] text-slate-500 font-mono">
                {isRegister ? (
                  <>
                    Already have an account?{" "}
                    <button type="button" onClick={toggleMode} className="text-cyan-400 hover:text-cyan-300 transition underline underline-offset-2">
                      Sign in
                    </button>
                  </>
                ) : (
                  <>
                    Don&apos;t have an account?{" "}
                    <button type="button" onClick={toggleMode} className="text-cyan-400 hover:text-cyan-300 transition underline underline-offset-2">
                      Register here
                    </button>
                  </>
                )}
              </p>
            </div>
          </div>

          {/* Security disclaimer */}
          <div className="mt-4 flex items-center justify-center gap-1.5 text-[10px] text-slate-600 font-mono">
            <Lock size={10} />
            <span>Encrypted with TLS · PBKDF2‑SHA256 · JWT Bearer Auth</span>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Login;