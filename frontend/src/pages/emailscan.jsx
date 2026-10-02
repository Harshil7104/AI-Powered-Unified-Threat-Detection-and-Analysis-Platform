import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import axios from "axios";
import { Mail, Search, AlertTriangle, ShieldCheck, ShieldAlert, Loader2, ArrowRight, CornerDownRight, CheckCircle2, XCircle } from "lucide-react";
import ThreatScoreGauge from "../components/ThreatScoreGauge";
import "../components/UrlScanner.css"; // Reuse card and status layouts

const SAMPLE_EMAILS = [
  {
    label: "🚨 PayPal Phishing",
    sender: "security-alert@paypa1-update.com",
    subject: "Urgent: Your PayPal account has been restricted",
    body: "Dear customer, we detected unauthorized login attempts from a new IP address. To secure your funds, please click the link below to verify your identity within 24 hours: http://paypa1-update.com/login. If you fail to verify, your account will be suspended permanently."
  },
  {
    label: "⚠️ Free Domain Impersonation",
    sender: "netflix.support.desk@gmail.com",
    subject: "Payment Declined - Update Netflix Billing info",
    body: "Your membership could not be renewed. We were unable to charge your card. Please update your details by replying to this email or clicking our portal. Thank you, Netflix Support Team."
  },
  {
    label: "🛡️ Safe Work Email",
    sender: "hr@company.com",
    subject: "Quarterly Performance Review Schedule",
    body: "Hi team, please find the schedule for our Q3 reviews starting next Monday. Let me know if you have any calendar conflicts. Thanks, HR team."
  }
];

function EmailScan() {
  const [sender, setSender] = useState("");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const navigate = useNavigate();
  const userEmail = localStorage.getItem("userEmail") || "User";

  const handleLogout = () => {
    localStorage.removeItem("isLoggedIn");
    localStorage.removeItem("userEmail");
    navigate("/");
  };

  const handleScan = async (e) => {
    if (e) e.preventDefault();
    if (!sender.trim() || !body.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await axios.post("http://localhost:8000/email/scan", {
        sender: sender.trim(),
        subject: subject.trim(),
        body: body.trim()
      });
      setResult(response.data);
    } catch (err) {
      console.error("Email scan error:", err);
      if (err.response && err.response.data && err.response.data.detail) {
        setError(err.response.data.detail);
      } else {
        setError("Failed to run email scanning. Verify backend connection.");
      }
    } finally {
      setLoading(false);
    }
  };

  const handlePresetClick = (sample) => {
    setSender(sample.sender);
    setSubject(sample.subject);
    setBody(sample.body);
    // Auto scan
    setTimeout(() => {
      setLoading(true);
      setError(null);
      setResult(null);
      axios.post("http://localhost:8000/email/scan", {
        sender: sample.sender,
        subject: sample.subject,
        body: sample.body
      }).then(res => {
        setResult(res.data);
        setLoading(false);
      }).catch(err => {
        console.error(err);
        setError("Preset scan failed.");
        setLoading(false);
      });
    }, 100);
  };

  const navItems = [
    { name: "Dashboard", path: "/dashboard", icon: "📊" },
    { name: "URL Scan", path: "/url-scan", icon: "🔗" },
    { name: "Email Scan", path: "/email-scan", icon: "📧" },
    { name: "File Scan", path: "/file-scan", icon: "📁" },
    { name: "AI Chat", path: "/ai-chat", icon: "🤖" },
    { name: "Reports", path: "/reports", icon: "📄" },
  ];

  return (
    <div className="min-h-screen flex bg-slate-950 text-white font-sans">
      {/* Sidebar */}
      <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col justify-between">
        <div>
          <div className="p-6 text-lg font-black tracking-wider border-b border-slate-800 text-white flex items-center gap-2">
            <span className="text-2xl">🛡️</span>
            <span>THREATSHIELD <span className="text-cyan-400 font-normal">AI</span></span>
          </div>
          <nav className="p-4 space-y-1">
            {navItems.map((item) => (
              <Link
                key={item.path}
                to={item.path}
                className={`flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm font-mono transition-all duration-200 ${
                  item.path === "/email-scan"
                    ? "bg-slate-800 text-cyan-400 border border-slate-700/50"
                    : "text-slate-400 hover:text-white hover:bg-slate-850"
                }`}
              >
                <span>{item.icon}</span>
                <span>{item.name}</span>
              </Link>
            ))}
          </nav>
        </div>
        <div className="p-4 border-t border-slate-800 text-xs text-slate-500 font-mono">
          System: Active v1.0.0
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col overflow-y-auto">
        {/* Header */}
        <header className="bg-slate-900/50 backdrop-blur-md border-b border-slate-800 px-6 py-4 flex justify-between items-center sticky top-0 z-10">
          <h2 className="text-sm font-mono font-bold tracking-tight text-white flex items-center gap-2">
            <Mail size={16} className="text-cyan-400" />
            <span>EMAIL_INTELLIGENCE_SCANNER</span>
          </h2>
          <div className="flex items-center gap-4">
            <span className="text-xs font-mono text-slate-400 bg-slate-950 border border-slate-800 px-3 py-1.5 rounded-lg">
              {userEmail}
            </span>
            <button
              onClick={handleLogout}
              className="text-xs bg-red-650 hover:bg-red-600 text-white font-mono px-3 py-1.5 rounded-lg transition"
            >
              LOGOUT
            </button>
          </div>
        </header>

        {/* Content Body */}
        <main className="flex-1 p-6 space-y-6 max-w-6xl w-full mx-auto">
          <div>
            <h1 className="text-2xl font-black text-white font-mono">
              Email Threat Analysis
            </h1>
            <p className="text-slate-400 text-sm mt-1">
              Inspect email senders, subject lines, body copy, and verify embedded hyperlinks using defensive rules.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
            {/* Input Column */}
            <div className="lg:col-span-3 space-y-5">
              <form onSubmit={handleScan} className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
                <div className="flex justify-between items-center border-b border-slate-800 pb-3">
                  <span className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                    <Search size={14} className="text-cyan-400" />
                    Input Diagnostic Details
                  </span>
                </div>

                <div>
                  <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-500 mb-1">
                    Sender Address (From)
                  </label>
                  <input
                    type="text"
                    value={sender}
                    onChange={(e) => setSender(e.target.value)}
                    placeholder="e.g. alert-support@pay-online.com"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-400 font-mono transition"
                    required
                  />
                </div>

                <div>
                  <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-500 mb-1">
                    Subject Line
                  </label>
                  <input
                    type="text"
                    value={subject}
                    onChange={(e) => setSubject(e.target.value)}
                    placeholder="e.g. Account Security Precaution Alert"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-400 transition"
                  />
                </div>

                <div>
                  <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-500 mb-1">
                    Email Body Copy
                  </label>
                  <textarea
                    value={body}
                    onChange={(e) => setBody(e.target.value)}
                    placeholder="Paste entire text content of the email here..."
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-400 font-sans transition h-40 resize-none"
                    required
                  />
                </div>

                <button
                  type="submit"
                  disabled={loading || !sender.trim() || !body.trim()}
                  className="w-full bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 hover:text-black font-semibold py-2.5 rounded-lg transition duration-200 disabled:opacity-40 font-mono text-sm uppercase tracking-wider"
                >
                  {loading ? (
                    <span className="flex items-center justify-center gap-2">
                      <Loader2 size={16} className="animate-spin" />
                      Deconstruct Analysis...
                    </span>
                  ) : (
                    "Execute Email Scan"
                  )}
                </button>
              </form>

              {/* Sample Presets */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
                <span className="text-xs font-mono uppercase tracking-wider text-slate-400 block border-b border-slate-800 pb-2">
                  Select Threat Templates
                </span>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                  {SAMPLE_EMAILS.map((sample, idx) => (
                    <button
                      key={idx}
                      onClick={() => handlePresetClick(sample)}
                      className="bg-slate-950 border border-slate-850 hover:border-slate-750 text-left p-3 rounded-lg text-xs transition-all duration-200"
                    >
                      <p className="font-bold text-slate-200">{sample.label}</p>
                      <p className="text-[10px] text-slate-500 truncate mt-1">{sample.sender}</p>
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Output Column */}
            <div className="lg:col-span-2 space-y-5">
              {error && (
                <div className="bg-red-500/10 border border-red-500/20 text-red-400 text-sm p-4 rounded-xl font-mono flex items-start gap-3">
                  <AlertTriangle size={18} className="mt-0.5 shrink-0" />
                  <div>{error}</div>
                </div>
              )}

              {loading && !result && (
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 flex flex-col items-center justify-center text-slate-500 font-mono text-sm">
                  <Loader2 size={32} className="animate-spin text-cyan-400 mb-3 animate-duration-1000" />
                  <p>Processing text payloads...</p>
                  <p className="text-[10px] text-slate-650 mt-1">Analyzing content headers and references</p>
                </div>
              )}

              {!loading && !result && !error && (
                <div className="bg-slate-900/60 border border-slate-850 border-dashed rounded-xl p-12 text-center text-slate-500 font-mono text-sm flex flex-col items-center justify-center">
                  <Mail size={40} className="text-slate-700 mb-3" />
                  <p>Awaiting Diagnostics</p>
                  <p className="text-[10px] text-slate-600 mt-1.5 max-w-[240px]">
                    Pre-fill a sample template or copy and paste email content to initiate check.
                  </p>
                </div>
              )}

              {result && (
                <div className="space-y-5 animate-fadeIn">
                  {/* Gauge */}
                  <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex items-center justify-center">
                    <ThreatScoreGauge score={result.risk_score} status={result.status} />
                  </div>

                  {/* Diagnostic Checks */}
                  <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
                    <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 border-b border-slate-800 pb-2 flex items-center gap-2">
                      <span>🔬</span>
                      <span>Security Checks Run</span>
                    </h3>
                    <div className="space-y-3">
                      {result.checks.map((check, idx) => (
                        <div key={idx} className="flex gap-3 bg-slate-950 p-3 rounded-lg border border-slate-850">
                          {check.passed && check.severity === "safe" ? (
                            <CheckCircle2 size={18} className="text-emerald-500 shrink-0 mt-0.5" />
                          ) : check.severity === "warning" ? (
                            <AlertTriangle size={18} className="text-yellow-500 shrink-0 mt-0.5" />
                          ) : (
                            <XCircle size={18} className="text-red-500 shrink-0 mt-0.5" />
                          )}
                          <div className="text-xs font-mono">
                            <div className="flex items-center gap-2 font-bold text-slate-200">
                              <span>{check.name}</span>
                              <span className={`text-[8px] px-1 rounded ${
                                check.severity === "safe" ? "bg-emerald-500/10 text-emerald-400" :
                                check.severity === "warning" ? "bg-yellow-500/10 text-yellow-400" :
                                "bg-red-500/10 text-red-400"
                              }`}>
                                {check.severity}
                              </span>
                            </div>
                            <p className="text-slate-400 mt-1 leading-normal font-sans text-[11px]">{check.message}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Extracted URLs Scan results */}
                  {result.details && result.details.url_scans && result.details.url_scans.length > 0 && (
                    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
                      <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 border-b border-slate-800 pb-2 flex items-center gap-2">
                        <span>🔗</span>
                        <span>Hyperlinks Extracted ({result.details.urls_detected})</span>
                      </h3>
                      <div className="space-y-2.5">
                        {result.details.url_scans.map((urlScan, idx) => (
                          <div key={idx} className="bg-slate-950 p-2.5 rounded-lg border border-slate-850 flex justify-between items-center text-xs">
                            <div className="truncate pr-4 max-w-[200px]">
                              <p className="font-mono text-[10px] text-slate-450 truncate" title={urlScan.url}>
                                {urlScan.url}
                              </p>
                            </div>
                            <div className="flex items-center gap-2 shrink-0">
                              <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded ${
                                urlScan.status === "Safe" ? "bg-emerald-500/10 text-emerald-400" :
                                urlScan.status === "Suspicious" ? "bg-yellow-500/10 text-yellow-400" :
                                "bg-red-500/10 text-red-400"
                              }`}>
                                {urlScan.status}
                              </span>
                              <span className="font-mono font-bold text-slate-450">
                                {urlScan.risk_score}%
                              </span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}

export default EmailScan;