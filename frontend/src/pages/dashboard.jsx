import { useState, useEffect } from "react";
import { useNavigate, Link } from "react-router-dom";
import axios from "axios";
import { Shield, AlertTriangle, FileText, Activity, ShieldAlert, CheckCircle, RefreshCw } from "lucide-react";

function Dashboard() {
  const [stats, setStats] = useState({
    total_scans: 0,
    threats_detected: 0,
    reports_generated: 0,
    by_type: { url: 0, email: 0, file: 0 },
    by_status: { Safe: 0, Suspicious: 0, "High Risk": 0 },
    recent_activity: []
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const navigate = useNavigate();
  const userEmail = localStorage.getItem("userEmail") || "User";

  const fetchStats = async () => {
    setLoading(true);
    setError("");
    try {
      const response = await axios.get("http://localhost:8000/reports/stats");
      setStats(response.data);
    } catch (err) {
      console.error("Dashboard stats fetch error:", err);
      setError("Failed to sync cyber telemetry. Please ensure backend is running.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  const handleLogout = () => {
    localStorage.removeItem("isLoggedIn");
    localStorage.removeItem("userEmail");
    navigate("/");
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
                  item.path === "/dashboard"
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

      {/* Main content area */}
      <div className="flex-1 flex flex-col overflow-y-auto">
        {/* Header */}
        <header className="bg-slate-900/50 backdrop-blur-md border-b border-slate-800 px-6 py-4 flex justify-between items-center sticky top-0 z-10">
          <div className="flex items-center gap-3">
            <h2 className="text-lg font-bold font-mono tracking-tight text-white flex items-center gap-2">
              <Activity size={18} className="text-cyan-400 animate-pulse" />
              <span>COMMAND_CENTER</span>
            </h2>
            {error && (
              <span className="text-xs bg-red-500/10 border border-red-500/20 text-red-400 px-2 py-0.5 rounded font-mono">
                OFFLINE
              </span>
            )}
          </div>
          <div className="flex items-center gap-4">
            <button
              onClick={fetchStats}
              className="p-1.5 rounded-lg border border-slate-800 hover:bg-slate-800 text-slate-400 hover:text-white transition"
              title="Refresh Telemetry"
            >
              <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
            </button>
            <span className="text-xs font-mono text-slate-400 bg-slate-950 border border-slate-800 px-3 py-1.5 rounded-lg">
              Analyst: {userEmail}
            </span>
            <button
              onClick={handleLogout}
              className="text-xs bg-red-600/80 hover:bg-red-600 text-white font-mono px-3 py-1.5 rounded-lg transition"
            >
              LOGOUT
            </button>
          </div>
        </header>

        {/* Content */}
        <main className="flex-1 p-6 space-y-6 max-w-7xl w-full mx-auto">
          {error && (
            <div className="bg-red-500/10 border border-red-500/20 text-red-400 text-sm p-4 rounded-xl font-mono flex items-center gap-3">
              <AlertTriangle size={20} />
              <div>{error}</div>
            </div>
          )}

          {/* Metrics summary grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex items-center justify-between">
              <div>
                <p className="text-slate-500 text-xs font-mono uppercase tracking-wider">Total Evaluated</p>
                <p className="text-3xl font-black text-white font-mono mt-1">
                  {loading ? "..." : stats.total_scans}
                </p>
              </div>
              <div className="p-3 rounded-lg bg-blue-500/10 text-blue-400">
                <Shield size={24} />
              </div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex items-center justify-between">
              <div>
                <p className="text-slate-500 text-xs font-mono uppercase tracking-wider">Threats Flagged</p>
                <p className="text-3xl font-black text-red-400 font-mono mt-1">
                  {loading ? "..." : stats.threats_detected}
                </p>
              </div>
              <div className="p-3 rounded-lg bg-red-500/10 text-red-400">
                <ShieldAlert size={24} />
              </div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex items-center justify-between">
              <div>
                <p className="text-slate-500 text-xs font-mono uppercase tracking-wider">Reports Logged</p>
                <p className="text-3xl font-black text-emerald-400 font-mono mt-1">
                  {loading ? "..." : stats.reports_generated}
                </p>
              </div>
              <div className="p-3 rounded-lg bg-emerald-500/10 text-emerald-400">
                <FileText size={24} />
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Scans breakdown */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 lg:col-span-1 space-y-6">
              <h3 className="text-sm font-bold font-mono tracking-wider text-slate-300 uppercase border-b border-slate-800 pb-3">
                Telemetry Breakdown
              </h3>
              
              <div className="space-y-4">
                <div>
                  <div className="flex justify-between text-xs font-mono text-slate-400 mb-1">
                    <span>URLs Check</span>
                    <span>{stats.by_type.url}</span>
                  </div>
                  <div className="w-full bg-slate-950 rounded-full h-1.5">
                    <div
                      className="bg-cyan-500 h-1.5 rounded-full transition-all duration-500"
                      style={{
                        width: `${
                          stats.total_scans > 0 ? (stats.by_type.url / stats.total_scans) * 100 : 0
                        }%`,
                      }}
                    />
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-xs font-mono text-slate-400 mb-1">
                    <span>Emails Check</span>
                    <span>{stats.by_type.email}</span>
                  </div>
                  <div className="w-full bg-slate-950 rounded-full h-1.5">
                    <div
                      className="bg-purple-500 h-1.5 rounded-full transition-all duration-500"
                      style={{
                        width: `${
                          stats.total_scans > 0 ? (stats.by_type.email / stats.total_scans) * 100 : 0
                        }%`,
                      }}
                    />
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-xs font-mono text-slate-400 mb-1">
                    <span>Files Check</span>
                    <span>{stats.by_type.file}</span>
                  </div>
                  <div className="w-full bg-slate-950 rounded-full h-1.5">
                    <div
                      className="bg-blue-500 h-1.5 rounded-full transition-all duration-500"
                      style={{
                        width: `${
                          stats.total_scans > 0 ? (stats.by_type.file / stats.total_scans) * 100 : 0
                        }%`,
                      }}
                    />
                  </div>
                </div>
              </div>

              <div className="border-t border-slate-800 pt-4 space-y-2">
                <div className="flex justify-between text-xs font-mono text-slate-400">
                  <span>Safe Assets:</span>
                  <span className="text-emerald-400">{stats.by_status.Safe || 0}</span>
                </div>
                <div className="flex justify-between text-xs font-mono text-slate-400">
                  <span>Suspicious:</span>
                  <span className="text-yellow-400">{stats.by_status.Suspicious || 0}</span>
                </div>
                <div className="flex justify-between text-xs font-mono text-slate-400">
                  <span>High Risk:</span>
                  <span className="text-red-400">{stats.by_status["High Risk"] || 0}</span>
                </div>
              </div>
            </div>

            {/* Recent activity log */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 lg:col-span-2 space-y-4">
              <div className="flex justify-between items-center border-b border-slate-800 pb-3">
                <h3 className="text-sm font-bold font-mono tracking-wider text-slate-300 uppercase">
                  Real-time Threat Activity Feed
                </h3>
                <Link
                  to="/reports"
                  className="text-xs text-cyan-400 hover:underline font-mono"
                >
                  VIEW_ALL_LOGS &rarr;
                </Link>
              </div>

              {loading ? (
                <div className="flex flex-col items-center justify-center py-12 text-slate-500 font-mono text-xs">
                  <span className="w-6 h-6 border-2 border-slate-700 border-t-cyan-400 rounded-full animate-spin mb-2" />
                  Syncing telemetry logs...
                </div>
              ) : stats.recent_activity.length === 0 ? (
                <div className="text-center py-12 text-slate-500 font-mono text-sm">
                  🛡️ No threat activity recorded. Get started by running a scanner!
                </div>
              ) : (
                <div className="divide-y divide-slate-800/50">
                  {stats.recent_activity.map((activity) => (
                    <div
                      key={activity.id}
                      className="py-3 flex justify-between items-center group hover:bg-slate-850/40 px-2 rounded-lg transition duration-200"
                    >
                      <div className="flex items-center gap-3">
                        <span className="text-base">
                          {activity.scan_type === "url" ? "🔗" : activity.scan_type === "email" ? "📧" : "📁"}
                        </span>
                        <div className="max-w-md">
                          <p className="text-xs font-mono font-bold truncate text-slate-200">
                            {activity.target}
                          </p>
                          <p className="text-[10px] text-slate-500 font-mono mt-0.5">
                            ID: {activity.id} • {activity.created_at}
                          </p>
                        </div>
                      </div>
                      
                      <div className="flex items-center gap-3">
                        <span className={`text-[10px] px-2 py-0.5 rounded font-mono border ${
                          activity.status === "Safe"
                            ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
                            : activity.status === "Suspicious"
                            ? "bg-yellow-500/10 border-yellow-500/20 text-yellow-400"
                            : "bg-red-500/10 border-red-500/20 text-red-400"
                        }`}>
                          {activity.status.toUpperCase()}
                        </span>
                        <span className="text-xs font-mono font-bold text-slate-400 group-hover:text-white">
                          Score: {activity.risk_score}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}

export default Dashboard;