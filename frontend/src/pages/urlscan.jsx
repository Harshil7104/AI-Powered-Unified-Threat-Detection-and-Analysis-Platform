import { useNavigate, Link } from "react-router-dom";
import { Globe } from "lucide-react";
import UrlScanner from "../components/UrlScanner";

function UrlScan() {
  const navigate = useNavigate();
  const userEmail = localStorage.getItem("userEmail") || "User";

  const handleLogout = () => {
    localStorage.removeItem("isLoggedIn");
    localStorage.removeItem("userEmail");
    localStorage.removeItem("token");
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
      <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col justify-between shrink-0">
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
                  item.path === "/url-scan"
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
            <Globe size={16} className="text-cyan-400" />
            <span>URL_THREAT_DETECTION_ENGINE</span>
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
              URL Threat Scan & Analysis
            </h1>
            <p className="text-slate-400 text-sm mt-1">
              Analyze URLs for phishing, suspicious redirects, insecure protocols, WHOIS age, and global threat intelligence.
            </p>
          </div>

          <UrlScanner />
        </main>
      </div>
    </div>
  );
}

export default UrlScan;