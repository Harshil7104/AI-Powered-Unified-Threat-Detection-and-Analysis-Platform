import { useNavigate, Link } from "react-router-dom";
import UrlScanner from "../components/UrlScanner";

function UrlScan() {
  const navigate = useNavigate();
  const userEmail = localStorage.getItem("userEmail") || "User";

  const handleLogout = () => {
    localStorage.removeItem("isLoggedIn");
    localStorage.removeItem("userEmail");
    navigate("/");
  };

  const navItems = [
    { name: "Dashboard", path: "/dashboard" },
    { name: "URL Scan", path: "/url-scan" },
    { name: "Email Scan", path: "/email-scan" },
    { name: "File Scan", path: "/file-scan" },
    { name: "AI Chat", path: "/ai-chat" },
    { name: "Reports", path: "/reports" },
  ];

  return (
    <div className="min-h-screen flex bg-orange-50">
      {/* Sidebar */}
      <aside className="w-64 bg-slate-900 text-white flex flex-col">
        <div className="p-6 text-xl font-bold border-b border-slate-700">
          🛡️ ThreatShield AI
        </div>
        <nav className="flex-1 p-4 space-y-2">
          {navItems.map((item) => (
            <Link
              key={item.path}
              to={item.path}
              className={`block px-4 py-2 rounded-lg hover:bg-slate-700 transition ${
                item.path === "/url-scan" ? "bg-slate-800" : ""
              }`}
            >
              {item.name}
            </Link>
          ))}
        </nav>
      </aside>

      {/* Main content area */}
      <div className="flex-1 flex flex-col">
        {/* Header */}
        <header className="bg-white shadow-sm px-6 py-4 flex justify-between items-center">
          <h2 className="text-lg font-semibold text-slate-800">URL Scanner</h2>
          <div className="flex items-center gap-4">
            <span className="text-sm text-slate-600">{userEmail}</span>
            <button
              onClick={handleLogout}
              className="text-sm bg-red-500 hover:bg-red-600 text-white px-3 py-1.5 rounded-lg transition"
            >
              Logout
            </button>
          </div>
        </header>

        {/* Content */}
        <main className="flex-1 p-6 overflow-y-auto">
          <div className="mb-6">
            <h1 className="text-2xl font-bold text-slate-800 mb-2">
              URL Threat Scan
            </h1>
            <p className="text-slate-600">
              Analyze URLs for phishing, suspicious redirects, insecure protocols, and other risk indicators.
            </p>
          </div>

          <UrlScanner />
        </main>
      </div>
    </div>
  );
}

export default UrlScan;