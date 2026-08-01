import { useNavigate, Link } from "react-router-dom";

function Dashboard() {
  const navigate = useNavigate();
  const userEmail = localStorage.getItem("userEmail") || "User";

  const handleLogout = () => {
    localStorage.removeItem("isLoggedIn");
    localStorage.removeItem("userEmail");
    navigate("/");
  };

  const navItems = [
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
              className="block px-4 py-2 rounded-lg hover:bg-slate-700 transition"
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
          <h2 className="text-lg font-semibold text-slate-800">Dashboard</h2>
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
        <main className="flex-1 p-6">
          <h1 className="text-2xl font-bold text-slate-800 mb-2">
            Welcome back!
          </h1>
          <p className="text-slate-600 mb-6">
            Select a scanner from the sidebar to get started.
          </p>

          {/* Placeholder stat cards */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="bg-white rounded-xl shadow p-5">
              <p className="text-slate-500 text-sm">Total Scans</p>
              <p className="text-2xl font-bold text-slate-800">0</p>
            </div>
            <div className="bg-white rounded-xl shadow p-5">
              <p className="text-slate-500 text-sm">Threats Detected</p>
              <p className="text-2xl font-bold text-slate-800">0</p>
            </div>
            <div className="bg-white rounded-xl shadow p-5">
              <p className="text-slate-500 text-sm">Reports Generated</p>
              <p className="text-2xl font-bold text-slate-800">0</p>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}

export default Dashboard;