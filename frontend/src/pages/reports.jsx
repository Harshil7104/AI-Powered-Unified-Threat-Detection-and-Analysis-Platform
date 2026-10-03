import { useState, useEffect } from "react";
import { useNavigate, Link } from "react-router-dom";
import axios from "axios";
import { FileText, Search, Trash2, Filter, AlertTriangle, ShieldCheck, RefreshCw, X, ChevronRight, Eye, Loader2, Download } from "lucide-react";
import ThreatScoreGauge from "../components/ThreatScoreGauge";
import "../components/UrlScanner.css"; // reuse layouts

function Reports() {
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selectedReport, setSelectedReport] = useState(null);
  const [loadingDetails, setLoadingDetails] = useState(false);
  const [downloadingId, setDownloadingId] = useState(null);
  
  // Filters
  const [search, setSearch] = useState("");
  const [scanType, setScanType] = useState("");
  const [statusFilter, setStatusFilter] = useState("");

  const navigate = useNavigate();
  const userEmail = localStorage.getItem("userEmail") || "User";

  const handleDownloadPdf = async (reportId, scanType, e) => {
    if (e) e.stopPropagation();
    setDownloadingId(reportId);
    try {
      const response = await axios.get(`http://localhost:8000/reports/${reportId}/pdf`, {
        responseType: "blob"
      });
      const blob = new Blob([response.data], { type: "application/pdf" });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", `ThreatShield_Report_${scanType?.toUpperCase() || "SCAN"}_${reportId}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error("PDF download error:", err);
      alert("Failed to download PDF report. Please verify backend connection.");
    } finally {
      setDownloadingId(null);
    }
  };

  const fetchReports = async () => {
    setLoading(true);
    setError("");
    try {
      const params = {};
      if (scanType) params.scan_type = scanType;
      if (statusFilter) params.status = statusFilter;
      if (search.trim()) params.search = search.trim();
      
      const response = await axios.get("http://localhost:8000/reports/", { params });
      setReports(response.data);
    } catch (err) {
      console.error("Fetch reports error:", err);
      setError("Failed to fetch logs from reports database.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReports();
  }, [scanType, statusFilter]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    fetchReports();
  };

  const handleSelectReport = async (id) => {
    setLoadingDetails(true);
    try {
      const response = await axios.get(`http://localhost:8000/reports/${id}`);
      setSelectedReport(response.data);
    } catch (err) {
      console.error("Load report details error:", err);
      alert("Failed to load report details.");
    } finally {
      setLoadingDetails(false);
    }
  };

  const handleDeleteReport = async (id, e) => {
    if (e) e.stopPropagation();
    if (!confirm("Are you sure you want to delete this threat log?")) return;

    try {
      await axios.delete(`http://localhost:8000/reports/${id}`);
      setReports(prev => prev.filter(rep => rep.id !== id));
      if (selectedReport && selectedReport.id === id) {
        setSelectedReport(null);
      }
    } catch (err) {
      console.error("Delete report error:", err);
      alert("Failed to delete report.");
    }
  };

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
    <div className="min-h-screen flex bg-slate-955 text-white font-sans">
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
                  item.path === "/reports"
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
      <div className="flex-1 flex flex-col h-screen overflow-hidden bg-slate-950">
        {/* Header */}
        <header className="bg-slate-900/50 backdrop-blur-md border-b border-slate-800 px-6 py-4 flex justify-between items-center shrink-0">
          <h2 className="text-sm font-mono font-bold tracking-tight text-white flex items-center gap-2">
            <FileText size={16} className="text-cyan-400" />
            <span>THREAT_LOGS_DATABASE</span>
          </h2>
          <div className="flex items-center gap-4">
            <button
              onClick={fetchReports}
              className="p-1.5 rounded-lg border border-slate-800 hover:bg-slate-800 text-slate-400 hover:text-white transition"
              title="Refresh Logs"
            >
              <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
            </button>
            <span className="text-xs font-mono text-slate-400 bg-slate-950 border border-slate-800 px-3 py-1.5 rounded-lg">
              {userEmail}
            </span>
            <button
              onClick={handleLogout}
              className="text-xs bg-red-655 hover:bg-red-600 text-white font-mono px-3 py-1.5 rounded-lg transition"
            >
              LOGOUT
            </button>
          </div>
        </header>

        {/* Inner layout split */}
        <div className="flex-1 flex overflow-hidden">
          
          {/* List panel */}
          <div className="flex-1 flex flex-col p-6 overflow-y-auto space-y-4">
            
            {/* Filter and Search Bar */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shrink-0">
              <form onSubmit={handleSearchSubmit} className="flex flex-col md:flex-row gap-3">
                <div className="flex-1 relative">
                  <Search size={16} className="absolute left-3 top-3 text-slate-500" />
                  <input
                    type="text"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder="Search by target (URL, sender, filename)..."
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-10 pr-4 py-2.5 text-xs text-white focus:outline-none focus:border-cyan-400 font-mono transition"
                  />
                </div>
                
                <div className="flex gap-2">
                  <div className="relative">
                    <select
                      value={scanType}
                      onChange={(e) => setScanType(e.target.value)}
                      className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2.5 text-xs text-slate-350 focus:outline-none focus:border-cyan-400 font-mono transition"
                    >
                      <option value="">All Types</option>
                      <option value="url">URL</option>
                      <option value="email">Email</option>
                      <option value="file">File</option>
                    </select>
                  </div>

                  <div className="relative">
                    <select
                      value={statusFilter}
                      onChange={(e) => setStatusFilter(e.target.value)}
                      className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2.5 text-xs text-slate-350 focus:outline-none focus:border-cyan-400 font-mono transition"
                    >
                      <option value="">All Statuses</option>
                      <option value="Safe">Safe</option>
                      <option value="Suspicious">Suspicious</option>
                      <option value="High Risk">High Risk</option>
                    </select>
                  </div>
                  
                  <button
                    type="submit"
                    className="bg-slate-800 hover:bg-slate-705 border border-slate-700 text-xs px-4 py-2.5 rounded-lg font-mono transition text-slate-200"
                  >
                    Query
                  </button>
                </div>
              </form>
            </div>

            {/* List log container */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden flex-1">
              
              {loading ? (
                <div className="flex flex-col items-center justify-center py-20 text-slate-550 font-mono text-xs">
                  <Loader2 size={24} className="animate-spin text-cyan-400 mb-2" />
                  Running database query...
                </div>
              ) : reports.length === 0 ? (
                <div className="text-center py-20 text-slate-500 font-mono text-xs">
                  📁 No threat history matching parameters.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse text-xs font-mono">
                    <thead>
                      <tr className="bg-slate-950 border-b border-slate-800 text-slate-400 uppercase text-[9px] tracking-wider">
                        <th className="py-3.5 px-4">Type</th>
                        <th className="py-3.5 px-4">Target Payload</th>
                        <th className="py-3.5 px-4">Risk Index</th>
                        <th className="py-3.5 px-4">Status</th>
                        <th className="py-3.5 px-4">Timestamp</th>
                        <th className="py-3.5 px-4 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/40">
                      {reports.map((report) => (
                        <tr
                          key={report.id}
                          onClick={() => handleSelectReport(report.id)}
                          className={`hover:bg-slate-850/60 cursor-pointer transition duration-150 ${
                            selectedReport && selectedReport.id === report.id ? "bg-slate-800/50" : ""
                          }`}
                        >
                          <td className="py-3.5 px-4 font-bold text-slate-400">
                            {report.scan_type.toUpperCase()}
                          </td>
                          <td className="py-3.5 px-4 max-w-xs truncate font-sans font-medium text-slate-200">
                            {report.target}
                          </td>
                          <td className="py-3.5 px-4 font-bold text-slate-300">
                            {report.risk_score}%
                          </td>
                          <td className="py-3.5 px-4">
                            <span className={`px-2 py-0.5 rounded text-[9px] border ${
                              report.status === "Safe" ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400" :
                              report.status === "Suspicious" ? "bg-yellow-500/10 border-yellow-500/20 text-yellow-400" :
                              "bg-red-500/10 border-red-500/20 text-red-400"
                            }`}>
                              {report.status.toUpperCase()}
                            </span>
                          </td>
                          <td className="py-3.5 px-4 text-slate-500 text-[10px]">
                            {report.created_at}
                          </td>
                          <td className="py-3.5 px-4 text-right">
                            <div className="flex justify-end gap-1.5">
                              <button
                                onClick={(e) => handleDownloadPdf(report.id, report.scan_type, e)}
                                className="p-1 text-slate-400 hover:text-emerald-400 transition"
                                title="Download PDF Report"
                              >
                                {downloadingId === report.id ? (
                                  <Loader2 size={14} className="animate-spin text-emerald-400" />
                                ) : (
                                  <Download size={14} />
                                )}
                              </button>
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleSelectReport(report.id);
                                }}
                                className="p-1 text-slate-400 hover:text-cyan-400 transition"
                                title="Inspect Details"
                              >
                                <Eye size={14} />
                              </button>
                              <button
                                onClick={(e) => handleDeleteReport(report.id, e)}
                                className="p-1 text-slate-400 hover:text-red-400 transition"
                                title="Delete Log"
                              >
                                <Trash2 size={14} />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>

          {/* Details Inspector Panel */}
          {selectedReport && (
            <div className="w-[450px] bg-slate-900 border-l border-slate-800 flex flex-col h-full overflow-hidden shrink-0 animate-slideLeft">
              {/* Details Top bar */}
              <div className="bg-slate-950 px-4 py-3 border-b border-slate-800 flex justify-between items-center shrink-0">
                <span className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-400 flex items-center gap-1.5">
                  <span>🔬</span>
                  <span>Inspect Threat Detail</span>
                </span>
                <button
                  onClick={() => setSelectedReport(null)}
                  className="text-slate-450 hover:text-white p-0.5 rounded transition"
                >
                  <X size={16} />
                </button>
              </div>

              {/* Details Content */}
              <div className="flex-1 overflow-y-auto p-5 space-y-5">
                
                {/* Score section */}
                <div className="flex items-center justify-center bg-slate-950 p-4 rounded-xl border border-slate-850">
                  <ThreatScoreGauge score={selectedReport.risk_score} status={selectedReport.status} />
                </div>

                {/* Metadata */}
                <div className="bg-slate-950/60 p-4 rounded-xl border border-slate-850 space-y-2.5 font-mono text-[11px] text-slate-400">
                  <div className="flex justify-between">
                    <span>REPORT_ID:</span>
                    <span className="text-slate-200">{selectedReport.id}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>SCAN_TYPE:</span>
                    <span className="text-slate-200 uppercase">{selectedReport.scan_type}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>TIMESTAMP:</span>
                    <span className="text-slate-200">{selectedReport.created_at}</span>
                  </div>
                  <div className="pt-2 border-t border-slate-850">
                    <p className="text-[10px] text-slate-550 uppercase mb-1">TARGET_VALUE</p>
                    <p className="text-slate-200 break-all leading-normal font-sans font-medium">{selectedReport.target}</p>
                  </div>
                </div>

                {/* Details Json Viewer */}
                <div className="space-y-2">
                  <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-1">
                    <ChevronRight size={14} className="text-cyan-400" />
                    <span>Scan Payload Manifest</span>
                  </h4>
                  
                  <div className="bg-slate-950 p-4 rounded-xl border border-slate-850 overflow-x-auto text-[10px] font-mono text-cyan-400 max-h-[250px] overflow-y-auto">
                    <pre>{JSON.stringify(selectedReport.details, null, 2)}</pre>
                  </div>
                </div>
              </div>
              
              <div className="p-4 border-t border-slate-800 bg-slate-950 shrink-0 space-y-2">
                <button
                  onClick={(e) => handleDownloadPdf(selectedReport.id, selectedReport.scan_type, e)}
                  className="w-full bg-emerald-950/20 hover:bg-emerald-900/30 border border-emerald-500/30 text-emerald-400 font-semibold py-2 rounded-lg transition duration-200 font-mono text-xs uppercase tracking-wider flex items-center justify-center gap-1.5"
                >
                  {downloadingId === selectedReport.id ? (
                    <Loader2 size={13} className="animate-spin text-emerald-400" />
                  ) : (
                    <Download size={13} />
                  )}
                  Download PDF Report
                </button>
                <button
                  onClick={() => navigate("/ai-chat", { state: { scanContext: selectedReport } })}
                  className="w-full bg-cyan-950/20 hover:bg-cyan-900/30 border border-cyan-500/30 text-cyan-400 font-semibold py-2 rounded-lg transition duration-200 font-mono text-xs uppercase tracking-wider flex items-center justify-center gap-1.5"
                >
                  <span>🤖</span>
                  Ask AI to Explain Threat
                </button>
                <button
                  onClick={() => handleDeleteReport(selectedReport.id)}
                  className="w-full bg-red-950/20 hover:bg-red-900/30 border border-red-500/20 text-red-400 font-semibold py-2 rounded-lg transition duration-200 font-mono text-xs uppercase tracking-wider flex items-center justify-center gap-1.5"
                >
                  <Trash2 size={12} />
                  Purge Log Record
                </button>
              </div>
            </div>
          )}

        </div>
      </div>
    </div>
  );
}

export default Reports;