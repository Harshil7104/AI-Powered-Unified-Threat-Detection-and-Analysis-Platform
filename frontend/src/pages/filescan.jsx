import { useState, useRef } from "react";
import { useNavigate, Link } from "react-router-dom";
import axios from "axios";
import { FileUp, File, ShieldAlert, ShieldCheck, AlertTriangle, Loader2, CheckCircle2, XCircle, Code, Server } from "lucide-react";
import ThreatScoreGauge from "../components/ThreatScoreGauge";
import "../components/UrlScanner.css"; // Reuse card layouts

function FileScan() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const fileInputRef = useRef(null);
  const navigate = useNavigate();
  const userEmail = localStorage.getItem("userEmail") || "User";

  const handleLogout = () => {
    localStorage.removeItem("isLoggedIn");
    localStorage.removeItem("userEmail");
    navigate("/");
  };

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setSelectedFile(e.dataTransfer.files[0]);
      setResult(null);
      setError(null);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
      setResult(null);
      setError(null);
    }
  };

  const executeScan = async () => {
    if (!selectedFile) return;
    setLoading(true);
    setError(null);
    setResult(null);

    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
      const response = await axios.post("http://localhost:8000/file/scan", formData, {
        headers: {
          "Content-Type": "multipart/form-data",
        },
      });
      setResult(response.data);
    } catch (err) {
      console.error("File scan error:", err);
      if (err.response && err.response.data && err.response.data.detail) {
        setError(err.response.data.detail);
      } else {
        setError("Failed to complete file scanner telemetry. Check server connection.");
      }
    } finally {
      setLoading(false);
    }
  };

  const triggerFileInput = () => {
    fileInputRef.current.click();
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
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
                  item.path === "/file-scan"
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
            <FileUp size={16} className="text-cyan-400" />
            <span>FILE_INTELLIGENCE_SCANNER</span>
          </h2>
          <div className="flex items-center gap-4">
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

        {/* Content Body */}
        <main className="flex-1 p-6 space-y-6 max-w-6xl w-full mx-auto">
          <div>
            <h1 className="text-2xl font-black text-white font-mono">
              Static File Scanning & Analysis
            </h1>
            <p className="text-slate-400 text-sm mt-1">
              Upload binaries, scripts, or active documents to calculate hashes (MD5, SHA-256) and query global Threat Intelligence feeds.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
            {/* Input Drop Column */}
            <div className="lg:col-span-3 space-y-5">
              <div
                onDragEnter={handleDrag}
                onDragOver={handleDrag}
                onDragLeave={handleDrag}
                onDrop={handleDrop}
                onClick={triggerFileInput}
                className={`bg-slate-900/40 border-2 border-dashed rounded-2xl p-10 text-center cursor-pointer transition-all duration-300 flex flex-col items-center justify-center relative min-h-[300px] ${
                  dragActive
                    ? "border-cyan-400 bg-cyan-500/5"
                    : "border-slate-800 hover:border-slate-700 hover:bg-slate-900/60"
                }`}
              >
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleFileChange}
                  className="hidden"
                />

                <FileUp size={48} className={`text-slate-500 mb-4 transition ${dragActive ? "text-cyan-400 scale-110" : ""}`} />
                
                <h3 className="font-bold text-white text-base font-mono">
                  Drag and drop file here
                </h3>
                <p className="text-slate-400 text-xs mt-1 max-w-[280px] mx-auto leading-relaxed">
                  Support any local file, calculated hashes are queried directly on the Threatshield node.
                </p>
                <button
                  type="button"
                  className="mt-5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs px-4 py-2 rounded-lg font-mono transition"
                >
                  Browse Local Files
                </button>
              </div>

              {selectedFile && (
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 animate-fadeIn">
                  <div className="flex items-center gap-3 border-b border-slate-800 pb-3">
                    <File size={28} className="text-cyan-400 shrink-0" />
                    <div className="truncate">
                      <p className="text-xs font-mono font-bold text-slate-200 truncate">{selectedFile.name}</p>
                      <p className="text-[10px] text-slate-500 font-mono mt-0.5">{formatBytes(selectedFile.size)}</p>
                    </div>
                  </div>

                  <button
                    onClick={executeScan}
                    disabled={loading}
                    className="w-full bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 hover:text-black font-semibold py-2.5 rounded-lg transition duration-200 disabled:opacity-40 font-mono text-sm uppercase tracking-wider shadow-lg shadow-cyan-500/10"
                  >
                    {loading ? (
                      <span className="flex items-center justify-center gap-2">
                        <Loader2 size={16} className="animate-spin" />
                        Calculating Digests...
                      </span>
                    ) : (
                      "Start File Diagnostic"
                    )}
                  </button>
                </div>
              )}
            </div>

            {/* Output Diagnostics Column */}
            <div className="lg:col-span-2 space-y-5">
              {error && (
                <div className="bg-red-500/10 border border-red-500/20 text-red-400 text-sm p-4 rounded-xl font-mono flex items-start gap-3">
                  <AlertTriangle size={18} className="mt-0.5 shrink-0" />
                  <div>{error}</div>
                </div>
              )}

              {loading && !result && (
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 flex flex-col items-center justify-center text-slate-500 font-mono text-sm">
                  <Loader2 size={32} className="animate-spin text-cyan-400 mb-3" />
                  <p>Hashing file payload...</p>
                  <p className="text-[10px] text-slate-650 mt-1">Cross referencing VirusTotal database</p>
                </div>
              )}

              {!loading && !result && !error && (
                <div className="bg-slate-900/60 border border-slate-850 border-dashed rounded-xl p-12 text-center text-slate-500 font-mono text-sm flex flex-col items-center justify-center min-h-[300px]">
                  <Server size={40} className="text-slate-700 mb-3" />
                  <p>Awaiting Diagnostics</p>
                  <p className="text-[10px] text-slate-600 mt-1.5 max-w-[240px]">
                    Drag a script, executable, or document onto the panel to execute structural and reputation hashes.
                  </p>
                </div>
              )}

              {result && (
                <div className="space-y-5 animate-fadeIn">
                  {/* Gauge */}
                  <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex items-center justify-center">
                    <ThreatScoreGauge score={result.risk_score} status={result.status} />
                  </div>

                  {/* Hashes Info */}
                  <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3 font-mono text-xs">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-slate-355 border-b border-slate-800 pb-2">
                      Checksum Hash Sums
                    </h3>
                    <div>
                      <p className="text-[9px] text-slate-500 uppercase">MD5 DIGEST</p>
                      <p className="bg-slate-950 p-2 rounded border border-slate-850 text-slate-300 select-all break-all mt-1">{result.md5}</p>
                    </div>
                    <div className="mt-2">
                      <p className="text-[9px] text-slate-500 uppercase">SHA-256 DIGEST</p>
                      <p className="bg-slate-950 p-2 rounded border border-slate-850 text-slate-300 select-all break-all mt-1">{result.sha256}</p>
                    </div>
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

                  {/* VirusTotal Info */}
                  {result.virustotal && result.virustotal.status === "success" && (
                    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
                      <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 border-b border-slate-800 pb-2 flex items-center gap-2">
                        <span>🔍</span>
                        <span>VirusTotal Detections</span>
                      </h3>
                      <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                        <div className="bg-slate-950 p-2.5 rounded border border-slate-850">
                          <p className="text-[9px] text-slate-500 uppercase">MALICIOUS</p>
                          <p className="text-base font-black text-red-400 mt-0.5">{result.virustotal.malicious}</p>
                        </div>
                        <div className="bg-slate-950 p-2.5 rounded border border-slate-850">
                          <p className="text-[9px] text-slate-500 uppercase">SUSPICIOUS</p>
                          <p className="text-base font-black text-yellow-400 mt-0.5">{result.virustotal.suspicious}</p>
                        </div>
                        <div className="bg-slate-950 p-2.5 rounded border border-slate-850">
                          <p className="text-[9px] text-slate-500 uppercase">HARMLESS</p>
                          <p className="text-base font-black text-emerald-400 mt-0.5">{result.virustotal.harmless}</p>
                        </div>
                        <div className="bg-slate-950 p-2.5 rounded border border-slate-850">
                          <p className="text-[9px] text-slate-500 uppercase">REPUTATION</p>
                          <p className="text-base font-black text-blue-400 mt-0.5">{result.virustotal.reputation}</p>
                        </div>
                      </div>
                      <div className="bg-slate-955 p-2 rounded text-[10px] text-slate-500 font-mono text-center">
                        Detected format: {result.virustotal.type_description}
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

export default FileScan;