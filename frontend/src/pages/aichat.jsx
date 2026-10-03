import { useState, useRef, useEffect } from "react";
import { useNavigate, useLocation, Link } from "react-router-dom";
import axios from "axios";
import { MessageSquare, Send, Terminal, Cpu, Loader2, Bot, User, Trash2, X, Sparkles } from "lucide-react";
import "../components/UrlScanner.css"; // reuse layouts

function AiChat() {
  const navigate = useNavigate();
  const location = useLocation();
  const initialScanContext = location.state?.scanContext || null;
  const [scanContext, setScanContext] = useState(initialScanContext);

  const [messages, setMessages] = useState(() => {
    if (initialScanContext) {
      const target = initialScanContext.target || initialScanContext.url || initialScanContext.filename || "Active Entity";
      const score = initialScanContext.risk_score !== undefined ? initialScanContext.risk_score : "N/A";
      const status = initialScanContext.status || "Assessed";
      return [
        {
          role: "assistant",
          content: `🛡️ ThreatShield AI Copilot ready with active context for: **${target}**.\n\nAssessed Threat Level: **${score}/100 (${status})**.\n\nAsk me to analyze the security indicators, explain the findings, or provide immediate remediation steps.`
        }
      ];
    }
    return [
      {
        role: "assistant",
        content: "System Initialized. I am ThreatShield AI. Ask me security analysis questions regarding suspicious domains, indicators of compromise, file scanners, or phishing patterns."
      }
    ];
  });

  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [source, setSource] = useState(null);
  const messagesEndRef = useRef(null);
  const userEmail = localStorage.getItem("userEmail") || "User";

  const handleLogout = () => {
    localStorage.removeItem("isLoggedIn");
    localStorage.removeItem("userEmail");
    localStorage.removeItem("token");
    navigate("/");
  };

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const sendQuery = async (queryText) => {
    if (!queryText.trim() || loading) return;

    const userPrompt = queryText.trim();
    setInput("");

    const updatedMessages = [...messages, { role: "user", content: userPrompt }];
    setMessages(updatedMessages);
    setLoading(true);

    try {
      const historyPayload = updatedMessages.slice(1, -1).map(msg => ({
        role: msg.role,
        content: msg.content
      }));

      const payload = {
        message: userPrompt,
        history: historyPayload
      };
      if (scanContext) {
        payload.scan_context = scanContext;
      }

      const response = await axios.post("http://localhost:8000/chat/", payload);

      setMessages(prev => [...prev, {
        role: "assistant",
        content: response.data.response
      }]);
      setSource(response.data.source);
    } catch (err) {
      console.error("AI Chat error:", err);
      setMessages(prev => [...prev, {
        role: "assistant",
        content: "Error: Failed to connect to security assistant. Please verify uvicorn backend server is online."
      }]);
      setSource("system-error");
    } finally {
      setLoading(false);
    }
  };

  const handleSend = (e) => {
    e.preventDefault();
    sendQuery(input);
  };

  const clearChat = () => {
    setMessages([
      {
        role: "assistant",
        content: "System reset. ThreatShield AI console ready. State query parameters cleared."
      }
    ]);
    setSource(null);
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
                className={`flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm font-mono transition-all duration-200 ${item.path === "/ai-chat"
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
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Header */}
        <header className="bg-slate-900/50 backdrop-blur-md border-b border-slate-800 px-6 py-4 flex justify-between items-center shrink-0">
          <h2 className="text-sm font-mono font-bold tracking-tight text-white flex items-center gap-2">
            <MessageSquare size={16} className="text-cyan-400" />
            <span>AI_SECURITY_COPILOT</span>
          </h2>

          <div className="flex items-center gap-4">
            {source && (
              <span className="text-[10px] font-mono border border-slate-800 bg-slate-950 px-2 py-0.5 rounded text-cyan-400 flex items-center gap-1">
                <Cpu size={10} />
                ENG: {source.toUpperCase()}
              </span>
            )}
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

        {/* Chat Console Area */}
        <div className="flex-1 flex flex-col overflow-hidden bg-slate-950 p-6">
          <div className="flex-1 bg-slate-900 border border-slate-800 rounded-xl flex flex-col overflow-hidden relative">

            {/* Terminal Top bar */}
            <div className="bg-slate-950 px-4 py-2 border-b border-slate-800 flex justify-between items-center text-xs font-mono text-slate-400 shrink-0">
              <span className="flex items-center gap-1.5 text-cyan-400">
                <Terminal size={14} />
                threatshield-analyst-terminal
              </span>
              <button
                onClick={clearChat}
                className="text-[10px] text-slate-500 hover:text-red-400 flex items-center gap-1 transition"
                title="Clear Logs"
              >
                <Trash2 size={12} />
                RESET_CONSOLE
              </button>
            </div>

            {/* Scan Context Active Banner */}
            {scanContext && (
              <div className="bg-cyan-950/30 border-b border-cyan-800/40 px-4 py-2.5 flex items-center justify-between shrink-0 font-mono text-xs text-cyan-300">
                <div className="flex items-center gap-2 truncate pr-4">
                  <Sparkles size={14} className="text-cyan-400 shrink-0" />
                  <span className="font-bold text-white uppercase text-[10px] bg-cyan-900/50 px-1.5 py-0.5 rounded border border-cyan-700/50">
                    {scanContext.scan_type || "SCAN"} CONTEXT
                  </span>
                  <span className="truncate text-slate-200">
                    {scanContext.target || scanContext.url || scanContext.filename}
                  </span>
                  <span className="text-[10px] text-cyan-400 shrink-0">
                    (Score: {scanContext.risk_score}% - {scanContext.status})
                  </span>
                </div>
                <button
                  onClick={() => setScanContext(null)}
                  className="text-slate-400 hover:text-white p-1 rounded transition shrink-0"
                  title="Dismiss Context"
                >
                  <X size={14} />
                </button>
              </div>
            )}

            {/* Chat Messages */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4 font-mono text-xs leading-relaxed">
              {messages.map((msg, index) => (
                <div
                  key={index}
                  className={`flex gap-3 max-w-3xl p-3 rounded-lg ${msg.role === "assistant"
                      ? "bg-slate-950/40 border border-slate-850/60 text-slate-200"
                      : "bg-slate-800/30 border border-slate-800 text-cyan-400 self-end ml-auto"
                    }`}
                >
                  <div className="shrink-0 mt-0.5">
                    {msg.role === "assistant" ? (
                      <Bot size={16} className="text-cyan-400" />
                    ) : (
                      <User size={16} className="text-blue-400" />
                    )}
                  </div>
                  <div className="flex-1 whitespace-pre-wrap font-sans text-sm">
                    {msg.content}
                  </div>
                </div>
              ))}

              {loading && (
                <div className="flex gap-3 bg-slate-950/40 border border-slate-850/60 p-3 rounded-lg max-w-3xl text-slate-500">
                  <Bot size={16} className="text-slate-655 shrink-0 mt-0.5" />
                  <div className="flex items-center gap-2 font-mono text-xs">
                    <Loader2 size={14} className="animate-spin text-cyan-400" />
                    Computing threat query...
                  </div>
                </div>
              )}

              <div ref={messagesEndRef} />
            </div>

            {/* Quick Context Prompt Chips */}
            {scanContext && (
              <div className="px-4 py-2 bg-slate-950/40 border-t border-slate-850 flex gap-2 overflow-x-auto text-[11px] font-mono shrink-0">
                <button
                  type="button"
                  onClick={() => sendQuery("Explain the main threat indicators found in this scan.")}
                  className="bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-cyan-500/40 text-slate-300 hover:text-cyan-300 px-3 py-1 rounded-full whitespace-nowrap transition"
                >
                  🔍 Explain Threat Indicators
                </button>
                <button
                  type="button"
                  onClick={() => sendQuery("What immediate remediation and defense steps should I take?")}
                  className="bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-cyan-500/40 text-slate-300 hover:text-cyan-300 px-3 py-1 rounded-full whitespace-nowrap transition"
                >
                  🛡️ Recommended Remediation
                </button>
                <button
                  type="button"
                  onClick={() => sendQuery("Is it safe for internal network users to access this target?")}
                  className="bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-cyan-500/40 text-slate-300 hover:text-cyan-300 px-3 py-1 rounded-full whitespace-nowrap transition"
                >
                  ⚠️ Safe to Whitelist?
                </button>
              </div>
            )}

            {/* Input Form */}
            <form onSubmit={handleSend} className="p-4 border-t border-slate-800 bg-slate-950/60 shrink-0">
              <div className="flex gap-3">
                <input
                  type="text"
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  placeholder={scanContext ? `Ask about this ${scanContext.scan_type || 'threat'} scan...` : "Ask a security question (e.g., 'What are email DKIM checks?')..."}
                  className="flex-1 bg-slate-950 border border-slate-800 text-white rounded-lg px-4 py-3 text-xs focus:outline-none focus:border-cyan-400 font-mono transition"
                  disabled={loading}
                />
                <button
                  type="submit"
                  disabled={loading || !input.trim()}
                  className="bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 hover:text-black p-3 rounded-lg transition duration-200 disabled:opacity-40 shrink-0"
                >
                  <Send size={16} />
                </button>
              </div>
            </form>

          </div>
        </div>
      </div>
    </div>
  );
}

export default AiChat;