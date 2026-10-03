import { useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";

function Login() {
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [successMsg, setSuccessMsg] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSuccessMsg("");

    if (!email || !password) {
      setError("Please fill in all fields.");
      return;
    }

    if (isRegister && password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    if (isRegister && password.length < 6) {
      setError("Password must be at least 6 characters long.");
      return;
    }

    setLoading(true);

    const endpoint = isRegister
      ? "http://localhost:8000/auth/register"
      : "http://localhost:8000/auth/login";

    try {
      const response = await axios.post(endpoint, { email, password });
      
      setSuccessMsg(isRegister ? "Registration successful! Logging in..." : "Login successful!");
      
      setTimeout(() => {
        localStorage.setItem("isLoggedIn", "true");
        localStorage.setItem("userEmail", response.data.email);
        if (response.data.token) {
          localStorage.setItem("token", response.data.token);
        }
        setLoading(false);
        navigate("/dashboard");
      }, 800);
    } catch (err) {
      console.error("Auth error:", err);
      if (err.response && err.response.data && err.response.data.detail) {
        setError(err.response.data.detail);
      } else {
        setError("Failed to connect to the authentication server. Ensure the backend is running.");
      }
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950 px-4 relative overflow-hidden">
      {/* Decorative cyber grid or lighting */}
      <div className="absolute top-[-20%] left-[-20%] w-[60%] h-[60%] rounded-full bg-cyan-500/10 blur-[150px]" />
      <div className="absolute bottom-[-20%] right-[-20%] w-[60%] h-[60%] rounded-full bg-blue-500/10 blur-[150px]" />

      <form
        onSubmit={handleSubmit}
        className="backdrop-blur-md bg-slate-900/80 border border-slate-800 shadow-2xl rounded-2xl p-8 w-full max-w-md relative z-10 transition-all duration-300"
      >
        <div className="flex flex-col items-center mb-6">
          <div className="text-4xl mb-2">🛡️</div>
          <h1 className="text-2xl font-black tracking-tight text-white">
            THREATSHIELD <span className="text-cyan-400 font-bold">AI</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-mono uppercase tracking-widest">
            Unified Threat Detection
          </p>
        </div>

        <h2 className="text-lg font-medium text-slate-200 mb-4 text-center">
          {isRegister ? "Create Analyst Account" : "Access Threat Panel"}
        </h2>

        {error && (
          <div className="bg-red-500/10 border border-red-500/20 text-red-400 text-sm py-2 px-3 rounded-lg mb-4 text-center font-mono">
            {error}
          </div>
        )}

        {successMsg && (
          <div className="bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-sm py-2 px-3 rounded-lg mb-4 text-center font-mono">
            {successMsg}
          </div>
        )}

        <div className="mb-4">
          <label className="block text-xs font-mono uppercase tracking-wider text-slate-400 mb-1.5">
            Security Email
          </label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full bg-slate-950/80 border border-slate-800 text-white rounded-lg px-4 py-2.5 focus:outline-none focus:border-cyan-400 transition font-mono"
            placeholder="analyst@domain.com"
          />
        </div>

        <div className="mb-4">
          <label className="block text-xs font-mono uppercase tracking-wider text-slate-400 mb-1.5">
            Key Passphrase
          </label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full bg-slate-950/80 border border-slate-800 text-white rounded-lg px-4 py-2.5 focus:outline-none focus:border-cyan-400 transition font-mono"
            placeholder="••••••••"
          />
        </div>

        {isRegister && (
          <div className="mb-6 animate-fadeIn">
            <label className="block text-xs font-mono uppercase tracking-wider text-slate-400 mb-1.5">
              Confirm Passphrase
            </label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="w-full bg-slate-950/80 border border-slate-800 text-white rounded-lg px-4 py-2.5 focus:outline-none focus:border-cyan-400 transition font-mono"
              placeholder="••••••••"
            />
          </div>
        )}

        <button
          type="submit"
          disabled={loading}
          className="w-full bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 hover:text-black font-semibold py-3 rounded-lg transition duration-200 disabled:opacity-50 font-mono uppercase tracking-wider shadow-lg shadow-cyan-500/20 mt-2"
        >
          {loading ? (
            <span className="flex items-center justify-center gap-2">
              <span className="w-4 h-4 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
              Verifying...
            </span>
          ) : isRegister ? (
            "Initialize Account"
          ) : (
            "Authenticate Credentials"
          )}
        </button>

        <div className="mt-6 text-center">
          <button
            type="button"
            onClick={() => {
              setIsRegister(!isRegister);
              setError("");
              setSuccessMsg("");
            }}
            className="text-xs text-cyan-400 hover:text-cyan-300 transition font-mono underline"
          >
            {isRegister ? "Already registered? Login here" : "Need credentials? Register here"}
          </button>
        </div>
      </form>
    </div>
  );
}

export default Login;