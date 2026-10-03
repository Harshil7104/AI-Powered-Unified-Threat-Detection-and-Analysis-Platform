# pyrefly: ignore [missing-import]
from fastapi import APIRouter
# pyrefly: ignore [missing-import]
from pydantic import BaseModel
import os
import json
from typing import Optional, List, Dict, Any
# pyrefly: ignore [missing-import]
import ollama
# pyrefly: ignore [missing-import]
from dotenv import load_dotenv
# pyrefly: ignore [missing-import]  
from pathlib import Path

# Load env variables
env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")

router = APIRouter(prefix="/chat", tags=["AI Chat Assistant"])

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    message: str
    history: List[ChatMessage] = []
    scan_context: Optional[Dict[str, Any]] = None

SECURITY_QA = {
    "phishing": "Phishing is a social engineering attack where cybercriminals impersonate legitimate organizations to steal sensitive data like login credentials or financial information. Safeguards include inspecting the sender domain closely, looking out for urgency keywords, and never clicking links directly from unsolicited emails.",
    "malware": "Malware (malicious software) is any code written to harm, exploit, or gain unauthorized access to systems. Types include viruses, ransomware, spyware, Trojans, and adware. Prevent infections by updating all software regularly and deploying active antivirus monitoring.",
    "ransomware": "Ransomware encrypts a victim's files, with the attacker demanding a ransom to restore access. Protect your systems by maintaining regular offline backups, conducting user awareness training, and disabling macros from untrusted email attachments.",
    "whois": "WHOIS is a public database containing domain registration details, such as owner contact information, registrar name, and registration dates. It is highly useful in tracking down the legitimacy and age of suspicious domains.",
    "ssl": "SSL/TLS certificates encrypt data between the browser and server. When scanning, verify the issuer (e.g., Let's Encrypt, DigiCert) and check the expiry date. Insecure sites (no HTTPS or expired certificates) are prime hosts for credentials harvesting.",
    "virustotal": "VirusTotal is a threat intelligence tool that aggregates scanners and blacklisting engines to inspect files, URLs, domains, and IP addresses. Multiple detections from VirusTotal strongly indicate a threat.",
    "hello": "Hello! I am ThreatShield AI, your unified threat detection and security advisor. Ask me anything about URLs, files, emails, or general cybersecurity principles!",
    "hi": "Hi there! I am ThreatShield AI. How can I assist you with threat intelligence or cybersecurity analysis today?",
}

def build_scan_context_string(scan_context: Dict[str, Any]) -> str:
    target = scan_context.get("target") or scan_context.get("url") or scan_context.get("filename") or scan_context.get("sender") or "Target Object"
    scan_type = scan_context.get("scan_type", "security scan")
    risk_score = scan_context.get("risk_score", "N/A")
    status = scan_context.get("status", "Unknown")
    
    findings = []
    checks = scan_context.get("checks", [])
    for c in checks:
        passed = c.get("passed", True)
        name = c.get("name", "Check")
        msg = c.get("message", "")
        sev = c.get("severity", "info")
        mark = "[PASS]" if passed else ("[DANGER]" if sev == "danger" else "[WARNING]")
        findings.append(f"{mark} {name}: {msg}")

    findings_text = "\n".join(findings) if findings else "No specific check breakdown available."

    return (
        f"\n\n--- [ACTIVE THREAT SCAN CONTEXT] ---\n"
        f"Scan Vector: {scan_type.upper()}\n"
        f"Target: {target}\n"
        f"Risk Score: {risk_score}/100 (Status: {status})\n"
        f"Findings & Indicators:\n{findings_text}\n"
        f"-------------------------------------\n"
    )

def fallback_security_assistant(user_message: str, scan_context: Optional[Dict[str, Any]] = None) -> str:
    msg = user_message.lower()
    
    # If scan context was provided, give a smart context-aware breakdown
    if scan_context:
        target = scan_context.get("target") or scan_context.get("url") or scan_context.get("filename") or "Target Item"
        score = scan_context.get("risk_score", 0)
        status = scan_context.get("status", "Unknown")
        checks = scan_context.get("checks", [])
        
        flagged = [c for c in checks if not c.get("passed", True)]
        
        advice = []
        if status == "High Risk" or score >= 60:
            advice.append("[CRITICAL] Immediate Action: Block and isolate this target. Do not open, execute, or click any links.")
        elif status == "Suspicious" or score >= 25:
            advice.append("[WARNING] Precautionary Action: Exercise caution. Verify through out-of-band channels before proceeding.")
        else:
            advice.append("[CLEAN] Clean Status: No critical threat indicators were identified. Follow standard hygiene.")
            
        flagged_summary = "\n".join([f"• **{f.get('name')}:** {f.get('message')}" for f in flagged]) if flagged else "• No active flags triggered."
        
        return (
            f"[ThreatShield AI Assistant (Rule-Based Fallback)]\n\n"
            f"### Scan Analysis for `{target}`\n"
            f"**Assessed Risk:** {score}/100 — **{status}**\n\n"
            f"**Key Findings:**\n{flagged_summary}\n\n"
            f"**Recommended Mitigation:**\n" + "\n".join(advice) + "\n\n"
            f"*(Note: Ollama LLM is currently unconfigured or offline. Running in deterministic heuristic mode)*"
        )
        
    for key, response in SECURITY_QA.items():
        if key in msg:
            return f"[ThreatShield AI] {response}\n\n*(Note: Ollama LLM is currently offline. Operating in simulation mode)*"
            
    return (
        f"[ThreatShield AI] I received your query: \"{user_message}\".\n\n"
        "Since the local Ollama LLM server is currently offline or unreachable, I am operating "
        "in simulation mode. You can ask me about:\n"
        "• **Phishing** indicators and email header analysis.\n"
        "• **Malware** execution and entropy inspection.\n"
        "• **WHOIS** age calculation and **SSL** validity.\n"
        "• **VirusTotal** and AlienVault threat intelligence."
    )

@router.post("/")
def chat_with_assistant(payload: ChatRequest):
    context_str = ""
    if payload.scan_context:
        context_str = build_scan_context_string(payload.scan_context)
        
    try:
        system_content = (
            "You are ThreatShield AI, a professional cyber threat intelligence and forensics assistant. "
            "You help security analysts inspect URLs, emails, and files. "
            "Be concise, technical, precise, and action-oriented. Provide clear mitigation steps."
        )
        if context_str:
            system_content += f"\nHere is the current scan context the user is inquiring about:{context_str}"
            
        messages = [
            {"role": "system", "content": system_content}
        ]
        
        for item in payload.history:
            messages.append({
                "role": item.role,
                "content": item.content
            })
            
        user_content = payload.message
        if context_str and not payload.history:
            user_content = f"{user_content}\n\n(Refer to the active scan context provided above)"
            
        messages.append({
            "role": "user",
            "content": user_content
        })
        
        client = ollama.Client(host=OLLAMA_URL)
        
        # Preferred models list: user's installed model first, then standard variants, including Qwen
        preferred_models = [
            'llama3.1:8b', 'llama3.1', 'llama3', 'llama3.2:3b', 'llama3.2',
            'qwen2.5:7b', 'qwen2.5', 'qwen2', 'qwen'
        ]
        
        for model_name in preferred_models:
            try:
                response = client.chat(model=model_name, messages=messages)
                return {"response": response['message']['content'], "source": f"ollama ({model_name})"}
            except Exception:
                continue
        
        # If none of the preferred models work, try any available model
        try:
            models_list = client.list()
            if isinstance(models_list, dict):
                available = [m.get('name', '') for m in models_list.get('models', [])]
            else:
                available = [m.model if hasattr(m, 'model') else str(m) for m in models_list]
            
            available = [m for m in available if m]
            if available:
                fallback_model = available[0]
                response = client.chat(model=fallback_model, messages=messages)
                return {"response": response['message']['content'], "source": f"ollama ({fallback_model})"}
        except Exception:
            pass
            
        # Return fallback
        return {
            "response": fallback_security_assistant(payload.message, payload.scan_context),
            "source": "simulator"
        }
                
    except Exception as e:
        print(f"Ollama integration error: {e}")
        return {
            "response": fallback_security_assistant(payload.message, payload.scan_context),
            "source": "simulator"
        }
