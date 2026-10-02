# pyrefly: ignore [missing-import]
from fastapi import APIRouter
# pyrefly: ignore [missing-import]
from pydantic import BaseModel
import os
# pyrefly: ignore [missing-import]
import ollama
# pyrefly: ignore [missing-import]
from dotenv import load_dotenv
# pyrefly: ignore [missing-import]
from pathlib import Path

# Load env variables using path relative to backend directory
env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")

router = APIRouter(prefix="/chat", tags=["AI Chat Assistant"])

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    message: str
    history: list[ChatMessage] = []

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

def fallback_security_assistant(user_message: str) -> str:
    msg = user_message.lower()
    for key, response in SECURITY_QA.items():
        if key in msg:
            return f"[ThreatShield Simulator] {response}\n\n*(Note: Ollama LLM is currently unconfigured or offline. Running in local simulation mode)*"
            
    return (
        f"[ThreatShield Simulator] I received your query: \"{user_message}\".\n\n"
        "Since the local Ollama LLM server is currently offline or unreachable, I am operating "
        "in simulation mode. You can ask me about common terms such as:\n"
        "• **Phishing** or spam email signals.\n"
        "• **Malware** or ransomware definitions.\n"
        "• **WHOIS** lookup or **SSL** certificate verification.\n"
        "• **VirusTotal** scanner intelligence."
    )

@router.post("/")
def chat_with_assistant(payload: ChatRequest):
    try:
        # Construct message payload for Ollama
        messages = [
            {
                "role": "system",
                "content": "You are ThreatShield AI, a professional cyber threat intelligence and analysis assistant. "
                           "You help security analysts identify threats in URLs, emails, and uploaded files. "
                           "Be concise, clear, and action-oriented. Provide detailed security explanations when asked."
            }
        ]
        
        # Load history
        for item in payload.history:
            messages.append({
                "role": item.role,
                "content": item.content
            })
            
        # Append current user prompt
        messages.append({
            "role": "user",
            "content": payload.message
        })
        
        client = ollama.Client(host=OLLAMA_URL)
        
        # Try preferred models in order: user's installed model first
        preferred_models = ['llama3.1:8b', 'llama3.1', 'llama3', 'llama3.2:3b', 'llama3.2']
        
        for model_name in preferred_models:
            try:
                response = client.chat(model=model_name, messages=messages)
                return {"response": response['message']['content'], "source": f"ollama ({model_name})"}
            except Exception:
                continue
        
        # If none of the preferred models work, try any available model
        try:
            models_list = client.list()
            # Handle both old format (dict with 'models' key) and new format (list of Model objects)
            if isinstance(models_list, dict):
                available = [m.get('name', '') for m in models_list.get('models', [])]
            else:
                available = [m.model if hasattr(m, 'model') else str(m) for m in models_list]
            
            available = [m for m in available if m]  # Filter empty
            if available:
                fallback_model = available[0]
                response = client.chat(model=fallback_model, messages=messages)
                return {"response": response['message']['content'], "source": f"ollama ({fallback_model})"}
            else:
                raise Exception("Ollama server connected but no models are loaded. Run 'ollama pull llama3.2:3b'")
        except Exception:
            raise Exception("Ollama server connected but no models are loaded. Run 'ollama pull llama3.2:3b'")
                
    except Exception as e:
        print(f"Ollama integration error: {e}")
        return {"response": fallback_security_assistant(payload.message), "source": "simulator"}
