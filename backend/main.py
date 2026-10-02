from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database.db import Base, engine
import database.models # Load models to register on Base

# Create tables on startup
Base.metadata.create_all(bind=engine)

# Import API Routers
from api.health import router as health_router
from api.url import router as url_router
from api.auth import router as auth_router
from api.email_scan import router as email_router
from api.file_scan import router as file_router
from api.chat import router as chat_router
from api.reports import router as reports_router

app = FastAPI(
    title="AI-Powered Unified Threat Detection Platform API",
    version="1.0.0"
)

# CORS Middleware to allow React frontend connection
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins for local development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router)
app.include_router(url_router)
app.include_router(auth_router)
app.include_router(email_router)
app.include_router(file_router)
app.include_router(chat_router)
app.include_router(reports_router)

@app.get("/")
def home():
    return {
        "message": "AI Unified Threat Detection API",
        "status": "online",
        "version": "1.0.0"
    }