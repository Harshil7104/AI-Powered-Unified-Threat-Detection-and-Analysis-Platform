# from fastapi import FastAPI

# app = FastAPI(
#     title="AI Unified Threat Detection API",
#     version="1.0.0"
# )

# @app.get("/")
# def home():
#     return {"message": "Backend Running Successfully"}


from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.health import router as health_router
from api.url import router as url_router

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

@app.get("/")
def home():
    return {
        "message": "AI Unified Threat Detection API",
        "status": "online",
        "version": "1.0.0"
    }