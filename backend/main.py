# from fastapi import FastAPI

# app = FastAPI(
#     title="AI Unified Threat Detection API",
#     version="1.0.0"
# )

# @app.get("/")
# def home():
#     return {"message": "Backend Running Successfully"}


from fastapi import FastAPI
from api.health import router

app = FastAPI()

app.include_router(router)

@app.get("/")
def home():
    return {"message":"AI Unified Threat Detection"}