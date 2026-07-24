from fastapi import APIRouter

router = APIRouter(prefix="/url", tags=["URL Scanner"])

@router.post("/scan")
def scan_url():
    return {"message": "URL Scan API"}