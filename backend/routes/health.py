from fastapi import APIRouter

router = APIRouter()


@router.get("/", summary="API Health Check")
async def health_check():
    return {"status": "ok", "message": "Odin's Eye API is running"}
