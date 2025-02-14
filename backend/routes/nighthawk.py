from fastapi import APIRouter, Query
from backend.services.nighthawk import check_url

router = APIRouter()


@router.get("/check", summary="Check URL on Nighthawk")
async def api_check_nighthawk(url: str = Query(..., description="URL to check")):
    """
    Check if a URL is flagged by Nighthawk (Phishfort).
    """
    return await check_url(url)
