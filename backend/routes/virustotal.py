from fastapi import APIRouter, Query, Depends, UploadFile, File, Request
from backend.services.virustotal import (
    check_attachment,
    scan_attachment,
    check_url,
    scan_url,
)
from backend.utils.rate_limiter import get_rate_limiter
import os
import shutil

router = APIRouter()


# ✅ Rate limiting dependency
def rate_limit_dependency(request: Request, limiter=Depends(get_rate_limiter)):
    """Apply rate limiting to every API request based on client IP."""
    client_id = request.client.host
    limiter.check_limit(client_id)


UPLOAD_DIR = "./uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


@router.get(
    "/check_attachment",
    summary="Check a file hash on VirusTotal",
    dependencies=[Depends(rate_limit_dependency)],
)
async def api_check_attachment(
    file_hash: str = Query(..., description="SHA256 file hash")
):
    """Check if a file hash exists in VirusTotal's database."""
    return await check_attachment(file_hash)  # ✅ Ensure `await` is used


@router.post(
    "/scan_attachment",
    summary="Upload and scan a file with VirusTotal",
    dependencies=[Depends(rate_limit_dependency)],
)
async def api_scan_attachment(file: UploadFile = File(...)):
    """Uploads a file and scans it with VirusTotal."""
    file_path = os.path.join(UPLOAD_DIR, file.filename)

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    result = await scan_attachment(file_path)  # ✅ Add `await`

    os.remove(file_path)  # ✅ Clean up the uploaded file

    return result


@router.get(
    "/check_url",
    summary="Check a URL on VirusTotal",
    dependencies=[Depends(rate_limit_dependency)],
)
async def api_check_url(url: str = Query(..., description="URL to check")):
    """Check if a URL is flagged in VirusTotal."""
    return await check_url(url)  # ✅ Add `await`


@router.post(
    "/scan_url",
    summary="Submit a URL to VirusTotal for scanning",
    dependencies=[Depends(rate_limit_dependency)],
)
async def api_scan_url(url: str = Query(..., description="URL to scan")):
    """Submit a URL to VirusTotal for scanning."""
    return await scan_url(url)  # ✅ Add `await`
