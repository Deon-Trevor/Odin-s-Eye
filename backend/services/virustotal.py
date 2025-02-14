import os
import vt
import logging
from fastapi import HTTPException
from dotenv import load_dotenv
from typing import Dict, Any
import asyncio

# Setup Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get API Key
load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUS_TOTAL_KEY")

# Ensure API key is set
if not VIRUSTOTAL_API_KEY:
    raise RuntimeError("VirusTotal API key is not set. Add it to the .env file.")
pass


async def check_attachment(file_hash: str) -> Dict[str, Any]:
    """Check if a file hash exists in VirusTotal's database (ASYNC)."""
    async with vt.Client(
        VIRUSTOTAL_API_KEY
    ) as client:  # ✅ FIX: Use async context manager
        try:
            analysis = await client.get_object_async(
                f"/files/{file_hash}"
            )  # ✅ FIX: Await async call
            reputation = analysis.reputation
            verdict = get_verdict(reputation)

            logger.info(f"VirusTotal Verdict for {file_hash}: {verdict}")
            return {
                "file_hash": file_hash,
                "verdict": verdict,
                "analysis": analysis.to_dict(),
            }  # ✅ FIX: Use `.to_dict()`

        except vt.error.APIError as error:
            if error.code == "NotFoundError":
                logger.warning(
                    f"{file_hash} not found in VirusTotal. Recommend scanning."
                )
                return {
                    "file_hash": file_hash,
                    "verdict": "Not Found",
                    "message": "File not found in VirusTotal.",
                }
            logger.error(f"Error retrieving VirusTotal verdict: {error}")
            raise HTTPException(
                status_code=500, detail=f"VirusTotal API error: {error}"
            )

        except Exception as error:
            logger.error(f"Unexpected error on {file_hash}: {error}")
            raise HTTPException(status_code=500, detail=f"Unexpected error: {error}")


async def scan_attachment(file_path: str) -> Dict[str, Any]:
    """Upload and scan a file with VirusTotal (ASYNC)."""
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail=f"File not found: {file_path}")

    async with vt.Client(
        VIRUSTOTAL_API_KEY
    ) as client:  # ✅ FIX: Use async context manager
        try:
            with open(file_path, "rb") as file:
                analysis = await client.scan_file_async(
                    file
                )  # ✅ FIX: Await async call

            reputation = analysis.reputation
            verdict = get_verdict(reputation)
            logger.info(f"VirusTotal Verdict for {file_path}: {verdict}")

            return {
                "filename": os.path.basename(file_path),
                "verdict": verdict,
                "analysis": analysis.to_dict(),  # ✅ FIX: Use `.to_dict()`
            }

        except Exception as error:
            logger.error(f"Error scanning {file_path}: {error}")
            raise HTTPException(
                status_code=500, detail=f"VirusTotal scanning error: {error}"
            )


async def check_url(url: str) -> Dict[str, Any]:
    """Check if a URL is flagged in VirusTotal (ASYNC)."""
    async with vt.Client(
        VIRUSTOTAL_API_KEY
    ) as client:  # ✅ FIX: Use async context manager
        try:
            url_id = vt.url_id(url)
            url_scan = await client.get_object_async(
                f"/urls/{url_id}"
            )  # ✅ FIX: Await async call
            reputation = url_scan.reputation
            verdict = get_verdict(reputation)

            logger.info(f"VirusTotal Verdict for {url}: {verdict}")
            return {
                "url": url,
                "verdict": verdict,
                "analysis": url_scan.to_dict(),
            }  # ✅ FIX: Use `.to_dict()`

        except vt.error.APIError as error:
            if error.code == "NotFoundError":
                logger.warning(f"{url} not found in VirusTotal. Submitting for scan.")
                return {
                    "url": url,
                    "verdict": "Not Found",
                    "message": "URL not found in VirusTotal.",
                }
            logger.error(f"Error retrieving VirusTotal verdict: {error}")
            raise HTTPException(
                status_code=500, detail=f"VirusTotal API error: {error}"
            )

        except Exception as error:
            logger.error(f"Unexpected error on {url}: {error}")
            raise HTTPException(status_code=500, detail=f"Unexpected error: {error}")


async def scan_url(url: str) -> Dict[str, Any]:
    """Submit a URL to VirusTotal for scanning (ASYNC)."""
    async with vt.Client(
        VIRUSTOTAL_API_KEY
    ) as client:  # ✅ FIX: Use async context manager
        try:
            analysis = await client.scan_url_async(url)  # ✅ FIX: Await async call
            reputation = analysis.reputation
            verdict = get_verdict(reputation)

            logger.info(f"VirusTotal Verdict for {url}: {verdict}")
            return {
                "url": url,
                "verdict": verdict,
                "analysis": analysis.to_dict(),
            }  # ✅ FIX: Use `.to_dict()`

        except Exception as error:
            logger.error(f"Error scanning {url}: {error}")
            raise HTTPException(
                status_code=500, detail=f"VirusTotal scanning error: {error}"
            )


def get_verdict(reputation: int) -> str:
    """Determine a verdict based on VirusTotal reputation score."""
    if reputation <= -50:
        return "Entirely Malicious"
    elif -50 < reputation < 0:
        return "Has Malicious Code"
    elif 0 <= reputation < 50:
        return "Mostly Clean"
    else:
        return "Completely Clean"
