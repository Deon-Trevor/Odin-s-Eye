import os
import aiohttp
import logging
from fastapi import HTTPException
from typing import Dict, Any

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Update API key reference
ODIN_CLIENT_ID = "AP-Eye"
NIGHTHAWK_CLIENT_VERSION = "1.0.0"


async def check_url(url: str) -> Dict[str, Any]:
    """
    Asynchronously check if a URL is flagged by Nighthawk (Phishfort).
    """
    lookup_api = f"https://lookup.phishfort.com/api/lookup?url={url}"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url=lookup_api,
                headers={
                    "x-client-id": NIGHTHAWK_CLIENT_VERSION,
                    "x-client-version": NIGHTHAWK_CLIENT_VERSION,
                },
                timeout=aiohttp.ClientTimeout(total=10),
            ) as response:
                try:
                    data = await response.json()
                except aiohttp.ContentTypeError:
                    logger.error(f"Invalid JSON response from Nighthawk API for {url}")
                    raise HTTPException(
                        status_code=500, detail="Invalid response from Nighthawk API"
                    )

                if "error" in data:
                    logger.error(f"Nighthawk API Error: {data['error']}")
                    raise HTTPException(
                        status_code=500, detail="Error checking Nighthawk status"
                    )

                is_dangerous = data.get("dangerous", False)
                verdict = "Entirely Malicious" if is_dangerous else "Completely Clean"

                logger.info(f"Nighthawk Verdict for {url}: {verdict}")

                return {
                    "url": url,
                    "verdict": verdict,
                    "dangerous": is_dangerous,
                    "nighthawk_response": data,
                }

    except aiohttp.ClientError as error:
        logger.error(f"Error checking {url}: {error}")
        raise HTTPException(status_code=500, detail=f"Unexpected error: {error}")
