import os
from fastapi import FastAPI
from dotenv import load_dotenv
from backend.routes.virustotal import router as vt_router
from backend.routes.email import router as email_router
from backend.routes.nighthawk import router as nighthawk_router
from fastapi.middleware.cors import CORSMiddleware

# Load environment variables from .env
load_dotenv()

app = FastAPI(
    title="AP-Eye",
    description="Threat Intelligence API for Email & URL Analysis",
    version="1.0.0",
)

# Register API routes
app.include_router(vt_router, prefix="/virustotal", tags=["VirusTotal"])
app.include_router(email_router, prefix="/email", tags=["Email Analysis"])
app.include_router(nighthawk_router, prefix="/nighthawk", tags=["Nighthawk URL Checks"])
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all domains (change later for security)
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)


@app.get("/", tags=["Root"])
async def root():
    return {
        "message": "Welcome to the AP-Eye",
        "environment": {
            "VIRUSTOTAL_KEY": "Loaded" if os.getenv("VIRUS_TOTAL_KEY") else "Missing",
            "PARTNER_API_PROD": (
                "Loaded" if os.getenv("PARTNER_API_PROD") else "Missing"
            ),
        },
    }
