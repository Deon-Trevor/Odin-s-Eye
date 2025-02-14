import os
import shutil
from fastapi import APIRouter, UploadFile, File, HTTPException
from backend.services.email_parser import parse_eml, parse_msg
from backend.utils.security import allowed_file, create_safe_temp_dir, sanitize_filename
from backend.utils.helpers import save_uploaded_file

router = APIRouter()


@router.post("/analyze", summary="Upload and analyze email")
async def analyze_email(file: UploadFile = File(...)):
    filename = sanitize_filename(file.filename)

    if not allowed_file(filename):
        raise HTTPException(status_code=400, detail="Unsupported file type")

    # Save the file securely
    temp_dir = create_safe_temp_dir()
    file_path = save_uploaded_file(temp_dir, file)

    # Parse email
    try:
        if filename.endswith(".eml"):
            analysis = parse_eml(file_path)
        elif filename.endswith(".msg"):
            analysis = parse_msg(file_path)
        else:
            raise HTTPException(status_code=400, detail="Unsupported file type")

        os.remove(file_path)  # Clean up
        return {"filename": filename, "analysis": analysis}

    except Exception as e:
        os.remove(file_path)  # Ensure cleanup
        raise HTTPException(status_code=500, detail=str(e))
