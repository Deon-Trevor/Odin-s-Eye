import os
import re

ALLOWED_EXTENSIONS = {"eml", "msg"}


def allowed_file(filename: str) -> bool:
    """Check if a file has an allowed extension."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def sanitize_filename(filename: str) -> str:
    """Sanitize filenames to prevent path traversal attacks."""
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", filename)


def create_safe_temp_dir():
    """Create a secure temporary directory for email file uploads."""
    temp_dir = "temp_emails"
    os.makedirs(temp_dir, exist_ok=True)
    return temp_dir
