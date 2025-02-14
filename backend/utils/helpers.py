import os
import shutil


def save_uploaded_file(upload_dir, file):
    """Save uploaded file to a secure temporary directory."""

    # Ensure the upload directory is writable and exists
    safe_upload_dir = os.path.abspath(upload_dir)  # Resolve full path

    if not os.access(os.path.dirname(safe_upload_dir), os.W_OK):
        # If the given path is not writable, use a fallback directory
        safe_upload_dir = (
            "/tmp/uploads" if os.path.exists("/tmp") else os.getcwd() + "/uploads"
        )

    os.makedirs(safe_upload_dir, exist_ok=True)  # Ensure directory exists

    # Secure file path
    file_path = os.path.join(safe_upload_dir, file.filename)

    # Save file safely
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    return file_path
