import base64

def check(data):
    try:
        if isinstance(data, str):
            sb_bytes = bytes(data, "ascii")
    
        elif isinstance(data, bytes):
            sb_bytes = data
    
        else:
            raise ValueError("Argument must be string or bytes")
    
        base64.b64decode(sb_bytes, validate=True)
    
        return True
    
    except Exception:
        return False
    
def decode(data, fallback="latin-1"):
    if check(data):
        try:
            return base64.b64decode(data).decode("utf-8")
        
        except UnicodeDecodeError:
            return base64.b64decode(data).decode(fallback)

    return data
