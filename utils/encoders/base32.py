import base64

def base32_prompt(prompt: str):
    return f"{base64.b32encode(prompt.encode('ascii')).decode('utf-8')}"

