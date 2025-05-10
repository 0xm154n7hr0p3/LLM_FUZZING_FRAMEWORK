import base64

def base64_prompt(prompt: str):
    return f"{base64.b64encode(prompt.encode('ascii')).decode('utf-8')}"
