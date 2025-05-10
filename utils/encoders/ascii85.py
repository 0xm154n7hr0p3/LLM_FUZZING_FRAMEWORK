import base64

def ascii85_prompt(prompt: str):
    return f"{base64.a85encode(prompt.encode('ascii')).decode('utf-8')}"
