import base64

def double_base64_prompt(prompt: str):
    first_encode = base64.b64encode(prompt.encode('ascii'))
    second_encode = base64.b64encode(first_encode)
    return f"{second_encode.decode('utf-8')}"