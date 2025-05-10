import codecs

def rot13_prompt(prompt: str):
    return f"{codecs.encode(prompt, 'rot_13')}"