def binary_encoding_prompt(prompt: str):
    return ''.join(format(ord(c), '08b') for c in prompt)