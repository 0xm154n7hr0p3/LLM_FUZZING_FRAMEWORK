def unicode_obfuscation_prompt(prompt: str):
    return ''.join(f'\\u{ord(c):04x}' for c in prompt)