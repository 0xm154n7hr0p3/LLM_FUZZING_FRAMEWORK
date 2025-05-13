import base64
import codecs

def piped_string(s): return '|'.join(s)

def base32_prompt(prompt: str):
    return f"{base64.b32encode(prompt.encode('utf-8')).decode('utf-8')}"

def base64_prompt(prompt: str):
    return f"{base64.b64encode(prompt.encode('utf-8')).decode('utf-8')}"

def binary_prompt(prompt: str):
    return ''.join(format(ord(c), '08b') for c in prompt)

def double_base64_prompt(prompt: str):
    first_encode = base64.b64encode(prompt.encode('utf-8'))
    second_encode = base64.b64encode(first_encode)
    return f"{second_encode.decode('utf-8')}"

def hex_prompt(prompt: str):
    return f"{prompt.encode('utf-8').hex()}"

def leet_prompt(prompt: str):
    leet_map = {
        'a': '4',
        'b': '8',
        'e': '3',
        'l': '1',
        'o': '0',
        's': '5',
    }

    result = ''
    for char in prompt:
        result += leet_map.get(char.lower(), char)
    
    return f"{result}"

def rot13_prompt(prompt: str):
    return f"{codecs.encode(prompt, 'rot_13')}"
    
def unicode_prompt(prompt: str):
    return ''.join(f'\\u{ord(c):04x}' for c in prompt)