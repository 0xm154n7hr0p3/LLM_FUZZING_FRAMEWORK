def leet_speak_prompt(prompt: str):
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
