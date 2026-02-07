import sys
import os

# Add current directory to sys.path so we can import tools.decode_tool
sys.path.append(os.getcwd())
from tools.decode_tool import decode

def main():
    encoded_str = 2034778706811038567
    
    try:
        with open('seed.txt', 'r', encoding='utf-8') as f:
            seed_content = f.read()
    except Exception as e:
        print(f"Error reading seed.txt: {e}")
        return

    print(f"Seed length: {len(seed_content)}")
    print(f"Seed starts with: {seed_content[:10]}")
    print(f"Seed ends with: {seed_content[-10:]}")

    # Case 1: Use as is
    print("\n--- Attempt 1: Raw content ---")
    try:
        res = decode(encoded_str, [seed_content])
        print(f"Result: {res}")
    except Exception as e:
        print(f"Error: {e}")

    # Case 2: Strip quotes if present
    if seed_content.startswith('"') and seed_content.endswith('"'):
        print("\n--- Attempt 2: Stripped quotes ---")
        stripped_seed = seed_content[1:-1]
        try:
            res = decode(encoded_str, [stripped_seed])
            print(f"Result: {res}")
        except Exception as e:
            print(f"Error: {e}")
            
    # Case 3: Handle escape sequences if it's a raw string literal representation
    # The file content has \uffdf which looks like an escape sequence.
    # If the file contains literal backslashes, we might need to decode them.
    print("\n--- Attempt 3: Decode unicode escapes ---")
    try:
        # This decodes things like \u0041 to A
        decoded_seed = seed_content.encode('utf-8').decode('unicode_escape')
        # If the file had quotes, we might need to strip them BEFORE decoding escapes or after?
        # Usually "string" -> strip quotes -> decode escapes.
        
        if decoded_seed.startswith('"') and decoded_seed.endswith('"'):
             decoded_seed = decoded_seed[1:-1]
             
        res = decode(encoded_str, [decoded_seed])
        print(f"Result: {res}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
