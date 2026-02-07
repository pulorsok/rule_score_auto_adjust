import sys
import os
import re

# Add current directory to sys.path so we can import tools.decode_tool
sys.path.append(os.getcwd())
# Import internal functions to patch them or use them
import tools.decode_tool as dt

def unescape_java_string(s):
    # Regex to find \uXXXX
    def replace_unicode(match):
        return chr(int(match.group(1), 16))
    return re.sub(r'\\u([0-9a-fA-F]{4})', replace_unicode, s)

def decode_variant(encoded_str_val, seed_array, shift_behavior):
    # ... Copy of decode logic but with adjustable shift ...
    # Or I can just Monkey Patch the decode tool?
    # No, better to inline the logic to be sure.
    
    encoded_str_val = int(encoded_str_val)
    
    CONST1 = 0x62A9D9381648E3F5
    CONST2 = 0xCB24D0A5C88C35F3

    j = 0xFFFFFFFF & encoded_str_val
    term1 = j ^ dt.unsigned_right_shift(j, 33)
    j2 = (term1 * CONST1) & 0xFFFFFFFFFFFFFFFF

    term2 = j2 ^ dt.unsigned_right_shift(j2, 28)
    term3 = (term2 * CONST2) & 0xFFFFFFFFFFFFFFFF
    arg_for_o0O0 = dt.unsigned_right_shift(term3, 32)
    jO0O0 = dt.o0O0(arg_for_o0O0)

    j3 = dt.unsigned_right_shift(jO0O0, 32) & 0xFFFF
    jO0O02 = dt.o0O0(jO0O0)

    part1 = dt.unsigned_right_shift(encoded_str_val, 32)
    part2 = j3
    part3 = dt.unsigned_right_shift(jO0O02, 16) & 0xFFFF0000
    
    i = dt.to_int32((part1 ^ part2) ^ part3)
    
    # Decoded index check
    # print(f"DEBUG: Calculated i (index): {i}")

    def get_seed_char(index):
        if index < 0: index = abs(index) # Safety?
        array_idx = index // 8191
        str_idx = index % 8191
        if 0 <= array_idx < len(seed_array):
            s = seed_array[array_idx]
            if 0 <= str_idx < len(s):
                return ord(s[str_idx])
        return 0 

    seed_char_val = get_seed_char(i)
    
    # VARIANT LOGIC HERE
    if shift_behavior == 'long_shift':
        # (long)char << 32
        shifted_char = seed_char_val << 32
    else:
        # (int)char << 32 => (int)char << 0 => char
        shifted_char = seed_char_val
        
    jO0O03 = dt.o0O0(jO0O02) ^ shifted_char
    jO0O03 = jO0O03 & 0xFFFFFFFFFFFFFFFF

    i2 = dt.to_int32(dt.unsigned_right_shift(jO0O03, 32) & 0xFFFF)
    # print(f"DEBUG: Calculated i2 (length): {i2}")
    
    c_arr = []
    if i2 > 1000:
        # print("DEBUG: Length > 1000, truncating for safety if enormous")
        pass

    for i3 in range(i2):
        i4 = i + i3 + 1
        
        seed_char_val_loop = get_seed_char(i4)
        
        if shift_behavior == 'long_shift':
            shifted_char_loop = seed_char_val_loop << 32
        else:
            shifted_char_loop = seed_char_val_loop
            
        jO0O03 = dt.o0O0(jO0O03) ^ shifted_char_loop
        jO0O03 = jO0O03 & 0xFFFFFFFFFFFFFFFF

        char_code = dt.unsigned_right_shift(jO0O03, 32) & 0xFFFF
        c_arr.append(chr(char_code))

    return "".join(c_arr)

def main():
    encoded_str = 2034778706811038567
    
    try:
        with open('seed.txt', 'r', encoding='utf-8') as f:
            content = f.read().strip()
    except Exception as e:
        print(f"Error reading seed.txt: {e}")
        return

    if content.startswith('"') and content.endswith('"'):
        content = content[1:-1]
        
    full_seed = unescape_java_string(content)
    # Split
    seed_array = [full_seed[i:i+8191] for i in range(0, len(full_seed), 8191)]
    
    print("--- Testing 'long_shift' behavior ((long)c << 32) ---")
    try:
        res = decode_variant(encoded_str, seed_array, 'long_shift')
        print(f"Result: {res}")
    except Exception as e:
        print(f"Error: {e}")

    print("\n--- Testing 'int_shift' behavior (c << 32 -> c) ---")
    try:
        res = decode_variant(encoded_str, seed_array, 'int_shift')
        print(f"Result: {res}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
