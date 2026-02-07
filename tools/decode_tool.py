import argparse
import sys
import os

def unsigned_right_shift(val, n):
    """Emulate Java's >>> operator for 64-bit integers."""
    return (val & 0xFFFFFFFFFFFFFFFF) >> n

def to_int32(val):
    """Emulate Java's int cast (truncate to 32 bits, signed)."""
    val = val & 0xFFFFFFFF
    if val & 0x80000000:
        return val - 0x100000000
    return val

def to_char(val):
    """Emulate Java's char cast (truncate to 16 bits, unsigned)."""
    return val & 0xFFFF

def to_short(n):
    """Emulate Java's short cast (truncate to 16 bits, signed)."""
    n = n & 0xFFFF
    if n & 0x8000:
        return n - 0x10000
    return n

def urshift_32(val, n):
    """Emulate Java's >>> operator for 32-bit integers."""
    return (val & 0xFFFFFFFF) >> n

def o0O0(j):
    # s = (short) (j & 65535)
    s = to_short(j & 0xFFFF)
    
    # s2 = (short) ((j >>> 16) & 65535)
    s2 = to_short(unsigned_right_shift(j, 16) & 0xFFFF)
    
    # s3 = (short) (s + s2)
    s3 = to_short(s + s2)
    
    # s4 = (short) (s2 ^ s)
    s4 = to_short(s2 ^ s)
    
    # Term A: ((short) ((s4 >>> 22) | (s4 << 10)))
    # s4 >>> 22 (as int)
    t1 = urshift_32(s4, 22)
    # s4 << 10 (as int)
    t2 = to_int32(s4 << 10)
    A = to_short(t1 | t2)
    
    # Term B: ((short) (((short) ((s3 >>> 23) | (s3 << 9))) + s))
    t3 = urshift_32(s3, 23)
    t4 = to_int32(s3 << 9)
    inner = to_short(t3 | t4)
    B = to_short(inner + s)
    
    # LHS: ( (A | (B << 16)) << 16 )
    t5 = to_int32(B << 16)
    t6 = to_int32(A | t5)
    LHS = to_int32(t6 << 16)
    
    # Term C: ((short) (((short) (((short) ((s << 13) | (s >>> 19))) ^ s4)) ^ (s4 << 5)))
    p1a = to_int32(s << 13)
    p1b = urshift_32(s, 19)
    p1 = to_short(p1a | p1b)
    
    p2 = to_short(p1 ^ s4)
    p3a = to_int32(s4 << 5)
    C = to_short(p2 ^ p3a)
    
    # Result
    return to_int32(LHS | C)

def decode(encoded_str_val, seed_array):
    # Constants
    CONST1 = 0x62A9D9381648E3F5  # 7109453100751455733L
    CONST2 = 0xCB24D0A5C88C35F3  # -3808689974395783757L (in 64-bit 2's complement)

    # long j = 4294967295L & encodedStr;
    j = 0xFFFFFFFF & encoded_str_val
    
    # long j2 = (j ^ (j >>> 33)) * 7109453100751455733L;
    # Since j is 32-bit (from the mask above), j >> 33 is 0.
    term1 = j ^ unsigned_right_shift(j, 33) # Effectively just j
    j2 = (term1 * CONST1) & 0xFFFFFFFFFFFFFFFF

    # long jO0O0 = OO0OO.o0O0(((j2 ^ (j2 >>> 28)) * (-3808689974395783757L)) >>> 32);
    term2 = j2 ^ unsigned_right_shift(j2, 28)
    term3 = (term2 * CONST2) & 0xFFFFFFFFFFFFFFFF
    arg_for_o0O0 = unsigned_right_shift(term3, 32)
    jO0O0 = o0O0(arg_for_o0O0)

    # long j3 = (jO0O0 >>> 32) & 65535;
    j3 = unsigned_right_shift(jO0O0, 32) & 0xFFFF

    # long jO0O02 = OO0OO.o0O0(jO0O0);
    jO0O02 = o0O0(jO0O0)

    # int i = (int) (((encodedStr >>> 32) ^ j3) ^ ((jO0O02 >>> 16) & (-65536)));
    # Java int is 32-bit signed.
    part1 = unsigned_right_shift(encoded_str_val, 32)
    part2 = j3
    part3 = unsigned_right_shift(jO0O02, 16) & 0xFFFF0000 # -65536 is 0xFFFF0000 in 32-bit context
    
    i = to_int32((part1 ^ part2) ^ part3)

    # Accessing seed char: seed[i / 8191].charAt(i % 8191)
    def get_seed_char(index):
        # Handle array logic
        array_idx = index // 8191
        str_idx = index % 8191
        if 0 <= array_idx < len(seed_array):
            s = seed_array[array_idx]
            if 0 <= str_idx < len(s):
                return ord(s[str_idx])
        return 0 # Fallback/Error

    # long jO0O03 = OO0OO.o0O0(jO0O02) ^ (seed[i / 8191].charAt(i % 8191) << 32);
    seed_char_val = get_seed_char(i)
    jO0O03 = o0O0(jO0O02) ^ (seed_char_val << 32)
    jO0O03 = jO0O03 & 0xFFFFFFFFFFFFFFFF # Ensure 64-bit

    # int i2 = (int) ((jO0O03 >>> 32) & 65535);
    i2 = to_int32(unsigned_right_shift(jO0O03, 32) & 0xFFFF)
    
    # char[] cArr = new char[i2];
    c_arr = []

    # for (int i3 = 0; i3 < i2; i3++) { ... }
    for i3 in range(i2):
        i4 = i + i3 + 1
        
        # jO0O03 = OO0OO.o0O0(jO0O03) ^ (seed[i4 / 8191].charAt(i4 % 8191) << 32);
        seed_char_val_loop = get_seed_char(i4)
        jO0O03 = o0O0(jO0O03) ^ (seed_char_val_loop << 32)
        jO0O03 = jO0O03 & 0xFFFFFFFFFFFFFFFF

        # cArr[i3] = (char) ((jO0O03 >>> 32) & 65535);
        char_code = unsigned_right_shift(jO0O03, 32) & 0xFFFF
        c_arr.append(chr(char_code))

    return "".join(c_arr)

def main():
    parser = argparse.ArgumentParser(description="Decode encoded string using seed.")
    parser.add_argument("--encodedStr", type=int, required=True, help="The encoded long integer value.")
    parser.add_argument("--seed", type=str, nargs='+', help="The seed string(s). If multiple, they form the array.")
    
    args = parser.parse_args()

    # Fallback to environment variable DECODE_SEED if --seed is not provided
    seed = args.seed
    if not seed:
        env_seed = os.getenv("DECODE_SEED")
        if env_seed:
            # Assume comma-separated if multiple seeds are in the env var
            seed = env_seed.split(",")
        else:
            print("Error: The --seed argument or DECODE_SEED environment variable is required.", file=sys.stderr)
            sys.exit(1)
    
    try:
        result = decode(args.encodedStr, seed)
        print(result)
    except Exception as e:
        print(f"Error decoding: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
