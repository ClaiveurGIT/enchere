import time
import hmac
import hashlib
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Symmetric Encryption Processing
def process_symmetric(token_length, mode_type):
    payload = b'Sample payload for symmetric processing.'
    token = get_random_bytes(token_length // 8)
    vector = get_random_bytes(16)

    print(f"\n[ SYM ] Mode: {mode_type}, Token Length: {token_length} bits")

    # Encoding
    start_proc = time.perf_counter()
    cipher = AES.new(token, AES.MODE_CBC, iv=vector)
    padded_payload = payload + b' ' * (16 - len(payload) % 16)
    encoded = cipher.encrypt(padded_payload)
    end_proc = time.perf_counter()
    print(f"Encoding Duration: {(end_proc - start_proc) * 1000:.3f} ms")

    # Decoding
    start_dec = time.perf_counter()
    decipher = AES.new(token, AES.MODE_CBC, iv=vector)
    decoded = decipher.decrypt(encoded).rstrip(b' ')
    end_dec = time.perf_counter()
    print(f"Decoding Duration: {(end_dec - start_dec) * 1000:.3f} ms")

    print(f"Decoded Payload: {decoded.decode('utf-8')}")

    return {"method": "SYM", "token_length": token_length, "mode_type": mode_type, "encode_time": end_proc - start_proc, "decode_time": end_dec - start_dec}

# Asymmetric Encryption Processing
def process_asymmetric(key_depth):
    key = RSA.generate(key_depth)
    public_key = key.publickey()

    payload = b'Sample payload for asymmetric processing.'

    print(f"\n[ ASYM ] Key Depth: {key_depth} bits")

    # Encoding
    start_proc = time.perf_counter()
    cipher = PKCS1_OAEP.new(public_key)
    encoded = cipher.encrypt(payload)
    end_proc = time.perf_counter()
    print(f"Encoding Duration: {(end_proc - start_proc) * 1000:.3f} ms")

    # Decoding
    start_dec = time.perf_counter()
    decipher = PKCS1_OAEP.new(key)
    decoded = decipher.decrypt(encoded)
    end_dec = time.perf_counter()
    print(f"Decoding Duration: {(end_dec - start_dec) * 1000:.3f} ms")

    print(f"Decoded Payload: {decoded.decode('utf-8')}")

    return {"method": "ASYM", "key_depth": key_depth, "encode_time": end_proc - start_proc, "decode_time": end_dec - start_dec}

# Integrity Verification Processing
def process_integrity(hash_type, token_length):
    payload = b'Sample payload for integrity verification.'
    token = get_random_bytes(token_length // 8)

    print(f"\n[ INTG ] Hash Type: {hash_type}, Token Length: {token_length} bits")

    # Validation
    start_proc = time.perf_counter()
    validator = hmac.new(token, payload, getattr(hashlib, hash_type))
    result = validator.hexdigest()
    end_proc = time.perf_counter()
    print(f"Validation Duration: {(end_proc - start_proc) * 1000:.3f} ms")

    print(f"Validation Result: {result}")

    return {"method": "INTG", "hash_type": hash_type, "token_length": token_length, "duration": end_proc - start_proc}

# Execute Processing
def execute_processes():
    sym128 = process_symmetric(128, 'AES-128-CBC')
    sym256 = process_symmetric(256, 'AES-256-CBC')

    asym1024 = process_asymmetric(1024)
    asym2048 = process_asymmetric(2048)
    asym4096 = process_asymmetric(4096)

    intg_sha256 = process_integrity('sha256', 256)
    intg_sha512 = process_integrity('sha512', 512)

    print("\n--- Summary ---")
    print(f"Fastest Method: {sym128['method']} ({sym128['mode_type']})")
    print(f"Strongest Key: {asym4096['key_depth']} bits")
    print(f"Integrity Check: {intg_sha512['hash_type']}")
    print("\n--- End of Summary ---")

if __name__ == "__main__":
    execute_processes()
