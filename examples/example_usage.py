# examples/example_usage.py
from modules.noble_bridge import NobleBridge
import secrets

def main():
    print("Starting test…")
    js_dir = 'bridge'  # path where bridge.js and noble-*.js live
    key = secrets.token_bytes(32)
    nonce_gcm = secrets.token_bytes(12)
    nonce_chacha = secrets.token_bytes(12)
    nonce_xchacha = secrets.token_bytes(24)
    aad = b'header'
    msg = b'hello world'
    salt = secrets.token_bytes(16)

    with NobleBridge(js_dir=js_dir) as nb:
        print("Bridge started, running operations…")

        # AES-GCM
        ct = nb.aes_gcm_encrypt(key, nonce_gcm, msg, aad)
        pt = nb.aes_gcm_decrypt(key, nonce_gcm, ct, aad)
        assert pt == msg
        print("AES-GCM OK")

        # ChaCha20-Poly1305
        ct2 = nb.chacha20poly1305_encrypt(key, nonce_chacha, msg, aad)
        pt2 = nb.chacha20poly1305_decrypt(key, nonce_chacha, ct2, aad)
        assert pt2 == msg
        print("ChaCha20-Poly1305 OK")

        # XChaCha20-Poly1305
        ct3 = nb.xchacha20poly1305_encrypt(key, nonce_xchacha, msg, aad)
        pt3 = nb.xchacha20poly1305_decrypt(key, nonce_xchacha, ct3, aad)
        assert pt3 == msg
        print("XChaCha20-Poly1305 OK")

        # Hashes / MACs / KDFs
        _ = nb.sha3_256(b'data')
        _ = nb.hmac_sha256(key, b'data')
        _ = nb.hkdf_sha256(key, salt, b'ctx', 42)
        print("Hashes/HMAC/HKDF OK")

        # Argon2id
        _ = nb.argon2id(b'password', salt, t=2, m=65536, p=1, dkLen=32, version=19)
        print("Argon2id OK")

        # Constant-time compare
        mac = nb.hmac_sha256(key, b'data')
        assert nb.ct_equal(mac, mac)
        assert not nb.ct_equal(mac, b'\x00' * len(mac))
        print("Constant-time compare OK")

    print("All operations OK, script finished.")

if __name__ == '__main__':
    main()
