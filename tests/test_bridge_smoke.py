import secrets
from modules.noble_bridge import NobleBridge

def test_smoke_all_ops():
    js_dir = "bridge"
    key = secrets.token_bytes(32)
    nonce_gcm = secrets.token_bytes(12)
    nonce_chacha = secrets.token_bytes(12)
    nonce_xchacha = secrets.token_bytes(24)
    aad = b"header"
    msg = b"hello world"
    salt = secrets.token_bytes(16)

    with NobleBridge(js_dir=js_dir) as nb:
        ct = nb.aes_gcm_encrypt(key, nonce_gcm, msg, aad)
        assert nb.aes_gcm_decrypt(key, nonce_gcm, ct, aad) == msg

        ct2 = nb.chacha20poly1305_encrypt(key, nonce_chacha, msg, aad)
        assert nb.chacha20poly1305_decrypt(key, nonce_chacha, ct2, aad) == msg

        ct3 = nb.xchacha20poly1305_encrypt(key, nonce_xchacha, msg, aad)
        assert nb.xchacha20poly1305_decrypt(key, nonce_xchacha, ct3, aad) == msg

        assert len(nb.sha3_256(b"data")) == 32
        assert len(nb.hmac_sha256(key, b"data")) == 32
        assert len(nb.hkdf_sha256(key, salt, b"ctx", 42)) == 42

        assert len(nb.argon2id(b"password", salt, t=2, m=65536, p=1, dkLen=32, version=19)) == 32

        mac = nb.hmac_sha256(key, b"data")
        assert nb.ct_equal(mac, mac) is True
        assert nb.ct_equal(mac, b"\x00" * len(mac)) is False
