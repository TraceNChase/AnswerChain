import unittest
import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from modules import crypto_bridge, sss_bridge

class TestIntegrationBridges(unittest.IsolatedAsyncioTestCase):
    def test_crypto_sha3_256(self):
        result = crypto_bridge.sha3_256(b"hello world")
        self.assertEqual(result.hex(), "644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938")
    def test_crypto_aes_gcm_roundtrip(self):
        key, nonce = crypto_bridge.random_bytes(32), crypto_bridge.random_bytes(12)
        decrypted = crypto_bridge.aes_gcm_decrypt(key, nonce, crypto_bridge.aes_gcm_encrypt(key, nonce, b"test", None), None)
        self.assertEqual(b"test", decrypted)
    async def test_sss_roundtrip(self):
        shares = await sss_bridge.sss_split(b"secret", 5, 3)
        self.assertEqual(b"secret", await sss_bridge.sss_combine(shares[:3]))
    async def test_sss_insufficient_shares_fails(self):
        shares = await sss_bridge.sss_split(b"secret", 5, 3)
        with self.assertRaises(RuntimeError):
            await sss_bridge.sss_combine(shares[:2])