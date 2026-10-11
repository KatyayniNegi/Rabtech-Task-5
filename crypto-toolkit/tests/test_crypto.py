import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from crypto_toolkit import aes_gcm, hmac_utils, rsa_signatures  # noqa: E402

try:
    from crypto_toolkit import password_hashing
    HAVE_BCRYPT = True
except ImportError:  # bcrypt not installed
    HAVE_BCRYPT = False


class TestAESGCM(unittest.TestCase):
    def setUp(self):
        self.key = aes_gcm.generate_key()

    def test_roundtrip(self):
        self.assertEqual(aes_gcm.decrypt(self.key, aes_gcm.encrypt(self.key, b"hello")), b"hello")

    def test_empty_plaintext(self):
        self.assertEqual(aes_gcm.decrypt(self.key, aes_gcm.encrypt(self.key, b"")), b"")

    def test_random_iv_each_time(self):
        a, b = aes_gcm.encrypt(self.key, b"same"), aes_gcm.encrypt(self.key, b"same")
        self.assertNotEqual(a, b)
        self.assertNotEqual(a[1:13], b[1:13])

    def test_key_length(self):
        self.assertEqual(len(self.key), 32)
        with self.assertRaises(ValueError):
            aes_gcm.encrypt(b"short", b"x")

    def test_tamper_ciphertext(self):
        blob = bytearray(aes_gcm.encrypt(self.key, b"hello world"))
        blob[-1] ^= 1
        with self.assertRaises(aes_gcm.DecryptionError):
            aes_gcm.decrypt(self.key, bytes(blob))

    def test_tamper_nonce(self):
        blob = bytearray(aes_gcm.encrypt(self.key, b"hello world"))
        blob[1] ^= 1
        with self.assertRaises(aes_gcm.DecryptionError):
            aes_gcm.decrypt(self.key, bytes(blob))

    def test_wrong_key(self):
        blob = aes_gcm.encrypt(self.key, b"x")
        with self.assertRaises(aes_gcm.DecryptionError):
            aes_gcm.decrypt(aes_gcm.generate_key(), blob)

    def test_aad_mismatch(self):
        blob = aes_gcm.encrypt(self.key, b"x", b"ctx-a")
        with self.assertRaises(aes_gcm.DecryptionError):
            aes_gcm.decrypt(self.key, blob, b"ctx-b")

    def test_malformed(self):
        with self.assertRaises(aes_gcm.DecryptionError):
            aes_gcm.decrypt(self.key, b"\x01short")

    def test_b64_helpers(self):
        t = aes_gcm.encrypt_to_b64(self.key, "héllo ✓")
        self.assertEqual(aes_gcm.decrypt_from_b64(self.key, t), "héllo ✓")


class TestHMAC(unittest.TestCase):
    def test_valid_and_tampered(self):
        k = os.urandom(32)
        t = hmac_utils.compute_hmac(k, b"msg")
        self.assertTrue(hmac_utils.verify_hmac(k, b"msg", t))
        self.assertFalse(hmac_utils.verify_hmac(k, b"msG", t))
        self.assertFalse(hmac_utils.verify_hmac(os.urandom(32), b"msg", t))

    def test_rfc4231_case6_known_answer(self):
        key = b"\xaa" * 131
        msg = b"Test Using Larger Than Block-Size Key - Hash Key First"
        self.assertEqual(
            hmac_utils.compute_hmac(key, msg).hex(),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        )

    def test_short_key_rejected(self):
        with self.assertRaises(ValueError):
            hmac_utils.compute_hmac(b"short", b"m")


class TestRSA(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.priv, cls.pub = rsa_signatures.generate_rsa_keypair()

    def test_key_size(self):
        self.assertEqual(self.priv.key_size, 2048)

    def test_sign_verify(self):
        s = rsa_signatures.sign(self.priv, b"data")
        self.assertTrue(rsa_signatures.verify(self.pub, b"data", s))
        self.assertFalse(rsa_signatures.verify(self.pub, b"datA", s))

    def test_signatures_are_probabilistic(self):
        self.assertNotEqual(rsa_signatures.sign(self.priv, b"d"), rsa_signatures.sign(self.priv, b"d"))

    def test_wrong_key_fails(self):
        _, other_pub = rsa_signatures.generate_rsa_keypair()
        s = rsa_signatures.sign(self.priv, b"data")
        self.assertFalse(rsa_signatures.verify(other_pub, b"data", s))

    def test_pem_roundtrip_encrypted(self):
        pem = rsa_signatures.serialize_private_key(self.priv, b"pw")
        self.assertIn(b"ENCRYPTED", pem)
        loaded = rsa_signatures.load_private_key(pem, b"pw")
        s = rsa_signatures.sign(loaded, b"x")
        pub = rsa_signatures.load_public_key(rsa_signatures.serialize_public_key(self.pub))
        self.assertTrue(rsa_signatures.verify(pub, b"x", s))
        with self.assertRaises(Exception):
            rsa_signatures.load_private_key(pem, b"wrong")


@unittest.skipUnless(HAVE_BCRYPT, "bcrypt not installed")
class TestPasswords(unittest.TestCase):
    def test_hash_verify(self):
        h = password_hashing.hash_password("s3cret-passphrase")
        self.assertTrue(password_hashing.verify_password("s3cret-passphrase", h))
        self.assertFalse(password_hashing.verify_password("wrong", h))

    def test_unique_salts(self):
        self.assertNotEqual(password_hashing.hash_password("same-pw"), password_hashing.hash_password("same-pw"))

    def test_long_password_not_truncated(self):
        h = password_hashing.hash_password("a" * 80)
        self.assertFalse(password_hashing.verify_password("a" * 72 + "b" * 8, h))

    def test_needs_rehash(self):
        h = password_hashing.hash_password("pw-long-enough", cost=10)
        self.assertTrue(password_hashing.needs_rehash(h, 12))
        self.assertFalse(password_hashing.needs_rehash(h, 10))

    def test_garbage_hash(self):
        self.assertFalse(password_hashing.verify_password("x", "not-a-hash"))


if __name__ == "__main__":
    unittest.main()
