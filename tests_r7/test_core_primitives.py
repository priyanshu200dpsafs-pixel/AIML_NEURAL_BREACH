"""Pure-logic tests (no FastAPI/DB needed). Run: python -m unittest tests_r7.test_core_primitives -v"""
import json, os, sys, tempfile, unittest
from datetime import datetime, timedelta, timezone
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "backend"))

from platform_ext.security import passwords, tokens, rbac
from platform_ext.security.ratelimit import RateLimiter
from platform_ext.ingest import contract as C
from platform_ext.releases import signing as S

COLS = [f"f{i}" for i in range(77)]
SECRET = "x" * 40
KW = dict(secret=SECRET, issuer="iss", audience="aud")


class PasswordTests(unittest.TestCase):
    def test_hash_and_verify(self):
        h = passwords.hash_password("correct horse battery")
        self.assertTrue(passwords.verify_password("correct horse battery", h))
        self.assertFalse(passwords.verify_password("wrong password!!", h))
        self.assertNotIn("correct horse", h)

    def test_policy(self):
        with self.assertRaises(ValueError):
            passwords.validate_password_policy("short")

    def test_garbage_hash_is_false(self):
        self.assertFalse(passwords.verify_password("x" * 14, "not-a-hash"))


class TokenTests(unittest.TestCase):
    def test_roundtrip(self):
        t = tokens.encode_jwt({"sub": "u1"}, ttl=60, typ="access", **KW)
        self.assertEqual(tokens.decode_jwt(t, typ="access", **KW)["sub"], "u1")

    def test_session_expiration(self):
        t = tokens.encode_jwt({"sub": "u1"}, ttl=60, typ="access", now=1000, **KW)
        with self.assertRaises(tokens.TokenError):
            tokens.decode_jwt(t, typ="access", now=1000 + 61, **KW)

    def test_wrong_type_rejected(self):
        t = tokens.encode_jwt({"sub": "u1"}, ttl=60, typ="ws", **KW)
        with self.assertRaises(tokens.TokenError):
            tokens.decode_jwt(t, typ="access", **KW)

    def test_wrong_secret_and_audience_rejected(self):
        t = tokens.encode_jwt({"sub": "u1"}, ttl=60, typ="access", **KW)
        with self.assertRaises(tokens.TokenError):
            tokens.decode_jwt(t, typ="access", secret="y" * 40, issuer="iss", audience="aud")
        with self.assertRaises(tokens.TokenError):
            tokens.decode_jwt(t, typ="access", secret=SECRET, issuer="iss", audience="other")

    def test_alg_none_rejected(self):
        import jwt
        t = jwt.encode({"sub": "u", "typ": "access", "iss": "iss", "aud": "aud", "iat": 1, "exp": 9999999999}, None, algorithm="none")
        with self.assertRaises(tokens.TokenError):
            tokens.decode_jwt(t, typ="access", **KW)

    def test_opaque_token_hash(self):
        plain, h = tokens.new_opaque_token()
        self.assertEqual(h, tokens.sha256_hex(plain))
        self.assertNotEqual(plain, h)

    def test_device_bearer(self):
        did = "a" * 8 + "-" + "b" * 4 + "-" + "c" * 4 + "-" + "d" * 4 + "-" + "e" * 12
        self.assertEqual(tokens.parse_device_bearer(tokens.make_device_bearer(did, "sec")), (did, "sec"))
        with self.assertRaises(tokens.TokenError):
            tokens.parse_device_bearer("nodot")


class RbacTests(unittest.TestCase):
    def test_matrix(self):
        self.assertTrue(rbac.has_permission("viewer", rbac.P_ALERTS_READ))
        self.assertFalse(rbac.has_permission("viewer", rbac.P_ALERTS_WRITE))
        self.assertTrue(rbac.has_permission("analyst", rbac.P_ALERTS_WRITE))
        self.assertFalse(rbac.has_permission("analyst", rbac.P_DEVICES_MANAGE))
        self.assertTrue(rbac.has_permission("admin", rbac.P_DEVICES_MANAGE))
        self.assertFalse(rbac.has_permission("admin", rbac.P_ORG_MANAGE))
        self.assertTrue(rbac.has_permission("owner", rbac.P_ORG_MANAGE))
        self.assertFalse(rbac.has_permission("nonsense", rbac.P_ALERTS_READ))

    def test_role_assignment(self):
        self.assertFalse(rbac.can_assign_role("admin", "owner"))
        self.assertFalse(rbac.can_assign_role("admin", "admin"))
        self.assertTrue(rbac.can_assign_role("admin", "viewer"))
        self.assertFalse(rbac.can_assign_role("analyst", "viewer"))
        self.assertTrue(rbac.can_assign_role("owner", "admin"))


class RateLimitTests(unittest.TestCase):
    def test_blocks_then_refills(self):
        r = RateLimiter()
        res = [r.allow("k", 60, burst=3, now=0.0) for _ in range(5)]
        self.assertEqual(res, [True, True, True, False, False])
        self.assertTrue(r.allow("k", 60, burst=3, now=2.0))   # 1 token/sec refill
        self.assertTrue(r.allow("other", 60, burst=3, now=0.0))  # keys are independent


def good_features():
    return {c: 1.5 for c in COLS}


NOW = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)
TS = "2026-11-09T11:59:00Z"


class ContractTests(unittest.TestCase):
    def test_columns_loader_formats(self):
        for payload in (COLS, {"feature_columns": COLS}):
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
                json.dump(payload, f)
            self.assertEqual(len(C.load_feature_columns(f.name)), 77)
            os.unlink(f.name)

    def test_valid_batch(self):
        out = C.validate_batch([{"observed_at": TS, "features": good_features()}], COLS, max_flows=10, max_skew_seconds=3600, now=NOW)
        self.assertEqual(len(out[0]["features"]), 77)

    def test_missing_feature_rejected(self):
        f = good_features(); f.pop("f3")
        with self.assertRaises(C.ContractError):
            C.validate_features(f, COLS)

    def test_extra_feature_rejected(self):
        f = good_features(); f["payload_bytes"] = 1
        with self.assertRaises(C.ContractError):
            C.validate_features(f, COLS)

    def test_bad_types_rejected(self):
        for bad in ("1", None, True, float("nan"), float("inf"), [1]):
            f = good_features(); f["f0"] = bad
            with self.assertRaises(C.ContractError, msg=repr(bad)):
                C.validate_features(f, COLS)

    def test_oversized_and_empty_batch_rejected(self):
        flows = [{"observed_at": TS, "features": good_features()}] * 11
        with self.assertRaises(C.ContractError):
            C.validate_batch(flows, COLS, max_flows=10, max_skew_seconds=3600, now=NOW)
        with self.assertRaises(C.ContractError):
            C.validate_batch([], COLS, max_flows=10, max_skew_seconds=3600, now=NOW)

    def test_extra_flow_keys_rejected(self):
        with self.assertRaises(C.ContractError):
            C.validate_batch([{"observed_at": TS, "features": good_features(), "raw_packet": "AAAA"}], COLS,
                             max_flows=10, max_skew_seconds=3600, now=NOW)

    def test_timestamps(self):
        for bad in ("2026-11-09T11:59:00", "garbage", 123, "2020-01-01T00:00:00Z"):
            with self.assertRaises(C.ContractError, msg=repr(bad)):
                C.parse_timestamp(bad, now=NOW, max_skew_seconds=3600)

    def test_error_reports_flow_index(self):
        bad = good_features(); bad.pop("f1")
        try:
            C.validate_batch([{"observed_at": TS, "features": good_features()}, {"observed_at": TS, "features": bad}],
                             COLS, max_flows=10, max_skew_seconds=3600, now=NOW)
        except C.ContractError as e:
            self.assertEqual(e.index, 1)


class SigningTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pub = S.generate_keypair_b64()
        self.trusted = {"k1": self.pub}
        self.meta = {"version": "1.2.3", "channel": "stable", "os": "windows", "arch": "x86_64",
                     "sha256": S.sha256_bytes(b"artifact"), "size": 8, "expires": "2027-01-01T00:00:00Z"}

    def test_valid(self):
        sig = S.sign_metadata(self.meta, self.priv)
        S.verify_signed_metadata(self.meta, sig, "k1", self.trusted, now=NOW)

    def test_tampered_metadata_rejected(self):
        sig = S.sign_metadata(self.meta, self.priv)
        self.meta["sha256"] = S.sha256_bytes(b"evil")
        with self.assertRaises(S.SignatureError):
            S.verify_signed_metadata(self.meta, sig, "k1", self.trusted, now=NOW)

    def test_untrusted_key_and_wrong_key_rejected(self):
        sig = S.sign_metadata(self.meta, self.priv)
        with self.assertRaises(S.SignatureError):
            S.verify_signed_metadata(self.meta, sig, "unknown", self.trusted, now=NOW)
        _, other_pub = S.generate_keypair_b64()
        with self.assertRaises(S.SignatureError):
            S.verify_signed_metadata(self.meta, sig, "k1", {"k1": other_pub}, now=NOW)

    def test_expired_rejected(self):
        sig = S.sign_metadata(self.meta, self.priv)
        with self.assertRaises(S.SignatureError):
            S.verify_signed_metadata(self.meta, sig, "k1", self.trusted, now=datetime(2028, 1, 1, tzinfo=timezone.utc))

    def test_binding(self):
        S.check_artifact_binding(self.meta, sha256=self.meta["sha256"], size=8, version="1.2.3", channel="stable", os_name="windows", cpu_arch="x86_64")
        with self.assertRaises(S.SignatureError):
            S.check_artifact_binding(self.meta, sha256=self.meta["sha256"], size=8, version="1.2.3", channel="beta", os_name="windows", cpu_arch="x86_64")

    def test_file_digest(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"artifact")
        self.assertEqual(S.sha256_file(f.name), S.sha256_bytes(b"artifact")); os.unlink(f.name)

    def test_versions(self):
        self.assertLess(S.parse_version("1.2.3"), S.parse_version("1.10.0"))
        with self.assertRaises(ValueError):
            S.parse_version("1.2")


if __name__ == "__main__":
    unittest.main()
