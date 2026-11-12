import unittest
from verify_ota import CERTIFICATE, certificates, validate


class OtaIdentityTests(unittest.TestCase):
    def test_reads_legacy_and_scheme_labelled_signers(self):
        for label in ('Signer #1', 'V2 Signer:', 'V3 Signer:', 'V3.1 Signer:'):
            with self.subTest(label=label):
                self.assertEqual(certificates(label + ' certificate SHA-256 digest: ' + CERTIFICATE), [CERTIFICATE])

    def test_keeps_unknown_signers_and_ignores_non_signer_certificate_metadata(self):
        output = '\n'.join(['V2 Signer: certificate SHA-256 digest: ' + CERTIFICATE,
                            'V3 Signer: certificate SHA-256 digest: ' + CERTIFICATE,
                            'Signer #2 certificate SHA-256 digest: ' + 'f' * 64,
                            'Source Stamp Signer certificate SHA-256 digest: ' + 'a' * 64])
        self.assertEqual(certificates(output), [CERTIFICATE, 'f' * 64])
        with self.assertRaises(ValueError):
            validate(dict(package='com.core.mdm', certificates=certificates(output), versionCode=115, versionName='0.9.50'), self.previous, 'v0.9.50')

    def test_refuses_unrecognized_or_truncated_signer_output(self):
        self.assertEqual(certificates('V2 Signer: certificate SHA-256 digest: ' + CERTIFICATE[:-1]), [])
        self.assertEqual(certificates('unrecognized certificate SHA-256 digest: ' + CERTIFICATE), [])

    def setUp(self):
        self.previous = dict(package="com.core.mdm", certificates=[CERTIFICATE], versionCode=114, versionName="0.9.49")
        self.candidate = dict(self.previous, versionCode=115, versionName="0.9.50")

    def test_accepts_matching_production_upgrade(self):
        validate(self.candidate, self.previous, "v0.9.50")

    def test_rejects_wrong_or_additional_signers(self):
        for certificates in ([], ["debug"], [CERTIFICATE, "extra"]):
            with self.subTest(certificates=certificates), self.assertRaises(ValueError):
                validate(dict(self.candidate, certificates=certificates), self.previous, "v0.9.50")

    def test_rejects_package_change(self):
        with self.assertRaises(ValueError):
            validate(dict(self.candidate, package="com.other.app"), self.previous, "v0.9.50")

    def test_rejects_downgrade_or_same_version(self):
        for code in (113, 114):
            with self.subTest(code=code), self.assertRaises(ValueError):
                validate(dict(self.candidate, versionCode=code), self.previous, "v0.9.50")

    def test_rejects_mismatched_or_nonrelease_tag(self):
        for tag in ("v0.9.49", "build-123", "v0.9.50\n"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                validate(self.candidate, self.previous, tag)


if __name__ == "__main__":
    unittest.main()
