import copy
import hashlib
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from promote_candidate import api_environment, extract_candidate, validate_provenance, validate_report, validate_request, validate_public_transfer, CERTIFICATE

REQUEST = json.loads((pathlib.Path(__file__).parent.parent / 'promotion-request.json').read_text())


class PromotionSafeguards(unittest.TestCase):
    def test_public_transport_is_limited_to_the_canonical_release_bucket_and_receipt(self):
        request = dict(REQUEST, transport='firebase-public-release-artifact', bucket='techeaz-core-mdm.firebasestorage.app',
                       stagingCommit='a' * 40, objectName='ota-candidates/v0.9.50/test/verified-candidate.zip',
                       artifactUrl='https://firebasestorage.googleapis.com/v0/b/techeaz-core-mdm.firebasestorage.app/o/ota-candidates%2Fv0.9.50%2Ftest%2Fverified-candidate.zip?alt=media&token=00000000-0000-0000-0000-000000000000')
        validate_public_transfer(request)
        for changes in ({'artifactUrl': 'https://example.org/payload'}, {'bucket': 'someone-else'},
                        {'stagingCommit': ''}, {'objectName': '../unexpected'}, {'transport': 'arbitrary-url'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate_public_transfer(dict(request, **changes))

    def test_private_read_credential_is_never_used_for_release_writes(self):
        with patch.dict('os.environ', {'GH_TOKEN': 'release-token', 'SOURCE_ARTIFACTS_TOKEN': 'read-only-source-token'}, clear=True):
            self.assertEqual(api_environment('repos/coremdm/coremdm/actions/artifacts/1')['GH_TOKEN'], 'read-only-source-token')
            self.assertEqual(api_environment('repos/coremdm/releases/releases/latest')['GH_TOKEN'], 'release-token')
        with patch.dict('os.environ', {'GH_TOKEN': 'release-token'}, clear=True), self.assertRaises(ValueError):
            api_environment('repos/coremdm/coremdm/actions/artifacts/1')

    def test_request_rejects_invalid_versions_commits_and_artifact_pins(self):
        validate_request(REQUEST)
        for changes in ({'versionCode': 114}, {'sourceCommit': 'main'}, {'verifierCommit': 'b' * 40},
                        {'artifactDigest': 'unknown'}, {'artifactId': True}, {'tag': 'v0.9.50\n'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate_request(dict(REQUEST, **changes))

    def provenance(self):
        artifact = dict(id=REQUEST['artifactId'], name='verified-ota-candidate', expired=False,
                        digest=REQUEST['artifactDigest'], workflow_run={'id': REQUEST['verificationRun']})
        def run(key, commit):
            return dict(id=REQUEST[key], repository={'full_name': 'coremdm/coremdm'},
                        head_sha=REQUEST[commit], head_branch='main', event='push', status='completed', conclusion='success')
        return artifact, run('verificationRun', 'verifierCommit'), run('sourceBuildRun', 'sourceCommit')

    def test_refuses_foreign_untrusted_or_failed_builds(self):
        validate_provenance(REQUEST, *self.provenance())
        for target, changes in ((0, {'expired': True}), (0, {'digest': 'sha256:' + 'a' * 64}),
                                (0, {'workflow_run': {'id': 123}}), (1, {'conclusion': 'failure'}),
                                (1, {'event': 'pull_request'}), (2, {'head_sha': 'b' * 40}),
                                (2, {'repository': {'full_name': 'someone/mirror'}})):
            values = list(copy.deepcopy(self.provenance()))
            values[target].update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate_provenance(REQUEST, *values)

    def test_report_must_match_pinned_production_source_and_version(self):
        report = dict(tag='v0.9.50', versionName='0.9.50', versionCode=115, previousVersionCode=114,
                      sourceCommit=REQUEST['sourceCommit'], sourceRepository='coremdm/coremdm',
                      distributionRepository='coremdm/releases', package='com.core.mdm', certificates=[CERTIFICATE])
        validate_report(report, REQUEST)
        for changes in ({'certificates': ['debug']}, {'sourceCommit': 'a' * 40}, {'versionCode': 116},
                        {'previousVersionCode': 113}, {'package': 'another.app'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate_report(dict(report, **changes), REQUEST)

    def test_archive_digest_and_safe_contents_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            archive = root / 'artifact.zip'
            with zipfile.ZipFile(archive, 'w') as bundle:
                bundle.writestr('candidate/app-release.apk', b'candidate')
                bundle.writestr('ota-verification.json', '{}')
            digest = 'sha256:' + hashlib.sha256(archive.read_bytes()).hexdigest()
            extract_candidate(archive, digest, root / 'extracted')
            self.assertEqual((root / 'extracted/app-release.apk').read_bytes(), b'candidate')
            with self.assertRaises(ValueError):
                extract_candidate(archive, 'sha256:' + '0' * 64, root / 'wrong-digest')
            with zipfile.ZipFile(archive, 'a') as bundle:
                bundle.writestr('../unexpected.txt', 'must not escape')
            digest = 'sha256:' + hashlib.sha256(archive.read_bytes()).hexdigest()
            with self.assertRaises(ValueError):
                extract_candidate(archive, digest, root / 'unexpected')


if __name__ == '__main__':
    unittest.main()
