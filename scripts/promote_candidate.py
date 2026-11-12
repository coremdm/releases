"""Promote an immutable, verified canonical build using only the release repo token."""
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import urllib.parse
import urllib.request
import zipfile

SOURCE = 'coremdm/coremdm'
DISTRIBUTION = 'coremdm/releases'
VERIFIER = 'a765da3be98eb5a8376670e246179a8937d81cd1'
CERTIFICATE = '432840faf7c8019bcbc4ee39dd9594f3568f5d0422f94242b27bee45804837ea'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_request(request):
    for key in ('tag', 'previousTag'):
        require(isinstance(request.get(key), str) and re.fullmatch(r'v\d+\.\d+\.\d+', request[key]), 'Invalid release tag')
    for key in ('sourceCommit', 'verifierCommit'):
        require(isinstance(request.get(key), str) and re.fullmatch('[0-9a-f]{40}', request[key]), 'Invalid pinned commit')
    require(request['verifierCommit'] == VERIFIER, 'Unexpected verifier source')
    for key in ('versionCode', 'previousVersionCode', 'sourceBuildRun', 'verificationRun', 'artifactId'):
        require(type(request.get(key)) is int and request[key] > 0, 'Invalid version or run identifier')
    require(request['versionCode'] > request['previousVersionCode'], 'Candidate must increase the version code')
    require(isinstance(request.get('artifactDigest'), str) and re.fullmatch('sha256:[0-9a-f]{64}', request['artifactDigest']), 'Missing pinned artifact digest')


def validate_provenance(request, artifact, verification, build):
    for run, run_id, commit in ((verification, request['verificationRun'], request['verifierCommit']),
                                (build, request['sourceBuildRun'], request['sourceCommit'])):
        require(run.get('id') == run_id and run.get('repository', {}).get('full_name') == SOURCE, 'Unexpected build repository or run')
        require(run.get('head_sha') == commit and run.get('head_branch') == 'main' and run.get('event') == 'push', 'Unexpected source commit or event')
        require(run.get('status') == 'completed' and run.get('conclusion') == 'success', 'Source validation did not pass')
    require(artifact.get('id') == request['artifactId'] and artifact.get('name') == 'verified-ota-candidate', 'Unexpected artifact identity')
    require(artifact.get('expired') is False and artifact.get('digest') == request['artifactDigest'], 'Artifact expired or changed')
    require(artifact.get('workflow_run', {}).get('id') == request['verificationRun'], 'Artifact belongs to another run')


def extract_candidate(archive, digest, destination):
    require('sha256:' + hashlib.sha256(archive.read_bytes()).hexdigest() == digest, 'Downloaded archive does not match the pinned digest')
    with zipfile.ZipFile(archive) as bundle:
        files = [entry for entry in bundle.infolist() if not entry.is_dir()]
        apks = [entry for entry in files if entry.filename in ('app-release.apk', 'candidate/app-release.apk')]
        reports = [entry for entry in files if entry.filename == 'ota-verification.json']
        require(len(files) == 2 and len(apks) == 1 and len(reports) == 1, 'Unexpected candidate archive contents')
        require(apks[0].file_size <= 100_000_000 and reports[0].file_size <= 64_000, 'Candidate archive is too large')
        destination.mkdir(parents=True, exist_ok=True)
        for entry, name in ((apks[0], 'app-release.apk'), (reports[0], 'ota-verification.json')):
            (destination / name).write_bytes(bundle.read(entry))


def validate_report(report, request):
    expected = dict(tag=request['tag'], versionName=request['tag'][1:], versionCode=request['versionCode'],
                    previousVersionCode=request['previousVersionCode'], sourceCommit=request['sourceCommit'],
                    sourceRepository=SOURCE, distributionRepository=DISTRIBUTION, package='com.core.mdm',
                    certificates=[CERTIFICATE])
    require(all(report.get(key) == value for key, value in expected.items()), 'Candidate report disagrees with the release request')


def validate_public_transfer(request):
    require(request.get('transport') == 'firebase-public-release-artifact', 'Unexpected transfer transport')
    require(request.get('bucket') == 'techeaz-core-mdm.firebasestorage.app', 'Unexpected public artifact bucket')
    require(isinstance(request.get('stagingCommit'), str) and re.fullmatch('[0-9a-f]{40}', request['stagingCommit']), 'Canonical staging receipt is not pinned')
    object_name = request.get('objectName', '')
    require(object_name.startswith('ota-candidates/' + request['tag'] + '/') and '..' not in object_name.split('/'), 'Unexpected public artifact object')
    url = urllib.parse.urlparse(request.get('artifactUrl', ''))
    require(url.scheme == 'https' and url.hostname == 'firebasestorage.googleapis.com' and url.port in (None, 443)
            and url.username is None and url.password is None and not url.fragment, 'Unexpected transfer origin')
    require(urllib.parse.unquote(url.path) == '/v0/b/' + request['bucket'] + '/o/' + object_name, 'Public transfer path disagrees with the receipt')
    query = urllib.parse.parse_qs(url.query)
    require(set(query) == {'alt', 'token'} and query['alt'] == ['media'] and len(query['token']) == 1
            and re.fullmatch('[0-9a-fA-F-]{36}', query['token'][0]), 'Unexpected public artifact download parameters')


def gh_json(endpoint):
    return json.loads(subprocess.check_output(['gh', 'api', endpoint], text=True, env=api_environment(endpoint)))


def api_environment(endpoint):
    environment = os.environ.copy()
    if endpoint.startswith(f'repos/{SOURCE}/'):
        require(bool(environment.get('SOURCE_ARTIFACTS_TOKEN')), 'Private canonical artifacts require SOURCE_ARTIFACTS_TOKEN with read-only contents/actions access')
        environment['GH_TOKEN'] = environment['SOURCE_ARTIFACTS_TOKEN']
    return environment


def find_release(releases, tag):
    matches = [release for release in releases if release.get('tag_name') == tag]
    require(len(matches) <= 1, 'Multiple releases claim the requested version')
    return matches[0] if matches else None


def validate_release_assets(release, candidate):
    require({asset['name'] for asset in release.get('assets', [])} == {'app-release.apk', 'ota-verification.json'}, 'Release upload is incomplete')
    for asset in release['assets']:
        require(asset['size'] == (candidate / asset['name']).stat().st_size, 'Uploaded candidate asset size changed')


def main(request_path, verifier):
    request = json.loads(request_path.read_text(encoding='utf-8'))
    validate_request(request)
    require(os.environ.get('GITHUB_REPOSITORY') == DISTRIBUTION, 'Publication must run in the releases repository')
    public_transfer = request.get('transport') == 'firebase-public-release-artifact'
    if public_transfer:
        validate_public_transfer(request)
    else:
        artifact = gh_json(f'repos/{SOURCE}/actions/artifacts/{request["artifactId"]}')
        verification = gh_json(f'repos/{SOURCE}/actions/runs/{request["verificationRun"]}')
        build = gh_json(f'repos/{SOURCE}/actions/runs/{request["sourceBuildRun"]}')
        validate_provenance(request, artifact, verification, build)
    latest = gh_json(f'repos/{DISTRIBUTION}/releases/latest')
    require(latest.get('tag_name') in (request['previousTag'], request['tag']), 'The production release changed; review a new promotion request')
    work = pathlib.Path(os.environ['RUNNER_TEMP']) / 'coremdm-promotion'
    work.mkdir()
    archive = work / 'candidate.zip'
    with archive.open('wb') as output:
        if public_transfer:
            with urllib.request.urlopen(request['artifactUrl'], timeout=60) as response:
                downloaded = 0
                while chunk := response.read(1024 * 1024):
                    downloaded += len(chunk)
                    require(downloaded <= 100_000_000, 'Transfer archive is too large')
                    output.write(chunk)
        else:
            endpoint = f'repos/{SOURCE}/actions/artifacts/{request["artifactId"]}/zip'
            subprocess.run(['gh', 'api', endpoint], stdout=output, check=True, env=api_environment(endpoint))
    candidate = work / 'candidate'
    extract_candidate(archive, request['artifactDigest'], candidate)
    report = json.loads((candidate / 'ota-verification.json').read_text(encoding='utf-8'))
    validate_report(report, request)
    previous = work / 'previous'
    previous.mkdir()
    subprocess.run(['gh', 'release', 'download', request['previousTag'], '--repo', DISTRIBUTION,
                    '--pattern', 'app-release.apk', '--dir', str(previous)], check=True)
    tools = sorted((pathlib.Path(os.environ['ANDROID_HOME']) / 'build-tools').iterdir(),
                   key=lambda p: tuple(int(n) for n in re.findall(r'\d+', p.name)))[-1]
    independent = work / 'independent-verification.json'
    subprocess.run([sys.executable, str(verifier), '--tools', str(tools), '--apk', str(candidate / 'app-release.apk'),
                    '--previous', str(previous / 'app-release.apk'), '--tag', request['tag'],
                    '--source', request['sourceCommit'], '--report', str(independent)], check=True)
    require(json.loads(independent.read_text()) == report, 'Independent APK verification disagrees with the build report')
    notes = work / 'release-notes.md'
    notes.write_text(f'Production-signed CoreMDM {request["tag"]}, version code {request["versionCode"]}.\n\n'
                     f'Source: https://github.com/{SOURCE}/commit/{request["sourceCommit"]}\n\n'
                     'Package, production signer, artifact integrity and increasing OTA version verified before publication.\n', encoding='utf-8')
    release = find_release(gh_json(f'repos/{DISTRIBUTION}/releases?per_page=100'), request['tag'])
    if release is None:
        subprocess.run(['gh', 'release', 'create', request['tag'], '--repo', DISTRIBUTION, '--target', os.environ['GITHUB_SHA'],
                        '--draft', '--title', 'CoreMDM ' + request['tag'], '--notes-file', str(notes),
                        str(candidate / 'app-release.apk'), str(candidate / 'ota-verification.json')], check=True)
        release = find_release(gh_json(f'repos/{DISTRIBUTION}/releases?per_page=100'), request['tag'])
    require(release is not None, 'Uploaded release draft was not found')
    validate_release_assets(release, candidate)
    # Drafts may not have a Git tag yet. Address draft/assets by their IDs, not the tag endpoint.
    for asset in release['assets']:
        downloaded = work / ('uploaded-' + asset['name'])
        with downloaded.open('wb') as output:
            subprocess.run(['gh', 'api', '-H', 'Accept: application/octet-stream', f'repos/{DISTRIBUTION}/releases/assets/{asset["id"]}'], stdout=output, check=True)
        require(hashlib.sha256(downloaded.read_bytes()).digest() == hashlib.sha256((candidate / asset['name']).read_bytes()).digest(), 'Uploaded release asset bytes changed')
    if release.get('draft') is True:
        publication = work / 'publish.json'
        publication.write_text(json.dumps({'draft': False, 'make_latest': 'true'}), encoding='utf-8')
        subprocess.run(['gh', 'api', '--method', 'PATCH', f'repos/{DISTRIBUTION}/releases/{release["id"]}', '--input', str(publication)], stdout=subprocess.DEVNULL, check=True)
    published = gh_json(f'repos/{DISTRIBUTION}/releases/{release["id"]}')
    require(published.get('draft') is False and published.get('tag_name') == request['tag'], 'Release was not published')
    published_files = work / 'published'
    published_files.mkdir()
    subprocess.run(['gh', 'release', 'download', request['tag'], '--repo', DISTRIBUTION, '--dir', str(published_files)], check=True)
    for name in ('app-release.apk', 'ota-verification.json'):
        require(hashlib.sha256((published_files / name).read_bytes()).digest() == hashlib.sha256((candidate / name).read_bytes()).digest(), 'Published asset bytes do not match the verified candidate')
    print('Published verified production OTA ' + request['tag'])


if __name__ == '__main__':
    main(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]))
