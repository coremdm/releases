"""Validate OTA identity before publication; reads public certificate metadata only."""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess

CERTIFICATE = "432840faf7c8019bcbc4ee39dd9594f3568f5d0422f94242b27bee45804837ea"
PACKAGE = "com.core.mdm"


def certificates(output):
    # New build tools label signers by signature scheme; older tools number them.
    pattern = r"^(?:Signer #\d+|V[1-4](?:\.\d+)? Signer(?: #\d+)?):? certificate SHA-256 digest: ([0-9a-fA-F]{64})\s*$"
    return list(dict.fromkeys(value.lower() for value in re.findall(pattern, output, re.MULTILINE)))


def tool(directory, name):
    for candidate in (directory / name, directory / (name + ".exe"), directory / (name + ".bat")):
        if candidate.exists():
            return str(candidate)
    raise FileNotFoundError(f"Android build tool {name} was not found")


def validate(candidate, previous, tag):
    if candidate["certificates"] != [CERTIFICATE] or previous["certificates"] != [CERTIFICATE]:
        raise ValueError("APK must have the established production signer")
    if candidate["package"] != PACKAGE or previous["package"] != PACKAGE:
        raise ValueError("OTA package identity mismatch")
    if candidate["versionCode"] <= previous["versionCode"]:
        raise ValueError("OTA versionCode must increase")
    if not re.fullmatch(r"v\d+\.\d+\.\d+", tag) or tag[1:] != candidate["versionName"]:
        raise ValueError("Release tag must match the APK versionName")


def inspect(apk, tools):
    certs = subprocess.check_output([tool(tools, "apksigner"), "verify", "--print-certs", str(apk)], text=True)
    badging = subprocess.check_output([tool(tools, "aapt"), "dump", "badging", str(apk)], text=True)
    match = re.search(r"package: name='([^']+)' versionCode='(\d+)' versionName='([^']+)'", badging)
    if not match:
        raise ValueError("APK package metadata is missing")
    package, code, name = match.groups()
    return {"package": package, "versionCode": int(code), "versionName": name,
            "certificates": certificates(certs),
            "sha256": hashlib.sha256(apk.read_bytes()).hexdigest()}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for argument in ("tools", "apk", "previous", "tag", "source", "report"):
        parser.add_argument("--" + argument, required=True)
    args = parser.parse_args()
    candidate = inspect(pathlib.Path(args.apk), pathlib.Path(args.tools))
    previous = inspect(pathlib.Path(args.previous), pathlib.Path(args.tools))
    validate(candidate, previous, args.tag)
    report = {**candidate, "tag": args.tag, "sourceRepository": "coremdm/coremdm", "sourceCommit": args.source,
              "distributionRepository": "coremdm/releases", "previousVersionCode": previous["versionCode"]}
    pathlib.Path(args.report).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
