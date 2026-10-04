#!/usr/bin/env python3
"""Scan Chrome's explicit CPE; prove coverage with a known-vulnerable Chrome first."""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def chrome_package(sbom):
    packages = sbom.get('packages', [])
    if len(packages) != 1 or packages[0].get('name') != 'Google Chrome':
        raise ValueError('CGW_BROWSER_SBOM_IDENTITY')
    package = packages[0]
    version = package.get('versionInfo', '')
    if not re.fullmatch(r'[0-9]+(?:\.[0-9]+){3}', version):
        raise ValueError('CGW_BROWSER_SBOM_VERSION')
    cpe = 'cpe:2.3:a:google:chrome:' + version + ':*:*:*:*:*:*:*'
    refs = package.get('externalRefs', [])
    if not any(ref.get('referenceType') == 'cpe23Type' and ref.get('referenceLocator') == cpe for ref in refs):
        raise ValueError('CGW_BROWSER_SBOM_CPE')
    return package


def scan(sbom, report, config, env):
    subprocess.run(['grype', '--config', str(config), 'sbom:' + str(sbom),
                    '--output', 'json', '--file', str(report)], check=True, env=env, timeout=600)
    result = json.loads(report.read_text(encoding='utf-8'))
    if result.get('descriptor', {}).get('version') != '0.120.0' or not isinstance(result.get('matches'), list):
        raise ValueError('CGW_BROWSER_SCANNER_REPORT')
    if result.get('ignoredMatches'):
        raise ValueError('CGW_BROWSER_SCANNER_SUPPRESSED')
    return result


def high_matches(result):
    return [match for match in result['matches']
            if match['vulnerability']['severity'].lower() in ('high', 'critical')]


def main(sbom_path, report_path):
    sbom = json.loads(sbom_path.read_text(encoding='utf-8'))
    package = chrome_package(sbom)
    env = {key: value for key, value in os.environ.items() if not key.startswith('GRYPE_')}
    with tempfile.TemporaryDirectory(prefix='cgw-browser-scan-') as temporary:
        directory = Path(temporary)
        config = directory / 'grype.yaml'
        config.write_text('check-for-app-update: false\nignore: []\nexclude: []\n'
                          'match:\n  stock:\n    using-cpes: true\n'
                          'db:\n  auto-update: true\n  validate-age: true\n'
                          '  validate-by-hash-on-start: true\n  require-update-check: true\n', encoding='utf-8')
        # Same package/CPE shape and scanner/database, only a known-vulnerable version.
        # A scanner that silently drops this generic package must fail, not bless Chrome.
        sentinel = copy.deepcopy(sbom)
        sentinel_package = sentinel['packages'][0]
        sentinel_package['versionInfo'] = '115.0.5790.171'
        sentinel_package['externalRefs'] = [{'referenceCategory': 'SECURITY', 'referenceType': 'cpe23Type',
            'referenceLocator': 'cpe:2.3:a:google:chrome:115.0.5790.171:*:*:*:*:*:*:*'}]
        sentinel_path = directory / 'vulnerable-chrome.spdx.json'
        sentinel_path.write_text(json.dumps(sentinel), encoding='utf-8')
        coverage = scan(sentinel_path, directory / 'coverage.json', config, env)
        detected = [match for match in high_matches(coverage)
                    if match['artifact']['name'] == 'Google Chrome'
                    and match['artifact']['version'] == '115.0.5790.171'
                    and any(detail.get('matcher') == 'stock-matcher' for detail in match.get('matchDetails', []))]
        if not detected:
            raise ValueError('CGW_BROWSER_SCANNER_NO_CPE_COVERAGE')
        report_path.parent.mkdir(parents=True, exist_ok=True)
        result = scan(sbom_path, report_path, config, env)
        blocked = high_matches(result)
        print(json.dumps({'gate': 'browser-vulnerabilities', 'scanner': 'grype-0.120.0',
                          'version': package['versionInfo'], 'knownVulnerableChromeDetected': True,
                          'highCritical': len(blocked), 'matches': len(result['matches'])}))
        if blocked:
            raise SystemExit('CGW_BROWSER_HIGH_CRITICAL')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sbom', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    main(args.sbom.resolve(), args.report.resolve())
