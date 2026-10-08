"""
Asset catalog for the Rapid7 Nexpose simulator. Each asset combines a
Business Corp persona (or a generated server) with a Nexpose-shaped payload.
"""
import random
from datetime import timedelta

from .base import (
    EXTRA_OS,
    USERS,
    fake_mac,
    iso_z,
    os_for_persona,
    os_summary,
    past_date,
)
from .vulnerabilities import compatible_vulns


# Software roles per hostname, on top of the platform derived from the OS. They decide
# which catalog CVEs an asset can realistically carry (see CVE_REQUIREMENTS).
# Hosts not listed here only get their OS platform (windows-server, linux, ...).
ASSET_ROLES = {
    'srv-web-01.business.org':     ['java', 'web'],
    'srv-web-02.business.org':     ['web', 'php'],
    'srv-db-01.business.org':      ['postgresql'],
    'srv-db-02.business.org':      ['postgresql'],
    'srv-mail.business.org':       ['exchange'],
    'srv-ad-01.business.org':      ['domain-controller'],
    'srv-monitoring.business.org': ['grafana'],
    'srv-ci.business.org':         ['java', 'teamcity'],
    'cloud-app-01.business.org':   ['java', 'activemq'],
}


EXTRA_SERVER_SEED = [
    # hostname, ip, os_name, site_id
    ('srv-web-01.business.org',   '10.10.20.51', 'Windows Server 2019', 1),
    ('srv-web-02.business.org',   '10.10.20.52', 'Ubuntu 22.04 LTS',    1),
    ('srv-db-01.business.org',    '10.10.20.53', 'Debian 12',            1),
    ('srv-db-02.business.org',    '10.10.20.54', 'Debian 12',            2),
    ('srv-mail.business.org',     '10.10.20.55', 'Windows Server 2019', 1),
    ('srv-ad-01.business.org',    '10.10.20.56', 'Windows Server 2022', 1),
    ('srv-fs-01.business.org',    '10.10.20.57', 'Windows Server 2019', 1),
    ('srv-vpn.business.org',      '10.10.20.58', 'Ubuntu 20.04 LTS',    1),
    ('srv-monitoring.business.org','10.10.20.59','Debian 12',            4),
    ('srv-ci.business.org',       '10.10.20.60', 'Ubuntu 22.04 LTS',    4),
    ('cloud-lb-01.business.org',  '10.20.30.10', 'Ubuntu 22.04 LTS',    3),
    ('cloud-app-01.business.org', '10.20.30.11', 'Debian 12',            3),
]

SERVICES_CATALOG = [
    {'family': 'HTTP', 'name': 'HTTP', 'port': 80,  'product': 'nginx',  'protocol': 'tcp'},
    {'family': 'HTTPS','name': 'HTTPS','port': 443, 'product': 'nginx',  'protocol': 'tcp'},
    {'family': 'SSH',  'name': 'SSH',  'port': 22,  'product': 'OpenSSH','protocol': 'tcp'},
    {'family': 'SMB',  'name': 'CIFS', 'port': 445, 'product': 'Microsoft SMB', 'protocol': 'tcp'},
    {'family': 'RDP',  'name': 'RDP',  'port': 3389,'product': 'Microsoft RDP', 'protocol': 'tcp'},
    {'family': 'PostgreSQL','name':'PostgreSQL','port':5432,'product':'PostgreSQL','protocol':'tcp'},
]


def _vuln_counts(vulns):
    crit = sum(1 for v in vulns if v['severity'] == 'Critical')
    sev = sum(1 for v in vulns if v['severity'] == 'Severe')
    mod = sum(1 for v in vulns if v['severity'] == 'Moderate')
    return {
        'critical': crit, 'severe': sev, 'moderate': mod,
        'total': crit + sev + mod,
        'exploits': sum(v.get('exploits', 0) for v in vulns),
        'malwareKits': sum(v.get('malwareKits', 0) for v in vulns),
    }


def asset_platforms(hostname, os_fp):
    """Platform + role tags used to pick CVEs compatible with this asset."""
    family = (os_fp.get('family') or '').lower()
    if family == 'windows':
        if (os_fp.get('type') or '').lower() == 'server':
            tags = {'windows-server'}
        else:
            tags = {'windows-client', 'office', 'browser'}
    elif family == 'macos':
        tags = {'macos', 'browser'}
    elif family == 'ios':
        tags = {'ios'}
    elif family == 'pan-os':
        tags = {'panos'}
    else:
        tags = {'linux'}
    return tags | set(ASSET_ROLES.get((hostname or '').lower(), []))


def _pick_services(r, os_fp):
    """Pick a small subset of services based on OS type."""
    fam = os_fp.get('family', '').lower()
    if fam == 'windows':
        candidates = ['SMB', 'RDP', 'HTTPS', 'HTTP']
    elif fam == 'linux':
        candidates = ['SSH', 'HTTP', 'HTTPS', 'PostgreSQL']
    elif fam == 'pan-os':
        candidates = ['HTTPS']
    else:
        candidates = ['SSH', 'HTTPS']
    picked = r.sample(candidates, k=min(len(candidates), r.randint(1, 3)))
    return [s for s in SERVICES_CATALOG if s['name'] in picked or s['family'] in picked]


def _asset_risk(vulns):
    return round(sum(v.get('riskScore', 0) for v in vulns), 2)


def _persona_assets(vulns_pool, r):
    assets = []
    for idx, persona in enumerate(USERS):
        fp = os_for_persona(persona)
        pool = compatible_vulns(vulns_pool, asset_platforms(persona['hostname'], fp))
        vulns = r.sample(pool, k=min(len(pool), r.randint(4, 12)))
        last_scan = past_date(min_days=0, max_days=3)
        site_id = 5 if persona.get('machine_type') in ('laptop', 'mobile') else 1
        assets.append({
            'id': 100 + idx,
            'ip': persona['internal_ip'],
            'mac': fake_mac(),
            'hostName': persona['hostname'],
            'os': os_summary(fp),
            'osFingerprint': fp,
            'type': 'workstation',
            'assessedForVulnerabilities': True,
            'assessedForPolicies': True,
            'riskScore': _asset_risk(vulns),
            'vulnerabilities': _vuln_counts(vulns),
            'sites': [site_id],
            'services': _pick_services(r, fp),
            'addresses': [{'ip': persona['internal_ip'], 'mac': fake_mac()}],
            'hostNames': [{'name': persona['hostname'], 'source': 'dns'}],
            'ids': [{'source': 'nexpose', 'id': str(100 + idx)}],
            'history': [{
                'date': iso_z(last_scan),
                'scanId': 5000,
                'type': 'SCAN',
                'version': 1,
                'vulnerabilityExceptions': 0,
            }],
            'lastAssessedForVulnerabilities': iso_z(last_scan),
            'lastScanEnd': iso_z(last_scan),
            'lastScanStart': iso_z(last_scan - timedelta(minutes=30)),
            'links': [{'href': f'/api/3/assets/{100 + idx}', 'rel': 'self'}],
            '_vulns': vulns,
        })
    return assets


def _extra_assets(vulns_pool, r, count):
    assets = []
    seed = EXTRA_SERVER_SEED[:count]
    for idx, (hostname, ip, os_name, site_id) in enumerate(seed):
        fp = EXTRA_OS.get(os_name) or EXTRA_OS['Ubuntu 22.04 LTS']
        pool = compatible_vulns(vulns_pool, asset_platforms(hostname, fp))
        vulns = r.sample(pool, k=min(len(pool), r.randint(8, 20)))
        last_scan = past_date(min_days=0, max_days=5)
        asset_id = 200 + idx
        assets.append({
            'id': asset_id,
            'ip': ip,
            'mac': fake_mac(),
            'hostName': hostname,
            'os': os_summary(fp),
            'osFingerprint': fp,
            'type': 'server',
            'assessedForVulnerabilities': True,
            'assessedForPolicies': True,
            'riskScore': _asset_risk(vulns),
            'vulnerabilities': _vuln_counts(vulns),
            'sites': [site_id],
            'services': _pick_services(r, fp),
            'addresses': [{'ip': ip, 'mac': fake_mac()}],
            'hostNames': [{'name': hostname, 'source': 'dns'}],
            'ids': [{'source': 'nexpose', 'id': str(asset_id)}],
            'history': [{
                'date': iso_z(last_scan),
                'scanId': 5000,
                'type': 'SCAN',
                'version': 1,
                'vulnerabilityExceptions': 0,
            }],
            'lastAssessedForVulnerabilities': iso_z(last_scan),
            'lastScanEnd': iso_z(last_scan),
            'lastScanStart': iso_z(last_scan - timedelta(minutes=45)),
            'links': [{'href': f'/api/3/assets/{asset_id}', 'rel': 'self'}],
            '_vulns': vulns,
        })
    return assets


def build_assets_catalog(vulns_pool, extra_count=12):
    r = random.Random(4242)
    assets = _persona_assets(vulns_pool, r)
    assets.extend(_extra_assets(vulns_pool, r, extra_count))
    return assets


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------

def asset_summary(asset):
    """List-view payload (drops the internal `_vulns` field)."""
    return {k: v for k, v in asset.items() if not k.startswith('_')}


def asset_vulnerability_row(asset, vuln):
    """One row of GET /assets/{id}/vulnerabilities."""
    return {
        'id': vuln['id'],
        'instances': 1,
        'results': [
            {
                'checkId': vuln['id'],
                'exceptions': [],
                'key': '',
                'links': [
                    {'href': f'/api/3/assets/{asset["id"]}/vulnerabilities/{vuln["id"]}/solution',
                     'rel': 'Solution'},
                ],
                'port': 0,
                'proof': f'<p>Product version indicates vulnerability {vuln["id"]}.</p>',
                'protocol': 'tcp',
                'since': asset['lastAssessedForVulnerabilities'],
                'status': 'vulnerable',
            },
        ],
        'since': asset['lastAssessedForVulnerabilities'],
        'status': 'vulnerable',
    }


def asset_vulnerability_solution(asset, vuln):
    """
    Payload for GET /assets/{id}/vulnerabilities/{vuln_id}/solution.

    Returned as a Nexpose {resources: [...]} envelope.
    """
    from .vulnerabilities import solution_for
    return solution_for(vuln)
