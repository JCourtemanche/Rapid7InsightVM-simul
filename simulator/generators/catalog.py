"""Single instantiation of the whole Rapid7 Nexpose dataset."""
from config import Config

from .assets import build_assets_catalog
from .scans import ScanStore, build_engines_catalog, build_historical_scans
from .sites import build_sites_catalog
from .vulnerabilities import build_vulnerability_catalog


VULNERABILITIES = build_vulnerability_catalog(count=Config.VULN_COUNT)
ASSETS = build_assets_catalog(VULNERABILITIES, extra_count=Config.EXTRA_SERVERS)
SITES = build_sites_catalog()
ENGINES = build_engines_catalog()
SCAN_STORE = ScanStore(build_historical_scans())

# Sum up site counts (asset count, vulnerability roll-up)
_site_asset_ids: dict[int, list] = {}
_site_vuln_counts: dict[int, dict] = {}
for _a in ASSETS:
    for _sid in _a['sites']:
        _site_asset_ids.setdefault(_sid, []).append(_a['id'])
        counts = _site_vuln_counts.setdefault(_sid, {'critical': 0, 'severe': 0, 'moderate': 0, 'total': 0})
        for k in counts:
            counts[k] += _a['vulnerabilities'].get(k, 0)
for _s in SITES:
    _s['assets'] = len(_site_asset_ids.get(_s['id'], []))
    _s['vulnerabilities'] = _site_vuln_counts.get(_s['id'], {'critical': 0, 'severe': 0, 'moderate': 0, 'total': 0})

VULNERABILITIES_BY_ID = {v['id']: v for v in VULNERABILITIES}
VULNERABILITIES_BY_CVE = {v['cves'][0]: v for v in VULNERABILITIES if v['cves']}
ASSETS_BY_ID = {a['id']: a for a in ASSETS}
SITES_BY_ID = {s['id']: s for s in SITES}
ENGINES_BY_ID = {e['id']: e for e in ENGINES}


def assets_in_site(site_id):
    return [a for a in ASSETS if int(site_id) in a['sites']]
