"""Site catalog for the Rapid7 Nexpose simulator."""
from .base import iso_z, past_date


SITE_SEED = [
    (1, 'HQ Paris',        'Corporate headquarters',                'static',  'high',      12800),
    (2, 'DR Site',         'Disaster recovery site - Lyon',         'static',  'normal',     4200),
    (3, 'Cloud Ops',       'Public cloud production workloads',     'dynamic', 'very_high', 18500),
    (4, 'Dev Lab',         'R&D development lab',                   'static',  'low',        1300),
    (5, 'Remote Workers',  'Agent-based remote workforce assets',   'agent',   'normal',     6100),
]


def build_sites_catalog():
    sites = []
    for sid, name, desc, stype, importance, risk in SITE_SEED:
        last_scan = past_date(min_days=1, max_days=14)
        sites.append({
            'id': sid,
            'name': name,
            'description': desc,
            'type': stype,
            'importance': importance,
            'riskScore': risk,
            'assets': 0,  # filled in by catalog.py once assets are built
            'vulnerabilities': {'critical': 0, 'severe': 0, 'moderate': 0, 'total': 0},
            'scanTemplate': 'discovery' if stype == 'dynamic' else 'full-audit',
            'scanEngine': 1,
            'lastScanTime': iso_z(last_scan),
            'connectionType': 'authenticated' if stype != 'agent' else 'agent',
            'links': [
                {'href': f'/api/3/sites/{sid}',              'rel': 'self'},
                {'href': f'/api/3/sites/{sid}/assets',       'rel': 'Site Assets'},
                {'href': f'/api/3/sites/{sid}/scans',        'rel': 'Site Scans'},
                {'href': f'/api/3/sites/{sid}/scan_credentials', 'rel': 'Site Scan Credentials'},
                {'href': f'/api/3/sites/{sid}/scan_schedules',   'rel': 'Site Scan Schedules'},
            ],
        })
    return sites
